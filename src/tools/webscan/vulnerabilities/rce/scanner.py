#!/usr/bin/env python3

import time
import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

class RCEScanner:
    """Scanner for detecting Remote Code Execution (RCE) vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the RCE Scanner with a reference to the main scanner instance
        
        Args:
            scanner_instance: The main WebScanner instance
        """
        self.scanner = scanner_instance
        self.target_url = scanner_instance.target_url
        self.headers = scanner_instance.headers
        self.timeout = scanner_instance.timeout
        self.verbose = scanner_instance.verbose
        self.max_threads = scanner_instance.max_threads
        self.vulnerabilities = scanner_instance.vulnerabilities
        self.forms = scanner_instance.forms
        
        # List of RCE payloads for various platforms
        self.rce_payloads = [
            # Linux commands
            "sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "& sleep 5 &",
            "; sleep 5;",
            "| sleep 5 |",
            "|| sleep 5",
            "&& sleep 5",
            # Python code
            "eval('__import__(\"time\").sleep(5)')",
            "exec('import time; time.sleep(5)')",
            # PHP code
            "<?php sleep(5); ?>",
            "<?php system('sleep 5'); ?>",
            "<?php passthru('sleep 5'); ?>",
            "<?php exec('sleep 5'); ?>",
            "<?php shell_exec('sleep 5'); ?>",
            # Ruby code
            "<%= sleep 5 %>",
            "<%= `sleep 5` %>",
            # Node.js
            "res.end(require('child_process').execSync('sleep 5').toString())"
        ]
        
        # Indicators of successful code execution in the response
        self.indicators = [
            "syntax error",
            "undefined variable",
            "command not found",
            "shell_exec",
            "system(",
            "exec(",
            "eval(",
            "ReferenceError",
            "TypeError",
            "SyntaxError",
            "unexpected token",
            "ValueError",
            "ZeroDivisionError",
            "subprocess",
            "module 'os'",
            "child_process"
        ]
    
    def test_form(self, form):
        """
        Test a single form for RCE vulnerabilities
        
        Args:
            form (dict): Form data containing action, method, and inputs
        """
        url = form.get('action', self.target_url)
        
        # Handle relative URLs
        if not url.startswith(('http://', 'https://')):
            if url.startswith('/'):
                # Absolute path relative to domain
                parsed_url = urlparse(self.target_url)
                url = f"{parsed_url.scheme}://{parsed_url.netloc}{url}"
            else:
                # Relative path to current directory
                url = urljoin(self.target_url, url)
        
        method = form.get('method', 'get').lower()
        inputs = form.get('inputs', [])
        
        if not inputs:
            return
        
        for payload in self.rce_payloads:
            for input_field in inputs:
                # Create a copy of the form data for each test
                data = {}
                for inp in inputs:
                    input_name = inp.get('name', '')
                    input_value = inp.get('value', '')
                    
                    if input_name == input_field.get('name'):
                        data[input_name] = payload
                    else:
                        data[input_name] = input_value
                
                try:
                    if self.verbose:
                        print(f"  Testing {method.upper()} {url} with payload in {input_field.get('name')}: {payload}")
                    
                    # Record the start time
                    start_time = time.time()
                    
                    # Send the request
                    if method == 'post':
                        response = requests.post(url, data=data, headers=self.headers, 
                                               timeout=self.timeout, 
                                               verify=False, 
                                               allow_redirects=False)
                    else:
                        response = requests.get(url, params=data, headers=self.headers, 
                                              timeout=self.timeout, 
                                              verify=False, 
                                              allow_redirects=False)
                    
                    # Calculate the time the request took
                    request_time = time.time() - start_time
                    
                    # Check for time delay (indicating blind RCE)
                    if "sleep 5" in payload and request_time > 4.5:
                        vulnerability = {
                            'type': 'Remote Code Execution (RCE)',
                            'url': url,
                            'method': method.upper(),
                            'parameter': input_field.get('name', ''),
                            'payload': payload,
                            'evidence': f"Time delay detected: {request_time:.2f} seconds",
                            'severity': 'Critical'
                        }
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"  [!] RCE vulnerability (time-based) found at {url}" + Style.RESET_ALL)
                            print(Fore.RED + f"      Parameter: {input_field.get('name', '')}" + Style.RESET_ALL)
                            print(Fore.RED + f"      Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.RED + f"      Evidence: Time delay detected: {request_time:.2f} seconds" + Style.RESET_ALL)
                    
                    # Check for indicators in the response content
                    response_text = response.text.lower()
                    for indicator in self.indicators:
                        if indicator.lower() in response_text:
                            vulnerability = {
                                'type': 'Remote Code Execution (RCE)',
                                'url': url,
                                'method': method.upper(),
                                'parameter': input_field.get('name', ''),
                                'payload': payload,
                                'evidence': f"Response contains indicator: {indicator}",
                                'severity': 'Critical'
                            }
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"  [!] RCE vulnerability found at {url}" + Style.RESET_ALL)
                                print(Fore.RED + f"      Parameter: {input_field.get('name', '')}" + Style.RESET_ALL)
                                print(Fore.RED + f"      Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.RED + f"      Evidence: Response contains indicator: {indicator}" + Style.RESET_ALL)
                            break
                
                except requests.Timeout:
                    # Timeout could indicate command execution (especially with sleep payloads)
                    vulnerability = {
                        'type': 'Remote Code Execution (RCE)',
                        'url': url,
                        'method': method.upper(),
                        'parameter': input_field.get('name', ''),
                        'payload': payload,
                        'evidence': 'Request timed out (potential blind command execution)',
                        'severity': 'Critical'
                    }
                    self.vulnerabilities.append(vulnerability)
                    
                    if self.verbose:
                        print(Fore.RED + f"  [!] Potential RCE vulnerability found at {url}" + Style.RESET_ALL)
                        print(Fore.RED + f"      Parameter: {input_field.get('name', '')}" + Style.RESET_ALL)
                        print(Fore.RED + f"      Payload: {payload}" + Style.RESET_ALL)
                        print(Fore.RED + f"      Evidence: Request timed out (potential blind command execution)" + Style.RESET_ALL)
                
                except Exception as e:
                    if self.verbose:
                        print(Fore.YELLOW + f"  [!] Error testing {url}: {str(e)}" + Style.RESET_ALL)
    
    def run(self):
        """
        Test for Remote Code Execution (RCE) vulnerabilities in forms.
        
        Returns:
            int: Number of RCE vulnerabilities found
        """
        if not self.forms:
            if self.verbose:
                print(Fore.YELLOW + "[*] No forms found to test for RCE vulnerabilities" + Style.RESET_ALL)
            return 0
            
        if self.verbose:
            print(Fore.BLUE + "[*] Testing forms for Remote Code Execution (RCE) vulnerabilities..." + Style.RESET_ALL)
        
        # Test each form for RCE vulnerabilities
        rce_count = len([v for v in self.vulnerabilities if v.get('type') == 'Remote Code Execution (RCE)'])
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            list(executor.map(self.test_form, self.forms))
        
        # Count how many RCE vulnerabilities were found
        rce_vulnerabilities = sum(1 for v in self.vulnerabilities if v.get('type') == 'Remote Code Execution (RCE)')
        rce_vulnerabilities_found = rce_vulnerabilities - rce_count
        
        print(Fore.GREEN + f"[+] Completed RCE testing, found {rce_vulnerabilities_found} vulnerabilities" + Style.RESET_ALL)
        return rce_vulnerabilities_found 