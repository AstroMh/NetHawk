#!/usr/bin/env python3

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

class OpenRedirectScanner:
    """Scanner for detecting Open Redirect vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the Open Redirect Scanner with a reference to the main scanner instance
        
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
        
        # Common URL parameters that might be vulnerable to open redirect
        self.redirect_parameters = [
            'redirect', 'url', 'return', 'next', 'redir', 'r', 
            'redirect_uri', 'redirect_url', 'goto', 'target', 
            'destination', 'rurl', 'returnUrl', 'retURL', 
            'returnURL', 'return_url', 'go', 'link'
        ]
        
        # Payloads to test for open redirect vulnerabilities
        self.redirect_payloads = [
            'https://example.com', 
            '//example.com', 
            'javascript:alert("Open Redirect")',
            '\\\\example.com',
            'https:example.com',
            '///example.com',
            '/\\example.com'
        ]
    
    def test_url_parameter(self, url):
        """
        Test URL parameters for open redirect vulnerabilities
        
        Args:
            url (str): URL to test
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Parse the URL to get query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Check if the URL has any query parameters, if not, return
        if not query_params:
            return vulnerabilities
            
        # Check if any of the parameters might be used for redirection
        for param_name in self.redirect_parameters:
            if param_name in query_params:
                # Test with different payloads
                for payload in self.redirect_payloads:
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
                        # Set allow_redirects to False to see the 3xx response
                        response = self.session.get(modified_url, timeout=self.timeout, allow_redirects=False)
                        
                        # Check for 3xx redirect responses
                        if 300 <= response.status_code < 400:
                            location = response.headers.get('Location', '')
                            
                            # Check if the redirect leads to our payload domain
                            if 'example.com' in location or 'javascript:' in location:
                                vulnerability = {
                                    'type': 'Open Redirect',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': f"Redirects to: {location}",
                                    'status_code': response.status_code,
                                    'severity': 'Medium'
                                }
                                vulnerabilities.append(vulnerability)
                                self.vulnerabilities.append(vulnerability)
                                
                                if self.verbose:
                                    print(Fore.RED + f"[!] Open Redirect found at {url} in parameter {param_name}" + Style.RESET_ALL)
                                    print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                    print(Fore.YELLOW + f"    Redirects to: {location}" + Style.RESET_ALL)
                                
                                # Found a vulnerability, no need to test more payloads for this parameter
                                break
                    
                    except Exception as e:
                        if self.verbose:
                            print(Fore.YELLOW + f"  [!] Error testing {url}: {str(e)}" + Style.RESET_ALL)
                        continue
        
        return vulnerabilities
    
    def run(self):
        """
        Test for open redirect vulnerabilities in URL parameters
        
        Returns:
            int: Number of open redirect vulnerabilities found
        """
        redirect_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'Open Redirect')
        
        if self.verbose:
            print(Fore.BLUE + "[*] Testing for open redirect vulnerabilities..." + Style.RESET_ALL)
        
        # Test URL parameters for open redirect
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(self.test_url_parameter, self.discovered_urls))
        
        # Count how many open redirect vulnerabilities were found
        redirect_vulnerabilities = sum(1 for v in self.vulnerabilities if v.get('type') == 'Open Redirect')
        redirect_vulnerabilities_found = redirect_vulnerabilities - redirect_count
        
        print(Fore.GREEN + f"[+] Completed open redirect testing, found {redirect_vulnerabilities_found} vulnerabilities" + Style.RESET_ALL)
        return redirect_vulnerabilities_found 