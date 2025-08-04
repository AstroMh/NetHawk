#!/usr/bin/env python3

import urllib.parse
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

class CRLFScanner:
    """Scanner for detecting CRLF (Carriage Return Line Feed) Injection vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the CRLF Scanner with a reference to the main scanner instance
        
        Args:
            scanner_instance: The main WebScanner instance
        """
        self.scanner = scanner_instance
        self.target_url = scanner_instance.target_url
        self.session = scanner_instance.session
        self.timeout = scanner_instance.timeout
        self.verbose = scanner_instance.verbose
        self.max_threads = scanner_instance.max_threads
        self.vulnerabilities = []
        self.discovered_urls = scanner_instance.discovered_urls
        
        # CRLF payloads to test
        self.crlf_payloads = [
            "%0D%0ASet-Cookie:crlf=injection",
            "%0ASet-Cookie:crlf=injection",
            "%0DSet-Cookie:crlf=injection",
            "%23%0D%0ASet-Cookie:crlf=injection",
            "%25%30%44%25%30%41Set-Cookie:crlf=injection",
            "%E5%98%8D%E5%98%8ASet-Cookie:crlf=injection",
            "%0D%0ASet-Cookie:crlf=injection%0D%0A",
            "\r\nSet-Cookie:crlf=injection",
            "%0D%0AContent-Length:%200%0D%0A%0D%0AHTTPResponse:crlf=injection",
            "?%0D%0ASet-Cookie:crlf=injection",
            "\r\n\tSet-Cookie:crlf=injection",
            "\r\t\nSet-Cookie:crlf=injection",
            "\r\n    Set-Cookie:crlf=injection",
            "%0D%0AX-XSS-Protection:0%0D%0ASet-Cookie:crlf=injection"
        ]
        
        # Patterns to look for in headers indicating successful CRLF injection
        self.crlf_indicators = [
            "crlf=injection"
        ]
    
    def run(self):
        """Run the CRLF scanner on all discovered URLs"""
        if self.verbose:
            print(Fore.BLUE + "[*] Starting CRLF injection scanner..." + Style.RESET_ALL)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            list(executor.map(self.scan_url, self.discovered_urls))
            
        if self.verbose:
            print(Fore.BLUE + f"[*] CRLF scan completed. Found {len(self.vulnerabilities)} vulnerabilities." + Style.RESET_ALL)
            
        return self.vulnerabilities
        
    def scan_url(self, url):
        """
        Scan a single URL for CRLF injections
        
        Args:
            url (str): The URL to scan
        """
        try:
            if self.verbose:
                print(Fore.BLUE + f"  [+] Scanning {url} for CRLF injections" + Style.RESET_ALL)
                
            # Parse the URL to get parameters
            parsed_url = urlparse(url)
            
            # If URL has parameters, test each one
            if parsed_url.query:
                self.test_url_parameters(url)
                
        except Exception as e:
            if self.verbose:
                print(Fore.RED + f"  [-] Error scanning {url} for CRLF injections: {str(e)}" + Style.RESET_ALL)
            
    def test_url_parameters(self, url):
        """
        Test URL parameters for CRLF injection vulnerabilities
        
        Args:
            url (str): The URL to test
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return
            
        # Test each parameter
        for param_name, param_values in query_params.items():
            for payload in self.crlf_payloads:
                # Create a copy of the query parameters
                modified_params = query_params.copy()
                
                # Modify the current parameter with the CRLF payload
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
                    # Send the request with the modified URL
                    response = requests.get(modified_url, timeout=self.timeout, allow_redirects=False)
                    
                    # Check if the CRLF injection was successful by looking at response headers
                    for indicator in self.crlf_indicators:
                        cookie_header = response.headers.get('Set-Cookie', '')
                        if indicator in cookie_header:
                            vuln = {
                                'type': 'CRLF Injection',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f"Set-Cookie: {cookie_header}",
                                'severity': 'Medium',
                                'risk_score': 60,
                                'cwe': 'CWE-113',
                                'description': 'CRLF Injection allows attackers to inject headers into the HTTP response, potentially leading to cookie-based attacks or cache poisoning.',
                                'remediation': 'Implement proper input validation and output encoding. Avoid using user-controlled input in HTTP response headers.',
                                'references': [
                                    'https://owasp.org/www-community/vulnerabilities/CRLF_Injection',
                                    'https://cwe.mitre.org/data/definitions/113.html'
                                ]
                            }
                            
                            self.vulnerabilities.append(vuln)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] Found CRLF injection vulnerability at {url}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Parameter: {param_name}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Evidence: {cookie_header}" + Style.RESET_ALL)
                                
                except Exception as e:
                    if self.verbose:
                        print(Fore.YELLOW + f"  [!] Error testing {modified_url}: {str(e)}" + Style.RESET_ALL)
                    continue
    
    def add_vulnerability(self, url, param_name, payload, evidence):
        """Add a vulnerability to the list"""
        vuln = {
            'type': 'CRLF Injection',
            'url': url,
            'parameter': param_name,
            'payload': payload,
            'evidence': evidence,
            'severity': 'Medium',
            'risk_score': 60,
            'cwe': 'CWE-113',
            'description': 'CRLF Injection allows attackers to inject headers into the HTTP response, potentially leading to cookie-based attacks or cache poisoning.',
            'remediation': 'Implement proper input validation and output encoding. Avoid using user-controlled input in HTTP response headers.',
            'references': [
                'https://owasp.org/www-community/vulnerabilities/CRLF_Injection',
                'https://cwe.mitre.org/data/definitions/113.html'
            ]
        }
        
        self.vulnerabilities.append(vuln)
        
        if self.verbose:
            print(Fore.RED + f"[!] Found CRLF injection vulnerability at {url}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"    Parameter: {param_name}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"    Evidence: {evidence}" + Style.RESET_ALL) 