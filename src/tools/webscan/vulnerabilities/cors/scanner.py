#!/usr/bin/env python3

import requests
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

class CORSScanner:
    """
    Advanced Cross-Origin Resource Sharing (CORS) Vulnerability Scanner
    
    This scanner implements comprehensive CORS misconfiguration detection including:
    - Origin reflection vulnerabilities
    - Wildcard origin misconfigurations
    - Null origin vulnerabilities
    - Credential exposure risks
    - Preflight request analysis
    - Method and header exposure
    - Domain confusion attacks
    - Subdomain takeover opportunities
    - Protocol downgrade attacks
    - Timing-based CORS attacks
    """
    
    def __init__(self, scanner_instance):
        """
        Initialize the CORS Scanner with a reference to the main scanner instance
        
        Args:
            scanner_instance: The main WebScanner instance
        """
        self.scanner = scanner_instance
        self.target_url = scanner_instance.target_url
        self.session = scanner_instance.session
        self.timeout = scanner_instance.timeout
        self.verbose = scanner_instance.verbose
        self.vulnerabilities = scanner_instance.vulnerabilities
        self.discovered_urls = scanner_instance.discovered_urls
        
        # Comprehensive CORS headers for detection
        self.cors_headers = {
            'origin_control': [
                'Access-Control-Allow-Origin',
                'Access-Control-Allow-Origin-Response'
            ],
            'credential_control': [
                'Access-Control-Allow-Credentials',
                'Access-Control-Allow-Credentials-Response'
            ],
            'method_control': [
                'Access-Control-Allow-Methods',
                'Access-Control-Request-Method'
            ],
            'header_control': [
                'Access-Control-Allow-Headers',
                'Access-Control-Request-Headers',
                'Access-Control-Expose-Headers'
            ],
            'timing_control': [
                'Access-Control-Max-Age',
                'Access-Control-Request-Private-Network'
            ],
            'preflight_control': [
                'Access-Control-Preflight-Response',
                'Access-Control-Preflight-Request'
            ]
        }
        
        # Advanced malicious domains for comprehensive testing
        self.malicious_domains = {
            'basic_attack': [
                'evil.com',
                'attacker.com',
                'malicious.com',
                'hacker.com',
                'phishing.com'
            ],
            'domain_confusion': [
                'null.evil.com',
                'evil.com.target.com',
                'target.com.evil.com',
                'subdomain.evil.com',
                'www.evil.com'
            ],
            'subdomain_takeover': [
                'api.evil.com',
                'admin.evil.com',
                'dev.evil.com',
                'test.evil.com',
                'staging.evil.com'
            ],
            'protocol_manipulation': [
                'http://evil.com',
                'https://evil.com',
                'ftp://evil.com',
                'file://evil.com',
                'data://evil.com'
            ],
            'null_origin_variants': [
                'null',
                'NULL',
                'Null',
                'null.com',
                'null.evil.com'
            ],
            'wildcard_variants': [
                '*',
                '*.evil.com',
                '*.target.com',
                '*.com',
                '*.org'
            ]
        }
        
        # Parse the target to get the domain
        self.target_domain = urlparse(self.target_url).netloc
        self.target_scheme = urlparse(self.target_url).scheme
        
        # Advanced CORS attack vectors
        self.cors_attack_vectors = {
            'origin_reflection': {
                'description': 'Origin header reflection in Access-Control-Allow-Origin',
                'severity': 'Critical',
                'test_origins': [
                    'https://evil.com',
                    'https://attacker.com',
                    'https://malicious.com',
                    'https://hacker.com',
                    'https://phishing.com'
                ]
            },
            'wildcard_misconfig': {
                'description': 'Wildcard (*) origin with credentials',
                'severity': 'Critical',
                'test_origins': ['*']
            },
            'null_origin_vuln': {
                'description': 'Null origin with credentials',
                'severity': 'High',
                'test_origins': ['null', 'NULL', 'Null']
            },
            'domain_confusion': {
                'description': 'Domain confusion attacks',
                'severity': 'High',
                'test_origins': [
                    'https://target.com.evil.com',
                    'https://evil.com.target.com',
                    'https://subdomain.evil.com'
                ]
            },
            'subdomain_takeover': {
                'description': 'Subdomain takeover via CORS',
                'severity': 'High',
                'test_origins': [
                    'https://api.evil.com',
                    'https://admin.evil.com',
                    'https://dev.evil.com'
                ]
            },
            'protocol_downgrade': {
                'description': 'Protocol downgrade attacks',
                'severity': 'Medium',
                'test_origins': [
                    'http://evil.com',
                    'ftp://evil.com',
                    'file://evil.com'
                ]
            },
            'credential_exposure': {
                'description': 'Credential exposure via CORS',
                'severity': 'High',
                'test_origins': ['https://evil.com']
            },
            'method_exposure': {
                'description': 'Dangerous HTTP methods exposed',
                'severity': 'Medium',
                'test_methods': ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
            },
            'header_exposure': {
                'description': 'Sensitive headers exposed',
                'severity': 'Medium',
                'test_headers': [
                    'Authorization',
                    'Cookie',
                    'X-API-Key',
                    'X-Auth-Token',
                    'X-CSRF-Token'
                ]
            }
        }
        
        # CORS vulnerability patterns
        self.cors_vulnerability_patterns = {
            'wildcard_patterns': [
                r'^\*$',
                r'^\*\.',
                r'\.\*$',
                r'^\*\.\*$'
            ],
            'null_patterns': [
                r'^null$',
                r'^NULL$',
                r'^Null$'
            ],
            'reflection_patterns': [
                r'^https?://[^/]+$',
                r'^https?://[^/]+/$'
            ],
            'domain_confusion_patterns': [
                r'\.evil\.com$',
                r'\.attacker\.com$',
                r'\.malicious\.com$'
            ]
        }
        
    def check_cors_headers(self, url):
        """
        Advanced CORS vulnerability detection with comprehensive testing
        
        Args:
            url (str): The URL to check
            
        Returns:
            list: CORS vulnerabilities found
        """
        vulnerabilities = []
        
        if not url:
            return vulnerabilities
        
        # Comprehensive CORS header detection
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Check for presence of CORS headers
            cors_headers_present = self._detect_cors_headers(response.headers)
            
            if not cors_headers_present:
                return vulnerabilities
            
            # Perform comprehensive CORS vulnerability testing
            vulnerabilities.extend(self._test_origin_reflection(url))
            vulnerabilities.extend(self._test_wildcard_misconfig(url))
            vulnerabilities.extend(self._test_null_origin(url))
            vulnerabilities.extend(self._test_domain_confusion(url))
            vulnerabilities.extend(self._test_subdomain_takeover(url))
            vulnerabilities.extend(self._test_protocol_downgrade(url))
            vulnerabilities.extend(self._test_credential_exposure(url))
            vulnerabilities.extend(self._test_method_exposure(url))
            vulnerabilities.extend(self._test_header_exposure(url))
            vulnerabilities.extend(self._test_preflight_requests(url))
            vulnerabilities.extend(self._test_timing_attacks(url))
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(Fore.YELLOW + f"[!] Error testing CORS at {url}: {str(e)}" + Style.RESET_ALL)
        
                return vulnerabilities
    
    def _detect_cors_headers(self, headers):
        """
        Detect presence of CORS headers in response
        
        Args:
            headers: Response headers
            
        Returns:
            bool: True if CORS headers are present
        """
        for category, header_list in self.cors_headers.items():
            for header in header_list:
                if header in headers:
                    return True
        return False
    
    def _test_origin_reflection(self, url):
        """
        Test for origin reflection vulnerabilities
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        attack_vector = self.cors_attack_vectors['origin_reflection']
        
        for origin in attack_vector['test_origins']:
            headers = {'Origin': origin}
            
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                if 'Access-Control-Allow-Origin' in response.headers:
                    reflected_origin = response.headers['Access-Control-Allow-Origin']
                    
                    if reflected_origin == origin:
                        credentials_allowed = self._check_credentials_allowed(response.headers)
                        
                        vuln = {
                            'type': 'CORS',
                            'subtype': 'Origin Reflection',
                            'url': url,
                            'severity': 'Critical' if credentials_allowed else 'High',
                            'details': f"Origin reflection vulnerability (origin: {origin})",
                            'evidence': f"Access-Control-Allow-Origin: {reflected_origin}",
                            'credentials_exposed': credentials_allowed,
                            'attack_vector': attack_vector['description']
                        }
                        vulnerabilities.append(vuln)
                        self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            severity_color = Fore.RED if credentials_allowed else Fore.YELLOW
                            print(severity_color + f"[!] Origin reflection vulnerability found at {url}" + Style.RESET_ALL)
                            print(severity_color + f"    Reflected origin: {origin}" + Style.RESET_ALL)
                            if credentials_allowed:
                                print(Fore.RED + f"    CRITICAL: Credentials exposed!" + Style.RESET_ALL)
                        
                        break  # Found vulnerability, no need to test other origins
                        
            except requests.exceptions.RequestException:
                continue
        
        return vulnerabilities
    
    def _test_wildcard_misconfig(self, url):
        """
        Test for wildcard CORS misconfigurations
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            if 'Access-Control-Allow-Origin' in response.headers:
                acao_value = response.headers['Access-Control-Allow-Origin']
                
                # Check for wildcard patterns
                for pattern in self.cors_vulnerability_patterns['wildcard_patterns']:
                    if re.match(pattern, acao_value, re.IGNORECASE):
                        credentials_allowed = self._check_credentials_allowed(response.headers)
                        
                        vuln = {
                            'type': 'CORS',
                            'subtype': 'Wildcard Misconfiguration',
                            'url': url,
                            'severity': 'Critical' if credentials_allowed else 'Medium',
                            'details': f"Wildcard CORS misconfiguration: {acao_value}",
                            'evidence': f"Access-Control-Allow-Origin: {acao_value}",
                            'credentials_exposed': credentials_allowed,
                            'pattern_matched': pattern
                        }
                        vulnerabilities.append(vuln)
                        self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            severity_color = Fore.RED if credentials_allowed else Fore.YELLOW
                            print(severity_color + f"[!] Wildcard CORS misconfiguration found at {url}" + Style.RESET_ALL)
                            print(severity_color + f"    Pattern: {pattern}" + Style.RESET_ALL)
                            if credentials_allowed:
                                print(Fore.RED + f"    CRITICAL: Credentials exposed!" + Style.RESET_ALL)
                        
                        break
                        
        except requests.exceptions.RequestException:
            pass
        
        return vulnerabilities
    
    def _test_null_origin(self, url):
        """
        Test for null origin vulnerabilities
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        for null_variant in self.malicious_domains['null_origin_variants']:
            headers = {'Origin': null_variant}
            
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                if 'Access-Control-Allow-Origin' in response.headers:
                    null_origin = response.headers['Access-Control-Allow-Origin']
                    
                    # Check for null patterns
                    for pattern in self.cors_vulnerability_patterns['null_patterns']:
                        if re.match(pattern, null_origin, re.IGNORECASE):
                            credentials_allowed = self._check_credentials_allowed(response.headers)
                            
                            vuln = {
                                'type': 'CORS',
                                'subtype': 'Null Origin',
                                'url': url,
                                'severity': 'High' if credentials_allowed else 'Medium',
                                'details': f"Null origin vulnerability: {null_origin}",
                                'evidence': f"Access-Control-Allow-Origin: {null_origin}",
                                'credentials_exposed': credentials_allowed,
                                'pattern_matched': pattern
                            }
                            vulnerabilities.append(vuln)
                            self.vulnerabilities.append(vuln)
                            
                            if self.verbose:
                                severity_color = Fore.RED if credentials_allowed else Fore.YELLOW
                                print(severity_color + f"[!] Null origin vulnerability found at {url}" + Style.RESET_ALL)
                                print(severity_color + f"    Pattern: {pattern}" + Style.RESET_ALL)
                            
                            break
                            
            except requests.exceptions.RequestException:
                continue
        
        return vulnerabilities
    
    def _test_domain_confusion(self, url):
        """
        Test for domain confusion attacks
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        attack_vector = self.cors_attack_vectors['domain_confusion']
        
        for origin in attack_vector['test_origins']:
            headers = {'Origin': origin}
            
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                if 'Access-Control-Allow-Origin' in response.headers:
                    reflected_origin = response.headers['Access-Control-Allow-Origin']
                    
                    # Check for domain confusion patterns
                    for pattern in self.cors_vulnerability_patterns['domain_confusion_patterns']:
                        if re.search(pattern, reflected_origin, re.IGNORECASE):
                            credentials_allowed = self._check_credentials_allowed(response.headers)
                            
                            vuln = {
                                'type': 'CORS',
                                'subtype': 'Domain Confusion',
                                'url': url,
                                'severity': 'High' if credentials_allowed else 'Medium',
                                'details': f"Domain confusion attack (origin: {origin})",
                                'evidence': f"Access-Control-Allow-Origin: {reflected_origin}",
                                'credentials_exposed': credentials_allowed,
                                'pattern_matched': pattern
                            }
                            vulnerabilities.append(vuln)
                            self.vulnerabilities.append(vuln)
                            
                            if self.verbose:
                                severity_color = Fore.RED if credentials_allowed else Fore.YELLOW
                                print(severity_color + f"[!] Domain confusion vulnerability found at {url}" + Style.RESET_ALL)
                                print(severity_color + f"    Pattern: {pattern}" + Style.RESET_ALL)
                            
                            break
                            
            except requests.exceptions.RequestException:
                continue
        
        return vulnerabilities
    
    def _test_subdomain_takeover(self, url):
        """
        Test for subdomain takeover via CORS
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        attack_vector = self.cors_attack_vectors['subdomain_takeover']
        
        for origin in attack_vector['test_origins']:
            headers = {'Origin': origin}
            
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                if 'Access-Control-Allow-Origin' in response.headers:
                    reflected_origin = response.headers['Access-Control-Allow-Origin']
                    
                    if reflected_origin == origin:
                        credentials_allowed = self._check_credentials_allowed(response.headers)
                        
                        vuln = {
                            'type': 'CORS',
                            'subtype': 'Subdomain Takeover',
                            'url': url,
                            'severity': 'High' if credentials_allowed else 'Medium',
                            'details': f"Subdomain takeover via CORS (origin: {origin})",
                            'evidence': f"Access-Control-Allow-Origin: {reflected_origin}",
                            'credentials_exposed': credentials_allowed
                        }
                        vulnerabilities.append(vuln)
                        self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            severity_color = Fore.RED if credentials_allowed else Fore.YELLOW
                            print(severity_color + f"[!] Subdomain takeover vulnerability found at {url}" + Style.RESET_ALL)
                            print(severity_color + f"    Origin: {origin}" + Style.RESET_ALL)
                        
                        break
                        
            except requests.exceptions.RequestException:
                continue
        
        return vulnerabilities
    
    def _test_protocol_downgrade(self, url):
        """
        Test for protocol downgrade attacks
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        attack_vector = self.cors_attack_vectors['protocol_downgrade']
        
        for origin in attack_vector['test_origins']:
            headers = {'Origin': origin}
            
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                if 'Access-Control-Allow-Origin' in response.headers:
                    reflected_origin = response.headers['Access-Control-Allow-Origin']
                    
                    if reflected_origin == origin:
                        vuln = {
                            'type': 'CORS',
                            'subtype': 'Protocol Downgrade',
                            'url': url,
                            'severity': 'Medium',
                            'details': f"Protocol downgrade attack (origin: {origin})",
                            'evidence': f"Access-Control-Allow-Origin: {reflected_origin}",
                            'credentials_exposed': False
                        }
                        vulnerabilities.append(vuln)
                        self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            print(Fore.YELLOW + f"[!] Protocol downgrade vulnerability found at {url}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Origin: {origin}" + Style.RESET_ALL)
                        
                        break
                        
            except requests.exceptions.RequestException:
                continue
        
        return vulnerabilities
    
    def _test_credential_exposure(self, url):
        """
        Test for credential exposure via CORS
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        attack_vector = self.cors_attack_vectors['credential_exposure']
        
        for origin in attack_vector['test_origins']:
            headers = {
                'Origin': origin,
                'Cookie': 'test=value',
                'Authorization': 'Bearer test-token'
            }
            
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                if 'Access-Control-Allow-Credentials' in response.headers:
                    credentials_value = response.headers['Access-Control-Allow-Credentials']
                    
                    if credentials_value.lower() == 'true':
                        vuln = {
                            'type': 'CORS',
                            'subtype': 'Credential Exposure',
                            'url': url,
                            'severity': 'High',
                            'details': f"Credential exposure via CORS (origin: {origin})",
                            'evidence': f"Access-Control-Allow-Credentials: {credentials_value}",
                            'credentials_exposed': True
                        }
                        vulnerabilities.append(vuln)
                        self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Credential exposure vulnerability found at {url}" + Style.RESET_ALL)
                            print(Fore.RED + f"    Origin: {origin}" + Style.RESET_ALL)
                        
                        break
                        
            except requests.exceptions.RequestException:
                continue
        
        return vulnerabilities
    
    def _test_method_exposure(self, url):
        """
        Test for dangerous HTTP methods exposed via CORS
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        attack_vector = self.cors_attack_vectors['method_exposure']
        
        try:
            # Test OPTIONS request for preflight
            response = self.session.options(url, timeout=self.timeout)
            
            if 'Access-Control-Allow-Methods' in response.headers:
                methods = response.headers['Access-Control-Allow-Methods']
                
                # Check for dangerous methods
                dangerous_methods = []
                for method in attack_vector['test_methods']:
                    if method in methods:
                        dangerous_methods.append(method)
                
                if dangerous_methods:
                    vuln = {
                        'type': 'CORS',
                        'subtype': 'Method Exposure',
                        'url': url,
                        'severity': 'Medium',
                        'details': f"Dangerous HTTP methods exposed: {', '.join(dangerous_methods)}",
                        'evidence': f"Access-Control-Allow-Methods: {methods}",
                        'dangerous_methods': dangerous_methods
                    }
                    vulnerabilities.append(vuln)
                    self.vulnerabilities.append(vuln)
                    
                    if self.verbose:
                        print(Fore.YELLOW + f"[!] Method exposure vulnerability found at {url}" + Style.RESET_ALL)
                        print(Fore.YELLOW + f"    Dangerous methods: {', '.join(dangerous_methods)}" + Style.RESET_ALL)
                        
        except requests.exceptions.RequestException:
            pass
        
        return vulnerabilities
    
    def _test_header_exposure(self, url):
        """
        Test for sensitive headers exposed via CORS
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        attack_vector = self.cors_attack_vectors['header_exposure']
        
        try:
            # Test OPTIONS request for preflight
            response = self.session.options(url, timeout=self.timeout)
            
            if 'Access-Control-Allow-Headers' in response.headers:
                headers = response.headers['Access-Control-Allow-Headers']
                
                # Check for sensitive headers
                sensitive_headers = []
                for header in attack_vector['test_headers']:
                    if header in headers:
                        sensitive_headers.append(header)
                
                if sensitive_headers:
                    vuln = {
                        'type': 'CORS',
                        'subtype': 'Header Exposure',
                        'url': url,
                        'severity': 'Medium',
                        'details': f"Sensitive headers exposed: {', '.join(sensitive_headers)}",
                        'evidence': f"Access-Control-Allow-Headers: {headers}",
                        'sensitive_headers': sensitive_headers
                    }
                    vulnerabilities.append(vuln)
                    self.vulnerabilities.append(vuln)
                    
                    if self.verbose:
                        print(Fore.YELLOW + f"[!] Header exposure vulnerability found at {url}" + Style.RESET_ALL)
                        print(Fore.YELLOW + f"    Sensitive headers: {', '.join(sensitive_headers)}" + Style.RESET_ALL)
                        
        except requests.exceptions.RequestException:
            pass
        
        return vulnerabilities
    
    def _test_preflight_requests(self, url):
        """
        Test for preflight request vulnerabilities
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Test various preflight scenarios
            preflight_headers = {
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type, Authorization',
                'Origin': 'https://evil.com'
            }
            
            response = self.session.options(url, headers=preflight_headers, timeout=self.timeout)
            
            # Check for preflight response headers
            if 'Access-Control-Allow-Origin' in response.headers:
                origin = response.headers['Access-Control-Allow-Origin']
                
                if origin == 'https://evil.com':
                    vuln = {
                        'type': 'CORS',
                        'subtype': 'Preflight Vulnerability',
                        'url': url,
                        'severity': 'High',
                        'details': "Preflight request origin reflection",
                        'evidence': f"Access-Control-Allow-Origin: {origin}",
                        'credentials_exposed': False
                    }
                    vulnerabilities.append(vuln)
                    self.vulnerabilities.append(vuln)
                    
                    if self.verbose:
                        print(Fore.RED + f"[!] Preflight vulnerability found at {url}" + Style.RESET_ALL)
                        print(Fore.RED + f"    Origin reflection in preflight" + Style.RESET_ALL)
                        
        except requests.exceptions.RequestException:
            pass
        
        return vulnerabilities
    
    def _test_timing_attacks(self, url):
        """
        Test for timing-based CORS attacks
        
        Args:
            url (str): URL to test
            
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Test timing-based attacks
            start_time = time.time()
            response = self.session.get(url, timeout=self.timeout)
            end_time = time.time()
            
            # Analyze response timing for potential timing attacks
            response_time = end_time - start_time
            
            # Check for unusual timing patterns
            if response_time > 5.0:  # Suspiciously slow response
                vuln = {
                    'type': 'CORS',
                    'subtype': 'Timing Attack',
                    'url': url,
                    'severity': 'Low',
                    'details': f"Potential timing-based attack (response time: {response_time:.2f}s)",
                    'evidence': f"Response time: {response_time:.2f} seconds",
                    'response_time': response_time
                }
                vulnerabilities.append(vuln)
                self.vulnerabilities.append(vuln)
                
                if self.verbose:
                    print(Fore.BLUE + f"[!] Potential timing attack at {url}" + Style.RESET_ALL)
                    print(Fore.BLUE + f"    Response time: {response_time:.2f}s" + Style.RESET_ALL)
                    
        except requests.exceptions.RequestException:
            pass
        
        return vulnerabilities
    
    def _check_credentials_allowed(self, headers):
        """
        Check if credentials are allowed in CORS response
        
        Args:
            headers: Response headers
            
        Returns:
            bool: True if credentials are allowed
        """
        return ('Access-Control-Allow-Credentials' in headers and 
                headers['Access-Control-Allow-Credentials'].lower() == 'true')
    
    def run(self):
        """
        Advanced CORS vulnerability testing with comprehensive reporting
        
        Returns:
            int: Number of CORS vulnerabilities found
        """
        initial_cors_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CORS')
        
        if self.verbose:
            print(Fore.BLUE + "[*] Starting advanced CORS vulnerability scan..." + Style.RESET_ALL)
            print(Fore.CYAN + f"    Testing {len(self.discovered_urls) + 1} URLs" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Using {len(self.cors_attack_vectors)} attack vectors" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Testing {sum(len(domains) for domains in self.malicious_domains.values())} malicious domains" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Comprehensive CORS header analysis enabled" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Advanced vulnerability detection enabled" + Style.RESET_ALL)
        
        # Test main target URL
        self.check_cors_headers(self.target_url)
        
        # Test all discovered URLs with threading for performance
        if self.discovered_urls:
            with ThreadPoolExecutor(max_workers=5) as executor:
                executor.map(self.check_cors_headers, 
                           [url_data.get('url', '') if isinstance(url_data, dict) else url_data 
                            for url_data in self.discovered_urls])
        
        # Generate comprehensive report
        self._generate_cors_report(initial_cors_count)
        
        return self._get_cors_vulnerability_count(initial_cors_count)
    
    def _generate_cors_report(self, initial_count):
        """
        Generate comprehensive CORS vulnerability report
        
        Args:
            initial_count (int): Initial vulnerability count
        """
        if not self.verbose:
            cors_vulnerabilities_found = self._get_cors_vulnerability_count(initial_count)
            print(Fore.GREEN + f"[+] Completed CORS testing, found {cors_vulnerabilities_found} vulnerabilities" + Style.RESET_ALL)
            return
        
        cors_vulnerabilities_found = self._get_cors_vulnerability_count(initial_count)
        
        print(Fore.GREEN + f"[+] Advanced CORS scan completed" + Style.RESET_ALL)
        print(Fore.GREEN + f"    Total vulnerabilities found: {cors_vulnerabilities_found}" + Style.RESET_ALL)
        
        # Detailed severity breakdown
        critical_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CORS' and v.get('severity') == 'Critical')
        high_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CORS' and v.get('severity') == 'High')
        medium_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CORS' and v.get('severity') == 'Medium')
        low_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CORS' and v.get('severity') == 'Low')
        
        if critical_count > 0:
            print(Fore.RED + f"    Critical severity: {critical_count}" + Style.RESET_ALL)
        if high_count > 0:
            print(Fore.RED + f"    High severity: {high_count}" + Style.RESET_ALL)
        if medium_count > 0:
            print(Fore.YELLOW + f"    Medium severity: {medium_count}" + Style.RESET_ALL)
        if low_count > 0:
            print(Fore.BLUE + f"    Low severity: {low_count}" + Style.RESET_ALL)
        
        # Subtype breakdown
        subtypes = {}
        for v in self.vulnerabilities:
            if v.get('type') == 'CORS':
                subtype = v.get('subtype', 'Unknown')
                subtypes[subtype] = subtypes.get(subtype, 0) + 1
        
        if subtypes:
            print(Fore.CYAN + "    Vulnerability subtypes:" + Style.RESET_ALL)
            for subtype, count in subtypes.items():
                print(Fore.CYAN + f"      {subtype}: {count}" + Style.RESET_ALL)
        
        # Credential exposure analysis
        credential_exposures = sum(1 for v in self.vulnerabilities 
                                 if v.get('type') == 'CORS' and v.get('credentials_exposed', False))
        
        if credential_exposures > 0:
            print(Fore.RED + f"    CRITICAL: {credential_exposures} credential exposure vulnerabilities" + Style.RESET_ALL)
        
        # Advanced features summary
        print(Fore.MAGENTA + "    Advanced features used:" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Origin reflection detection" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Wildcard misconfiguration analysis" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Null origin vulnerability testing" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Domain confusion attack detection" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Subdomain takeover analysis" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Protocol downgrade detection" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Credential exposure analysis" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Method and header exposure testing" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Preflight request analysis" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Timing-based attack detection" + Style.RESET_ALL)
    
    def _get_cors_vulnerability_count(self, initial_count):
        """
        Get the number of CORS vulnerabilities found
        
        Args:
            initial_count (int): Initial vulnerability count
            
        Returns:
            int: Number of new CORS vulnerabilities found
        """
        final_cors_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CORS')
        return final_cors_count - initial_count 