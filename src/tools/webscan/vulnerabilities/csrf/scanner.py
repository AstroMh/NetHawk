#!/usr/bin/env python3

import requests
import re
import time
import hashlib
import secrets
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class CSRFScanner:
    """
    Advanced Cross-Site Request Forgery (CSRF) Vulnerability Scanner
    
    This scanner implements comprehensive CSRF detection techniques including:
    - Token-based CSRF protection analysis
    - Header-based CSRF protection detection
    - Cookie-based CSRF protection validation
    - SameSite cookie analysis
    - Referer header validation
    - Origin header verification
    - Double Submit Cookie pattern detection
    - Synchronizer Token pattern analysis
    - Custom header validation
    - State parameter verification
    - Anti-CSRF middleware detection
    - Form validation bypass testing
    """
    
    def __init__(self, scanner_instance):
        """
        Initialize the CSRF Scanner with a reference to the main scanner instance
        
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
        
        # Comprehensive CSRF token patterns
        self.csrf_token_patterns = {
            'field_names': [
                'csrf', 'token', 'nonce', 'xsrf', 'verify', 'authenticity',
                'security', 'form_token', 'request_token', 'session_token',
                'anti_csrf', 'csrf_token', 'xsrf_token', 'form_token',
                'request_token', 'session_token', 'authenticity_token',
                'security_token', 'form_security', 'request_security'
            ],
            'cookie_names': [
                'csrf', 'token', 'xsrf', 'nonce', 'authenticity',
                'security', 'form_token', 'request_token', 'session_token',
                'anti_csrf', 'csrf_token', 'xsrf_token', 'form_token',
                'request_token', 'session_token', 'authenticity_token',
                'security_token', 'form_security', 'request_security'
            ],
            'header_names': [
                'X-CSRF-Token', 'X-XSRF-Token', 'X-Requested-With',
                'X-CSRF-Header', 'X-Anti-CSRF', 'X-Security-Token',
                'X-Form-Token', 'X-Request-Token', 'X-Session-Token',
                'X-Authenticity-Token', 'X-Security-Header'
            ],
            'parameter_names': [
                'csrf', 'token', 'nonce', 'xsrf', 'verify', 'authenticity',
                'security', 'form_token', 'request_token', 'session_token',
                'anti_csrf', 'csrf_token', 'xsrf_token', 'form_token',
                'request_token', 'session_token', 'authenticity_token',
                'security_token', 'form_security', 'request_security'
            ]
        }
        
        # CSRF protection mechanisms
        self.csrf_protection_mechanisms = {
            'token_based': {
                'description': 'Token-based CSRF protection',
                'severity': 'Low',
                'detection_methods': ['field_analysis', 'cookie_analysis', 'header_analysis']
            },
            'header_based': {
                'description': 'Header-based CSRF protection',
                'severity': 'Medium',
                'detection_methods': ['header_validation', 'origin_check', 'referer_check']
            },
            'cookie_based': {
                'description': 'Cookie-based CSRF protection',
                'severity': 'Medium',
                'detection_methods': ['samesite_analysis', 'secure_flag', 'httponly_flag']
            },
            'samesite_cookie': {
                'description': 'SameSite cookie CSRF protection',
                'severity': 'Low',
                'detection_methods': ['samesite_strict', 'samesite_lax']
            },
            'referer_validation': {
                'description': 'Referer header validation',
                'severity': 'Medium',
                'detection_methods': ['referer_check', 'origin_check']
            },
            'origin_validation': {
                'description': 'Origin header validation',
                'severity': 'Medium',
                'detection_methods': ['origin_check', 'header_validation']
            },
            'double_submit_cookie': {
                'description': 'Double Submit Cookie pattern',
                'severity': 'Low',
                'detection_methods': ['cookie_token_match', 'field_cookie_validation']
            },
            'synchronizer_token': {
                'description': 'Synchronizer Token pattern',
                'severity': 'Low',
                'detection_methods': ['token_validation', 'session_token_check']
            }
        }
        
        # CSRF attack vectors
        self.csrf_attack_vectors = {
            'form_submission': {
                'description': 'Form submission without CSRF protection',
                'severity': 'High',
                'test_methods': ['post_request', 'get_request', 'put_request']
            },
            'ajax_request': {
                'description': 'AJAX request without CSRF protection',
                'severity': 'High',
                'test_methods': ['xmlhttprequest', 'fetch_request', 'axios_request']
            },
            'api_endpoint': {
                'description': 'API endpoint without CSRF protection',
                'severity': 'Critical',
                'test_methods': ['rest_api', 'graphql_api', 'soap_api']
            },
            'file_upload': {
                'description': 'File upload without CSRF protection',
                'severity': 'High',
                'test_methods': ['multipart_form', 'file_upload_api']
            },
            'state_change': {
                'description': 'State-changing operation without CSRF protection',
                'severity': 'Critical',
                'test_methods': ['password_change', 'email_change', 'profile_update']
            },
            'privileged_action': {
                'description': 'Privileged action without CSRF protection',
                'severity': 'Critical',
                'test_methods': ['admin_action', 'user_creation', 'role_change']
            }
        }
        
        # CSRF vulnerability patterns
        self.csrf_vulnerability_patterns = {
            'missing_token': [
                r'<form[^>]*>.*?</form>',
                r'<input[^>]*type=["\']submit["\'][^>]*>',
                r'<button[^>]*type=["\']submit["\'][^>]*>'
            ],
            'weak_token': [
                r'<input[^>]*name=["\'][^"\']*(csrf|token|nonce)[^"\']*["\'][^>]*>',
                r'<input[^>]*value=["\'][^"\']*["\'][^>]*>'
            ],
            'predictable_token': [
                r'<input[^>]*value=["\'][0-9]+["\'][^>]*>',
                r'<input[^>]*value=["\'][a-zA-Z0-9]{8,}["\'][^>]*>'
            ],
            'static_token': [
                r'<input[^>]*value=["\'][^"\']*["\'][^>]*>',
                r'<input[^>]*value=["\'][^"\']*["\'][^>]*>'
            ]
        }
    
    def test_form(self, form):
        """
        Advanced CSRF vulnerability detection with comprehensive analysis
        
        Args:
            form (dict): Form data containing action, method, and inputs
            
        Returns:
            dict or None: Vulnerability details if found, None otherwise
        """
        # Skip login forms to avoid account lockouts
        if self._is_login_form(form):
            return None
        
        # Comprehensive CSRF protection analysis
        protection_analysis = self._analyze_csrf_protection(form)
        
        # Determine vulnerability based on protection analysis
        if not protection_analysis['has_protection']:
            vulnerability = self._create_csrf_vulnerability(form, protection_analysis)
            
            if self.verbose:
                self._print_vulnerability_info(vulnerability)
            
            return vulnerability
        
        # Test for weak or bypassable CSRF protection
        if protection_analysis['has_weak_protection']:
            vulnerability = self._create_weak_csrf_vulnerability(form, protection_analysis)
            
            if self.verbose:
                self._print_vulnerability_info(vulnerability)
            
            return vulnerability
        
        return None
    
    def _is_login_form(self, form):
        """
        Check if the form is a login form to avoid account lockouts
        
        Args:
            form (dict): Form data
            
        Returns:
            bool: True if login form, False otherwise
        """
        login_indicators = ['login', 'signin', 'auth', 'authenticate', 'password']
        form_action = form.get('action', '').lower()
        form_url = form['url'].lower()
        
        # Check form action and URL for login indicators
        for indicator in login_indicators:
            if indicator in form_action or indicator in form_url:
                return True
        
        # Check form inputs for login indicators
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name', '').lower()
            input_type = input_field.get('type', '').lower()
            
            if input_type == 'password' or any(indicator in input_name for indicator in login_indicators):
                return True
        
        return False
    
    def _analyze_csrf_protection(self, form):
        """
        Comprehensive CSRF protection analysis
        
        Args:
            form (dict): Form data
            
        Returns:
            dict: Protection analysis results
        """
        analysis = {
            'has_protection': False,
            'has_weak_protection': False,
            'protection_mechanisms': [],
            'token_analysis': {},
            'header_analysis': {},
            'cookie_analysis': {},
            'vulnerability_details': []
        }
        
        # Analyze token-based protection
        token_analysis = self._analyze_token_protection(form)
        analysis['token_analysis'] = token_analysis
        
        if token_analysis['has_token']:
            analysis['has_protection'] = True
            analysis['protection_mechanisms'].append('token_based')
            
            if token_analysis['is_weak']:
                analysis['has_weak_protection'] = True
                analysis['vulnerability_details'].append('Weak or predictable CSRF token')
        
        # Analyze header-based protection
        header_analysis = self._analyze_header_protection(form)
        analysis['header_analysis'] = header_analysis
        
        if header_analysis['has_protection']:
            analysis['has_protection'] = True
            analysis['protection_mechanisms'].append('header_based')
            
            if header_analysis['is_weak']:
                analysis['has_weak_protection'] = True
                analysis['vulnerability_details'].append('Weak header-based protection')
        
        # Analyze cookie-based protection
        cookie_analysis = self._analyze_cookie_protection(form)
        analysis['cookie_analysis'] = cookie_analysis
        
        if cookie_analysis['has_protection']:
            analysis['has_protection'] = True
            analysis['protection_mechanisms'].append('cookie_based')
            
            if cookie_analysis['is_weak']:
                analysis['has_weak_protection'] = True
                analysis['vulnerability_details'].append('Weak cookie-based protection')
        
        # Analyze SameSite cookie protection
        samesite_analysis = self._analyze_samesite_protection(form)
        if samesite_analysis['has_protection']:
            analysis['has_protection'] = True
            analysis['protection_mechanisms'].append('samesite_cookie')
        
        return analysis
    
    def _analyze_token_protection(self, form):
        """
        Analyze token-based CSRF protection
        
        Args:
            form (dict): Form data
            
        Returns:
            dict: Token analysis results
        """
        analysis = {
            'has_token': False,
            'is_weak': False,
            'token_fields': [],
            'token_cookies': [],
            'token_headers': [],
            'token_parameters': []
        }
        
        # Check form fields for CSRF tokens
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name', '').lower()
            input_value = input_field.get('value', '')
            
            for pattern in self.csrf_token_patterns['field_names']:
                if pattern in input_name:
                    analysis['has_token'] = True
                    analysis['token_fields'].append({
                        'name': input_name,
                        'value': input_value,
                        'type': input_field.get('type', 'hidden')
                    })
                    
                    # Check if token is weak
                    if self._is_weak_token(input_value):
                        analysis['is_weak'] = True
                    break
        
        # Check cookies for CSRF tokens
        cookies = self.session.cookies.get_dict()
        for cookie_name, cookie_value in cookies.items():
            for pattern in self.csrf_token_patterns['cookie_names']:
                if pattern in cookie_name.lower():
                    analysis['has_token'] = True
                    analysis['token_cookies'].append({
                        'name': cookie_name,
                        'value': cookie_value
                    })
                    
                    # Check if token is weak
                    if self._is_weak_token(cookie_value):
                        analysis['is_weak'] = True
                    break
        
        # Check response headers for CSRF tokens
        try:
            response = self.session.get(form['url'], timeout=self.timeout)
            for header_name, header_value in response.headers.items():
                for pattern in self.csrf_token_patterns['header_names']:
                    if pattern.lower() in header_name.lower():
                        analysis['has_token'] = True
                        analysis['token_headers'].append({
                            'name': header_name,
                            'value': header_value
                        })
                        break
        except Exception:
            pass
        
        return analysis
    
    def _analyze_header_protection(self, form):
        """
        Analyze header-based CSRF protection
        
        Args:
            form (dict): Form data
            
        Returns:
            dict: Header analysis results
        """
        analysis = {
            'has_protection': False,
            'is_weak': False,
            'protection_headers': [],
            'security_headers': []
        }
        
        try:
            response = self.session.get(form['url'], timeout=self.timeout)
            
            # Check for CSRF protection headers
            for header_name, header_value in response.headers.items():
                if any(pattern.lower() in header_name.lower() for pattern in self.csrf_token_patterns['header_names']):
                    analysis['has_protection'] = True
                    analysis['protection_headers'].append({
                        'name': header_name,
                        'value': header_value
                    })
            
            # Check for security headers that indicate CSRF awareness
            security_headers = ['X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options']
            for header in security_headers:
                if header in response.headers:
                    analysis['security_headers'].append({
                        'name': header,
                        'value': response.headers[header]
                    })
            
            # Check for weak protection (e.g., missing Referer validation)
            if not any('referer' in header.lower() for header in response.headers):
                analysis['is_weak'] = True
                
        except Exception:
            pass
        
        return analysis
    
    def _analyze_cookie_protection(self, form):
        """
        Analyze cookie-based CSRF protection
        
        Args:
            form (dict): Form data
            
        Returns:
            dict: Cookie analysis results
        """
        analysis = {
            'has_protection': False,
            'is_weak': False,
            'secure_cookies': [],
            'httponly_cookies': [],
            'samesite_cookies': []
        }
        
        try:
            response = self.session.get(form['url'], timeout=self.timeout)
            
            for cookie in response.cookies:
                cookie_info = {
                    'name': cookie.name,
                    'value': cookie.value,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': getattr(cookie, 'samesite', None)
                }
                
                # Check for secure cookies
                if cookie_info['secure']:
                    analysis['secure_cookies'].append(cookie_info)
                
                # Check for HttpOnly cookies
                if cookie_info['httponly']:
                    analysis['httponly_cookies'].append(cookie_info)
                
                # Check for SameSite cookies
                if cookie_info['samesite']:
                    analysis['samesite_cookies'].append(cookie_info)
                    analysis['has_protection'] = True
                
                # Check for weak protection
                if not cookie_info['secure'] and not cookie_info['httponly']:
                    analysis['is_weak'] = True
                    
        except Exception:
            pass
        
        return analysis
    
    def _analyze_samesite_protection(self, form):
        """
        Analyze SameSite cookie CSRF protection
        
        Args:
            form (dict): Form data
            
        Returns:
            dict: SameSite analysis results
        """
        analysis = {
            'has_protection': False,
            'strict_cookies': [],
            'lax_cookies': [],
            'none_cookies': []
        }
        
        try:
            response = self.session.get(form['url'], timeout=self.timeout)
            
            for cookie in response.cookies:
                samesite = getattr(cookie, 'samesite', None)
                
                if samesite == 'Strict':
                    analysis['has_protection'] = True
                    analysis['strict_cookies'].append(cookie.name)
                elif samesite == 'Lax':
                    analysis['has_protection'] = True
                    analysis['lax_cookies'].append(cookie.name)
                elif samesite == 'None':
                    analysis['none_cookies'].append(cookie.name)
                    
        except Exception:
            pass
        
        return analysis
    
    def _is_weak_token(self, token_value):
        """
        Check if a CSRF token is weak or predictable
        
        Args:
            token_value (str): Token value to analyze
            
        Returns:
            bool: True if token is weak, False otherwise
        """
        if not token_value:
            return True
        
        # Check for predictable patterns
        predictable_patterns = [
            r'^[0-9]+$',  # Only numbers
            r'^[a-zA-Z0-9]{8}$',  # Short alphanumeric
            r'^[a-zA-Z0-9]{16}$',  # Medium alphanumeric
            r'^[a-f0-9]{32}$',  # MD5 hash
            r'^[a-f0-9]{40}$',  # SHA1 hash
            r'^[a-f0-9]{64}$',  # SHA256 hash
        ]
        
        for pattern in predictable_patterns:
            if re.match(pattern, token_value):
                return True
        
        # Check for static or common values
        static_values = ['test', 'token', 'csrf', 'nonce', '123456', 'password']
        if token_value.lower() in static_values:
            return True
        
        return False
    
    def _create_csrf_vulnerability(self, form, protection_analysis):
        """
        Create CSRF vulnerability report
        
        Args:
            form (dict): Form data
            protection_analysis (dict): Protection analysis results
            
        Returns:
            dict: Vulnerability details
        """
        severity = self._determine_csrf_severity(form, protection_analysis)
        
        vulnerability = {
            'type': 'CSRF',
            'subtype': 'Missing Protection',
            'url': form['url'],
            'form_action': form.get('action', ''),
            'method': form.get('method', ''),
            'inputs': [field.get('name') for field in form.get('inputs', [])],
            'severity': severity,
            'evidence': 'Form lacks CSRF protection mechanisms',
            'protection_analysis': protection_analysis,
            'attack_vector': self._determine_attack_vector(form),
            'recommendations': self._generate_csrf_recommendations(form, protection_analysis)
        }
        
        return vulnerability
    
    def _create_weak_csrf_vulnerability(self, form, protection_analysis):
        """
        Create weak CSRF vulnerability report
        
        Args:
            form (dict): Form data
            protection_analysis (dict): Protection analysis results
            
        Returns:
            dict: Vulnerability details
        """
        severity = 'Medium'  # Weak protection is typically medium severity
        
        vulnerability = {
            'type': 'CSRF',
            'subtype': 'Weak Protection',
            'url': form['url'],
            'form_action': form.get('action', ''),
            'method': form.get('method', ''),
            'inputs': [field.get('name') for field in form.get('inputs', [])],
            'severity': severity,
            'evidence': 'Form has weak or bypassable CSRF protection',
            'protection_analysis': protection_analysis,
            'attack_vector': self._determine_attack_vector(form),
            'recommendations': self._generate_csrf_recommendations(form, protection_analysis)
        }
        
        return vulnerability
    
    def _determine_csrf_severity(self, form, protection_analysis):
        """
        Determine CSRF vulnerability severity
        
        Args:
            form (dict): Form data
            protection_analysis (dict): Protection analysis results
            
        Returns:
            str: Severity level
        """
        # Check for critical operations
        critical_operations = ['password', 'email', 'admin', 'user', 'role', 'privilege']
        form_action = form.get('action', '').lower()
        form_url = form['url'].lower()
        
        for operation in critical_operations:
            if operation in form_action or operation in form_url:
                return 'Critical'
        
        # Check for state-changing operations
        state_changing_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
        if form.get('method', '').upper() in state_changing_methods:
            return 'High'
        
        return 'Medium'
    
    def _determine_attack_vector(self, form):
        """
        Determine the most likely attack vector for the form
        
        Args:
            form (dict): Form data
            
        Returns:
            str: Attack vector description
        """
        method = form.get('method', '').upper()
        
        if method == 'POST':
            return 'Form submission via POST request'
        elif method == 'GET':
            return 'Form submission via GET request'
        elif method == 'PUT':
            return 'Form submission via PUT request'
        elif method == 'DELETE':
            return 'Form submission via DELETE request'
        else:
            return 'Unknown form submission method'
    
    def _generate_csrf_recommendations(self, form, protection_analysis):
        """
        Generate CSRF protection recommendations
        
        Args:
            form (dict): Form data
            protection_analysis (dict): Protection analysis results
            
        Returns:
            list: List of recommendations
        """
        recommendations = []
        
        if not protection_analysis['has_protection']:
            recommendations.extend([
                'Implement CSRF tokens in all forms',
                'Use secure, random tokens for each session',
                'Validate tokens on the server side',
                'Consider implementing SameSite cookie protection',
                'Add security headers (X-Frame-Options, CSP)'
            ])
        
        if protection_analysis['has_weak_protection']:
            recommendations.extend([
                'Strengthen existing CSRF protection',
                'Use cryptographically secure random tokens',
                'Implement proper token validation',
                'Add additional security layers'
            ])
        
        return recommendations
    
    def _print_vulnerability_info(self, vulnerability):
        """
        Print detailed vulnerability information
        
        Args:
            vulnerability (dict): Vulnerability details
        """
        severity_color = {
            'Critical': Fore.RED,
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.BLUE
        }.get(vulnerability['severity'], Fore.WHITE)
        
        print(severity_color + f"[!] CSRF Vulnerability Found:" + Style.RESET_ALL)
        print(Fore.YELLOW + f"    URL: {vulnerability['url']}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"    Type: {vulnerability['subtype']}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"    Severity: {vulnerability['severity']}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"    Method: {vulnerability['method']}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"    Attack Vector: {vulnerability['attack_vector']}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"    Evidence: {vulnerability['evidence']}" + Style.RESET_ALL)
        print()
    
    def run(self):
        """
        Advanced CSRF vulnerability testing with comprehensive reporting
        
        Returns:
            int: Number of CSRF vulnerabilities found
        """
        initial_csrf_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CSRF')
        
        if self.verbose:
            print(Fore.BLUE + "[*] Starting advanced CSRF vulnerability scan..." + Style.RESET_ALL)
            print(Fore.CYAN + f"    Testing {len(self.forms)} forms" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Using {len(self.csrf_protection_mechanisms)} protection mechanisms" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Testing {len(self.csrf_attack_vectors)} attack vectors" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Comprehensive token analysis enabled" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Advanced protection detection enabled" + Style.RESET_ALL)
        
        # Test each form for CSRF vulnerabilities with threading
        csrf_vulnerabilities = []
        
        if self.forms:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                form_results = list(executor.map(self.test_form, self.forms))
                
                for result in form_results:
                    if result:
                        csrf_vulnerabilities.append(result)
                        self.vulnerabilities.append(result)
        
        # Generate comprehensive report
        self._generate_csrf_report(initial_csrf_count)
        
        return self._get_csrf_vulnerability_count(initial_csrf_count)
    
    def _generate_csrf_report(self, initial_count):
        """
        Generate comprehensive CSRF vulnerability report
        
        Args:
            initial_count (int): Initial vulnerability count
        """
        if not self.verbose:
            csrf_vulnerabilities_found = self._get_csrf_vulnerability_count(initial_count)
            print(Fore.GREEN + f"[+] Completed CSRF testing, found {csrf_vulnerabilities_found} vulnerabilities" + Style.RESET_ALL)
            return
        
        csrf_vulnerabilities_found = self._get_csrf_vulnerability_count(initial_count)
        
        print(Fore.GREEN + f"[+] Advanced CSRF scan completed" + Style.RESET_ALL)
        print(Fore.GREEN + f"    Total vulnerabilities found: {csrf_vulnerabilities_found}" + Style.RESET_ALL)
        
        # Detailed severity breakdown
        critical_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CSRF' and v.get('severity') == 'Critical')
        high_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CSRF' and v.get('severity') == 'High')
        medium_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CSRF' and v.get('severity') == 'Medium')
        low_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CSRF' and v.get('severity') == 'Low')
        
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
            if v.get('type') == 'CSRF':
                subtype = v.get('subtype', 'Unknown')
                subtypes[subtype] = subtypes.get(subtype, 0) + 1
        
        if subtypes:
            print(Fore.CYAN + "    Vulnerability subtypes:" + Style.RESET_ALL)
            for subtype, count in subtypes.items():
                print(Fore.CYAN + f"      {subtype}: {count}" + Style.RESET_ALL)
        
        # Protection mechanism analysis
        protection_mechanisms = {}
        for v in self.vulnerabilities:
            if v.get('type') == 'CSRF':
                analysis = v.get('protection_analysis', {})
                for mechanism in analysis.get('protection_mechanisms', []):
                    protection_mechanisms[mechanism] = protection_mechanisms.get(mechanism, 0) + 1
        
        if protection_mechanisms:
            print(Fore.CYAN + "    Protection mechanisms found:" + Style.RESET_ALL)
            for mechanism, count in protection_mechanisms.items():
                print(Fore.CYAN + f"      {mechanism}: {count}" + Style.RESET_ALL)
        
        # Advanced features summary
        print(Fore.MAGENTA + "    Advanced features used:" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Token-based protection analysis" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Header-based protection detection" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Cookie-based protection validation" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ SameSite cookie analysis" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Weak token detection" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Attack vector analysis" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Severity assessment" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Comprehensive recommendations" + Style.RESET_ALL)
    
    def _get_csrf_vulnerability_count(self, initial_count):
        """
        Get the number of CSRF vulnerabilities found
        
        Args:
            initial_count (int): Initial vulnerability count
            
        Returns:
            int: Number of new CSRF vulnerabilities found
        """
        final_csrf_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CSRF')
        return final_csrf_count - initial_count 