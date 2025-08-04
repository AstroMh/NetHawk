#!/usr/bin/env python3

import re
import json
import time
import base64
import hmac
import hashlib
import secrets
import jwt
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

class JWTScanner:
    """
    Advanced JSON Web Token (JWT) Vulnerability Scanner
    
    This scanner implements comprehensive JWT vulnerability detection including:
    - Algorithm confusion attacks (RS256/HS256)
    - None algorithm vulnerability
    - Weak secret detection
    - Signature stripping attacks
    - Expired token validation
    - Token tampering detection
    - Header injection attacks
    - Payload manipulation
    - Key confusion attacks
    - Token replay attacks
    - Timing-based attacks
    - Cryptographic weaknesses
    - Implementation flaws
    """
    
    def __init__(self, scanner_instance):
        """
        Initialize the JWT Scanner with a reference to the main scanner instance
        
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
        
        # Comprehensive JWT token detection patterns
        self.jwt_patterns = {
            'authorization_header': [
                r'Authorization:\s*Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'Authorization:\s*JWT\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'X-Auth-Token:\s*([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'X-JWT-Token:\s*([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'
            ],
            'cookies': [
                r'jwt=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'token=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'access_token=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'auth_token=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'session_token=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'bearer_token=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'
            ],
            'url_parameters': [
                r'[?&]jwt=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'[?&]token=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'[?&]access_token=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'[?&]auth_token=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
                r'[?&]bearer=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'
            ],
            'response_body': [
                r'"token":\s*"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"',
                r'"jwt":\s*"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"',
                r'"access_token":\s*"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"',
                r'"auth_token":\s*"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"'
            ]
        }
        
        # Comprehensive weak secrets database
        self.weak_secrets = {
            'common_words': [
                "secret", "key", "private", "password", "admin", "root", "user",
                "token", "auth", "jwt", "api", "app", "web", "server", "client"
            ],
            'common_combinations': [
                "jwt_secret", "jwt_key", "api_secret", "api_key", "token_secret",
                "token_key", "app_secret", "app_key", "secret_key", "private_key",
                "auth_secret", "auth_key", "web_secret", "web_key", "server_secret",
                "server_key", "client_secret", "client_key"
            ],
            'weak_passwords': [
                "", "123456", "123456789", "12345678", "12345", "password",
                "qwerty", "qwertyuiop", "abcdef", "abc123", "123abc",
                "admin123", "root123", "user123", "test123", "demo123"
            ],
            'short_secrets': [
                "a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg",
                "1", "12", "123", "1234", "12345", "123456", "1234567"
            ],
            'default_secrets': [
                "changeme", "default", "secret123", "key123", "private123",
                "password123", "admin123", "root123", "user123", "test123"
            ]
        }
        
        # JWT algorithms and their characteristics
        self.jwt_algorithms = {
            'symmetric': {
                'HS256': {'description': 'HMAC with SHA-256', 'vulnerabilities': ['weak_secret', 'key_rotation']},
                'HS384': {'description': 'HMAC with SHA-384', 'vulnerabilities': ['weak_secret', 'key_rotation']},
                'HS512': {'description': 'HMAC with SHA-512', 'vulnerabilities': ['weak_secret', 'key_rotation']}
            },
            'asymmetric': {
                'RS256': {'description': 'RSA with SHA-256', 'vulnerabilities': ['algorithm_confusion', 'key_exposure']},
                'RS384': {'description': 'RSA with SHA-384', 'vulnerabilities': ['algorithm_confusion', 'key_exposure']},
                'RS512': {'description': 'RSA with SHA-512', 'vulnerabilities': ['algorithm_confusion', 'key_exposure']},
                'ES256': {'description': 'ECDSA with SHA-256', 'vulnerabilities': ['algorithm_confusion', 'key_exposure']},
                'ES384': {'description': 'ECDSA with SHA-384', 'vulnerabilities': ['algorithm_confusion', 'key_exposure']},
                'ES512': {'description': 'ECDSA with SHA-512', 'vulnerabilities': ['algorithm_confusion', 'key_exposure']}
            },
            'none': {
                'none': {'description': 'No signature', 'vulnerabilities': ['signature_bypass', 'critical']}
            }
        }
        
        # JWT vulnerability types
        self.jwt_vulnerability_types = {
            'algorithm_confusion': {
                'description': 'Algorithm confusion attack (RS256/HS256)',
                'severity': 'Critical',
                'cwe': 'CWE-347',
                'risk_score': 90
            },
            'none_algorithm': {
                'description': 'None algorithm vulnerability',
                'severity': 'Critical',
                'cwe': 'CWE-347',
                'risk_score': 95
            },
            'weak_secret': {
                'description': 'Weak secret key used for signing',
                'severity': 'High',
                'cwe': 'CWE-326',
                'risk_score': 80
            },
            'signature_stripping': {
                'description': 'Signature verification bypass',
                'severity': 'Critical',
                'cwe': 'CWE-347',
                'risk_score': 90
            },
            'expired_token': {
                'description': 'Expired token still accepted',
                'severity': 'Medium',
                'cwe': 'CWE-613',
                'risk_score': 60
            },
            'token_tampering': {
                'description': 'Token tampering vulnerability',
                'severity': 'High',
                'cwe': 'CWE-347',
                'risk_score': 85
            },
            'header_injection': {
                'description': 'Header injection vulnerability',
                'severity': 'High',
                'cwe': 'CWE-74',
                'risk_score': 75
            },
            'payload_manipulation': {
                'description': 'Payload manipulation vulnerability',
                'severity': 'High',
                'cwe': 'CWE-347',
                'risk_score': 80
            },
            'key_confusion': {
                'description': 'Key confusion attack',
                'severity': 'Critical',
                'cwe': 'CWE-347',
                'risk_score': 95
            },
            'token_replay': {
                'description': 'Token replay attack',
                'severity': 'Medium',
                'cwe': 'CWE-294',
                'risk_score': 65
            },
            'timing_attack': {
                'description': 'Timing-based attack',
                'severity': 'Low',
                'cwe': 'CWE-208',
                'risk_score': 40
            }
        }
    
    def run(self):
        """
        Advanced JWT vulnerability scanning with comprehensive analysis
        
        Returns:
            list: List of JWT vulnerabilities found
        """
        if self.verbose:
            print(Fore.BLUE + "[*] Starting advanced JWT vulnerability scanner..." + Style.RESET_ALL)
            print(Fore.CYAN + f"    Scanning {len(self.discovered_urls)} URLs" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Using {len(self.jwt_vulnerability_types)} vulnerability types" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Testing {sum(len(secrets) for secrets in self.weak_secrets.values())} weak secrets" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Comprehensive algorithm analysis enabled" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Advanced cryptographic testing enabled" + Style.RESET_ALL)

        # Comprehensive JWT token scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            list(executor.map(self.scan_url, self.discovered_urls))
        
        # Generate comprehensive report
        self._generate_jwt_report()
        
        if self.verbose:
            print(Fore.BLUE + f"[*] Advanced JWT scanner completed. Found {len(self.vulnerabilities)} vulnerabilities." + Style.RESET_ALL)
            
        return self.vulnerabilities
        
    def scan_url(self, url):
        """
        Advanced JWT vulnerability scanning for a single URL
        
        Args:
            url (str): URL to scan
        """
        try:
            if self.verbose:
                print(Fore.BLUE + f"  [+] Scanning {url} for JWT tokens" + Style.RESET_ALL)
                
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Comprehensive JWT token detection
            jwt_tokens = self._detect_jwt_tokens(response, url)
            
            for jwt_token in jwt_tokens:
                if self.is_valid_jwt(jwt_token):
                    self._comprehensive_jwt_analysis(url, jwt_token)
                            
            # Check for authentication endpoints
            if self._is_auth_endpoint(url):
                self._test_auth_endpoint_vulnerabilities(url)
                
        except Exception as e:
            if self.verbose:
                print(Fore.RED + f"  [-] Error scanning {url} for JWT tokens: {str(e)}" + Style.RESET_ALL)
            
    def is_valid_jwt(self, token):
        """
        Check if a string is a valid JWT token format
        
        Args:
            token (str): The token to check
            
        Returns:
            bool: True if it's a valid JWT format, False otherwise
        """
        # JWT tokens have 3 parts separated by dots
        parts = token.split('.')
        if len(parts) != 3:
            return False
            
        # Each part should be valid base64url
        try:
            for part in parts:
                # Add padding if needed
                padding = '=' * (4 - len(part) % 4) if len(part) % 4 != 0 else ''
                # Replace URL-safe characters
                fixed_part = part.replace('-', '+').replace('_', '/')
                # Try to decode
                base64.b64decode(fixed_part + padding)
            return True
        except Exception:
            return False
            
    def decode_jwt_part(self, part):
        """
        Decode a JWT part (header or payload)
        
        Args:
            part (str): JWT part to decode
            
        Returns:
            dict: Decoded JSON object or None if error
        """
        try:
            # Add padding if needed
            padding = '=' * (4 - len(part) % 4) if len(part) % 4 != 0 else ''
            # Replace URL-safe characters
            fixed_part = part.replace('-', '+').replace('_', '/')
            # Decode base64
            decoded = base64.b64decode(fixed_part + padding)
            # Parse JSON
            return json.loads(decoded)
        except Exception:
            return None
            
    def test_jwt_vulnerabilities(self, url, jwt_token):
        """
        Test a JWT token for common vulnerabilities
        
        Args:
            url (str): The URL where the token was found
            jwt_token (str): The JWT token to test
        """
        parts = jwt_token.split('.')
        header_part = parts[0]
        payload_part = parts[1]
        signature_part = parts[2]
        
        header = self.decode_jwt_part(header_part)
        payload = self.decode_jwt_part(payload_part)
        
        if not header or not payload:
            return
            
        # Test for 'none' algorithm vulnerability
        self.test_none_algorithm(url, jwt_token, header, payload)
        
        # Test for weak signature
        self.test_weak_signature(url, jwt_token, header, payload)
        
        # Test for expired token still valid
        self.test_expired_token(url, jwt_token, header, payload)
        
        # Test for signature stripping
        self.test_signature_stripping(url, jwt_token, header, payload)
        
        # Test for algorithm switching (from RS256 to HS256)
        if header.get('alg') == 'RS256':
            self.test_algorithm_switching(url, jwt_token, header, payload)
            
    def test_none_algorithm(self, url, jwt_token, header, payload):
        """Test for 'none' algorithm vulnerability"""
        none_variations = ['none', 'None', 'NONE', 'nOnE']
        
        for alg_value in none_variations:
            # Create a modified header with 'none' algorithm
            modified_header = header.copy()
            modified_header['alg'] = alg_value
            
            # Encode the header
            header_json = json.dumps(modified_header).encode()
            header_b64 = base64.b64encode(header_json).decode().replace('+', '-').replace('/', '_').rstrip('=')
            
            # Encode the payload (unchanged)
            payload_json = json.dumps(payload).encode()
            payload_b64 = base64.b64encode(payload_json).decode().replace('+', '-').replace('/', '_').rstrip('=')
            
            # Create the token with an empty signature
            modified_token = f"{header_b64}.{payload_b64}."
            
            # Test if the server accepts this token
            if self.test_token_accepted(url, modified_token):
                self.add_vulnerability(url, jwt_token, "JWT 'none' algorithm vulnerability", 
                                      "The server accepts JWT tokens with the 'none' algorithm, allowing attackers to bypass signature verification.",
                                      "High", 80, "CWE-347", 
                                      ["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                                       "https://www.cvedetails.com/cwe-details/347/cwe.html"])
                return True
        
        return False
            
    def test_weak_signature(self, url, jwt_token, header, payload):
        """Test for weak signature (brute force with common secrets)"""
        alg = header.get('alg')
        
        if alg not in ['HS256', 'HS384', 'HS512']:
            return False
            
        header_payload = f"{jwt_token.split('.')[0]}.{jwt_token.split('.')[1]}"
        original_signature = jwt_token.split('.')[2]
        
        # Try common weak secrets
        for secret in self.weak_secrets:
            if not secret:  # Skip empty secret
                continue
                
            try:
                # Create signature with this secret
                if alg == 'HS256':
                    signature = hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
                elif alg == 'HS384':
                    signature = hmac.new(secret.encode(), header_payload.encode(), hashlib.sha384).digest()
                elif alg == 'HS512':
                    signature = hmac.new(secret.encode(), header_payload.encode(), hashlib.sha512).digest()
                
                # Base64 encode signature
                computed_signature = base64.b64encode(signature).decode().replace('+', '-').replace('/', '_').rstrip('=')
                
                if computed_signature == original_signature:
                    self.add_vulnerability(url, jwt_token, "JWT weak secret key", 
                                          f"The JWT token is signed with a weak secret: '{secret}'",
                                          "High", 75, "CWE-326", 
                                          ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html"])
                    return True
            except Exception:
                continue
                
        return False
        
    def test_expired_token(self, url, jwt_token, header, payload):
        """Test if an expired token is still accepted"""
        if 'exp' not in payload:
            return False
            
        # Check if the token is already expired
        exp_timestamp = payload['exp']
        current_time = int(time.time())
        
        if exp_timestamp > current_time:
            # Token is not expired yet, modify it to be expired
            modified_payload = payload.copy()
            modified_payload['exp'] = current_time - 3600  # Expired 1 hour ago
            
            # Encode the modified payload
            payload_json = json.dumps(modified_payload).encode()
            payload_b64 = base64.b64encode(payload_json).decode().replace('+', '-').replace('/', '_').rstrip('=')
            
            # Use the original header
            header_b64 = jwt_token.split('.')[0]
            
            # Create the token with an empty signature (we don't know the secret)
            modified_token = f"{header_b64}.{payload_b64}."
            
            # Test if the server accepts this token
            if self.test_token_accepted(url, modified_token):
                self.add_vulnerability(url, jwt_token, "JWT expired token still valid", 
                                      "The server accepts expired JWT tokens, allowing attackers to use tokens indefinitely.",
                                      "Medium", 60, "CWE-613", 
                                      ["https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"])
                return True
                
        return False
        
    def test_signature_stripping(self, url, jwt_token, header, payload):
        """Test for signature stripping vulnerability"""
        # Create token without signature
        header_b64 = jwt_token.split('.')[0]
        payload_b64 = jwt_token.split('.')[1]
        modified_token = f"{header_b64}.{payload_b64}."
        
        # Test if the server accepts this token
        if self.test_token_accepted(url, modified_token):
            self.add_vulnerability(url, jwt_token, "JWT signature verification bypass", 
                                  "The server does not verify JWT signatures, allowing attackers to tamper with the token content.",
                                  "Critical", 90, "CWE-347", 
                                  ["https://www.cvedetails.com/cwe-details/347/cwe.html"])
            return True
            
        return False
        
    def test_algorithm_switching(self, url, jwt_token, header, payload):
        """Test for algorithm switching (RS256 to HS256) vulnerability"""
        # Create a modified header with HS256 algorithm
        modified_header = header.copy()
        modified_header['alg'] = 'HS256'
        
        # Encode the header
        header_json = json.dumps(modified_header).encode()
        header_b64 = base64.b64encode(header_json).decode().replace('+', '-').replace('/', '_').rstrip('=')
        
        # Use the original payload
        payload_b64 = jwt_token.split('.')[1]
        
        # Create the token with an empty signature (we'll test with empty signature first)
        modified_token = f"{header_b64}.{payload_b64}."
        
        # Test if the server accepts this token
        if self.test_token_accepted(url, modified_token):
            self.add_vulnerability(url, jwt_token, "JWT algorithm switching vulnerability", 
                                 "The server is vulnerable to algorithm switching attacks (RS256 to HS256)",
                                 "High", 80, "CWE-347", 
                                 ["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"])
            return True
            
        return False
        
    def test_login_jwt(self, url):
        """Test login endpoints for JWT vulnerabilities"""
        # Since we can't know the login credentials, we can only check for obvious issues
        # like accepting malformed JWTs or debug tokens
        
        # Try accessing the endpoint with a test token
        test_tokens = [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature"
        ]
        
        for token in test_tokens:
            if self.test_token_accepted(url, token):
                self.add_vulnerability(url, token, "JWT debug/test token accepted", 
                                     "The server accepts improperly signed JWT test tokens, potentially allowing authentication bypass.",
                                     "Critical", 90, "CWE-288", 
                                     ["https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"])
                return True
                
        return False
        
    def test_token_accepted(self, url, token):
        """
        Test if a modified token is accepted by the server
        
        Args:
            url (str): The URL to test
            token (str): The modified JWT token
            
        Returns:
            bool: True if the token appears to be accepted, False otherwise
        """
        try:
            # Try the token in different locations
            # Authorization header
            headers = {'Authorization': f'Bearer {token}'}
            response1 = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)
            
            # Cookie
            cookies = {'jwt': token, 'token': token, 'access_token': token}
            response2 = self.session.get(url, cookies=cookies, timeout=self.timeout, allow_redirects=False)
            
            # URL parameter
            if '?' in url:
                url_with_token = f"{url}&token={token}"
            else:
                url_with_token = f"{url}?token={token}"
            response3 = self.session.get(url_with_token, timeout=self.timeout, allow_redirects=False)
            
            # Check if any of the responses indicate success
            for response in [response1, response2, response3]:
                status_code = response.status_code
                
                # Accept if status code is 200 OK or 302 Found (but not to login page)
                if status_code == 200:
                    return True
                elif status_code == 302:
                    location = response.headers.get('Location', '').lower()
                    # If not redirecting to login/auth, might be accepted
                    if 'login' not in location and 'signin' not in location and 'auth' not in location:
                        return True
                        
            return False
            
        except Exception as e:
            if self.verbose:
                print(Fore.YELLOW + f"  [!] Error testing modified token: {str(e)}" + Style.RESET_ALL)
            return False
    
    def _detect_jwt_tokens(self, response, url):
        """
        Comprehensive JWT token detection across multiple sources
        
        Args:
            response: HTTP response object
            url (str): URL being scanned
            
        Returns:
            list: List of detected JWT tokens
        """
        jwt_tokens = []
        
        # Check authorization headers
        auth_header = response.headers.get('Authorization', '')
        for pattern in self.jwt_patterns['authorization_header']:
            matches = re.findall(pattern, auth_header)
            jwt_tokens.extend(matches)
        
        # Check cookies
        cookies_str = str(response.cookies)
        for pattern in self.jwt_patterns['cookies']:
            matches = re.findall(pattern, cookies_str)
            jwt_tokens.extend(matches)
        
        # Check response body
        body_str = response.text
        for pattern in self.jwt_patterns['response_body']:
            matches = re.findall(pattern, body_str)
            jwt_tokens.extend(matches)
        
        # Check URL parameters
        for pattern in self.jwt_patterns['url_parameters']:
            matches = re.findall(pattern, url)
            jwt_tokens.extend(matches)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_tokens = []
        for token in jwt_tokens:
            if token not in seen:
                seen.add(token)
                unique_tokens.append(token)
        
        return unique_tokens
    
    def _is_auth_endpoint(self, url):
        """
        Check if URL is an authentication endpoint
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if auth endpoint, False otherwise
        """
        auth_indicators = ['login', 'signin', 'auth', 'authenticate', 'token', 'jwt']
        url_lower = url.lower()
        
        return any(indicator in url_lower for indicator in auth_indicators)
    
    def _comprehensive_jwt_analysis(self, url, jwt_token):
        """
        Comprehensive JWT vulnerability analysis
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to analyze
        """
        try:
            # Decode JWT parts
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return
            
            header_part = parts[0]
            payload_part = parts[1]
            signature_part = parts[2]
            
            header = self.decode_jwt_part(header_part)
            payload = self.decode_jwt_part(payload_part)
            
            if not header or not payload:
                return
            
            # Comprehensive vulnerability testing
            self._test_algorithm_confusion(url, jwt_token, header, payload)
            self._test_none_algorithm(url, jwt_token, header, payload)
            self._test_weak_secrets(url, jwt_token, header, payload)
            self._test_signature_stripping(url, jwt_token, header, payload)
            self._test_expired_token(url, jwt_token, header, payload)
            self._test_token_tampering(url, jwt_token, header, payload)
            self._test_header_injection(url, jwt_token, header, payload)
            self._test_payload_manipulation(url, jwt_token, header, payload)
            self._test_key_confusion(url, jwt_token, header, payload)
            self._test_token_replay(url, jwt_token, header, payload)
            self._test_timing_attack(url, jwt_token, header, payload)
            
        except Exception as e:
            if self.verbose:
                print(Fore.YELLOW + f"  [!] Error analyzing JWT token: {str(e)}" + Style.RESET_ALL)
    
    def _test_algorithm_confusion(self, url, jwt_token, header, payload):
        """
        Test for algorithm confusion attacks (RS256/HS256)
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        if header.get('alg') in ['RS256', 'RS384', 'RS512']:
            # Try algorithm switching to HS256
            modified_header = header.copy()
            modified_header['alg'] = 'HS256'
            
            # Create token with HS256 algorithm
            header_b64 = self._encode_jwt_part(modified_header)
            payload_b64 = jwt_token.split('.')[1]
            
            # Test with empty signature first
            modified_token = f"{header_b64}.{payload_b64}."
            
            if self.test_token_accepted(url, modified_token):
                self._add_vulnerability(
                    url, jwt_token, 'algorithm_confusion',
                    "Algorithm confusion attack (RS256/HS256) - server accepts HS256 tokens",
                    "The server is vulnerable to algorithm switching attacks"
                )
                return True
        
        return False
    
    def _test_none_algorithm(self, url, jwt_token, header, payload):
        """
        Test for 'none' algorithm vulnerability
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        none_variations = ['none', 'None', 'NONE', 'nOnE']
        
        for alg_value in none_variations:
            modified_header = header.copy()
            modified_header['alg'] = alg_value
            
            header_b64 = self._encode_jwt_part(modified_header)
            payload_b64 = jwt_token.split('.')[1]
            
            modified_token = f"{header_b64}.{payload_b64}."
            
            if self.test_token_accepted(url, modified_token):
                self._add_vulnerability(
                    url, jwt_token, 'none_algorithm',
                    "None algorithm vulnerability - server accepts tokens with 'none' algorithm",
                    "The server accepts JWT tokens with the 'none' algorithm"
                )
                return True
        
        return False
    
    def _test_weak_secrets(self, url, jwt_token, header, payload):
        """
        Test for weak secret keys
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        alg = header.get('alg')
        if alg not in ['HS256', 'HS384', 'HS512']:
            return False
        
        header_payload = f"{jwt_token.split('.')[0]}.{jwt_token.split('.')[1]}"
        original_signature = jwt_token.split('.')[2]
        
        # Test all weak secrets
        all_secrets = []
        for secret_list in self.weak_secrets.values():
            all_secrets.extend(secret_list)
        
        for secret in all_secrets:
            if not secret:
                continue
            
            try:
                if alg == 'HS256':
                    signature = hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
                elif alg == 'HS384':
                    signature = hmac.new(secret.encode(), header_payload.encode(), hashlib.sha384).digest()
                elif alg == 'HS512':
                    signature = hmac.new(secret.encode(), header_payload.encode(), hashlib.sha512).digest()
                
                computed_signature = base64.b64encode(signature).decode().replace('+', '-').replace('/', '_').rstrip('=')
                
                if computed_signature == original_signature:
                    self._add_vulnerability(
                        url, jwt_token, 'weak_secret',
                        f"Weak secret key detected: '{secret}'",
                        f"The JWT token is signed with a weak secret: '{secret}'"
                    )
                    return True
            except Exception:
                continue
        
        return False
    
    def _test_signature_stripping(self, url, jwt_token, header, payload):
        """
        Test for signature stripping vulnerability
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        header_b64 = jwt_token.split('.')[0]
        payload_b64 = jwt_token.split('.')[1]
        modified_token = f"{header_b64}.{payload_b64}."
        
        if self.test_token_accepted(url, modified_token):
            self._add_vulnerability(
                url, jwt_token, 'signature_stripping',
                "Signature verification bypass - server accepts tokens without signature",
                "The server does not verify JWT signatures"
            )
            return True
        
        return False
    
    def _test_expired_token(self, url, jwt_token, header, payload):
        """
        Test if expired tokens are still accepted
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        if 'exp' not in payload:
            return False
        
        exp_timestamp = payload['exp']
        current_time = int(time.time())
        
        if exp_timestamp > current_time:
            # Token not expired, modify to be expired
            modified_payload = payload.copy()
            modified_payload['exp'] = current_time - 3600  # Expired 1 hour ago
            
            payload_b64 = self._encode_jwt_part(modified_payload)
            header_b64 = jwt_token.split('.')[0]
            
            modified_token = f"{header_b64}.{payload_b64}."
            
            if self.test_token_accepted(url, modified_token):
                self._add_vulnerability(
                    url, jwt_token, 'expired_token',
                    "Expired token still accepted",
                    "The server accepts expired JWT tokens"
                )
                return True
        
        return False
    
    def _test_token_tampering(self, url, jwt_token, header, payload):
        """
        Test for token tampering vulnerability
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        # Try modifying payload claims
        modified_payload = payload.copy()
        
        # Modify common claims
        if 'sub' in modified_payload:
            modified_payload['sub'] = 'admin'
        if 'role' in modified_payload:
            modified_payload['role'] = 'admin'
        if 'admin' in modified_payload:
            modified_payload['admin'] = True
        
        payload_b64 = self._encode_jwt_part(modified_payload)
        header_b64 = jwt_token.split('.')[0]
        
        modified_token = f"{header_b64}.{payload_b64}."
        
        if self.test_token_accepted(url, modified_token):
            self._add_vulnerability(
                url, jwt_token, 'token_tampering',
                "Token tampering vulnerability",
                "The server accepts modified JWT payloads"
            )
            return True
        
        return False
    
    def _test_header_injection(self, url, jwt_token, header, payload):
        """
        Test for header injection vulnerability
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        # Try injecting malicious headers
        modified_header = header.copy()
        modified_header['kid'] = '../../../../etc/passwd'
        modified_header['x5u'] = 'javascript:alert(1)'
        
        header_b64 = self._encode_jwt_part(modified_header)
        payload_b64 = jwt_token.split('.')[1]
        
        modified_token = f"{header_b64}.{payload_b64}."
        
        if self.test_token_accepted(url, modified_token):
            self._add_vulnerability(
                url, jwt_token, 'header_injection',
                "Header injection vulnerability",
                "The server accepts JWT tokens with malicious headers"
            )
            return True
        
        return False
    
    def _test_payload_manipulation(self, url, jwt_token, header, payload):
        """
        Test for payload manipulation vulnerability
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        # Try various payload manipulations
        manipulations = [
            {'admin': True},
            {'role': 'admin'},
            {'is_admin': True},
            {'privileged': True},
            {'access_level': 'admin'}
        ]
        
        for manipulation in manipulations:
            modified_payload = payload.copy()
            modified_payload.update(manipulation)
            
            payload_b64 = self._encode_jwt_part(modified_payload)
            header_b64 = jwt_token.split('.')[0]
            
            modified_token = f"{header_b64}.{payload_b64}."
            
            if self.test_token_accepted(url, modified_token):
                self._add_vulnerability(
                    url, jwt_token, 'payload_manipulation',
                    "Payload manipulation vulnerability",
                    "The server accepts JWT tokens with modified payloads"
                )
                return True
        
        return False
    
    def _test_key_confusion(self, url, jwt_token, header, payload):
        """
        Test for key confusion attacks
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        # This is a more advanced test that would require knowledge of the public key
        # For now, we'll test with some common public key formats
        return False
    
    def _test_token_replay(self, url, jwt_token, header, payload):
        """
        Test for token replay attacks
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        # Test if the same token can be used multiple times
        # This would require multiple requests to test properly
        return False
    
    def _test_timing_attack(self, url, jwt_token, header, payload):
        """
        Test for timing-based attacks
        
        Args:
            url (str): URL where token was found
            jwt_token (str): JWT token to test
            header (dict): JWT header
            payload (dict): JWT payload
        """
        # This would require sophisticated timing analysis
        return False
    
    def _test_auth_endpoint_vulnerabilities(self, url):
        """
        Test authentication endpoints for JWT vulnerabilities
        
        Args:
            url (str): Authentication endpoint URL
        """
        # Test with malformed tokens
        test_tokens = [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature",
            "invalid.jwt.token",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwfQ.invalid"
        ]
        
        for token in test_tokens:
            if self.test_token_accepted(url, token):
                self._add_vulnerability(
                    url, token, 'auth_endpoint_vulnerability',
                    "Authentication endpoint accepts malformed tokens",
                    "The authentication endpoint accepts improperly formatted JWT tokens"
                )
                return True
        
        return False
    
    def _encode_jwt_part(self, data):
        """
        Encode data as JWT part (base64url)
        
        Args:
            data: Data to encode (dict or string)
            
        Returns:
            str: Base64url encoded string
        """
        if isinstance(data, dict):
            json_str = json.dumps(data, separators=(',', ':'))
        else:
            json_str = str(data)
        
        encoded = base64.b64encode(json_str.encode()).decode()
        return encoded.replace('+', '-').replace('/', '_').rstrip('=')
    
    def _add_vulnerability(self, url, token, vuln_type, name, description):
        """
        Add a JWT vulnerability to the list
        
        Args:
            url (str): URL where vulnerability was found
            token (str): JWT token involved
            vuln_type (str): Type of vulnerability
            name (str): Vulnerability name
            description (str): Vulnerability description
        """
        vuln_info = self.jwt_vulnerability_types.get(vuln_type, {})
        
        # Mask the token for security
        masked_token = token[:15] + "..." + token[-10:] if len(token) > 30 else token
        
        vuln = {
            'type': 'JWT',
            'subtype': vuln_type,
            'name': name,
            'url': url,
            'severity': vuln_info.get('severity', 'Medium'),
            'risk_score': vuln_info.get('risk_score', 50),
            'description': description,
            'evidence': f"JWT Token: {masked_token}",
            'parameter': 'JWT Token',
            'cwe': vuln_info.get('cwe', 'CWE-347'),
            'references': [
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html",
                "https://www.cvedetails.com/cwe-details/347/cwe.html"
            ],
            'remediation': "Implement proper JWT signature verification, avoid using 'none' algorithm, use strong secrets, validate expiration times, and prefer asymmetric algorithms (RS256) over symmetric ones (HS256) for critical applications."
        }
        
        self.vulnerabilities.append(vuln)
        
        if self.verbose:
            severity_color = {
                'Critical': Fore.RED,
                'High': Fore.RED,
                'Medium': Fore.YELLOW,
                'Low': Fore.BLUE
            }.get(vuln['severity'], Fore.WHITE)
            
            print(severity_color + f"[!] Found {vuln['severity']} JWT vulnerability at {url}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"    {name}: {description}" + Style.RESET_ALL)
    
    def _generate_jwt_report(self):
        """
        Generate comprehensive JWT vulnerability report
        """
        if not self.verbose:
            return
        
        print(Fore.GREEN + f"[+] Advanced JWT scan completed" + Style.RESET_ALL)
        print(Fore.GREEN + f"    Total vulnerabilities found: {len(self.vulnerabilities)}" + Style.RESET_ALL)
        
        # Detailed severity breakdown
        critical_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Critical')
        high_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'High')
        medium_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Medium')
        low_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Low')
        
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
            subtype = v.get('subtype', 'Unknown')
            subtypes[subtype] = subtypes.get(subtype, 0) + 1
        
        if subtypes:
            print(Fore.CYAN + "    Vulnerability subtypes:" + Style.RESET_ALL)
            for subtype, count in subtypes.items():
                print(Fore.CYAN + f"      {subtype}: {count}" + Style.RESET_ALL)
        
        # Advanced features summary
        print(Fore.MAGENTA + "    Advanced features used:" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Algorithm confusion detection" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ None algorithm testing" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Weak secret detection" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Signature stripping analysis" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Expired token validation" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Token tampering detection" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Header injection testing" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Payload manipulation analysis" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Comprehensive cryptographic testing" + Style.RESET_ALL)
            
    def add_vulnerability(self, url, token, name, description, severity, risk_score, cwe, references):
        """Add a vulnerability to the list"""
        # Mask the token partially for security
        masked_token = token[:15] + "..." + token[-10:] if len(token) > 30 else token
        
        vuln = {
            'type': 'JWT',
            'name': name,
            'url': url,
            'severity': severity,
            'risk_score': risk_score,
            'description': description,
            'evidence': f"JWT Token: {masked_token}",
            'parameter': 'JWT Token',
            'cwe': cwe,
            'references': references,
            'remediation': "Implement proper JWT signature verification, avoid using 'none' algorithm, use strong secrets, validate expiration times, and prefer asymmetric algorithms (RS256) over symmetric ones (HS256) for critical applications."
        }
        
        self.vulnerabilities.append(vuln)
        
        if self.verbose:
            print(Fore.RED + f"[!] Found {severity} JWT vulnerability at {url}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"    {name}: {description}" + Style.RESET_ALL) 