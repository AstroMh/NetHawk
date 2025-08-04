#!/usr/bin/env python3

import time
import re
import random
import string
import requests
from urllib.parse import urlparse, parse_qs, urljoin
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from colorama import Fore, Style

class IDORScanner:
    """Scanner for detecting Insecure Direct Object Reference (IDOR) vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the IDOR Scanner with a reference to the main scanner instance
        
        Args:
            scanner_instance: The main WebScanner instance
        """
        self.scanner = scanner_instance
        self.target_url = scanner_instance.target_url
        self.headers = scanner_instance.headers
        self.timeout = scanner_instance.timeout
        self.verbose = scanner_instance.verbose
        self.max_threads = scanner_instance.max_threads
        self.session = scanner_instance.session
        self.vulnerabilities = []
        
        # Reference to scanner's vulnerability collections
        self.main_vulnerabilities = scanner_instance.vulnerabilities
        self.idor_vulnerabilities = scanner_instance.idor_vulnerabilities
        
        # Patterns for potential IDOR parameters
        self.idor_param_patterns = [
            r'id',
            r'user(_)?id',
            r'account(_)?id',
            r'item(_)?id',
            r'order(_)?id',
            r'no',
            r'doc(_)?id',
            r'key',
            r'email',
            r'group(_)?id',
            r'profile(_)?id',
            r'file(_)?id'
        ]
        
        # Response patterns that might indicate access to unauthorized resources
        self.sensitive_patterns = [
            r'password',
            r'ssn',
            r'social.*security',
            r'credit.*card',
            r'secret',
            r'private',
            r'token',
            r'personal',
            r'admin',
            r'root',
            r'config'
        ]
    
    def _is_idor_parameter(self, param_name):
        """Check if parameter name matches IDOR patterns"""
        for pattern in self.idor_param_patterns:
            if re.match(pattern, param_name, re.IGNORECASE):
                return True
        return False
    
    def _contains_sensitive_data(self, content):
        """Check if content contains sensitive data patterns"""
        for pattern in self.sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def _get_random_id(self, original_id):
        """
        Generate a random ID value similar to the original
        """
        try:
            # If numeric ID
            if original_id.isdigit():
                # Try adjacent numbers
                possible_ids = [
                    str(int(original_id) + 1),
                    str(int(original_id) - 1),
                    str(int(original_id) + 100),
                    str(int(original_id) - 100)
                ]
                # Also try a completely different number with same length
                possible_ids.append(''.join(random.choices(string.digits, k=len(original_id))))
                return possible_ids
            
            # If GUID/UUID
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', original_id, re.IGNORECASE):
                # Generate similar formatted UUID
                uuid_parts = [
                    ''.join(random.choices(string.hexdigits[:16], k=8)),
                    ''.join(random.choices(string.hexdigits[:16], k=4)),
                    ''.join(random.choices(string.hexdigits[:16], k=4)),
                    ''.join(random.choices(string.hexdigits[:16], k=4)),
                    ''.join(random.choices(string.hexdigits[:16], k=12))
                ]
                return ['-'.join(uuid_parts)]
            
            # If alphanumeric
            else:
                # Generate random alphanumeric with same length
                return [''.join(random.choices(string.ascii_letters + string.digits, k=len(original_id)))]
        except:
            # Fallback
            return [str(random.randint(1000, 9999))]
    
    def scan_url_parameters(self, url):
        """
        Scan URL parameters for potential IDOR vulnerabilities
        
        Args:
            url: URL to scan
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Skip URLs without parameters
        if not query_params:
            return
        
        # Check each parameter
        for param_name, values in query_params.items():
            if not self._is_idor_parameter(param_name):
                continue
            
            original_value = values[0]
            
            # Skip empty values
            if not original_value:
                continue
                
            if self.verbose:
                print(f"  Testing IDOR on parameter {param_name} with value {original_value}")
            
            # Try different variations of the ID
            random_ids = self._get_random_id(original_value)
            original_response = None
            
            # Make the original request first to compare responses
            try:
                original_response = self.session.get(url, headers=self.headers, timeout=self.timeout)
                original_status = original_response.status_code
                original_content_length = len(original_response.text)
                original_content_type = original_response.headers.get('Content-Type', '')
            except Exception as e:
                if self.verbose:
                    print(f"  Error making original request: {e}")
                continue
            
            # Test each variation
            for random_id in random_ids:
                # Create modified URL
                modified_query = {}
                for p, v in query_params.items():
                    if p == param_name:
                        modified_query[p] = [random_id]
                    else:
                        modified_query[p] = v
                
                # Rebuild query string
                modified_query_str = '&'.join([f"{p}={v[0]}" for p, v in modified_query.items()])
                modified_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query_str}"
                
                try:
                    response = self.session.get(modified_url, headers=self.headers, timeout=self.timeout)
                    
                    # Look for potential IDOR indicators
                    if response.status_code == 200:
                        # Different success responses may indicate vulnerability
                        content_length_diff = abs(len(response.text) - original_content_length)
                        content_length_diff_percent = (content_length_diff / original_content_length) * 100
                        
                        evidence = []
                        
                        # Check for unexpected successful response (original access denied but modified allowed)
                        if original_status in [401, 403, 404] and response.status_code == 200:
                            evidence.append(f"Original request status: {original_status}, Modified request status: 200")
                        
                        # Significant content length difference can indicate different resource access
                        elif content_length_diff_percent > 5 and content_length_diff > 100:
                            evidence.append(f"Content length difference: {content_length_diff} bytes ({content_length_diff_percent:.2f}%)")
                        
                        # Check for sensitive data patterns in the response
                        if self._contains_sensitive_data(response.text):
                            evidence.append("Response contains potentially sensitive data patterns")
                        
                        if evidence:
                            vulnerability = {
                                'type': 'IDOR',
                                'url': url,
                                'method': 'GET',
                                'parameter': param_name,
                                'payload': f"Changed {param_name} from {original_value} to {random_id}",
                                'evidence': '; '.join(evidence),
                                'severity': 'High'
                            }
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"  [!] Potential IDOR vulnerability found at {url}" + Style.RESET_ALL)
                                print(Fore.RED + f"      Parameter: {param_name}" + Style.RESET_ALL)
                                print(Fore.RED + f"      Evidence: {'; '.join(evidence)}" + Style.RESET_ALL)
                                
                except Exception as e:
                    if self.verbose:
                        print(f"  Error testing modified request: {e}")
    
    def test_form(self, form):
        """
        Test a single form for IDOR vulnerabilities
        
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
        
        # Make baseline request first
        baseline_data = {}
        for inp in inputs:
            input_name = inp.get('name', '')
            input_value = inp.get('value', '')
            baseline_data[input_name] = input_value
        
        try:
            if method == 'post':
                baseline_response = self.session.post(url, data=baseline_data, headers=self.headers, 
                                                      timeout=self.timeout, allow_redirects=False)
            else:
                baseline_response = self.session.get(url, params=baseline_data, headers=self.headers, 
                                                     timeout=self.timeout, allow_redirects=False)
                
            baseline_content_length = len(baseline_response.text)
            baseline_status = baseline_response.status_code
            
        except Exception as e:
            if self.verbose:
                print(f"  Error making baseline request: {e}")
            return
        
        # Check each input for IDOR parameters
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_value = input_field.get('value', '')
            
            # Skip inputs that don't match IDOR patterns
            if not self._is_idor_parameter(input_name) or not input_value:
                continue
                
            random_ids = self._get_random_id(input_value)
            
            for random_id in random_ids:
                # Create a copy of the form data for testing
                modified_data = baseline_data.copy()
                modified_data[input_name] = random_id
                
                try:
                    if self.verbose:
                        print(f"  Testing IDOR on form {url}, parameter {input_name}, value changed to {random_id}")
                    
                    if method == 'post':
                        response = self.session.post(url, data=modified_data, headers=self.headers, 
                                                    timeout=self.timeout, allow_redirects=False)
                    else:
                        response = self.session.get(url, params=modified_data, headers=self.headers, 
                                                    timeout=self.timeout, allow_redirects=False)
                    
                    # Look for potential IDOR indicators
                    if response.status_code == 200:
                        # Different success responses may indicate vulnerability
                        content_length_diff = abs(len(response.text) - baseline_content_length)
                        content_length_diff_percent = (content_length_diff / baseline_content_length) * 100 if baseline_content_length > 0 else 0
                        
                        evidence = []
                        
                        # Check for unexpected successful response
                        if baseline_status in [401, 403, 404] and response.status_code == 200:
                            evidence.append(f"Baseline request status: {baseline_status}, Modified request status: 200")
                        
                        # Significant content length difference
                        elif content_length_diff_percent > 5 and content_length_diff > 100:
                            evidence.append(f"Content length difference: {content_length_diff} bytes ({content_length_diff_percent:.2f}%)")
                        
                        # Check for sensitive data patterns
                        if self._contains_sensitive_data(response.text):
                            evidence.append("Response contains potentially sensitive data patterns")
                        
                        if evidence:
                            vulnerability = {
                                'type': 'IDOR',
                                'url': url,
                                'method': method.upper(),
                                'parameter': input_name,
                                'payload': f"Changed {input_name} from {input_value} to {random_id}",
                                'evidence': '; '.join(evidence),
                                'severity': 'High'
                            }
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"  [!] Potential IDOR vulnerability found in form at {url}" + Style.RESET_ALL)
                                print(Fore.RED + f"      Parameter: {input_name}" + Style.RESET_ALL)
                                print(Fore.RED + f"      Evidence: {'; '.join(evidence)}" + Style.RESET_ALL)
                
                except Exception as e:
                    if self.verbose:
                        print(f"  Error testing modified form request: {e}")
    
    def run(self):
        """
        Run the IDOR scanner
        
        Returns:
            Dictionary with scan results summary
        """
        try:
            start_time = time.time()
            print(f"[*] Starting IDOR vulnerability scan against {self.target_url}")
            
            # Test discovered URLs with parameters
            if hasattr(self.scanner, 'discovered_urls') and self.scanner.discovered_urls:
                print(f"[*] Testing {len(self.scanner.discovered_urls)} URLs for IDOR vulnerabilities")
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    list(executor.map(self.scan_url_parameters, self.scanner.discovered_urls))
            
            # Test forms
            if hasattr(self.scanner, 'forms') and self.scanner.forms:
                print(f"[*] Testing {len(self.scanner.forms)} forms for IDOR vulnerabilities")
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    list(executor.map(self.test_form, self.scanner.forms))
            
            scan_time = time.time() - start_time
            
            # Add discovered vulnerabilities to scanner's vulnerability list
            for vuln in self.vulnerabilities:
                self.idor_vulnerabilities.append(vuln)
                self.main_vulnerabilities.append(vuln)
            
            print(f"[+] Completed IDOR testing, found {len(self.vulnerabilities)} vulnerabilities")
            
            return {
                'target': self.target_url,
                'vulnerabilities': self.vulnerabilities,
                'scan_time': scan_time,
                'total_vulnerabilities': len(self.vulnerabilities)
            }
        except Exception as e:
            print(f"[!] Error during IDOR scanning: {str(e)}")
            return {
                'target': self.target_url,
                'vulnerabilities': [],
                'scan_time': 0,
                'total_vulnerabilities': 0,
                'error': str(e)
            } 