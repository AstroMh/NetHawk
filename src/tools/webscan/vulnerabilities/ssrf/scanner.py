#!/usr/bin/env python3

import hashlib
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

class SSRFScanner:
    """Scanner for detecting Server-Side Request Forgery (SSRF) vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the SSRF Scanner with a reference to the main scanner instance
        
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
        
        # SSRF payloads
        self.ssrf_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://[::1]',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://instance-data/latest/meta-data/',     # GCP metadata
            'http://169.254.169.254/metadata/v1/',        # DigitalOcean metadata
            'http://169.254.169.254/metadata/instance?api-version=2019-06-01'  # Azure metadata
        ]
        
        # SSRF response indicators
        self.ssrf_indicators = [
            'private ip',
            'local address',
            'cannot connect to server',
            'connection refused',
            'timeout',
            'network is unreachable',
            'could not resolve host',
            'no route to host',
            'failed to connect'
        ]
    
    # Function to generate a unique callback URL for SSRF testing
    def generate_callback_url(self):
        """Generate a unique callback URL for blind SSRF detection"""
        random_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:10]
        return f"http://{random_id}.burpcollaborator.net"  # Example domain, won't actually reach anywhere
    
    def test_form(self, form):
        """
        Test a single form for SSRF vulnerabilities
        
        Args:
            form (dict): Form data containing action, method, and inputs
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Generate a unique callback URL
        callback_url = self.generate_callback_url()
        
        for input_field in form.get('inputs', []):
            # Skip input types that likely won't accept URLs
            if input_field.get('type') in ['hidden', 'password', 'checkbox', 'radio']:
                continue
                
            for payload in self.ssrf_payloads + [callback_url]:
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
                    if form.get('method', '').upper() == 'GET':
                        response = self.session.get(form.get('action', form['url']), params=data, timeout=self.timeout)
                    else:
                        response = self.session.post(form.get('action', form['url']), data=data, timeout=self.timeout)
                    
                    # Check for potential SSRF indicators in the response
                    for indicator in self.ssrf_indicators:
                        if indicator in response.text.lower():
                            vulnerability = {
                                'type': 'SSRF',
                                'url': form['url'],
                                'form_action': form.get('action', ''),
                                'method': form.get('method', ''),
                                'field': input_field.get('name'),
                                'payload': payload,
                                'indicator': indicator,
                                'severity': 'High',
                                'evidence': f"Response contains SSRF indicator: '{indicator}'"
                            }
                            vulnerabilities.append(vulnerability)
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] Potential SSRF vulnerability in form at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Indicator: {indicator}" + Style.RESET_ALL)
                            
                            # Return after finding first vulnerability
                            return vulnerabilities
                            
                except requests.exceptions.Timeout:
                    # Timeout might indicate a successful blind SSRF
                    vulnerability = {
                        'type': 'SSRF',
                        'url': form['url'],
                        'form_action': form.get('action', ''),
                        'method': form.get('method', ''),
                        'field': input_field.get('name'),
                        'payload': payload,
                        'indicator': "Request timeout",
                        'severity': 'Medium',
                        'evidence': "Request timed out, which may indicate successful SSRF"
                    }
                    vulnerabilities.append(vulnerability)
                    self.vulnerabilities.append(vulnerability)
                    
                    if self.verbose:
                        print(Fore.RED + f"[!] Potential SSRF vulnerability in form at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                        print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                        print(Fore.YELLOW + f"    Evidence: Request timed out" + Style.RESET_ALL)
                    
                    # Return after finding first vulnerability
                    return vulnerabilities
                    
                except Exception as e:
                    # Connection errors might indicate a successful SSRF
                    if 'ConnectTimeout' in str(e) or 'ConnectionError' in str(e):
                        vulnerability = {
                            'type': 'SSRF',
                            'url': form['url'],
                            'form_action': form.get('action', ''),
                            'method': form.get('method', ''),
                            'field': input_field.get('name'),
                            'payload': payload,
                            'indicator': str(e),
                            'severity': 'Medium',
                            'evidence': f"Request failed, which may indicate successful SSRF: {str(e)}"
                        }
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential SSRF vulnerability in form at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Error: {str(e)}" + Style.RESET_ALL)
                        
                        # Return after finding first vulnerability
                        return vulnerabilities
                    elif self.verbose:
                        print(Fore.YELLOW + f"  [!] Error testing {form['url']}: {str(e)}" + Style.RESET_ALL)
        
        return vulnerabilities
    
    def test_url_parameter(self, url):
        """
        Test URL parameters for SSRF vulnerabilities
        
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
            
        for param_name, param_value in query_params.items():
            # Skip parameters that are unlikely to be vulnerable to SSRF
            if len(param_value[0]) < 4:  # Too short to be a URL
                continue
                
            # Check if parameter might be used for URLs
            if any(url_hint in param_name.lower() for url_hint in ['url', 'link', 'site', 'path', 'dest', 'redirect', 'uri', 'source']):
                for payload in self.ssrf_payloads:
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
                        
                        # Check for potential SSRF indicators in the response
                        for indicator in self.ssrf_indicators:
                            if indicator in response.text.lower():
                                vulnerability = {
                                    'type': 'SSRF',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'indicator': indicator,
                                    'severity': 'High',
                                    'evidence': f"Response contains SSRF indicator: '{indicator}'"
                                }
                                vulnerabilities.append(vulnerability)
                                self.vulnerabilities.append(vulnerability)
                                
                                if self.verbose:
                                    print(Fore.RED + f"[!] Potential SSRF vulnerability at {url} in parameter {param_name}" + Style.RESET_ALL)
                                    print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                    print(Fore.YELLOW + f"    Indicator: {indicator}" + Style.RESET_ALL)
                                
                                # Found a vulnerability, move to the next parameter
                                break
                                
                    except requests.exceptions.Timeout:
                        # Timeout might indicate a successful blind SSRF
                        vulnerability = {
                            'type': 'SSRF',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'indicator': "Request timeout",
                            'severity': 'Medium',
                            'evidence': "Request timed out, which may indicate successful SSRF"
                        }
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential SSRF vulnerability at {url} in parameter {param_name}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Evidence: Request timed out" + Style.RESET_ALL)
                        
                        # Found a vulnerability, move to the next parameter
                        break
                        
                    except Exception as e:
                        # Connection errors might indicate a successful SSRF
                        if 'ConnectTimeout' in str(e) or 'ConnectionError' in str(e):
                            vulnerability = {
                                'type': 'SSRF',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'indicator': str(e),
                                'severity': 'Medium',
                                'evidence': f"Request failed, which may indicate successful SSRF: {str(e)}"
                            }
                            vulnerabilities.append(vulnerability)
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] Potential SSRF vulnerability at {url} in parameter {param_name}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Error: {str(e)}" + Style.RESET_ALL)
                            
                            # Found a vulnerability, move to the next parameter
                            break
                        elif self.verbose:
                            print(Fore.YELLOW + f"  [!] Error testing {url}: {str(e)}" + Style.RESET_ALL)
        
        return vulnerabilities
    
    def run(self):
        """
        Test for SSRF vulnerabilities in forms and URL parameters
        
        Returns:
            int: Number of SSRF vulnerabilities found
        """
        ssrf_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'SSRF')
        
        if self.verbose:
            print(Fore.BLUE + "[*] Testing for SSRF vulnerabilities..." + Style.RESET_ALL)
        
        # Test forms for SSRF
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            form_results = list(executor.map(self.test_form, self.forms))
        
        # Test URL parameters for SSRF
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            url_results = list(executor.map(self.test_url_parameter, self.discovered_urls))
        
        # Count how many SSRF vulnerabilities were found
        ssrf_vulnerabilities = sum(1 for v in self.vulnerabilities if v.get('type') == 'SSRF')
        ssrf_vulnerabilities_found = ssrf_vulnerabilities - ssrf_count
        
        print(Fore.GREEN + f"[+] Completed SSRF testing, found {ssrf_vulnerabilities_found} vulnerabilities" + Style.RESET_ALL)
        return ssrf_vulnerabilities_found 