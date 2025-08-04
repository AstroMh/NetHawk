#!/usr/bin/env python3

import re
import json
import base64
import requests
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style

class DeserializationScanner:
    """Scanner for detecting insecure deserialization vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the Deserialization Scanner with a reference to the main scanner instance
        
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
        self.tech_stack = scanner_instance.tech_stack
        
        # Deserialization signatures to look for
        self.signatures = {
            'java': [
                r'java\.io\.Serializable',
                r'rO0AB',  # Base64 Java serialized data marker
                r'ObjectInputStream',
                r'readObject',
                r'writeObject',
                r'com\.sun\.syndication',  # Known vulnerable library
                r'commons-collections',    # Known vulnerable library
                r'readUnshared',
                r'fastjson',
                r'jackson-databind'
            ],
            'php': [
                r'O:[0-9]+:"',  # PHP serialized object
                r's:[0-9]+:"',  # PHP serialized string
                r'a:[0-9]+:{',  # PHP serialized array
                r'unserialize\(',
                r'__wakeup',
                r'__destruct',
                r'__toString',
                r'__sleep',
                r'var_export',
                r'yaml_parse'
            ],
            'net': [
                r'BinaryFormatter',
                r'SoapFormatter',
                r'NetDataContractSerializer',
                r'ObjectStateFormatter',
                r'LosFormatter',
                r'__VIEWSTATE',
                r'__VIEWSTATEGENERATOR',
                r'System\.Runtime\.Serialization',
                r'JSON\.NET'
            ],
            'python': [
                r'pickle\.',
                r'_pickle',
                r'cPickle',
                r'shelve\.',
                r'marshal\.',
                r'yaml\.load',
                r'yaml\.unsafe_load',
                r'eval\(',
                r'__reduce__',
                r'dill\.'
            ],
            'node': [
                r'node-serialize',
                r'serialize-javascript',
                r'eval\(',
                r'uneval\(',
                r'deserialize\(',
                r'JSON\.parse'
            ],
            'ruby': [
                r'Marshal\.load',
                r'YAML\.load',
                r'constantize',
                r'to_yaml',
                r'from_yaml',
                r'object\.new',
                r'unsafe_load'
            ]
        }
        
        # Deserialization keywords in HTTP parameters
        self.suspicious_params = [
            'data', 'object', 'obj', 'serialized', 'input', 'state', 'file', 
            'stream', 'form', 'cmd', 'upload', 'ser', 'deser', 'deserialize', 
            'token', 'viewstate', 'payload', 'load', 'session', 'user', 'blob'
        ]
    
    def check_content_type(self, response):
        """Check content type for potential deserialization formats"""
        if not response or not response.headers:
            return False
            
        content_type = response.headers.get('Content-Type', '').lower()
        suspicious_content_types = [
            'application/json', 
            'application/xml', 
            'application/octet-stream', 
            'application/x-java-serialized-object',
            'application/x-php-serialized',
            'application/x-www-form-urlencoded'
        ]
        
        return any(ct in content_type for ct in suspicious_content_types)
    
    def analyze_response(self, response, url):
        """
        Analyze HTTP response for deserialization indicators
        
        Args:
            response: HTTP response object
            url: URL of the response
            
        Returns:
            list: Potential deserialization vulnerabilities
        """
        vulnerabilities = []
        
        if not response:
            return vulnerabilities
            
        # Check for deserialization signatures in response content
        for lang, patterns in self.signatures.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vuln = {
                            'type': 'Deserialization',
                            'url': url,
                            'language': lang,
                            'severity': 'High',
                            'details': f"Potential {lang} deserialization detected: {pattern}",
                            'evidence': pattern
                        }
                        vulnerabilities.append(vuln)
                        self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential {lang} deserialization found at {url}" + Style.RESET_ALL)
                            print(Fore.RED + f"    Pattern: {pattern}" + Style.RESET_ALL)
                        
                        # Once we find one pattern for a language, we don't need to check others
                        break
                except:
                    # Ignore any regex errors or encoding issues
                    pass
        
        return vulnerabilities
    
    def test_url(self, url):
        """
        Test a URL for deserialization vulnerabilities
        
        Args:
            url: URL to test
            
        Returns:
            list: Potential deserialization vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Get normal response
            response = self.session.get(url, timeout=self.timeout)
            
            # Analyze response content for deserialization patterns
            vulnerabilities.extend(self.analyze_response(response, url))
            
            # Check content type
            if self.check_content_type(response):
                vuln = {
                    'type': 'Deserialization',
                    'url': url,
                    'severity': 'Low',
                    'details': f"Suspicious content type: {response.headers.get('Content-Type')}",
                    'evidence': f"Content-Type: {response.headers.get('Content-Type')}"
                }
                vulnerabilities.append(vuln)
                self.vulnerabilities.append(vuln)
                
                if self.verbose:
                    print(Fore.YELLOW + f"[!] Suspicious content type at {url}" + Style.RESET_ALL)
                    print(Fore.YELLOW + f"    Content-Type: {response.headers.get('Content-Type')}" + Style.RESET_ALL)
            
            # Parse URL for parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            # Check for suspicious parameters
            for param, values in query_params.items():
                param_lower = param.lower()
                
                # Check if the parameter name is suspicious
                if any(sus_param in param_lower for sus_param in self.suspicious_params):
                    for value in values:
                        # Check if the value looks like serialized data
                        # Java serialized data often begins with rO0
                        if value.startswith('rO0'):
                            vuln = {
                                'type': 'Deserialization',
                                'url': url,
                                'parameter': param,
                                'severity': 'High',
                                'details': f"Parameter '{param}' contains what appears to be Java serialized data",
                                'evidence': f"Parameter: {param}, Value starts with: rO0..."
                            }
                            vulnerabilities.append(vuln)
                            self.vulnerabilities.append(vuln)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] Java serialization detected in parameter '{param}' at {url}" + Style.RESET_ALL)
                        
                        # Check for PHP serialization patterns
                        elif re.match(r'^[aos]:[0-9]+:', value):
                            vuln = {
                                'type': 'Deserialization',
                                'url': url,
                                'parameter': param,
                                'severity': 'High',
                                'details': f"Parameter '{param}' contains what appears to be PHP serialized data",
                                'evidence': f"Parameter: {param}, Value pattern: {value[:20]}..."
                            }
                            vulnerabilities.append(vuln)
                            self.vulnerabilities.append(vuln)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] PHP serialization detected in parameter '{param}' at {url}" + Style.RESET_ALL)
                        
                        # Check for base64 encoded data
                        elif re.match(r'^[A-Za-z0-9+/]+={0,2}$', value) and len(value) > 8:
                            try:
                                # Try to decode as base64
                                decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
                                
                                # Check if the decoded content has serialization patterns
                                for lang, patterns in self.signatures.items():
                                    for pattern in patterns:
                                        if re.search(pattern, decoded, re.IGNORECASE):
                                            vuln = {
                                                'type': 'Deserialization',
                                                'url': url,
                                                'parameter': param,
                                                'language': lang,
                                                'severity': 'High',
                                                'details': f"Parameter '{param}' contains base64-encoded {lang} serialized data",
                                                'evidence': f"Parameter: {param}, Decoded contains: {pattern}"
                                            }
                                            vulnerabilities.append(vuln)
                                            self.vulnerabilities.append(vuln)
                                            
                                            if self.verbose:
                                                print(Fore.RED + f"[!] Base64-encoded {lang} serialization detected in parameter '{param}' at {url}" + Style.RESET_ALL)
                            except:
                                # Not valid base64 or couldn't decode
                                pass
            
            # Check for .NET ViewState
            if '__VIEWSTATE' in response.text:
                viewstate_value = re.search(r'id="__VIEWSTATE" value="([^"]+)"', response.text)
                if viewstate_value:
                    vuln = {
                        'type': 'Deserialization',
                        'url': url,
                        'severity': 'Medium',
                        'details': "ASP.NET ViewState detected, may be vulnerable to deserialization if not properly protected",
                        'evidence': "ViewState parameter found"
                    }
                    vulnerabilities.append(vuln)
                    self.vulnerabilities.append(vuln)
                    
                    if self.verbose:
                        print(Fore.YELLOW + f"[!] ASP.NET ViewState detected at {url}" + Style.RESET_ALL)
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(Fore.YELLOW + f"[!] Error testing deserialization at {url}: {str(e)}" + Style.RESET_ALL)
        
        return vulnerabilities
    
    def test_post_request(self, url, data=None, json_data=None):
        """
        Test a POST request for deserialization vulnerabilities
        
        Args:
            url: URL to test
            data: Form data to send
            json_data: JSON data to send
            
        Returns:
            list: Potential deserialization vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Make a POST request
            if json_data:
                response = self.session.post(url, json=json_data, timeout=self.timeout)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout)
            
            # Analyze response
            vulnerabilities.extend(self.analyze_response(response, url))
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(Fore.YELLOW + f"[!] Error testing POST deserialization at {url}: {str(e)}" + Style.RESET_ALL)
        
        return vulnerabilities
    
    def run(self):
        """
        Run tests for deserialization vulnerabilities
        
        Returns:
            int: Number of deserialization vulnerabilities found
        """
        vuln_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'Deserialization')
        
        if self.verbose:
            print(Fore.BLUE + "[*] Testing for deserialization vulnerabilities..." + Style.RESET_ALL)
        
        # Test main target URL
        self.test_url(self.target_url)
        
        # Test discovered URLs
        for url_data in self.discovered_urls:
            url = url_data.get('url', '') if isinstance(url_data, dict) else url_data
            self.test_url(url)
            
            # If technology stack suggests a vulnerable framework, test it more thoroughly
            if 'java' in str(self.tech_stack).lower():
                # Test Java frameworks
                self.test_post_request(url, json_data={'foo': 'bar'})
            
            if 'php' in str(self.tech_stack).lower():
                # Test PHP-specific endpoints
                php_endpoints = [url + '/index.php', url + '/api.php', url + '/admin.php']
                for endpoint in php_endpoints:
                    self.test_url(endpoint)
            
            if '.net' in str(self.tech_stack).lower() or 'asp' in str(self.tech_stack).lower():
                # Test .NET-specific patterns
                self.test_url(url)
            
            if 'node' in str(self.tech_stack).lower() or 'javascript' in str(self.tech_stack).lower():
                # Test Node.js endpoints
                self.test_post_request(url, json_data={'data': 'test'})
        
        # Count new vulnerabilities
        deser_vulnerabilities = sum(1 for v in self.vulnerabilities if v.get('type') == 'Deserialization')
        deser_vulnerabilities_found = deser_vulnerabilities - vuln_count
        
        print(Fore.GREEN + f"[+] Completed deserialization testing, found {deser_vulnerabilities_found} vulnerabilities" + Style.RESET_ALL)
        
        return deser_vulnerabilities_found 