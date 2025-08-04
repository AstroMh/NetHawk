#!/usr/bin/env python3

import socket
import time
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

class RequestSmugglingScanner:
    """Scanner for detecting HTTP Request Smuggling vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the HTTP Request Smuggling Scanner
        
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
        
        # Parse the target URL to get the host
        parsed_url = urlparse(self.target_url)
        self.target_host = parsed_url.netloc
        self.target_port = 443 if parsed_url.scheme == 'https' else 80
        self.use_ssl = parsed_url.scheme == 'https'
        
        # CL.TE payloads (Content-Length < Transfer-Encoding)
        self.clte_payloads = [
            # Basic CL.TE payload
            "POST / HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X",
            
            # Alternative CL.TE payload
            "POST / HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "12\r\n"
            "smuggled request\r\n"
            "0\r\n"
            "\r\n"
        ]
        
        # TE.CL payloads (Transfer-Encoding < Content-Length)
        self.tecl_payloads = [
            # Basic TE.CL payload
            "POST / HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Content-Length: 3\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "3\r\n"
            "ABC\r\n"
            "0\r\n"
            "\r\n",
            
            # Alternative TE.CL payload
            "POST / HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5c\r\n"
            "GET / HTTP/1.1\r\n"
            "Host: {}\r\n"
            "X-Padding: {}\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
        ]
        
        # Obfuscated TE payloads to bypass validation
        self.obfuscated_te_payloads = [
            # Obfuscated Transfer-Encoding header
            "POST / HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-encoding: cow\r\n"
            "\r\n"
            "5\r\n"
            "ABCDE\r\n"
            "0\r\n"
            "\r\n",
            
            # Obfuscated with tabs
            "POST / HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding:\tchunked\r\n"
            "\r\n"
            "5\r\n"
            "ABCDE\r\n"
            "0\r\n"
            "\r\n",
            
            # Obfuscated with spaces
            "POST / HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked \r\n"
            "\r\n"
            "5\r\n"
            "ABCDE\r\n"
            "0\r\n"
            "\r\n"
        ]
    
    def run(self):
        """Run the HTTP Request Smuggling scanner"""
        if self.verbose:
            print(Fore.BLUE + "[*] Starting HTTP Request Smuggling scanner..." + Style.RESET_ALL)

        try:
            # Test the main target URL
            self.test_request_smuggling(self.target_url)
            
            # Test a subset of discovered URLs (only those on the same host)
            urls_to_test = []
            for url in self.discovered_urls:
                parsed = urlparse(url)
                if parsed.netloc == self.target_host and len(urls_to_test) < 5:  # Limit to 5 URLs to avoid excessive testing
                    urls_to_test.append(url)
                    
            with ThreadPoolExecutor(max_workers=min(3, self.max_threads)) as executor:  # Limit to 3 threads max
                list(executor.map(self.test_request_smuggling, urls_to_test))
                
        except Exception as e:
            if self.verbose:
                print(Fore.RED + f"  [-] Error in HTTP Request Smuggling scanner: {str(e)}" + Style.RESET_ALL)
            
        if self.verbose:
            print(Fore.BLUE + f"[*] HTTP Request Smuggling scan completed. Found {len(self.vulnerabilities)} vulnerabilities." + Style.RESET_ALL)
            
        return self.vulnerabilities
    
    def test_request_smuggling(self, url):
        """
        Test a URL for HTTP Request Smuggling
        
        Args:
            url (str): The URL to test
        """
        try:
            if self.verbose:
                print(Fore.BLUE + f"  [+] Testing {url} for HTTP Request Smuggling" + Style.RESET_ALL)
                
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            path = parsed_url.path if parsed_url.path else "/"
            
            # Test CL.TE vulnerabilities
            self.test_clte(host, path)
            
            # Test TE.CL vulnerabilities
            self.test_tecl(host, path)
            
            # Test obfuscated TE vulnerabilities
            self.test_obfuscated_te(host, path)
                
        except Exception as e:
            if self.verbose:
                print(Fore.RED + f"  [-] Error testing {url} for HTTP Request Smuggling: {str(e)}" + Style.RESET_ALL)
    
    def test_clte(self, host, path):
        """
        Test for CL.TE (Content-Length < Transfer-Encoding) vulnerabilities
        
        Args:
            host (str): Target host
            path (str): Target path
        """
        for payload in self.clte_payloads:
            formatted_payload = payload.format(host)
            
            try:
                # Send the payload using a raw socket
                response_time, response = self.send_raw_request(host, formatted_payload)
                
                # Check for signs of request smuggling (delayed response, unusual status codes)
                if response_time > self.timeout - 1:  # Near timeout
                    self.add_vulnerability(
                        f"{'https' if self.use_ssl else 'http'}://{host}{path}",
                        "CL.TE",
                        formatted_payload,
                        f"Long response time: {response_time}s"
                    )
                elif "HTTP/1.1 400" not in response and "HTTP/1.1 500" not in response:
                    # If server doesn't reject with 400 Bad Request or 500 Server Error, might be vulnerable
                    self.add_vulnerability(
                        f"{'https' if self.use_ssl else 'http'}://{host}{path}",
                        "CL.TE",
                        formatted_payload,
                        f"Unexpected response: {response[:50]}..."
                    )
                    
            except Exception as e:
                if self.verbose:
                    print(Fore.YELLOW + f"  [!] Error testing CL.TE on {host}: {str(e)}" + Style.RESET_ALL)
                continue
    
    def test_tecl(self, host, path):
        """
        Test for TE.CL (Transfer-Encoding < Content-Length) vulnerabilities
        
        Args:
            host (str): Target host
            path (str): Target path
        """
        for payload in self.tecl_payloads:
            # Generate random padding to make the smuggled request unique
            padding = "A" * 10
            formatted_payload = payload.format(host, host, padding)
            
            try:
                # Send the payload using a raw socket
                response_time, response = self.send_raw_request(host, formatted_payload)
                
                # Check for signs of request smuggling
                if response_time > self.timeout - 1:  # Near timeout
                    self.add_vulnerability(
                        f"{'https' if self.use_ssl else 'http'}://{host}{path}",
                        "TE.CL",
                        formatted_payload,
                        f"Long response time: {response_time}s"
                    )
                elif "HTTP/1.1 400" not in response and "HTTP/1.1 500" not in response:
                    # If server doesn't reject with 400 Bad Request or 500 Server Error, might be vulnerable
                    self.add_vulnerability(
                        f"{'https' if self.use_ssl else 'http'}://{host}{path}",
                        "TE.CL",
                        formatted_payload,
                        f"Unexpected response: {response[:50]}..."
                    )
                    
            except Exception as e:
                if self.verbose:
                    print(Fore.YELLOW + f"  [!] Error testing TE.CL on {host}: {str(e)}" + Style.RESET_ALL)
                continue
    
    def test_obfuscated_te(self, host, path):
        """
        Test for vulnerabilities using obfuscated Transfer-Encoding headers
        
        Args:
            host (str): Target host
            path (str): Target path
        """
        for payload in self.obfuscated_te_payloads:
            formatted_payload = payload.format(host)
            
            try:
                # Send the payload using a raw socket
                response_time, response = self.send_raw_request(host, formatted_payload)
                
                # Check for signs of request smuggling
                if response_time > self.timeout - 1:  # Near timeout
                    self.add_vulnerability(
                        f"{'https' if self.use_ssl else 'http'}://{host}{path}",
                        "Obfuscated TE",
                        formatted_payload,
                        f"Long response time: {response_time}s"
                    )
                elif "HTTP/1.1 400" not in response and "HTTP/1.1 500" not in response:
                    # If server doesn't reject with 400 Bad Request or 500 Server Error, might be vulnerable
                    self.add_vulnerability(
                        f"{'https' if self.use_ssl else 'http'}://{host}{path}",
                        "Obfuscated TE",
                        formatted_payload,
                        f"Unexpected response: {response[:50]}..."
                    )
                    
            except Exception as e:
                if self.verbose:
                    print(Fore.YELLOW + f"  [!] Error testing obfuscated TE on {host}: {str(e)}" + Style.RESET_ALL)
                continue
    
    def send_raw_request(self, host, payload):
        """
        Send a raw HTTP request to detect request smuggling
        
        Args:
            host (str): Target host
            payload (str): HTTP request payload
            
        Returns:
            tuple: (response_time, response_data)
        """
        sock = None
        try:
            # Create a socket
            port = self.target_port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Establish connection
            sock.connect((host, port))
            
            # Wrap with SSL if needed
            if self.use_ssl:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            # Send the request and measure response time
            start_time = time.time()
            sock.sendall(payload.encode())
            
            # Receive data
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break
                    
            end_time = time.time()
            response_time = end_time - start_time
            
            return response_time, response.decode('utf-8', errors='ignore')
            
        except socket.timeout:
            # Timeout may indicate vulnerability
            return self.timeout, ""
        except Exception as e:
            raise e
        finally:
            # Close socket
            if sock:
                sock.close()
    
    def add_vulnerability(self, url, technique, payload, evidence):
        """Add a vulnerability to the list"""
        # Only show part of the payload for readability
        short_payload = payload.replace("\r\n", "\\r\\n")
        if len(short_payload) > 100:
            short_payload = short_payload[:100] + "..."
            
        vuln = {
            'type': 'HTTP Request Smuggling',
            'url': url,
            'technique': technique,
            'payload': short_payload,
            'evidence': evidence,
            'severity': 'High',
            'risk_score': 80,
            'cwe': 'CWE-444',
            'description': 'HTTP Request Smuggling vulnerabilities occur when front-end and back-end servers interpret HTTP requests differently, allowing an attacker to "smuggle" requests to the back-end server.',
            'remediation': 'Ensure all servers in the chain interpret HTTP requests consistently. Implement proper validation of Content-Length and Transfer-Encoding headers. Use HTTP/2 if possible, which has more strict parsing rules.',
            'references': [
                'https://portswigger.net/web-security/request-smuggling',
                'https://owasp.org/www-community/attacks/HTTP_Request_Smuggling',
                'https://cwe.mitre.org/data/definitions/444.html'
            ]
        }
        
        self.vulnerabilities.append(vuln)
        
        if self.verbose:
            print(Fore.RED + f"[!] Found HTTP Request Smuggling vulnerability at {url}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"    Technique: {technique}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"    Evidence: {evidence}" + Style.RESET_ALL) 