#!/usr/bin/env python3

import socket
import ssl
import datetime
import time
import re
import subprocess
from colorama import Fore, Style
from urllib.parse import urlparse

class SSLTLSScanner:
    """Scanner for detecting SSL/TLS vulnerabilities and misconfigurations"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the SSL/TLS Scanner with a reference to the main scanner instance
        
        Args:
            scanner_instance: The main WebScanner instance
        """
        self.scanner = scanner_instance
        self.target_url = scanner_instance.target_url
        self.timeout = scanner_instance.timeout
        self.verbose = scanner_instance.verbose
        self.vulnerabilities = scanner_instance.vulnerabilities
        self.ssl_tls_vulnerabilities = scanner_instance.ssl_tls_vulnerabilities
        
        # Parse the target URL
        parsed_url = urlparse(self.target_url)
        self.hostname = parsed_url.hostname
        self.port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        
        # Define vulnerable protocols and ciphers
        self.vulnerable_protocols = {
            'SSLv2': 'Critical - SSLv2 is deprecated and insecure',
            'SSLv3': 'High - SSLv3 is vulnerable to POODLE attack',
            'TLSv1.0': 'Medium - TLSv1.0 is vulnerable to BEAST attack',
            'TLSv1.1': 'Low - TLSv1.1 has known weaknesses'
        }
        
        self.weak_ciphers = [
            'NULL', 'EXPORT', 'DES', '3DES', 'RC2', 'RC4', 'MD5', 'eNULL', 'aNULL'
        ]
    
    def check_certificate(self):
        """
        Check the SSL certificate for issues like expiration and common name mismatch
        
        Returns:
            list: Certificate issues found
        """
        issues = []
        
        try:
            # Create a context with the highest available protocol
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check for certificate expiration
                    if 'notAfter' in cert:
                        expire_date = ssl.cert_time_to_seconds(cert['notAfter'])
                        current_time = time.time()
                        days_remaining = (expire_date - current_time) / (60 * 60 * 24)
                        
                        if days_remaining < 0:
                            issue = {
                                'type': 'SSL/TLS',
                                'subtype': 'Certificate Expired',
                                'severity': 'High',
                                'details': f"SSL certificate expired on {cert['notAfter']}"
                            }
                            issues.append(issue)
                            self.ssl_tls_vulnerabilities.append(issue)
                        elif days_remaining < 30:
                            issue = {
                                'type': 'SSL/TLS',
                                'subtype': 'Certificate Expiring Soon',
                                'severity': 'Medium',
                                'details': f"SSL certificate expires in {int(days_remaining)} days"
                            }
                            issues.append(issue)
                            self.ssl_tls_vulnerabilities.append(issue)
                    
                    # Check if common name matches hostname
                    common_name_match = False
                    for field in cert.get('subject', []):
                        for key, value in field:
                            if key == 'commonName':
                                cn = value
                                if cn == self.hostname or (cn.startswith('*.') and self.hostname.endswith(cn[2:])):
                                    common_name_match = True
                    
                    if not common_name_match:
                        issue = {
                            'type': 'SSL/TLS',
                            'subtype': 'CN Mismatch',
                            'severity': 'Medium',
                            'details': f"Certificate common name does not match hostname: {self.hostname}"
                        }
                        issues.append(issue)
                        self.ssl_tls_vulnerabilities.append(issue)
                    
                    # Check for self-signed certificate
                    if cert.get('issuer') == cert.get('subject'):
                        issue = {
                            'type': 'SSL/TLS',
                            'subtype': 'Self-Signed Certificate',
                            'severity': 'Medium',
                            'details': "Certificate is self-signed"
                        }
                        issues.append(issue)
                        self.ssl_tls_vulnerabilities.append(issue)
        
        except (socket.error, ssl.SSLError, OSError) as e:
            if self.verbose:
                print(Fore.RED + f"[!] Error checking certificate: {str(e)}" + Style.RESET_ALL)
        
        return issues
    
    def check_protocols(self):
        """
        Check for vulnerable SSL/TLS protocols
        
        Returns:
            list: Protocol vulnerabilities found
        """
        vulnerabilities = []
        
        for protocol_name, vulnerability_desc in self.vulnerable_protocols.items():
            protocol = getattr(ssl, f'PROTOCOL_{protocol_name.replace(".", "_")}', None)
            
            if protocol is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock) as ssock:
                        # If we can establish a connection, the protocol is supported
                        issue = {
                            'type': 'SSL/TLS',
                            'subtype': f'Vulnerable Protocol: {protocol_name}',
                            'severity': vulnerability_desc.split(' - ')[0],
                            'details': vulnerability_desc.split(' - ')[1]
                        }
                        vulnerabilities.append(issue)
                        self.ssl_tls_vulnerabilities.append(issue)
                        
                        if self.verbose:
                            print(Fore.YELLOW + f"[!] Server supports vulnerable protocol: {protocol_name}" + Style.RESET_ALL)
            
            except (socket.error, ssl.SSLError, OSError):
                # If we can't connect, the protocol is not supported (good)
                pass
        
        return vulnerabilities
    
    def check_for_heartbleed(self):
        """
        Check for Heartbleed vulnerability (CVE-2014-0160)
        
        Returns:
            bool: True if vulnerable, False otherwise
        """
        try:
            # Try to use testssl.sh if available
            result = subprocess.run(
                ['testssl.sh', '--heartbleed', self.hostname],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if "VULNERABLE" in result.stdout:
                issue = {
                    'type': 'SSL/TLS',
                    'subtype': 'Heartbleed',
                    'severity': 'Critical',
                    'details': "Server is vulnerable to Heartbleed (CVE-2014-0160)"
                }
                self.ssl_tls_vulnerabilities.append(issue)
                
                if self.verbose:
                    print(Fore.RED + "[!] Server is vulnerable to Heartbleed!" + Style.RESET_ALL)
                
                return True
            
            return False
        
        except (subprocess.SubprocessError, FileNotFoundError):
            # If testssl.sh is not available, we can't check for Heartbleed effectively
            # without implementing the actual exploit (which we won't do)
            if self.verbose:
                print(Fore.YELLOW + "[!] Could not check for Heartbleed. Install testssl.sh for better results." + Style.RESET_ALL)
            
            return False
    
    def run(self):
        """
        Run all SSL/TLS vulnerability checks
        
        Returns:
            int: Number of SSL/TLS vulnerabilities found
        """
        if self.verbose:
            print(Fore.BLUE + "[*] Testing for SSL/TLS vulnerabilities..." + Style.RESET_ALL)
        
        # Skip if not HTTPS
        if not self.target_url.startswith('https://'):
            print(Fore.YELLOW + "[!] Target is not using HTTPS. Skipping SSL/TLS checks." + Style.RESET_ALL)
            return 0
        
        vuln_count = len(self.ssl_tls_vulnerabilities)
        
        # Check certificate
        self.check_certificate()
        
        # Check vulnerable protocols
        self.check_protocols()
        
        # Check for Heartbleed
        self.check_for_heartbleed()
        
        # Count new vulnerabilities
        new_vulns = len(self.ssl_tls_vulnerabilities) - vuln_count
        
        print(Fore.GREEN + f"[+] Completed SSL/TLS testing, found {new_vulns} vulnerabilities" + Style.RESET_ALL)
        
        return new_vulns 