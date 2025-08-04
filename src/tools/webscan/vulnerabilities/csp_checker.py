#!/usr/bin/env python3

import re
import requests
from colorama import Fore, Style
from urllib.parse import urlparse

class CSPScanner:
    """Scanner for detecting Content Security Policy (CSP) misconfigurations and vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the CSP Scanner with a reference to the main scanner instance
        
        Args:
            scanner_instance: The main WebScanner instance
        """
        self.scanner = scanner_instance
        self.target_url = scanner_instance.target_url
        self.session = scanner_instance.session
        self.timeout = scanner_instance.timeout
        self.verbose = scanner_instance.verbose
        self.vulnerabilities = scanner_instance.vulnerabilities
        
        # CSP headers to check
        self.csp_headers = [
            'Content-Security-Policy',
            'Content-Security-Policy-Report-Only',
            'X-Content-Security-Policy', # Older versions
            'X-WebKit-CSP' # Older versions
        ]
        
        # Insecure CSP configurations
        self.insecure_csp_directives = {
            "default-src": ["'unsafe-inline'", "'unsafe-eval'", "data:", "http:", "*"],
            "script-src": ["'unsafe-inline'", "'unsafe-eval'", "data:", "http:", "*"],
            "style-src": ["'unsafe-inline'", "data:", "http:", "*"],
            "img-src": ["data:", "http:", "*"],
            "font-src": ["data:", "http:", "*"],
            "connect-src": ["http:", "*"],
            "frame-src": ["http:", "*"],
            "frame-ancestors": ["'none'", "*"],
            "object-src": ["*"],
            "base-uri": ["*"]
        }
        
        # Domain patterns that are considered unsafe in CSP
        self.unsafe_domains = [
            r'\.github\.io',  # GitHub Pages
            r'\.firebaseapp\.com',  # Firebase
            r'\.githubusercontent\.com',  # GitHub user content
            r'pastebin\.com',
            r'codepen\.io',
            r'jsfiddle\.net',
            r'jsbin\.com',
            r'unpkg\.com',
            r'jsdelivr\.net'  # CDNs that could be considered risky
        ]
    
    def parse_csp_header(self, csp_header):
        """
        Parse a CSP header into a dictionary of directives
        
        Args:
            csp_header (str): CSP header value
            
        Returns:
            dict: Dictionary of CSP directives
        """
        directives = {}
        
        if not csp_header:
            return directives
            
        parts = csp_header.split(';')
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
                
            directive_parts = part.split(None, 1)
            
            if len(directive_parts) == 1:
                # Directive with no values
                directives[directive_parts[0]] = []
            else:
                directive_name = directive_parts[0]
                directive_values = directive_parts[1].split()
                directives[directive_name] = directive_values
                
        return directives
    
    def analyze_csp(self, url, headers):
        """
        Analyze CSP headers for vulnerabilities
        
        Args:
            url (str): The URL being analyzed
            headers (dict): HTTP headers from the response
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Check if any CSP header is present
        csp_present = False
        csp_header_value = None
        
        for header in self.csp_headers:
            if header in headers:
                csp_present = True
                csp_header_value = headers[header]
                break
                
        if not csp_present:
            vuln = {
                'type': 'CSP',
                'url': url,
                'severity': 'Medium',
                'details': "Content Security Policy not implemented",
                'evidence': "CSP header not present in response",
                'recommendation': "Implement Content Security Policy to protect against XSS attacks"
            }
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)
            
            if self.verbose:
                print(Fore.YELLOW + f"[!] No Content Security Policy found at {url}" + Style.RESET_ALL)
                
            return vulnerabilities
        
        # If CSP is in "report-only" mode, it's not enforcing
        if 'Content-Security-Policy-Report-Only' in headers and 'Content-Security-Policy' not in headers:
            vuln = {
                'type': 'CSP',
                'url': url,
                'severity': 'Low',
                'details': "Content Security Policy in report-only mode",
                'evidence': f"CSP Report-Only: {headers['Content-Security-Policy-Report-Only']}",
                'recommendation': "Move from report-only to enforcement mode after testing"
            }
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)
            
            if self.verbose:
                print(Fore.YELLOW + f"[!] CSP in report-only mode at {url}" + Style.RESET_ALL)
        
        # Parse the CSP header for detailed analysis
        csp_directives = self.parse_csp_header(csp_header_value)
        
        # Check for missing essential directives
        essential_directives = ['default-src', 'script-src', 'object-src']
        missing_directives = [directive for directive in essential_directives if directive not in csp_directives]
        
        if missing_directives:
            vuln = {
                'type': 'CSP',
                'url': url,
                'severity': 'Medium',
                'details': f"Missing essential CSP directives: {', '.join(missing_directives)}",
                'evidence': f"CSP: {csp_header_value}",
                'recommendation': f"Add the following directives to your CSP: {', '.join(missing_directives)}"
            }
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)
            
            if self.verbose:
                print(Fore.YELLOW + f"[!] Missing essential CSP directives at {url}: {', '.join(missing_directives)}" + Style.RESET_ALL)
        
        # Check for insecure directives
        for directive, insecure_values in self.insecure_csp_directives.items():
            if directive in csp_directives:
                directive_values = csp_directives[directive]
                
                insecure_found = [value for value in directive_values if value in insecure_values]
                
                if insecure_found:
                    severity = 'Critical' if directive in ['script-src', 'default-src'] and "'unsafe-inline'" in insecure_found else 'High'
                    
                    vuln = {
                        'type': 'CSP',
                        'url': url,
                        'severity': severity,
                        'details': f"Insecure {directive} directive with values: {', '.join(insecure_found)}",
                        'evidence': f"CSP {directive}: {' '.join(directive_values)}",
                        'recommendation': f"Remove insecure values from the {directive} directive"
                    }
                    vulnerabilities.append(vuln)
                    self.vulnerabilities.append(vuln)
                    
                    if self.verbose:
                        print(Fore.RED + f"[!] Insecure CSP directive {directive} at {url}" + Style.RESET_ALL)
                        print(Fore.RED + f"    Insecure values: {', '.join(insecure_found)}" + Style.RESET_ALL)
        
        # Check for unsafe domains in CSP
        for directive, values in csp_directives.items():
            for domain in values:
                # Skip special values
                if domain.startswith("'") or domain in ['http:', 'https:', 'data:', 'blob:', 'mediastream:', 'filesystem:']:
                    continue
                    
                # Check against unsafe domains
                for unsafe_pattern in self.unsafe_domains:
                    if re.search(unsafe_pattern, domain):
                        vuln = {
                            'type': 'CSP',
                            'url': url,
                            'severity': 'Medium',
                            'details': f"Potentially unsafe domain in {directive}: {domain}",
                            'evidence': f"CSP {directive}: {' '.join(values)}",
                            'recommendation': f"Review and if possible remove {domain} from your CSP"
                        }
                        vulnerabilities.append(vuln)
                        self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            print(Fore.YELLOW + f"[!] Potentially unsafe domain in CSP at {url}" + Style.RESET_ALL)
                            print(Fore.YELLOW + f"    {directive}: {domain}" + Style.RESET_ALL)
                        
                        break
        
        # Check for nonce or hash usage (best practice)
        has_nonce_or_hash = False
        
        for directive, values in csp_directives.items():
            if directive in ['script-src', 'style-src']:
                for value in values:
                    if value.startswith("'nonce-") or value.startswith("'sha"):
                        has_nonce_or_hash = True
                        break
        
        if not has_nonce_or_hash and ('script-src' in csp_directives or 'style-src' in csp_directives):
            vuln = {
                'type': 'CSP',
                'url': url,
                'severity': 'Low',
                'details': "CSP does not use nonces or hashes for script/style validation",
                'evidence': f"CSP: {csp_header_value}",
                'recommendation': "Consider using nonces or hashes for better CSP protection"
            }
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)
            
            if self.verbose:
                print(Fore.YELLOW + f"[!] CSP without nonces/hashes at {url}" + Style.RESET_ALL)
        
        # Check for deprecated CSP headers
        for header in ['X-Content-Security-Policy', 'X-WebKit-CSP']:
            if header in headers:
                vuln = {
                    'type': 'CSP',
                    'url': url,
                    'severity': 'Low',
                    'details': f"Deprecated CSP header: {header}",
                    'evidence': f"{header}: {headers[header]}",
                    'recommendation': "Use the standard Content-Security-Policy header instead"
                }
                vulnerabilities.append(vuln)
                self.vulnerabilities.append(vuln)
                
                if self.verbose:
                    print(Fore.YELLOW + f"[!] Deprecated CSP header at {url}: {header}" + Style.RESET_ALL)
        
        # Check if report-uri/report-to is defined (good practice)
        has_reporting = 'report-uri' in csp_directives or 'report-to' in csp_directives
        
        if not has_reporting:
            vuln = {
                'type': 'CSP',
                'url': url,
                'severity': 'Info',
                'details': "CSP reporting not configured",
                'evidence': f"CSP: {csp_header_value}",
                'recommendation': "Add a report-uri or report-to directive to collect CSP violation reports"
            }
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)
            
            if self.verbose:
                print(Fore.BLUE + f"[i] CSP reporting not configured at {url}" + Style.RESET_ALL)
        
        return vulnerabilities
    
    def run(self):
        """
        Check for CSP vulnerabilities
        
        Returns:
            int: Number of CSP vulnerabilities found
        """
        vuln_count = sum(1 for v in self.vulnerabilities if v.get('type') == 'CSP')
        
        if self.verbose:
            print(Fore.BLUE + "[*] Checking Content Security Policy..." + Style.RESET_ALL)
        
        try:
            # Send request to target URL
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            # Check for CSP issues
            self.analyze_csp(self.target_url, response.headers)
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(Fore.YELLOW + f"[!] Error checking CSP at {self.target_url}: {str(e)}" + Style.RESET_ALL)
        
        # Count new vulnerabilities
        csp_vulnerabilities = sum(1 for v in self.vulnerabilities if v.get('type') == 'CSP')
        csp_vulnerabilities_found = csp_vulnerabilities - vuln_count
        
        print(Fore.GREEN + f"[+] Completed CSP checking, found {csp_vulnerabilities_found} issues" + Style.RESET_ALL)
        
        return csp_vulnerabilities_found 