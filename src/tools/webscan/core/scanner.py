#!/usr/bin/env python3

import os
import time
import logging
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

# Import external dependencies
from termcolor import colored
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import modules from our package
try:
    from src.tools.webscan.info_gathering.server_info import gather_server_info as external_gather_server_info
except ImportError:
    print(colored("[!] ", 'red') + "Server info gathering module not found.")
    def external_gather_server_info(self): return {}

try:
    from src.tools.webscan.crawlers.url_crawler import discover_urls as external_discover_urls
except ImportError:
    print(colored("[!] ", 'red') + "URL crawler module not found.")
    def external_discover_urls(self): self.discovered_urls = []; return self.discovered_urls

try:
    from src.tools.webscan.crawlers.form_finder import find_forms as external_find_forms
except ImportError:
    print(colored("[!] ", 'red') + "Form finder module not found.")
    def external_find_forms(self): self.forms = []; return self.forms

try:
    from src.tools.webscan.vulnerabilities.headers.scanner import check_security_headers as external_check_security_headers
except ImportError:
    print(colored("[!] ", 'yellow') + "Security headers scanner module not found. This feature will be added in a future update.")
    def external_check_security_headers(self): pass

try:
    from src.tools.webscan.info_gathering.tech_detection import detect_tech_stack as external_detect_tech_stack
except ImportError:
    print(colored("[!] ", 'red') + "Tech detection module not found.")
    def external_detect_tech_stack(self): self.tech_stack = []; return self.tech_stack

try:
    from src.tools.webscan.info_gathering.subdomain_enum import enumerate_subdomains as external_enumerate_subdomains
except ImportError:
    print(colored("[!] ", 'yellow') + "Subdomain enumeration module not found. This feature will be added in a future update.")
    def external_enumerate_subdomains(self): self.subdomains = []; return self.subdomains

try:
    from src.tools.webscan.crawlers.directory_brute import brute_force_directories as external_brute_force_directories
except ImportError:
    print(colored("[!] ", 'yellow') + "Directory brute force module not found. This feature will be added in a future update.")
    def external_brute_force_directories(self): self.directories = []; return self.directories

try:
    from src.tools.webscan.reporting.report_generator import generate_report as external_generate_report
except ImportError:
    print(colored("[!] ", 'red') + "Report generator module not found.")
    def external_generate_report(self, report_format): return "path/to/report"

# Import vulnerability scanner classes
try:
    from src.tools.webscan.vulnerabilities.rce import RCEScanner
except ImportError:
    print(colored("[!] ", 'red') + "RCE scanner module not found.")

try:
    from src.tools.webscan.vulnerabilities.command_injection import CommandInjectionScanner
except ImportError:
    print(colored("[!] ", 'red') + "Command injection scanner module not found.")

try:
    from src.tools.webscan.vulnerabilities.sqli import SQLIScanner
except ImportError:
    print(colored("[!] ", 'red') + "SQL injection scanner module not found.")

try:
    from src.tools.webscan.vulnerabilities.xss import XSSScanner
except ImportError:
    print(colored("[!] ", 'red') + "XSS scanner module not found.")

try:
    from src.tools.webscan.vulnerabilities.lfi import LFIScanner
except ImportError:
    print(colored("[!] ", 'red') + "LFI scanner module not found.")

try:
    from src.tools.webscan.vulnerabilities.open_redirect import OpenRedirectScanner
except ImportError:
    print(colored("[!] ", 'red') + "Open redirect scanner module not found.")

try:
    from src.tools.webscan.vulnerabilities.idor import IDORScanner
except ImportError:
    print(colored("[!] ", 'red') + "IDOR scanner module not found.")

# These will be implemented later and uncommented as they're added
# try:
#     from src.tools.webscan.vulnerabilities.csrf import CSRFScanner
# except ImportError:
#     print(colored("[!] ", 'red') + "CSRF scanner module not found.")

# try:
#     from src.tools.webscan.vulnerabilities.cors import CORSScanner
# except ImportError:
#     print(colored("[!] ", 'red') + "CORS scanner module not found.")

# try:
#     from src.tools.webscan.vulnerabilities.ssrf import SSRFScanner
# except ImportError:
#     print(colored("[!] ", 'red') + "SSRF scanner module not found.")

# try:
#     from src.tools.webscan.vulnerabilities.xxe import XXEScanner
# except ImportError:
#     print(colored("[!] ", 'red') + "XXE scanner module not found.")

# try:
#     from src.tools.webscan.vulnerabilities.deserialization import DeserializationScanner
# except ImportError:
#     print(colored("[!] ", 'red') + "Deserialization scanner module not found.")

from src.tools.webscan.vulnerabilities.ssl_tls.scanner import SSLScanner
from src.tools.webscan.vulnerabilities.ssrf.scanner import SSRFScanner
from src.tools.webscan.vulnerabilities.csp.scanner import CSPScanner
from src.tools.webscan.vulnerabilities.ssti.scanner import SSTIScanner
from src.tools.webscan.vulnerabilities.idor.scanner import IDORScanner
from src.tools.webscan.vulnerabilities.oauth.scanner import OAuthScanner
from src.tools.webscan.vulnerabilities.jwt.scanner import JWTScanner
from src.tools.webscan.vulnerabilities.crlf.scanner import CRLFScanner
from src.tools.webscan.vulnerabilities.request_smuggling.scanner import RequestSmugglingScanner

class WebScanner:
    """Web Vulnerability Scanner for identifying common web vulnerabilities"""
    def __init__(self, target_url, max_threads=10, timeout=5, verbose=False, db_uri=None):
        """
        Initialize the WebScanner with target URL and scanning parameters.
        
        Args:
            target_url (str): The target URL to scan.
            max_threads (int): Maximum number of threads for concurrent scanning.
            timeout (int): Timeout for HTTP requests in seconds.
            verbose (bool): Whether to print detailed output during scanning.
            db_uri (str): PostgreSQL connection URI for storing scan results. If None, uses environment variable or default.
        """
        self.target_url = target_url
        self.max_threads = max_threads
        self.timeout = timeout
        self.verbose = verbose
        self.start_time = datetime.now()
        self.discovered_urls = []
        self.forms = []
        self.vulnerabilities = []
        self.server_info = {}
        self.tech_stack = []
        self.subdomains = []
        self.directories = []
        
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
        self.deserialization_vulnerabilities = []
        self.xxe_vulnerabilities = []
        self.ssrf_vulnerabilities = []
        self.csp_vulnerabilities = []
        self.ssti_vulnerabilities = []
        self.idor_vulnerabilities = []
        self.oauth_vulnerabilities = []
        self.jwt_vulnerabilities = []
        self.crlf_vulnerabilities = []
        self.http_request_smuggling_vulnerabilities = []
        
        # Database integration
        self.db_uri = db_uri
        self.db = None
        self.scan_record = None
        
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
        
        # HTTP session for making requests
        self.session = self._setup_session()
        
        # Initialize vulnerability scanners
        self.headers = self.session.headers
        
    def _setup_session(self):
        """Create and configure a requests session"""
        # User agent rotation for evasion
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36 Edg/92.0.902.67'
        ]
        
        import random
        # Headers with random user agent
        headers = {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        # Session to maintain cookies
        session = requests.Session()
        session.headers.update(headers)
        return session
    
    def _get_base_url(self):
        """Extract the base URL (scheme + domain) from the target URL"""
        parsed = urlparse(self.target_url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def run(self, report_format='html'):
        """
        Execute the full scanner.
        
        Args:
            report_format (str): Format for the final report ('html', 'pdf', or 'json')
            
        Returns:
            str: Path to the generated report
        """
        print(colored("\n[+] ", 'green') + "Starting NetHawk Web Scanner")
        print(colored("[*] ", 'blue') + f"Target URL: {self.target_url}")
        print(colored("[*] ", 'blue') + f"Threads: {self.max_threads}")
        print(colored("[*] ", 'blue') + f"Timeout: {self.timeout} seconds")
        
        try:
            # Initialize DB connection
            if self.db_uri:
                try:
                    from src.tools.webscan.database.db_service import DBService
                    self.db = DBService(self.db_uri)
                    print(colored("[+] ", 'green') + "Database connection initialized")
                    
                    # Create initial scan record
                    self.scan_record = self.db.create_scan(self)
                    print(colored("[+] ", 'green') + f"Scan record created with ID: {self.scan_record.id}")
                except ImportError:
                    print(colored("[!] ", 'yellow') + "Database module not found. Continuing without database integration.")
                except Exception as e:
                    print(colored("[!] ", 'yellow') + f"Database error: {str(e)}. Continuing without database integration.")
            
            # INFORMATION GATHERING PHASE
            print(colored("\n[+] ", 'green') + "Starting information gathering phase")
            
            # Gather server information
            self.server_info = self.gather_server_info()
            
            # Analyze and store the module structure
            print(colored("\n[+] ", 'green') + "Analyzing webscan module structure")
            self.analyze_module_structure()
            
            # Detect technology stack
            self.tech_stack = self.detect_tech_stack()
            
            # Enumerate subdomains
            if urlparse(self.target_url).netloc:
                self.subdomains = self.enumerate_subdomains()
            
            # Save info to database
            if self.db and self.scan_record:
                try:
                    if self.server_info:
                        self.db.save_server_info(self.scan_record.id, self.server_info)
                    
                    if self.tech_stack:
                        self.db.save_tech_stack(self.scan_record.id, self.tech_stack)
                except Exception as e:
                    print(colored("[!] ", 'yellow') + f"Error saving information to database: {str(e)}")
            
            # CRAWLING PHASE
            print(colored("\n[+] ", 'green') + "Starting crawling phase")
            
            # Discover URLs
            self.discovered_urls = self.discover_urls()
            
            # Find forms
            self.forms = self.find_forms()
            
            # Brute force directories
            self.directories = self.brute_force_directories()
            
            # VULNERABILITY SCANNING PHASE
            print(colored("\n[+] ", 'green') + "Starting vulnerability scanning phase")
            
            # Run security header checks
            self.missing_headers = self.check_security_headers()
            
            # Run vulnerability scans
            self.run_vulnerability_scans()
            
            # Save vulnerabilities to database
            if self.db and self.scan_record:
                try:
                    vulns_saved = self.db.save_vulnerabilities(self.scan_record.id, self)
                    print(colored("[+] ", 'green') + f"Saved {vulns_saved} vulnerabilities to database")
                except Exception as e:
                    print(colored("[!] ", 'yellow') + f"Error saving vulnerabilities to database: {str(e)}")
            
            # REPORTING PHASE
            print(colored("\n[+] ", 'green') + "Generating report")
            report_path = self.generate_report(report_format)
            
            # Update scan record
            if self.db and self.scan_record:
                try:
                    self.db.complete_scan(self.scan_record, self)
                except Exception as e:
                    print(colored("[!] ", 'yellow') + f"Error updating scan record: {str(e)}")
            
            # Done
            print(colored("\n[+] ", 'green') + f"Scan completed in {datetime.now() - self.start_time}")
            print(colored("[+] ", 'green') + f"Report saved to: {report_path}")
            return report_path
            
        except KeyboardInterrupt:
            print(colored("\n[!] ", 'yellow') + "Scan interrupted by user")
            return None
        except Exception as e:
            print(colored("\n[!] ", 'red') + f"Error during scan: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            # Close DB connection if it exists
            if self.db:
                self.db.close()

    def gather_server_info(self):
        """
        Gather server information using the external module if available, otherwise return empty dict.
        """
        if self.verbose:
            print(colored("[*] ", 'blue') + "Gathering server info")
        return external_gather_server_info(self)

    def discover_urls(self):
        """
        Discover URLs on the target website using the external module if available.
        """
        if self.verbose:
            print(colored("[*] ", 'blue') + "Discovering URLs")
        return external_discover_urls(self)

    def find_forms(self):
        """
        Find forms on the target website using the external module if available.
        """
        if self.verbose:
            print(colored("[*] ", 'blue') + "Finding forms")
        return external_find_forms(self)

    def check_security_headers(self):
        """
        Check security headers of the target website using the external module if available.
        """
        if self.verbose:
            print(colored("[*] ", 'blue') + "Checking security headers")
        return external_check_security_headers(self)

    def detect_tech_stack(self):
        """
        Detect the technology stack of the target website using the external module if available.
        """
        if self.verbose:
            print(colored("[*] ", 'blue') + "Detecting technology stack")
        return external_detect_tech_stack(self)

    def enumerate_subdomains(self):
        """
        Enumerate subdomains of the target website using the external module if available.
        """
        if self.verbose:
            print(colored("[*] ", 'blue') + "Enumerating subdomains")
        return external_enumerate_subdomains(self)

    def brute_force_directories(self):
        """Brute force directories on the target site"""
        print(colored("[*] ", 'blue') + f"Brute forcing directories on {self.target_url}")
        self.directories = external_brute_force_directories(self)
        print(colored("[+] ", 'green') + f"Found {len(self.directories)} directories")
        return self.directories
    
    def analyze_module_structure(self, module_path=None):
        """
        Analyze the webscan module structure and save to database
        
        Args:
            module_path (str): Path to the webscan module directory. If None, uses the default.
        
        Returns:
            bool: True if successful, False otherwise
        """
        # If no path is provided, use the path of the current module
        if not module_path:
            # Get the path of the current directory (webscan)
            current_file = os.path.abspath(__file__)
            webscan_dir = os.path.dirname(os.path.dirname(current_file))
            module_path = webscan_dir
        
        print(colored("[*] ", 'blue') + f"Analyzing module structure at {module_path}")
        
        try:
            # Import the database service
            if self.db is None:
                from src.tools.webscan.database.db_service import DBService
                self.db = DBService(self.db_uri)
            
            # Save the module structure recursively
            self.db.save_module_structure(module_path)
            
            print(colored("[+] ", 'green') + "Module structure analysis completed and saved to database")
            return True
        except Exception as e:
            print(colored("[!] ", 'red') + f"Error analyzing module structure: {str(e)}")
            return False

    def generate_report(self, report_format):
        """
        Generate a report based on the scan results using the external module if available.
        
        Args:
            report_format (str): Format for the report (json, html, csv)
        
        Returns:
            str: Path to the generated report file
        """
        if self.verbose:
            print(colored("[*] ", 'blue') + f"Generating {report_format} report")
        return external_generate_report(self, report_format)

    def run_vulnerability_scans(self):
        """Run all vulnerability scans"""
        if self.verbose:
            print("Running vulnerability scanners...")
        
        # XSS Scanner
        from ..vulnerabilities.xss.scanner import XSSScanner
        if self.verbose:
            print("[+] Starting XSS scanner...")
        xss_scanner = XSSScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        xss_scanner.run()
        self.xss_vulnerabilities = xss_scanner.vulnerabilities
        # Save XSS vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'xss', 
                self.xss_vulnerabilities,
                "Cross-Site Scripting vulnerabilities allow attackers to inject malicious scripts into web pages"
            )
            print(f"[+] Saved {count} XSS vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save XSS vulnerabilities: {str(e)}")
        
        # SQL Injection Scanner
        from ..vulnerabilities.sqli.scanner import SQLiScanner
        if self.verbose:
            print("[+] Starting SQL Injection scanner...")
        sqli_scanner = SQLiScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        sqli_scanner.run()
        self.sqli_vulnerabilities = sqli_scanner.vulnerabilities
        # Save SQLi vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'sqli', 
                self.sqli_vulnerabilities,
                "SQL Injection vulnerabilities allow attackers to manipulate database queries"
            )
            print(f"[+] Saved {count} SQL Injection vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save SQL Injection vulnerabilities: {str(e)}")
        
        # Open Redirect Scanner
        from ..vulnerabilities.open_redirect.scanner import OpenRedirectScanner
        if self.verbose:
            print("[+] Starting Open Redirect scanner...")
        open_redirect_scanner = OpenRedirectScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        open_redirect_scanner.run()
        self.open_redirect_vulnerabilities = open_redirect_scanner.vulnerabilities
        # Save Open Redirect vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'open_redirect', 
                self.open_redirect_vulnerabilities,
                "Open Redirect vulnerabilities allow attackers to redirect users to malicious websites"
            )
            print(f"[+] Saved {count} Open Redirect vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save Open Redirect vulnerabilities: {str(e)}")
        
        # LFI Scanner
        from ..vulnerabilities.lfi.scanner import LFIScanner
        if self.verbose:
            print("[+] Starting LFI scanner...")
        lfi_scanner = LFIScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        lfi_scanner.run()
        self.lfi_vulnerabilities = lfi_scanner.vulnerabilities
        # Save LFI vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'lfi', 
                self.lfi_vulnerabilities,
                "Local File Inclusion vulnerabilities allow attackers to read files on the server"
            )
            print(f"[+] Saved {count} LFI vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save LFI vulnerabilities: {str(e)}")
            
        # CSRF Scanner
        from ..vulnerabilities.csrf.scanner import CSRFScanner
        if self.verbose:
            print("[+] Starting CSRF scanner...")
        csrf_scanner = CSRFScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        csrf_scanner.run()
        self.csrf_vulnerabilities = csrf_scanner.vulnerabilities
        # Save CSRF vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'csrf', 
                self.csrf_vulnerabilities,
                "Cross-Site Request Forgery vulnerabilities allow attackers to perform actions on behalf of authenticated users"
            )
            print(f"[+] Saved {count} CSRF vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save CSRF vulnerabilities: {str(e)}")
        
        # Command Injection Scanner
        from ..vulnerabilities.command_injection.scanner import CommandInjectionScanner
        if self.verbose:
            print("[+] Starting Command Injection scanner...")
        cmd_injection_scanner = CommandInjectionScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        cmd_injection_scanner.run()
        self.command_injection_vulnerabilities = cmd_injection_scanner.vulnerabilities
        # Save Command Injection vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'command_injection', 
                self.command_injection_vulnerabilities,
                "Command Injection vulnerabilities allow attackers to execute system commands on the server"
            )
            print(f"[+] Saved {count} Command Injection vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save Command Injection vulnerabilities: {str(e)}")
        
        # RCE Scanner
        from ..vulnerabilities.rce.scanner import RCEScanner
        if self.verbose:
            print("[+] Starting RCE scanner...")
        rce_scanner = RCEScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        rce_scanner.run()
        self.rce_vulnerabilities = rce_scanner.vulnerabilities
        # Save RCE vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'rce', 
                self.rce_vulnerabilities,
                "Remote Code Execution vulnerabilities allow attackers to execute arbitrary code on the server"
            )
            print(f"[+] Saved {count} RCE vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save RCE vulnerabilities: {str(e)}")
        
        # CORS Scanner
        from ..vulnerabilities.cors.scanner import CORSScanner
        if self.verbose:
            print("[+] Starting CORS scanner...")
        cors_scanner = CORSScanner(self.target_url, self.session, self.timeout, self.verbose)
        cors_scanner.run()
        self.cors_vulnerabilities = cors_scanner.vulnerabilities
        # Save CORS vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'cors', 
                self.cors_vulnerabilities,
                "Cross-Origin Resource Sharing misconfigurations can allow attackers to access sensitive data"
            )
            print(f"[+] Saved {count} CORS vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save CORS vulnerabilities: {str(e)}")
        
        # Security Headers Scanner
        from ..vulnerabilities.security_headers.scanner import SecurityHeadersScanner
        if self.verbose:
            print("[+] Starting Security Headers scanner...")
        headers_scanner = SecurityHeadersScanner(self.target_url, self.session, self.timeout, self.verbose)
        headers_scanner.run()
        self.missing_headers_vulnerabilities = headers_scanner.vulnerabilities
        # Save Security Headers vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'missing_headers', 
                self.missing_headers_vulnerabilities,
                "Missing security headers can expose the application to various attacks"
            )
            print(f"[+] Saved {count} missing security headers vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save security headers vulnerabilities: {str(e)}")
        
        # Deserialization Scanner
        from ..vulnerabilities.deserialization.scanner import DeserializationScanner
        if self.verbose:
            print("[+] Starting Deserialization scanner...")
        deserialization_scanner = DeserializationScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        deserialization_scanner.run()
        self.deserialization_vulnerabilities = deserialization_scanner.vulnerabilities
        # Save Deserialization vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'deserialization', 
                self.deserialization_vulnerabilities,
                "Insecure deserialization vulnerabilities can allow attackers to execute arbitrary code"
            )
            print(f"[+] Saved {count} Deserialization vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save Deserialization vulnerabilities: {str(e)}")
            
        # XXE Scanner
        from ..vulnerabilities.xxe.scanner import XXEScanner
        if self.verbose:
            print("[+] Starting XXE scanner...")
        xxe_scanner = XXEScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        xxe_scanner.run()
        self.xxe_vulnerabilities = xxe_scanner.vulnerabilities
        # Save XXE vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'xxe', 
                self.xxe_vulnerabilities,
                "XML External Entity vulnerabilities can allow attackers to read files or execute server-side requests"
            )
            print(f"[+] Saved {count} XXE vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save XXE vulnerabilities: {str(e)}")
            
        # SSL/TLS Scanner
        from ..vulnerabilities.ssl_tls.scanner import SSLTLSScanner
        if self.verbose:
            print("[+] Starting SSL/TLS scanner...")
        ssl_scanner = SSLTLSScanner(self.target_url, self.timeout, self.verbose)
        ssl_scanner.run()
        self.ssl_tls_vulnerabilities = ssl_scanner.vulnerabilities
        # Save SSL/TLS vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'ssl_tls', 
                self.ssl_tls_vulnerabilities,
                "SSL/TLS vulnerabilities can allow attackers to intercept or manipulate encrypted traffic"
            )
            print(f"[+] Saved {count} SSL/TLS vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save SSL/TLS vulnerabilities: {str(e)}")
        
        # SSRF Scanner
        from ..vulnerabilities.ssrf.scanner import SSRFScanner
        if self.verbose:
            print("[+] Starting SSRF scanner...")
        ssrf_scanner = SSRFScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        ssrf_scanner.run()
        self.ssrf_vulnerabilities = ssrf_scanner.vulnerabilities
        # Save SSRF vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'ssrf', 
                self.ssrf_vulnerabilities,
                "Server-Side Request Forgery vulnerabilities allow attackers to make requests from the server"
            )
            print(f"[+] Saved {count} SSRF vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save SSRF vulnerabilities: {str(e)}")
        
        # CSP Scanner
        from ..vulnerabilities.csp.scanner import CSPScanner
        if self.verbose:
            print("[+] Starting CSP scanner...")
        csp_scanner = CSPScanner(self.target_url, self.session, self.timeout, self.verbose)
        csp_scanner.run()
        self.csp_vulnerabilities = csp_scanner.vulnerabilities
        # Save CSP vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'csp', 
                self.csp_vulnerabilities,
                "Content Security Policy misconfigurations can allow various attacks including XSS"
            )
            print(f"[+] Saved {count} CSP vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save CSP vulnerabilities: {str(e)}")
            
        # SSTI Scanner
        from ..vulnerabilities.ssti.scanner import SSTIScanner
        if self.verbose:
            print("[+] Starting SSTI scanner...")
        ssti_scanner = SSTIScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        ssti_scanner.run()
        self.ssti_vulnerabilities = ssti_scanner.vulnerabilities
        # Save SSTI vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'ssti', 
                self.ssti_vulnerabilities,
                "Server-Side Template Injection vulnerabilities can allow attackers to execute code on the server"
            )
            print(f"[+] Saved {count} SSTI vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save SSTI vulnerabilities: {str(e)}")
        
        # Run IDOR scanner
        from ..vulnerabilities.idor.scanner import IDORScanner
        if self.verbose:
            print("[+] Starting IDOR scanner...")
        idor_scanner = IDORScanner(self.target_url, self.session, self.timeout, self.verbose, self.max_threads)
        idor_scanner.run()
        self.idor_vulnerabilities = idor_scanner.vulnerabilities
        # Save IDOR vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'idor', 
                self.idor_vulnerabilities,
                "Insecure Direct Object Reference vulnerabilities allow unauthorized access to resources"
            )
            print(f"[+] Saved {count} IDOR vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save IDOR vulnerabilities: {str(e)}")
        
        # Run CRLF scanner
        from ..vulnerabilities.crlf.scanner import CRLFScanner
        if self.verbose:
            print("[+] Starting CRLF injection scanner...")
        crlf_scanner = CRLFScanner(self)
        self.crlf_vulnerabilities = crlf_scanner.run()
        # Save CRLF vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'crlf', 
                self.crlf_vulnerabilities,
                "CRLF Injection vulnerabilities allow attackers to inject headers into HTTP responses, potentially leading to cross-site scripting or cache poisoning"
            )
            print(f"[+] Saved {count} CRLF vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save CRLF vulnerabilities: {str(e)}")
            
        # Run HTTP Request Smuggling scanner
        from ..vulnerabilities.request_smuggling.scanner import RequestSmugglingScanner
        if self.verbose:
            print("[+] Starting HTTP Request Smuggling scanner...")
        req_smuggling_scanner = RequestSmugglingScanner(self)
        self.http_request_smuggling_vulnerabilities = req_smuggling_scanner.run()
        # Save HTTP Request Smuggling vulnerabilities immediately after scanning
        try:
            count = self.db.save_single_vulnerability_type(
                self.scan_record.id, 
                'http_smuggling', 
                self.http_request_smuggling_vulnerabilities,
                "HTTP Request Smuggling vulnerabilities can bypass security controls by exploiting how front-end and back-end servers process requests differently"
            )
            print(f"[+] Saved {count} HTTP Request Smuggling vulnerabilities to database")
        except Exception as e:
            print(f"[-] Failed to save HTTP Request Smuggling vulnerabilities: {str(e)}")
        
        # Run OAuth scanner
        try:
            oauth_scanner = OAuthScanner(self)
            self.oauth_vulnerabilities = oauth_scanner.run()
            if self.verbose and self.oauth_vulnerabilities:
                print(f"Found {len(self.oauth_vulnerabilities)} OAuth vulnerabilities.")

            if self.db:
                self.db.save_single_vulnerability_type(
                    self.scan_record.id, "oauth", 
                    self.oauth_vulnerabilities,
                    "OAuth vulnerabilities can allow attackers to steal authorization tokens, perform open redirects, or execute CSRF attacks against the OAuth flow."
                )
        except Exception as e:
            print(f"Error running OAuth scanner: {str(e)}")
        
        # Run JWT scanner
        try:
            from ..vulnerabilities.jwt.scanner import JWTScanner
            if self.verbose:
                print("[+] Starting JWT scanner...")
            jwt_scanner = JWTScanner(self)
            self.jwt_vulnerabilities = jwt_scanner.run()
            if self.verbose and self.jwt_vulnerabilities:
                print(f"Found {len(self.jwt_vulnerabilities)} JWT vulnerabilities.")
                
            # Save JWT vulnerabilities immediately after scanning
            if self.db:
                count = self.db.save_single_vulnerability_type(
                    self.scan_record.id, 
                    'jwt', 
                    self.jwt_vulnerabilities,
                    "JWT vulnerabilities can allow attackers to forge tokens, bypass authentication, or access unauthorized data."
                )
                print(f"[+] Saved {count} JWT vulnerabilities to database")
        except Exception as e:
            print(f"Error running JWT scanner: {str(e)}")
        
        # Note: We still save all vulnerabilities at the end as well for redundancy
        if self.verbose:
            print("[+] All vulnerability scanners completed")
        
        # Combine all vulnerabilities into a single list for reporting
        for vuln in self.xss_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'XSS',
                'url': vuln['url'],
                'details': vuln
            })
        
        for vuln in self.sqli_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'SQL Injection',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.open_redirect_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'Open Redirect',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.lfi_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'Local File Inclusion',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.csrf_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'CSRF',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.command_injection_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'Command Injection',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.rce_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'Remote Code Execution',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.cors_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'CORS Misconfiguration',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.ssl_tls_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'SSL/TLS Issue',
                'url': self.target_url,
                'details': vuln
            })
            
        for vuln in self.missing_headers:
            self.vulnerabilities.append({
                'type': 'Missing Security Header',
                'url': self.target_url,
                'details': {'header': vuln}
            })
            
        for vuln in self.deserialization_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'Insecure Deserialization',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.xxe_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'XXE',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.ssrf_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'SSRF',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.csp_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'CSP Issue',
                'url': self.target_url,
                'details': vuln
            })
            
        for vuln in self.ssti_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'SSTI',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.idor_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'IDOR',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.oauth_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'OAuth',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.jwt_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'JWT',
                'url': vuln['url'],
                'details': vuln
            })
            
        for vuln in self.crlf_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'CRLF Injection',
                'url': self.target_url,
                'details': {'injection': vuln}
            })
            
        for vuln in self.http_request_smuggling_vulnerabilities:
            self.vulnerabilities.append({
                'type': 'HTTP Request Smuggling',
                'url': self.target_url,
                'details': {'injection': vuln}
            }) 