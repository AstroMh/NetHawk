#!/usr/bin/env python3

import os
import logging
import time
from typing import Dict, List, Any, Optional, Union
import requests
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

from .detector import XXEDetector
from .utils import generate_xxe_payloads, create_evil_dtd, generate_xxe_report

logger = logging.getLogger('nethawk')

class XXEScanner:
    """Scanner for XML External Entity (XXE) vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the XXE Scanner with a reference to the main scanner instance
        
        Args:
            scanner_instance: The main WebScanner instance
        """
        self.scanner = scanner_instance
        self.target_url = scanner_instance.target_url
        self.max_threads = scanner_instance.max_threads
        self.timeout = scanner_instance.timeout
        self.verbose = scanner_instance.verbose
        self.vulnerabilities = []
        
        # Store reference to main vulnerabilities list for aggregation
        self.main_vulnerabilities = scanner_instance.vulnerabilities
        self.xxe_vulnerabilities = scanner_instance.xxe_vulnerabilities
        
        # Configure session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        
        # Create detector instance
        self.detector = XXEDetector(self.session, self.timeout)
        
        # Generate payloads
        self.payloads = generate_xxe_payloads()
        
        if self.verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
            
    def scan(self, urls: List[str] = None, forms: List[Dict] = None) -> List[Dict[str, Any]]:
        """
        Scan for XXE vulnerabilities
        
        Args:
            urls: List of URLs to scan (optional)
            forms: List of forms to test (optional)
            
        Returns:
            List of dictionaries with vulnerability details
        """
        logger.info(f"Starting XXE vulnerability scan against {self.target_url}")
        start_time = time.time()
        
        # If no URLs provided, use target_url and discovered URLs from the scanner
        if not urls:
            urls = [self.target_url]
            if hasattr(self.scanner, 'discovered_urls') and self.scanner.discovered_urls:
                urls.extend(self.scanner.discovered_urls)
        
        # Step 1: Identify XML endpoints
        logger.info("Identifying potential XML endpoints...")
        xml_endpoints = self.detector.identify_xml_endpoints(urls)
        logger.info(f"Found {len(xml_endpoints)} potential XML endpoints")
        
        # Step 2: Identify XML forms if no forms provided
        if not forms:
            if hasattr(self.scanner, 'forms') and self.scanner.forms:
                xml_forms = self.scanner.forms
                logger.info(f"Using {len(xml_forms)} forms from scanner")
            else:
                logger.info("Identifying forms that might accept XML...")
                xml_forms = self.detector.identify_xml_forms(urls)
                logger.info(f"Found {len(xml_forms)} forms that might accept XML")
        else:
            xml_forms = forms
        
        # Step 3: Test endpoints with payloads
        logger.info("Testing endpoints for XXE vulnerabilities...")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            endpoint_futures = {executor.submit(self.detector.test_endpoint, endpoint, self.payloads): endpoint 
                               for endpoint in xml_endpoints}
            
            for future in endpoint_futures:
                result = future.result()
                if result:
                    self.vulnerabilities.append(result)
        
        # Step 4: Test forms
        logger.info("Testing forms for XXE vulnerabilities...")
        self._test_forms(xml_forms)
        
        # Step 5: Generate evil DTD for OOB XXE if vulnerabilities found
        if self.vulnerabilities:
            logger.info("Creating evil DTD for out-of-band XXE testing...")
            evil_dtd = create_evil_dtd(payload_type="oob")
            logger.debug(f"Evil DTD content: {evil_dtd}")
        
        scan_time = time.time() - start_time
        logger.info(f"XXE scan completed in {scan_time:.2f} seconds")
        logger.info(f"Found {len(self.vulnerabilities)} XXE vulnerabilities")
        
        # Add discovered vulnerabilities to scanner's dedicated XXE list and main list
        for vuln in self.vulnerabilities:
            self.xxe_vulnerabilities.append(vuln)
            self.main_vulnerabilities.append(vuln)
        
        return self.vulnerabilities
    
    def _test_forms(self, forms: List[Dict[str, Any]]) -> None:
        """
        Test forms for XXE vulnerabilities
        
        Args:
            forms: List of forms to test
        """
        for form in forms:
            url = form.get('url') or form.get('action')
            form_action = form.get('form_action') or form.get('action')
            form_method = form.get('method', 'POST')
            
            # Skip if no URL available
            if not url and not form_action:
                continue
                
            # Create full action URL if relative
            if form_action and not form_action.startswith(('http://', 'https://')):
                if form_action.startswith('/'):
                    # Absolute path
                    base_url = '/'.join(url.split('/')[:3])  # Get domain with scheme
                    action_url = base_url + form_action
                else:
                    # Relative path
                    action_url = '/'.join(url.split('/')[:-1]) + '/' + form_action
            else:
                action_url = form_action or url
            
            for payload in self.payloads:
                try:
                    logger.debug(f"Testing XXE payload on form at {action_url}")
                    
                    # Attempt to submit the form with the XML payload
                    if form_method.upper() == 'POST':
                        # Try different content types
                        for content_type in ['application/xml', 'text/xml', 'application/x-www-form-urlencoded']:
                            headers = {'Content-Type': content_type}
                            response = self.session.post(
                                action_url,
                                data=payload,
                                headers=headers,
                                timeout=self.timeout
                            )
                            
                            # Analyze response
                            from .utils import analyze_xxe_response
                            analysis = analyze_xxe_response(response.text)
                            
                            if analysis.get('vulnerable', False):
                                logger.info(f"XXE vulnerability detected in form at {action_url}")
                                vulnerability = {
                                    'type': 'XXE',
                                    'url': action_url,
                                    'method': 'POST',
                                    'form': True,
                                    'content_type': content_type,
                                    'parameter': 'XML Input',
                                    'severity': 'High',
                                    'evidence': analysis.get('evidence', ''),
                                    'payload': payload,
                                }
                                self.vulnerabilities.append(vulnerability)
                                break
                    
                except requests.RequestException as e:
                    logger.debug(f"Error testing XXE payload on form at {action_url}: {e}")
                    # Check if the error might indicate a successful XXE attack
                    if 'timeout' in str(e).lower():
                        # Potential blind XXE with timeout
                        vulnerability = {
                            'type': 'XXE',
                            'url': action_url,
                            'method': 'POST',
                            'form': True,
                            'parameter': 'XML Input',
                            'severity': 'High',
                            'evidence': str(e),
                            'payload': payload
                        }
                        self.vulnerabilities.append(vulnerability)
    
    def run(self) -> Dict[str, Any]:
        """
        Run the XXE scanner
        
        Returns:
            Dictionary with scan results summary
        """
        try:
            start_time = time.time()
            
            # Perform scan with the target URL
            self.scan()
            
            scan_time = time.time() - start_time
            
            print(f"[+] Completed XXE testing, found {len(self.vulnerabilities)} vulnerabilities")
            
            return {
                'target': self.target_url,
                'vulnerabilities': self.vulnerabilities,
                'scan_time': scan_time,
                'total_vulnerabilities': len(self.vulnerabilities)
            }
        except Exception as e:
            print(f"[!] Error during XXE scanning: {str(e)}")
            return {
                'target': self.target_url,
                'vulnerabilities': [],
                'scan_time': 0,
                'total_vulnerabilities': 0,
                'error': str(e)
            } 