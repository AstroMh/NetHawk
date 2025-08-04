#!/usr/bin/env python3

import re
import logging
import requests
from typing import Dict, List, Any, Optional, Union, Tuple
from bs4 import BeautifulSoup

logger = logging.getLogger('nethawk')

class XXEDetector:
    """XXE vulnerability detector for various XML inputs and endpoints"""
    
    def __init__(self, session: requests.Session, timeout: int = 10):
        """
        Initialize the XXE detector
        
        Args:
            session: Requests session to use for HTTP requests
            timeout: Request timeout in seconds
        """
        self.session = session
        self.timeout = timeout
        self.headers = {
            'Content-Type': 'application/xml',
            'Accept': '*/*'
        }
    
    def identify_xml_endpoints(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Identify potential XML endpoints based on URL patterns, content types, and responses
        
        Args:
            urls: List of URLs to check
            
        Returns:
            List of dictionaries with endpoint details
        """
        xml_endpoints = []
        xml_patterns = [
            r'\.xml$',
            r'\.wsdl$',
            r'\.soap$',
            r'/rss',
            r'/feed',
            r'/api',
            r'/xml',
            r'/service',
            r'/soap',
            r'/wsdl'
        ]
        
        for url in urls:
            # Check URL patterns
            if any(re.search(pattern, url, re.IGNORECASE) for pattern in xml_patterns):
                xml_endpoints.append({
                    'url': url,
                    'method': 'GET',
                    'confidence': 'Medium',
                    'source': 'URL pattern'
                })
                continue
            
            # Check response headers and content
            try:
                response = self.session.head(url, timeout=self.timeout)
                content_type = response.headers.get('Content-Type', '')
                
                if 'xml' in content_type.lower():
                    xml_endpoints.append({
                        'url': url,
                        'method': 'GET',
                        'confidence': 'High',
                        'source': 'Content-Type header'
                    })
                    continue
                
                # For non-XML content types, do a GET and check response body
                if 'text' in content_type.lower() or 'html' in content_type.lower():
                    response = self.session.get(url, timeout=self.timeout)
                    if '</xml>' in response.text or '<?xml' in response.text:
                        xml_endpoints.append({
                            'url': url,
                            'method': 'GET',
                            'confidence': 'Medium',
                            'source': 'Response body'
                        })
            
            except requests.RequestException as e:
                logger.debug(f"Error checking XML endpoint {url}: {e}")
        
        return xml_endpoints
    
    def identify_xml_forms(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Identify HTML forms that might accept XML input
        
        Args:
            urls: List of URLs to check
            
        Returns:
            List of dictionaries with form details
        """
        xml_forms = []
        
        for url in urls:
            try:
                response = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    # Check for XML-related attributes
                    if any(attr for attr in form.attrs if 'xml' in str(attr).lower()):
                        xml_forms.append({
                            'url': url,
                            'form_action': form.get('action', ''),
                            'form_method': form.get('method', 'POST').upper(),
                            'confidence': 'Medium',
                            'source': 'Form attributes'
                        })
                        continue
                    
                    # Check for hidden input fields that might indicate XML handling
                    inputs = form.find_all('input')
                    if any('xml' in input.get('name', '').lower() for input in inputs):
                        xml_forms.append({
                            'url': url,
                            'form_action': form.get('action', ''),
                            'form_method': form.get('method', 'POST').upper(),
                            'confidence': 'Medium',
                            'source': 'Input field names'
                        })
                        continue
                    
                    # Check for textareas that might accept XML
                    textareas = form.find_all('textarea')
                    if any('xml' in textarea.get('name', '').lower() for textarea in textareas):
                        xml_forms.append({
                            'url': url,
                            'form_action': form.get('action', ''),
                            'form_method': form.get('method', 'POST').upper(),
                            'confidence': 'High',
                            'source': 'Textarea field names'
                        })
            
            except (requests.RequestException, Exception) as e:
                logger.debug(f"Error identifying XML forms at {url}: {e}")
        
        return xml_forms
    
    def check_dtd_processing(self, url: str, method: str = 'POST') -> Dict[str, Any]:
        """
        Check if the endpoint processes DTDs by sending a basic XML with a simple entity
        
        Args:
            url: URL to test
            method: HTTP method to use
            
        Returns:
            Dictionary with test results
        """
        result = {
            'url': url,
            'method': method,
            'dtd_processing': False,
            'entity_processing': False,
            'evidence': '',
            'details': ''
        }
        
        # Simple XML with internal entity
        test_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE test [
        <!ENTITY test "ENTITY_TEST_STRING">
        ]>
        <test>&test;</test>"""
        
        try:
            if method.upper() == 'POST':
                response = self.session.post(
                    url, 
                    data=test_xml,
                    headers=self.headers,
                    timeout=self.timeout
                )
            else:
                response = self.session.get(
                    url,
                    headers=self.headers,
                    timeout=self.timeout
                )
            
            # Check if entity was processed
            if 'ENTITY_TEST_STRING' in response.text:
                result['entity_processing'] = True
                result['dtd_processing'] = True
                result['evidence'] = 'Entity was processed'
                result['details'] = 'The server appears to process XML entities, which may indicate vulnerability to XXE attacks'
            
            # Check for error messages that might indicate DTD processing
            dtd_patterns = [
                r'DOCTYPE',
                r'DTD',
                r'ENTITY',
                r'xml processing',
                r'xml parser'
            ]
            
            for pattern in dtd_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    result['dtd_processing'] = True
                    result['evidence'] = f"Found pattern: {pattern}"
                    result['details'] = 'Response contains references to XML/DTD processing'
                    break
        
        except requests.RequestException as e:
            logger.debug(f"Error testing DTD processing at {url}: {e}")
            result['details'] = f"Error during testing: {str(e)}"
        
        return result
    
    def test_endpoint(self, endpoint: Dict[str, Any], payloads: List[str]) -> Dict[str, Any]:
        """
        Test an endpoint for XXE vulnerabilities using the provided payloads
        
        Args:
            endpoint: Dictionary with endpoint details
            payloads: List of XXE payloads to test
            
        Returns:
            Dictionary with vulnerability details if found, or None
        """
        url = endpoint.get('url')
        method = endpoint.get('method', 'POST')
        
        # First check if DTD processing is enabled
        dtd_check = self.check_dtd_processing(url, method)
        if not dtd_check.get('dtd_processing', False):
            logger.debug(f"DTD processing appears to be disabled at {url}")
            return None
        
        # Test payloads
        for payload in payloads:
            try:
                logger.debug(f"Testing XXE payload on {url}")
                
                if method.upper() == 'POST':
                    response = self.session.post(
                        url,
                        data=payload,
                        headers=self.headers,
                        timeout=self.timeout
                    )
                else:
                    response = self.session.get(
                        url,
                        headers=self.headers,
                        timeout=self.timeout
                    )
                
                # Analyze response for signs of vulnerability
                from .utils import analyze_xxe_response
                analysis = analyze_xxe_response(response.text)
                
                if analysis.get('vulnerable', False):
                    logger.info(f"XXE vulnerability detected at {url}")
                    return {
                        'url': url,
                        'method': method,
                        'vulnerability_type': 'XXE',
                        'severity': 'High',
                        'confidence': analysis.get('confidence', 'Medium'),
                        'evidence': analysis.get('evidence', ''),
                        'details': analysis.get('details', ''),
                        'payload': payload,
                        'response_status': response.status_code,
                        'response_headers': dict(response.headers)
                    }
            
            except requests.RequestException as e:
                logger.debug(f"Error testing XXE payload on {url}: {e}")
                # Check if the error might indicate a successful XXE attack
                if 'timeout' in str(e).lower():
                    # Potential blind XXE with timeout
                    return {
                        'url': url,
                        'method': method,
                        'vulnerability_type': 'Blind XXE',
                        'severity': 'High',
                        'confidence': 'Medium',
                        'evidence': str(e),
                        'details': 'Request timeout occurred, which may indicate a successful blind XXE attack',
                        'payload': payload,
                        'response_status': None,
                        'response_headers': None
                    }
        
        return None 