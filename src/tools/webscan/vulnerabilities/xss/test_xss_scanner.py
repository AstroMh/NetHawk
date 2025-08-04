#!/usr/bin/env python3

"""
Advanced XSS Scanner Test Suite

This module provides comprehensive testing capabilities for the enhanced XSS scanner,
demonstrating various vulnerability detection techniques and payload effectiveness.
"""

import unittest
import requests
from unittest.mock import Mock, patch
from src.tools.webscan.vulnerabilities.xss import XSSScanner

class TestXSSScanner(unittest.TestCase):
    """Comprehensive test suite for the Advanced XSS Scanner"""
    
    def setUp(self):
        """Set up test environment"""
        # Mock scanner instance
        self.mock_scanner = Mock()
        self.mock_scanner.target_url = "http://test.example.com"
        self.mock_scanner.session = requests.Session()
        self.mock_scanner.timeout = 10
        self.mock_scanner.verbose = True
        self.mock_scanner.max_threads = 5
        self.mock_scanner.vulnerabilities = []
        self.mock_scanner.forms = []
        self.mock_scanner.discovered_urls = []
        
        # Initialize XSS scanner
        self.xss_scanner = XSSScanner(self.mock_scanner)
    
    def test_payload_database_initialization(self):
        """Test payload database initialization"""
        self.assertIsNotNone(self.xss_scanner.xss_payloads)
        self.assertIn('basic', self.xss_scanner.xss_payloads)
        self.assertIn('advanced_bypass', self.xss_scanner.xss_payloads)
        self.assertIn('polyglot', self.xss_scanner.xss_payloads)
        self.assertIn('waf_bypass', self.xss_scanner.xss_payloads)
        self.assertIn('csp_bypass', self.xss_scanner.xss_payloads)
    
    def test_context_detection(self):
        """Test context detection for different input fields"""
        # Test HTML context
        html_field = {'type': 'text', 'name': 'content', 'id': 'body'}
        context = self.xss_scanner._determine_input_context(html_field)
        self.assertEqual(context, 'html_context')
        
        # Test JavaScript context
        js_field = {'type': 'text', 'name': 'script', 'id': 'code'}
        context = self.xss_scanner._determine_input_context(js_field)
        self.assertEqual(context, 'javascript_context')
        
        # Test URL context
        url_field = {'type': 'url', 'name': 'link', 'id': 'href'}
        context = self.xss_scanner._determine_input_context(url_field)
        self.assertEqual(context, 'url_context')
        
        # Test CSS context
        css_field = {'type': 'text', 'name': 'style', 'id': 'css'}
        context = self.xss_scanner._determine_input_context(css_field)
        self.assertEqual(context, 'css_context')
    
    def test_payload_validation(self):
        """Test payload validation for different contexts"""
        # Valid JavaScript payload
        js_payload = '<script>alert("XSS")</script>'
        self.assertTrue(self.xss_scanner._validate_payload(js_payload, 'javascript_context'))
        
        # Valid CSS payload
        css_payload = 'expression(alert("XSS"))'
        self.assertTrue(self.xss_scanner._validate_payload(css_payload, 'css_context'))
        
        # Invalid payload for context
        invalid_payload = 'just text'
        self.assertFalse(self.xss_scanner._validate_payload(invalid_payload, 'javascript_context'))
        
        # Payload too long
        long_payload = 'x' * 1001
        self.assertFalse(self.xss_scanner._validate_payload(long_payload, 'html_context'))
    
    def test_encoded_variants_generation(self):
        """Test encoded payload variants generation"""
        original_payload = '<script>alert("XSS")</script>'
        variants = self.xss_scanner._generate_encoded_variants(original_payload)
        
        self.assertIsInstance(variants, list)
        self.assertGreater(len(variants), 0)
        
        # Check for HTML entity encoding
        html_encoded = '&lt;script&gt;alert("XSS")&lt;/script&gt;'
        self.assertIn(html_encoded, variants)
        
        # Check for URL encoding
        url_encoded = '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E'
        self.assertIn(url_encoded, variants)
    
    def test_severity_determination(self):
        """Test severity determination for different payloads"""
        # Critical severity
        critical_payload = '<script>alert("XSS")</script>'
        severity = self.xss_scanner._determine_severity(critical_payload, 'html_context')
        self.assertEqual(severity, 'Critical')
        
        # High severity
        high_payload = 'javascript:alert("XSS")'
        severity = self.xss_scanner._determine_severity(high_payload, 'url_context')
        self.assertEqual(severity, 'High')
        
        # Medium severity
        medium_payload = 'onmouseover="alert(\'XSS\')"'
        severity = self.xss_scanner._determine_severity(medium_payload, 'html_context')
        self.assertEqual(severity, 'Medium')
        
        # Low severity
        low_payload = 'just text'
        severity = self.xss_scanner._determine_severity(low_payload, 'html_context')
        self.assertEqual(severity, 'Low')
    
    def test_xss_vulnerability_detection(self):
        """Test XSS vulnerability detection"""
        # Mock response with XSS vulnerability
        mock_response = Mock()
        mock_response.text = '<html><body><script>alert("XSS")</script></body></html>'
        mock_response.headers = {}
        
        payload = '<script>alert("XSS")</script>'
        context = 'html_context'
        
        # Test vulnerability detection
        is_vulnerable = self.xss_scanner._check_xss_vulnerability(mock_response, payload, context)
        self.assertTrue(is_vulnerable)
    
    def test_javascript_context_vulnerability(self):
        """Test JavaScript context vulnerability detection"""
        response_text = 'var userInput = "alert(\'XSS\')"; eval(userInput);'
        payload = 'alert("XSS")'
        
        is_vulnerable = self.xss_scanner._check_javascript_context_vulnerability(response_text, payload)
        self.assertTrue(is_vulnerable)
    
    def test_css_context_vulnerability(self):
        """Test CSS context vulnerability detection"""
        response_text = 'background: expression(alert("XSS"));'
        payload = 'expression(alert("XSS"))'
        
        is_vulnerable = self.xss_scanner._check_css_context_vulnerability(response_text, payload)
        self.assertTrue(is_vulnerable)
    
    def test_xml_context_vulnerability(self):
        """Test XML context vulnerability detection"""
        response_text = '<![CDATA[<script>alert("XSS")</script>]]>'
        payload = '<script>alert("XSS")</script>'
        
        is_vulnerable = self.xss_scanner._check_xml_context_vulnerability(response_text, payload)
        self.assertTrue(is_vulnerable)
    
    def test_dom_xss_indicators(self):
        """Test DOM-based XSS indicators detection"""
        response_text = 'document.write(userInput);'
        payload = 'alert("XSS")'
        
        has_indicators = self.xss_scanner._check_dom_xss_indicators(response_text, payload)
        self.assertTrue(has_indicators)
    
    def test_stored_xss_indicators(self):
        """Test stored XSS indicators detection"""
        response_text = '<script>alert("XSS")</script>'
        payload = '<script>alert("XSS")</script>'
        
        has_indicators = self.xss_scanner._check_stored_xss_indicators(response_text, payload)
        self.assertTrue(has_indicators)
    
    def test_csp_bypass_opportunities(self):
        """Test CSP bypass opportunities detection"""
        mock_response = Mock()
        mock_response.headers = {'Content-Security-Policy': "script-src 'unsafe-inline'"}
        mock_response.text = ''
        
        has_bypass = self.xss_scanner._check_csp_bypass_opportunities(mock_response.headers, mock_response.text)
        self.assertTrue(has_bypass)
    
    def test_waf_bypass_evidence(self):
        """Test WAF bypass evidence detection"""
        mock_response = Mock()
        mock_response.headers = {'X-WAF-Instance': 'cloudflare'}
        mock_response.text = ''
        
        has_bypass = self.xss_scanner._check_waf_bypass_evidence(mock_response.headers, mock_response.text)
        self.assertTrue(has_bypass)
    
    def test_encoding_bypass_evidence(self):
        """Test encoding bypass evidence detection"""
        response_text = '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;'
        payload = '<script>alert("XSS")</script>'
        
        has_bypass = self.xss_scanner._check_encoding_bypass_evidence(response_text, payload)
        self.assertTrue(has_bypass)
    
    def test_evidence_generation(self):
        """Test evidence generation for vulnerabilities"""
        mock_response = Mock()
        mock_response.text = '<script>alert("XSS")</script>'
        mock_response.headers = {}
        
        payload = '<script>alert("XSS")</script>'
        evidence = self.xss_scanner._generate_evidence(mock_response, payload)
        
        self.assertIsInstance(evidence, str)
        self.assertGreater(len(evidence), 0)
        self.assertIn('Payload was reflected', evidence)
    
    def test_payload_category_detection(self):
        """Test payload category detection"""
        basic_payload = '<script>alert("XSS")</script>'
        category = self.xss_scanner._get_payload_category(basic_payload)
        self.assertEqual(category, 'basic')
        
        polyglot_payload = 'jaVasCript:/*-/*`/*\`/*`/*`/*`/alert("XSS")//`//`//`//`//`//`/'
        category = self.xss_scanner._get_payload_category(polyglot_payload)
        self.assertEqual(category, 'polyglot')
    
    def test_advanced_context_payloads(self):
        """Test advanced context payload generation"""
        context = 'html_context'
        input_field = {'type': 'text', 'name': 'content'}
        
        payloads = self.xss_scanner._get_advanced_context_payloads(context, input_field)
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        
        # Check for context-specific payloads
        html_payloads = self.xss_scanner.context_payloads['html_context']
        for payload in html_payloads[:3]:  # Check first 3 payloads
            self.assertIn(payload, payloads)
    
    @patch('requests.Session.get')
    def test_form_testing(self, mock_get):
        """Test form testing functionality"""
        # Mock response
        mock_response = Mock()
        mock_response.text = '<script>alert("XSS")</script>'
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_get.return_value = mock_response
        
        # Test form
        test_form = {
            'url': 'http://test.example.com/form',
            'action': 'http://test.example.com/submit',
            'method': 'POST',
            'inputs': [
                {'type': 'text', 'name': 'content'},
                {'type': 'email', 'name': 'email'},
                {'type': 'password', 'name': 'password'}
            ]
        }
        
        self.mock_scanner.forms = [test_form]
        
        # Test form
        vulnerabilities = self.xss_scanner.test_form(test_form)
        
        self.assertIsInstance(vulnerabilities, list)
        # Should find vulnerabilities due to mocked response
    
    @patch('requests.Session.get')
    def test_url_parameter_testing(self, mock_get):
        """Test URL parameter testing functionality"""
        # Mock response
        mock_response = Mock()
        mock_response.text = 'javascript:alert("XSS")'
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_get.return_value = mock_response
        
        # Test URL with parameters
        test_url = 'http://test.example.com/page?param=value&search=test'
        
        # Test URL parameter
        vulnerabilities = self.xss_scanner.test_url_parameter(test_url)
        
        self.assertIsInstance(vulnerabilities, list)
        # Should find vulnerabilities due to mocked response
    
    def test_comprehensive_report_generation(self):
        """Test comprehensive report generation"""
        # Add some test vulnerabilities
        test_vulnerability = {
            'type': 'XSS',
            'subtype': 'Reflected',
            'severity': 'High',
            'context': 'html_context',
            'payload': '<script>alert("XSS")</script>',
            'evidence': 'Payload reflected in response'
        }
        
        self.mock_scanner.vulnerabilities.append(test_vulnerability)
        
        # Test report generation
        self.xss_scanner._generate_xss_report(1)
        # Should not raise any exceptions
    
    def test_scanner_initialization(self):
        """Test scanner initialization with all required attributes"""
        self.assertEqual(self.xss_scanner.target_url, "http://test.example.com")
        self.assertEqual(self.xss_scanner.timeout, 10)
        self.assertTrue(self.xss_scanner.verbose)
        self.assertEqual(self.xss_scanner.max_threads, 5)
        self.assertIsInstance(self.xss_scanner.vulnerabilities, list)
        self.assertIsInstance(self.xss_scanner.forms, list)
        self.assertIsInstance(self.xss_scanner.discovered_urls, list)

def run_xss_scanner_demo():
    """Demonstrate the enhanced XSS scanner capabilities"""
    print("=== Advanced XSS Scanner Demo ===")
    
    # Create mock scanner instance
    mock_scanner = Mock()
    mock_scanner.target_url = "http://demo.example.com"
    mock_scanner.session = requests.Session()
    mock_scanner.timeout = 10
    mock_scanner.verbose = True
    mock_scanner.max_threads = 5
    mock_scanner.vulnerabilities = []
    mock_scanner.forms = []
    mock_scanner.discovered_urls = []
    
    # Initialize XSS scanner
    xss_scanner = XSSScanner(mock_scanner)
    
    print(f"✓ Scanner initialized successfully")
    print(f"✓ Payload categories: {len(xss_scanner.xss_payloads)}")
    print(f"✓ Detection patterns: {sum(len(patterns) for patterns in xss_scanner.xss_patterns.values())}")
    print(f"✓ Context payloads: {len(xss_scanner.context_payloads)}")
    
    # Demonstrate payload categories
    print("\n=== Payload Categories ===")
    for category, payloads in xss_scanner.xss_payloads.items():
        print(f"  {category}: {len(payloads)} payloads")
    
    # Demonstrate detection patterns
    print("\n=== Detection Patterns ===")
    for category, patterns in xss_scanner.xss_patterns.items():
        print(f"  {category}: {len(patterns)} patterns")
    
    # Demonstrate context payloads
    print("\n=== Context Payloads ===")
    for context, payloads in xss_scanner.context_payloads.items():
        print(f"  {context}: {len(payloads)} payloads")
    
    print("\n=== Demo Complete ===")

if __name__ == "__main__":
    # Run demo
    run_xss_scanner_demo()
    
    # Run tests
    unittest.main(verbosity=2) 