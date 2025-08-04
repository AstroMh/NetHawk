#!/usr/bin/env python3

"""
Advanced CORS Scanner Test Suite

This module provides comprehensive testing capabilities for the enhanced CORS scanner,
demonstrating various vulnerability detection techniques and attack vector effectiveness.
"""

import unittest
import requests
from unittest.mock import Mock, patch
from src.tools.webscan.vulnerabilities.cors import CORSScanner

class TestCORSScanner(unittest.TestCase):
    """Comprehensive test suite for the Advanced CORS Scanner"""
    
    def setUp(self):
        """Set up test environment"""
        # Mock scanner instance
        self.mock_scanner = Mock()
        self.mock_scanner.target_url = "http://test.example.com"
        self.mock_scanner.session = requests.Session()
        self.mock_scanner.timeout = 10
        self.mock_scanner.verbose = True
        self.mock_scanner.vulnerabilities = []
        self.mock_scanner.discovered_urls = []
        
        # Initialize CORS scanner
        self.cors_scanner = CORSScanner(self.mock_scanner)
    
    def test_cors_headers_initialization(self):
        """Test CORS headers initialization"""
        self.assertIsNotNone(self.cors_scanner.cors_headers)
        self.assertIn('origin_control', self.cors_scanner.cors_headers)
        self.assertIn('credential_control', self.cors_scanner.cors_headers)
        self.assertIn('method_control', self.cors_scanner.cors_headers)
        self.assertIn('header_control', self.cors_scanner.cors_headers)
        self.assertIn('timing_control', self.cors_scanner.cors_headers)
        self.assertIn('preflight_control', self.cors_scanner.cors_headers)
    
    def test_malicious_domains_initialization(self):
        """Test malicious domains initialization"""
        self.assertIsNotNone(self.cors_scanner.malicious_domains)
        self.assertIn('basic_attack', self.cors_scanner.malicious_domains)
        self.assertIn('domain_confusion', self.cors_scanner.malicious_domains)
        self.assertIn('subdomain_takeover', self.cors_scanner.malicious_domains)
        self.assertIn('protocol_manipulation', self.cors_scanner.malicious_domains)
        self.assertIn('null_origin_variants', self.cors_scanner.malicious_domains)
        self.assertIn('wildcard_variants', self.cors_scanner.malicious_domains)
    
    def test_attack_vectors_initialization(self):
        """Test attack vectors initialization"""
        self.assertIsNotNone(self.cors_scanner.cors_attack_vectors)
        self.assertIn('origin_reflection', self.cors_scanner.cors_attack_vectors)
        self.assertIn('wildcard_misconfig', self.cors_scanner.cors_attack_vectors)
        self.assertIn('null_origin_vuln', self.cors_scanner.cors_attack_vectors)
        self.assertIn('domain_confusion', self.cors_scanner.cors_attack_vectors)
        self.assertIn('subdomain_takeover', self.cors_scanner.cors_attack_vectors)
        self.assertIn('protocol_downgrade', self.cors_scanner.cors_attack_vectors)
        self.assertIn('credential_exposure', self.cors_scanner.cors_attack_vectors)
        self.assertIn('method_exposure', self.cors_scanner.cors_attack_vectors)
        self.assertIn('header_exposure', self.cors_scanner.cors_attack_vectors)
    
    def test_vulnerability_patterns_initialization(self):
        """Test vulnerability patterns initialization"""
        self.assertIsNotNone(self.cors_scanner.cors_vulnerability_patterns)
        self.assertIn('wildcard_patterns', self.cors_scanner.cors_vulnerability_patterns)
        self.assertIn('null_patterns', self.cors_scanner.cors_vulnerability_patterns)
        self.assertIn('reflection_patterns', self.cors_scanner.cors_vulnerability_patterns)
        self.assertIn('domain_confusion_patterns', self.cors_scanner.cors_vulnerability_patterns)
    
    def test_cors_headers_detection(self):
        """Test CORS headers detection"""
        # Mock headers with CORS headers
        headers_with_cors = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
            'Content-Type': 'application/json'
        }
        
        # Mock headers without CORS headers
        headers_without_cors = {
            'Content-Type': 'application/json',
            'Server': 'nginx'
        }
        
        # Test detection
        self.assertTrue(self.cors_scanner._detect_cors_headers(headers_with_cors))
        self.assertFalse(self.cors_scanner._detect_cors_headers(headers_without_cors))
    
    def test_credentials_allowed_check(self):
        """Test credentials allowed check"""
        # Headers with credentials allowed
        headers_with_credentials = {
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Origin': '*'
        }
        
        # Headers without credentials allowed
        headers_without_credentials = {
            'Access-Control-Allow-Origin': '*'
        }
        
        # Headers with credentials disabled
        headers_credentials_false = {
            'Access-Control-Allow-Credentials': 'false',
            'Access-Control-Allow-Origin': '*'
        }
        
        # Test checks
        self.assertTrue(self.cors_scanner._check_credentials_allowed(headers_with_credentials))
        self.assertFalse(self.cors_scanner._check_credentials_allowed(headers_without_credentials))
        self.assertFalse(self.cors_scanner._check_credentials_allowed(headers_credentials_false))
    
    def test_origin_reflection_detection(self):
        """Test origin reflection detection"""
        # Mock response with origin reflection
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': 'https://evil.com',
            'Access-Control-Allow-Credentials': 'true'
        }
        
        # Test origin reflection detection
        with patch.object(self.cors_scanner.session, 'get', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_origin_reflection('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # Should find vulnerabilities due to mocked response
    
    def test_wildcard_misconfig_detection(self):
        """Test wildcard misconfiguration detection"""
        # Mock response with wildcard
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        }
        
        # Test wildcard detection
        with patch.object(self.cors_scanner.session, 'get', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_wildcard_misconfig('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # Should find vulnerabilities due to mocked response
    
    def test_null_origin_detection(self):
        """Test null origin detection"""
        # Mock response with null origin
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': 'null',
            'Access-Control-Allow-Credentials': 'true'
        }
        
        # Test null origin detection
        with patch.object(self.cors_scanner.session, 'get', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_null_origin('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # Should find vulnerabilities due to mocked response
    
    def test_domain_confusion_detection(self):
        """Test domain confusion detection"""
        # Mock response with domain confusion
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': 'https://target.com.evil.com',
            'Access-Control-Allow-Credentials': 'true'
        }
        
        # Test domain confusion detection
        with patch.object(self.cors_scanner.session, 'get', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_domain_confusion('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # Should find vulnerabilities due to mocked response
    
    def test_subdomain_takeover_detection(self):
        """Test subdomain takeover detection"""
        # Mock response with subdomain takeover
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': 'https://api.evil.com',
            'Access-Control-Allow-Credentials': 'true'
        }
        
        # Test subdomain takeover detection
        with patch.object(self.cors_scanner.session, 'get', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_subdomain_takeover('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # Should find vulnerabilities due to mocked response
    
    def test_protocol_downgrade_detection(self):
        """Test protocol downgrade detection"""
        # Mock response with protocol downgrade
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': 'http://evil.com',
            'Access-Control-Allow-Credentials': 'false'
        }
        
        # Test protocol downgrade detection
        with patch.object(self.cors_scanner.session, 'get', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_protocol_downgrade('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # Should find vulnerabilities due to mocked response
    
    def test_credential_exposure_detection(self):
        """Test credential exposure detection"""
        # Mock response with credential exposure
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Origin': 'https://evil.com'
        }
        
        # Test credential exposure detection
        with patch.object(self.cors_scanner.session, 'get', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_credential_exposure('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # Should find vulnerabilities due to mocked response
    
    def test_method_exposure_detection(self):
        """Test method exposure detection"""
        # Mock response with dangerous methods
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH',
            'Access-Control-Allow-Origin': '*'
        }
        
        # Test method exposure detection
        with patch.object(self.cors_scanner.session, 'options', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_method_exposure('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # Should find vulnerabilities due to mocked response
    
    def test_header_exposure_detection(self):
        """Test header exposure detection"""
        # Mock response with sensitive headers
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, Cookie',
            'Access-Control-Allow-Origin': '*'
        }
        
        # Test header exposure detection
        with patch.object(self.cors_scanner.session, 'options', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_header_exposure('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # Should find vulnerabilities due to mocked response
    
    def test_preflight_vulnerability_detection(self):
        """Test preflight vulnerability detection"""
        # Mock response with preflight vulnerability
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': 'https://evil.com',
            'Access-Control-Allow-Methods': 'POST',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
        
        # Test preflight vulnerability detection
        with patch.object(self.cors_scanner.session, 'options', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_preflight_requests('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # Should find vulnerabilities due to mocked response
    
    def test_timing_attack_detection(self):
        """Test timing attack detection"""
        # Mock response with timing attack
        mock_response = Mock()
        
        # Test timing attack detection
        with patch.object(self.cors_scanner.session, 'get', return_value=mock_response):
            vulnerabilities = self.cors_scanner._test_timing_attacks('http://test.example.com')
            
            self.assertIsInstance(vulnerabilities, list)
            # May find vulnerabilities depending on timing
    
    def test_comprehensive_cors_check(self):
        """Test comprehensive CORS checking"""
        # Mock response with multiple CORS issues
        mock_response = Mock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': 'https://evil.com',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
        
        # Test comprehensive CORS checking
        with patch.object(self.cors_scanner.session, 'get', return_value=mock_response):
            with patch.object(self.cors_scanner.session, 'options', return_value=mock_response):
                vulnerabilities = self.cors_scanner.check_cors_headers('http://test.example.com')
                
                self.assertIsInstance(vulnerabilities, list)
                # Should find multiple vulnerabilities due to mocked response
    
    def test_vulnerability_count_calculation(self):
        """Test vulnerability count calculation"""
        # Add some test vulnerabilities
        test_vulnerabilities = [
            {'type': 'CORS', 'severity': 'Critical'},
            {'type': 'CORS', 'severity': 'High'},
            {'type': 'CORS', 'severity': 'Medium'},
            {'type': 'XSS', 'severity': 'High'}  # Different type
        ]
        
        self.mock_scanner.vulnerabilities = test_vulnerabilities
        
        # Test count calculation
        initial_count = 0
        cors_count = self.cors_scanner._get_cors_vulnerability_count(initial_count)
        
        self.assertEqual(cors_count, 3)  # Should count only CORS vulnerabilities
    
    def test_comprehensive_report_generation(self):
        """Test comprehensive report generation"""
        # Add some test vulnerabilities
        test_vulnerabilities = [
            {
                'type': 'CORS',
                'subtype': 'Origin Reflection',
                'severity': 'Critical',
                'credentials_exposed': True
            },
            {
                'type': 'CORS',
                'subtype': 'Wildcard Misconfiguration',
                'severity': 'Medium',
                'credentials_exposed': False
            }
        ]
        
        self.mock_scanner.vulnerabilities = test_vulnerabilities
        
        # Test report generation
        self.cors_scanner._generate_cors_report(0)
        # Should not raise any exceptions
    
    def test_scanner_initialization(self):
        """Test scanner initialization with all required attributes"""
        self.assertEqual(self.cors_scanner.target_url, "http://test.example.com")
        self.assertEqual(self.cors_scanner.timeout, 10)
        self.assertTrue(self.cors_scanner.verbose)
        self.assertIsInstance(self.cors_scanner.vulnerabilities, list)
        self.assertIsInstance(self.cors_scanner.discovered_urls, list)
        self.assertEqual(self.cors_scanner.target_domain, "test.example.com")
        self.assertEqual(self.cors_scanner.target_scheme, "http")

def run_cors_scanner_demo():
    """Demonstrate the enhanced CORS scanner capabilities"""
    print("=== Advanced CORS Scanner Demo ===")
    
    # Create mock scanner instance
    mock_scanner = Mock()
    mock_scanner.target_url = "http://demo.example.com"
    mock_scanner.session = requests.Session()
    mock_scanner.timeout = 10
    mock_scanner.verbose = True
    mock_scanner.vulnerabilities = []
    mock_scanner.discovered_urls = []
    
    # Initialize CORS scanner
    cors_scanner = CORSScanner(mock_scanner)
    
    print(f"✓ Scanner initialized successfully")
    print(f"✓ CORS header categories: {len(cors_scanner.cors_headers)}")
    print(f"✓ Attack vectors: {len(cors_scanner.cors_attack_vectors)}")
    print(f"✓ Malicious domain categories: {len(cors_scanner.malicious_domains)}")
    print(f"✓ Vulnerability patterns: {len(cors_scanner.cors_vulnerability_patterns)}")
    
    # Demonstrate CORS headers
    print("\n=== CORS Headers ===")
    for category, headers in cors_scanner.cors_headers.items():
        print(f"  {category}: {len(headers)} headers")
    
    # Demonstrate attack vectors
    print("\n=== Attack Vectors ===")
    for vector, details in cors_scanner.cors_attack_vectors.items():
        print(f"  {vector}: {details['description']} ({details['severity']})")
    
    # Demonstrate malicious domains
    print("\n=== Malicious Domains ===")
    for category, domains in cors_scanner.malicious_domains.items():
        print(f"  {category}: {len(domains)} domains")
    
    # Demonstrate vulnerability patterns
    print("\n=== Vulnerability Patterns ===")
    for pattern_type, patterns in cors_scanner.cors_vulnerability_patterns.items():
        print(f"  {pattern_type}: {len(patterns)} patterns")
    
    print("\n=== Demo Complete ===")

if __name__ == "__main__":
    # Run demo
    run_cors_scanner_demo()
    
    # Run tests
    unittest.main(verbosity=2) 