#!/usr/bin/env python3

"""
Advanced CSRF Scanner Test Suite

This module provides comprehensive testing capabilities for the enhanced CSRF scanner,
demonstrating various vulnerability detection techniques and protection mechanism analysis.
"""

import unittest
import requests
from unittest.mock import Mock, patch
from src.tools.webscan.vulnerabilities.csrf import CSRFScanner

class TestCSRFScanner(unittest.TestCase):
    """Comprehensive test suite for the Advanced CSRF Scanner"""
    
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
        
        # Initialize CSRF scanner
        self.csrf_scanner = CSRFScanner(self.mock_scanner)
    
    def test_csrf_token_patterns_initialization(self):
        """Test CSRF token patterns initialization"""
        self.assertIsNotNone(self.csrf_scanner.csrf_token_patterns)
        self.assertIn('field_names', self.csrf_scanner.csrf_token_patterns)
        self.assertIn('cookie_names', self.csrf_scanner.csrf_token_patterns)
        self.assertIn('header_names', self.csrf_scanner.csrf_token_patterns)
        self.assertIn('parameter_names', self.csrf_scanner.csrf_token_patterns)
    
    def test_csrf_protection_mechanisms_initialization(self):
        """Test CSRF protection mechanisms initialization"""
        self.assertIsNotNone(self.csrf_scanner.csrf_protection_mechanisms)
        self.assertIn('token_based', self.csrf_scanner.csrf_protection_mechanisms)
        self.assertIn('header_based', self.csrf_scanner.csrf_protection_mechanisms)
        self.assertIn('cookie_based', self.csrf_scanner.csrf_protection_mechanisms)
        self.assertIn('samesite_cookie', self.csrf_scanner.csrf_protection_mechanisms)
        self.assertIn('referer_validation', self.csrf_scanner.csrf_protection_mechanisms)
        self.assertIn('origin_validation', self.csrf_scanner.csrf_protection_mechanisms)
        self.assertIn('double_submit_cookie', self.csrf_scanner.csrf_protection_mechanisms)
        self.assertIn('synchronizer_token', self.csrf_scanner.csrf_protection_mechanisms)
    
    def test_csrf_attack_vectors_initialization(self):
        """Test CSRF attack vectors initialization"""
        self.assertIsNotNone(self.csrf_scanner.csrf_attack_vectors)
        self.assertIn('form_submission', self.csrf_scanner.csrf_attack_vectors)
        self.assertIn('ajax_request', self.csrf_scanner.csrf_attack_vectors)
        self.assertIn('api_endpoint', self.csrf_scanner.csrf_attack_vectors)
        self.assertIn('file_upload', self.csrf_scanner.csrf_attack_vectors)
        self.assertIn('state_change', self.csrf_scanner.csrf_attack_vectors)
        self.assertIn('privileged_action', self.csrf_scanner.csrf_attack_vectors)
    
    def test_csrf_vulnerability_patterns_initialization(self):
        """Test CSRF vulnerability patterns initialization"""
        self.assertIsNotNone(self.csrf_scanner.csrf_vulnerability_patterns)
        self.assertIn('missing_token', self.csrf_scanner.csrf_vulnerability_patterns)
        self.assertIn('weak_token', self.csrf_scanner.csrf_vulnerability_patterns)
        self.assertIn('predictable_token', self.csrf_scanner.csrf_vulnerability_patterns)
        self.assertIn('static_token', self.csrf_scanner.csrf_vulnerability_patterns)
    
    def test_login_form_detection(self):
        """Test login form detection"""
        # Login form with password field
        login_form = {
            'url': 'http://test.example.com/login',
            'action': '/login',
            'method': 'POST',
            'inputs': [
                {'name': 'username', 'type': 'text'},
                {'name': 'password', 'type': 'password'}
            ]
        }
        
        self.assertTrue(self.csrf_scanner._is_login_form(login_form))
        
        # Non-login form
        normal_form = {
            'url': 'http://test.example.com/contact',
            'action': '/contact',
            'method': 'POST',
            'inputs': [
                {'name': 'name', 'type': 'text'},
                {'name': 'email', 'type': 'email'},
                {'name': 'message', 'type': 'textarea'}
            ]
        }
        
        self.assertFalse(self.csrf_scanner._is_login_form(normal_form))
    
    def test_weak_token_detection(self):
        """Test weak token detection"""
        # Weak numeric token
        self.assertTrue(self.csrf_scanner._is_weak_token('123456'))
        
        # Weak short alphanumeric token
        self.assertTrue(self.csrf_scanner._is_weak_token('abc12345'))
        
        # Weak static token
        self.assertTrue(self.csrf_scanner._is_weak_token('test'))
        
        # Strong token
        self.assertFalse(self.csrf_scanner._is_weak_token('a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'))
        
        # Empty token
        self.assertTrue(self.csrf_scanner._is_weak_token(''))
    
    def test_token_protection_analysis(self):
        """Test token protection analysis"""
        # Form with CSRF token
        form_with_token = {
            'url': 'http://test.example.com/form',
            'action': '/submit',
            'method': 'POST',
            'inputs': [
                {'name': 'csrf_token', 'value': 'abc123', 'type': 'hidden'},
                {'name': 'name', 'type': 'text'}
            ]
        }
        
        analysis = self.csrf_scanner._analyze_token_protection(form_with_token)
        
        self.assertTrue(analysis['has_token'])
        self.assertIsInstance(analysis['token_fields'], list)
        self.assertEqual(len(analysis['token_fields']), 1)
    
    def test_header_protection_analysis(self):
        """Test header protection analysis"""
        # Mock response with security headers
        mock_response = Mock()
        mock_response.headers = {
            'X-CSRF-Token': 'abc123',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'"
        }
        
        form = {'url': 'http://test.example.com/form'}
        
        with patch.object(self.csrf_scanner.session, 'get', return_value=mock_response):
            analysis = self.csrf_scanner._analyze_header_protection(form)
            
            self.assertTrue(analysis['has_protection'])
            self.assertIsInstance(analysis['protection_headers'], list)
            self.assertIsInstance(analysis['security_headers'], list)
    
    def test_cookie_protection_analysis(self):
        """Test cookie protection analysis"""
        # Mock response with secure cookies
        mock_response = Mock()
        mock_cookie = Mock()
        mock_cookie.name = 'session'
        mock_cookie.value = 'abc123'
        mock_cookie.secure = True
        mock_cookie.has_nonstandard_attr = lambda attr: attr == 'HttpOnly'
        mock_cookie.samesite = 'Strict'
        
        mock_response.cookies = [mock_cookie]
        
        form = {'url': 'http://test.example.com/form'}
        
        with patch.object(self.csrf_scanner.session, 'get', return_value=mock_response):
            analysis = self.csrf_scanner._analyze_cookie_protection(form)
            
            self.assertTrue(analysis['has_protection'])
            self.assertIsInstance(analysis['secure_cookies'], list)
            self.assertIsInstance(analysis['httponly_cookies'], list)
            self.assertIsInstance(analysis['samesite_cookies'], list)
    
    def test_samesite_protection_analysis(self):
        """Test SameSite protection analysis"""
        # Mock response with SameSite cookies
        mock_response = Mock()
        mock_cookie = Mock()
        mock_cookie.name = 'session'
        mock_cookie.samesite = 'Strict'
        
        mock_response.cookies = [mock_cookie]
        
        form = {'url': 'http://test.example.com/form'}
        
        with patch.object(self.csrf_scanner.session, 'get', return_value=mock_response):
            analysis = self.csrf_scanner._analyze_samesite_protection(form)
            
            self.assertTrue(analysis['has_protection'])
            self.assertIn('session', analysis['strict_cookies'])
    
    def test_comprehensive_csrf_protection_analysis(self):
        """Test comprehensive CSRF protection analysis"""
        # Form with weak CSRF token
        form_with_weak_token = {
            'url': 'http://test.example.com/form',
            'action': '/submit',
            'method': 'POST',
            'inputs': [
                {'name': 'csrf_token', 'value': '123456', 'type': 'hidden'},
                {'name': 'name', 'type': 'text'}
            ]
        }
        
        # Mock response for header and cookie analysis
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.cookies = []
        
        with patch.object(self.csrf_scanner.session, 'get', return_value=mock_response):
            analysis = self.csrf_scanner._analyze_csrf_protection(form_with_weak_token)
            
            self.assertTrue(analysis['has_protection'])
            self.assertTrue(analysis['has_weak_protection'])
            self.assertIn('token_based', analysis['protection_mechanisms'])
            self.assertIn('Weak or predictable CSRF token', analysis['vulnerability_details'])
    
    def test_csrf_severity_determination(self):
        """Test CSRF severity determination"""
        # Critical operation (password change)
        critical_form = {
            'url': 'http://test.example.com/password/change',
            'action': '/password/change',
            'method': 'POST'
        }
        
        analysis = {'has_protection': False}
        severity = self.csrf_scanner._determine_csrf_severity(critical_form, analysis)
        self.assertEqual(severity, 'Critical')
        
        # High severity operation (POST request)
        high_form = {
            'url': 'http://test.example.com/form',
            'action': '/submit',
            'method': 'POST'
        }
        
        severity = self.csrf_scanner._determine_csrf_severity(high_form, analysis)
        self.assertEqual(severity, 'High')
        
        # Medium severity operation (GET request)
        medium_form = {
            'url': 'http://test.example.com/form',
            'action': '/submit',
            'method': 'GET'
        }
        
        severity = self.csrf_scanner._determine_csrf_severity(medium_form, analysis)
        self.assertEqual(severity, 'Medium')
    
    def test_attack_vector_determination(self):
        """Test attack vector determination"""
        # POST request
        post_form = {'method': 'POST'}
        attack_vector = self.csrf_scanner._determine_attack_vector(post_form)
        self.assertEqual(attack_vector, 'Form submission via POST request')
        
        # GET request
        get_form = {'method': 'GET'}
        attack_vector = self.csrf_scanner._determine_attack_vector(get_form)
        self.assertEqual(attack_vector, 'Form submission via GET request')
        
        # PUT request
        put_form = {'method': 'PUT'}
        attack_vector = self.csrf_scanner._determine_attack_vector(put_form)
        self.assertEqual(attack_vector, 'Form submission via PUT request')
        
        # DELETE request
        delete_form = {'method': 'DELETE'}
        attack_vector = self.csrf_scanner._determine_attack_vector(delete_form)
        self.assertEqual(attack_vector, 'Form submission via DELETE request')
    
    def test_csrf_recommendations_generation(self):
        """Test CSRF recommendations generation"""
        # Form without protection
        form = {'url': 'http://test.example.com/form'}
        analysis = {'has_protection': False, 'has_weak_protection': False}
        
        recommendations = self.csrf_scanner._generate_csrf_recommendations(form, analysis)
        
        self.assertIsInstance(recommendations, list)
        self.assertIn('Implement CSRF tokens in all forms', recommendations)
        self.assertIn('Use secure, random tokens for each session', recommendations)
        
        # Form with weak protection
        analysis = {'has_protection': True, 'has_weak_protection': True}
        
        recommendations = self.csrf_scanner._generate_csrf_recommendations(form, analysis)
        
        self.assertIn('Strengthen existing CSRF protection', recommendations)
        self.assertIn('Use cryptographically secure random tokens', recommendations)
    
    def test_csrf_vulnerability_creation(self):
        """Test CSRF vulnerability creation"""
        form = {
            'url': 'http://test.example.com/form',
            'action': '/submit',
            'method': 'POST',
            'inputs': [{'name': 'name', 'type': 'text'}]
        }
        
        analysis = {
            'has_protection': False,
            'has_weak_protection': False,
            'protection_mechanisms': [],
            'vulnerability_details': []
        }
        
        vulnerability = self.csrf_scanner._create_csrf_vulnerability(form, analysis)
        
        self.assertEqual(vulnerability['type'], 'CSRF')
        self.assertEqual(vulnerability['subtype'], 'Missing Protection')
        self.assertEqual(vulnerability['url'], form['url'])
        self.assertEqual(vulnerability['method'], 'POST')
        self.assertIn('recommendations', vulnerability)
        self.assertIn('attack_vector', vulnerability)
    
    def test_weak_csrf_vulnerability_creation(self):
        """Test weak CSRF vulnerability creation"""
        form = {
            'url': 'http://test.example.com/form',
            'action': '/submit',
            'method': 'POST',
            'inputs': [{'name': 'name', 'type': 'text'}]
        }
        
        analysis = {
            'has_protection': True,
            'has_weak_protection': True,
            'protection_mechanisms': ['token_based'],
            'vulnerability_details': ['Weak or predictable CSRF token']
        }
        
        vulnerability = self.csrf_scanner._create_weak_csrf_vulnerability(form, analysis)
        
        self.assertEqual(vulnerability['type'], 'CSRF')
        self.assertEqual(vulnerability['subtype'], 'Weak Protection')
        self.assertEqual(vulnerability['severity'], 'Medium')
        self.assertIn('recommendations', vulnerability)
        self.assertIn('attack_vector', vulnerability)
    
    def test_comprehensive_form_testing(self):
        """Test comprehensive form testing"""
        # Form without CSRF protection
        form_without_protection = {
            'url': 'http://test.example.com/form',
            'action': '/submit',
            'method': 'POST',
            'inputs': [{'name': 'name', 'type': 'text'}]
        }
        
        # Mock response for analysis
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.cookies = []
        
        with patch.object(self.csrf_scanner.session, 'get', return_value=mock_response):
            vulnerability = self.csrf_scanner.test_form(form_without_protection)
            
            self.assertIsNotNone(vulnerability)
            self.assertEqual(vulnerability['type'], 'CSRF')
            self.assertEqual(vulnerability['subtype'], 'Missing Protection')
    
    def test_vulnerability_count_calculation(self):
        """Test vulnerability count calculation"""
        # Add some test vulnerabilities
        test_vulnerabilities = [
            {'type': 'CSRF', 'severity': 'Critical'},
            {'type': 'CSRF', 'severity': 'High'},
            {'type': 'CSRF', 'severity': 'Medium'},
            {'type': 'XSS', 'severity': 'High'}  # Different type
        ]
        
        self.mock_scanner.vulnerabilities = test_vulnerabilities
        
        # Test count calculation
        initial_count = 0
        csrf_count = self.csrf_scanner._get_csrf_vulnerability_count(initial_count)
        
        self.assertEqual(csrf_count, 3)  # Should count only CSRF vulnerabilities
    
    def test_comprehensive_report_generation(self):
        """Test comprehensive report generation"""
        # Add some test vulnerabilities
        test_vulnerabilities = [
            {
                'type': 'CSRF',
                'subtype': 'Missing Protection',
                'severity': 'Critical',
                'protection_analysis': {
                    'protection_mechanisms': [],
                    'has_protection': False
                }
            },
            {
                'type': 'CSRF',
                'subtype': 'Weak Protection',
                'severity': 'Medium',
                'protection_analysis': {
                    'protection_mechanisms': ['token_based'],
                    'has_protection': True
                }
            }
        ]
        
        self.mock_scanner.vulnerabilities = test_vulnerabilities
        
        # Test report generation
        self.csrf_scanner._generate_csrf_report(0)
        # Should not raise any exceptions
    
    def test_scanner_initialization(self):
        """Test scanner initialization with all required attributes"""
        self.assertEqual(self.csrf_scanner.target_url, "http://test.example.com")
        self.assertEqual(self.csrf_scanner.timeout, 10)
        self.assertTrue(self.csrf_scanner.verbose)
        self.assertEqual(self.csrf_scanner.max_threads, 5)
        self.assertIsInstance(self.csrf_scanner.vulnerabilities, list)
        self.assertIsInstance(self.csrf_scanner.forms, list)

def run_csrf_scanner_demo():
    """Demonstrate the enhanced CSRF scanner capabilities"""
    print("=== Advanced CSRF Scanner Demo ===")
    
    # Create mock scanner instance
    mock_scanner = Mock()
    mock_scanner.target_url = "http://demo.example.com"
    mock_scanner.session = requests.Session()
    mock_scanner.timeout = 10
    mock_scanner.verbose = True
    mock_scanner.max_threads = 5
    mock_scanner.vulnerabilities = []
    mock_scanner.forms = []
    
    # Initialize CSRF scanner
    csrf_scanner = CSRFScanner(mock_scanner)
    
    print(f"✓ Scanner initialized successfully")
    print(f"✓ CSRF token pattern categories: {len(csrf_scanner.csrf_token_patterns)}")
    print(f"✓ Protection mechanisms: {len(csrf_scanner.csrf_protection_mechanisms)}")
    print(f"✓ Attack vectors: {len(csrf_scanner.csrf_attack_vectors)}")
    print(f"✓ Vulnerability patterns: {len(csrf_scanner.csrf_vulnerability_patterns)}")
    
    # Demonstrate CSRF token patterns
    print("\n=== CSRF Token Patterns ===")
    for category, patterns in csrf_scanner.csrf_token_patterns.items():
        print(f"  {category}: {len(patterns)} patterns")
    
    # Demonstrate protection mechanisms
    print("\n=== Protection Mechanisms ===")
    for mechanism, details in csrf_scanner.csrf_protection_mechanisms.items():
        print(f"  {mechanism}: {details['description']} ({details['severity']})")
    
    # Demonstrate attack vectors
    print("\n=== Attack Vectors ===")
    for vector, details in csrf_scanner.csrf_attack_vectors.items():
        print(f"  {vector}: {details['description']} ({details['severity']})")
    
    # Demonstrate vulnerability patterns
    print("\n=== Vulnerability Patterns ===")
    for pattern_type, patterns in csrf_scanner.csrf_vulnerability_patterns.items():
        print(f"  {pattern_type}: {len(patterns)} patterns")
    
    print("\n=== Demo Complete ===")

if __name__ == "__main__":
    # Run demo
    run_csrf_scanner_demo()
    
    # Run tests
    unittest.main(verbosity=2) 