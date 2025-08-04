#!/usr/bin/env python3

"""
Test file for the Advanced Route Extractor Module

This file demonstrates the capabilities of the RouteExtractor class
and provides examples of how to use it for comprehensive route extraction.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style

# Import the RouteExtractor class
from .route_extractor import RouteExtractor


class TestRouteExtractor(unittest.TestCase):
    """Test cases for the RouteExtractor class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create a mock scanner instance
        self.mock_scanner = Mock()
        self.mock_scanner.target_url = "https://example.com"
        self.mock_scanner.timeout = 10
        self.mock_scanner.verbose = True
        self.mock_scanner.max_threads = 5
        self.mock_scanner.discovered_urls = [
            "https://example.com/page1",
            "https://example.com/page2",
            "https://example.com/api/v1/users",
            "https://example.com/admin"
        ]
        
        # Create a mock session
        self.mock_session = Mock()
        self.mock_scanner.session = self.mock_session
        
        # Initialize the route extractor
        self.route_extractor = RouteExtractor(self.mock_scanner)
    
    def test_initialization(self):
        """Test RouteExtractor initialization"""
        self.assertEqual(self.route_extractor.target_url, "https://example.com")
        self.assertEqual(self.route_extractor.timeout, 10)
        self.assertTrue(self.route_extractor.verbose)
        self.assertEqual(self.route_extractor.max_threads, 5)
        self.assertIsInstance(self.route_extractor.all_routes, set)
        self.assertIsInstance(self.route_extractor.sitemap_routes, set)
        self.assertIsInstance(self.route_extractor.robots_routes, set)
    
    def test_sitemap_locations(self):
        """Test sitemap locations configuration"""
        expected_locations = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap/sitemap.xml',
            '/sitemap/sitemap_index.xml',
            '/sitemap1.xml',
            '/sitemap2.xml',
            '/sitemap3.xml',
            '/sitemap.txt',
            '/sitemap.html',
            '/sitemap/sitemap.html',
            '/sitemap/sitemap.txt',
            '/robots.txt'
        ]
        
        self.assertEqual(len(self.route_extractor.sitemap_locations), len(expected_locations))
        for location in expected_locations:
            self.assertIn(location, self.route_extractor.sitemap_locations)
    
    def test_route_patterns(self):
        """Test route patterns configuration"""
        expected_categories = ['api_endpoints', 'admin_panels', 'auth_routes', 'dynamic_routes']
        
        for category in expected_categories:
            self.assertIn(category, self.route_extractor.route_patterns)
            self.assertIsInstance(self.route_extractor.route_patterns[category], list)
            self.assertGreater(len(self.route_extractor.route_patterns[category]), 0)
    
    def test_ignore_extensions(self):
        """Test ignore extensions configuration"""
        expected_extensions = {'.jpg', '.jpeg', '.png', '.css', '.js', '.pdf'}
        
        for ext in expected_extensions:
            self.assertIn(ext, self.route_extractor.ignore_extensions)
    
    @patch('requests.Session.get')
    def test_xml_sitemap_parsing(self, mock_get):
        """Test XML sitemap parsing"""
        # Mock XML sitemap response
        xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url>
                <loc>https://example.com/page1</loc>
                <lastmod>2023-01-01</lastmod>
            </url>
            <url>
                <loc>https://example.com/page2</loc>
                <lastmod>2023-01-02</lastmod>
            </url>
        </urlset>'''
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'application/xml'}
        mock_response.text = xml_content
        mock_get.return_value = mock_response
        
        # Test XML sitemap parsing
        self.route_extractor._parse_xml_sitemap(xml_content, "https://example.com/sitemap.xml")
        
        # Check that routes were extracted
        self.assertIn("https://example.com/page1", self.route_extractor.sitemap_routes)
        self.assertIn("https://example.com/page2", self.route_extractor.sitemap_routes)
    
    @patch('requests.Session.get')
    def test_text_sitemap_parsing(self, mock_get):
        """Test text sitemap parsing"""
        # Mock text sitemap response
        text_content = '''# Sitemap
        https://example.com/page1
        https://example.com/page2
        https://example.com/api/v1/users'''
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/plain'}
        mock_response.text = text_content
        mock_get.return_value = mock_response
        
        # Test text sitemap parsing
        self.route_extractor._parse_text_sitemap(text_content, "https://example.com/sitemap.txt")
        
        # Check that routes were extracted
        self.assertIn("https://example.com/page1", self.route_extractor.sitemap_routes)
        self.assertIn("https://example.com/page2", self.route_extractor.sitemap_routes)
        self.assertIn("https://example.com/api/v1/users", self.route_extractor.sitemap_routes)
    
    @patch('requests.Session.get')
    def test_html_sitemap_parsing(self, mock_get):
        """Test HTML sitemap parsing"""
        # Mock HTML sitemap response
        html_content = '''<html>
        <body>
            <a href="/page1">Page 1</a>
            <a href="/page2">Page 2</a>
            <a href="/api/v1/users">API Users</a>
        </body>
        </html>'''
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.text = html_content
        mock_get.return_value = mock_response
        
        # Test HTML sitemap parsing
        self.route_extractor._parse_html_sitemap(html_content, "https://example.com/sitemap.html")
        
        # Check that routes were extracted
        self.assertIn("https://example.com/page1", self.route_extractor.sitemap_routes)
        self.assertIn("https://example.com/page2", self.route_extractor.sitemap_routes)
        self.assertIn("https://example.com/api/v1/users", self.route_extractor.sitemap_routes)
    
    @patch('requests.Session.get')
    def test_robots_txt_parsing(self, mock_get):
        """Test robots.txt parsing"""
        # Mock robots.txt response
        robots_content = '''User-agent: *
        Disallow: /admin
        Disallow: /private
        Allow: /public
        Sitemap: https://example.com/sitemap.xml'''
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/plain'}
        mock_response.text = robots_content
        mock_get.return_value = mock_response
        
        # Test robots.txt parsing
        self.route_extractor._extract_robots_routes()
        
        # Check that routes were extracted
        self.assertIn("https://example.com/admin", self.route_extractor.robots_routes)
        self.assertIn("https://example.com/private", self.route_extractor.robots_routes)
        self.assertIn("https://example.com/public", self.route_extractor.robots_routes)
    
    def test_route_validation(self):
        """Test route validation"""
        # Valid routes
        valid_routes = [
            "https://example.com/page1",
            "https://example.com/api/v1/users",
            "https://example.com/admin",
            "https://example.com/login"
        ]
        
        # Invalid routes
        invalid_routes = [
            "https://otherdomain.com/page1",
            "https://example.com/style.css",
            "https://example.com/script.js",
            "https://example.com/image.jpg"
        ]
        
        for route in valid_routes:
            self.assertTrue(self.route_extractor._is_valid_route(route))
        
        for route in invalid_routes:
            self.assertFalse(self.route_extractor._is_valid_route(route))
    
    def test_route_categorization(self):
        """Test route categorization"""
        # Test static routes
        static_routes = [
            "https://example.com/about.html",
            "https://example.com/contact",
            "https://example.com/privacy"
        ]
        
        # Test dynamic routes
        dynamic_routes = [
            "https://example.com/user/123",
            "https://example.com/post/a1b2c3d4",
            "https://example.com/search?q=test"
        ]
        
        # Test API routes
        api_routes = [
            "https://example.com/api/v1/users",
            "https://example.com/rest/data",
            "https://example.com/graphql"
        ]
        
        for route in static_routes:
            self.assertTrue(self.route_extractor._is_static_route(route))
        
        for route in dynamic_routes:
            self.assertTrue(self.route_extractor._is_dynamic_route(route))
        
        for route in api_routes:
            self.assertTrue(self.route_extractor._is_api_route(route))
    
    def test_js_route_extraction(self):
        """Test JavaScript route extraction"""
        # Mock JavaScript content
        js_content = '''
        const apiEndpoints = {
            users: "/api/v1/users",
            posts: "/api/v1/posts",
            comments: "/api/v1/comments"
        };
        
        const graphqlEndpoint = "/graphql";
        const restEndpoint = "/rest/v1/data";
        '''
        
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = js_content
        
        # Test JS route extraction
        with patch.object(self.route_extractor.session, 'get', return_value=mock_response):
            self.route_extractor._parse_js_file("https://example.com/app.js")
        
        # Check that API routes were extracted
        expected_routes = [
            "https://example.com/api/v1/users",
            "https://example.com/api/v1/posts",
            "https://example.com/api/v1/comments",
            "https://example.com/graphql",
            "https://example.com/rest/v1/data"
        ]
        
        for route in expected_routes:
            self.assertIn(route, self.route_extractor.api_routes)
    
    def test_comprehensive_route_extraction(self):
        """Test comprehensive route extraction"""
        # Mock the extraction methods
        with patch.object(self.route_extractor, '_extract_sitemap_routes'), \
             patch.object(self.route_extractor, '_extract_robots_routes'), \
             patch.object(self.route_extractor, '_extract_crawled_routes'), \
             patch.object(self.route_extractor, '_extract_api_routes'), \
             patch.object(self.route_extractor, '_categorize_routes'), \
             patch.object(self.route_extractor, '_generate_route_report'):
            
            # Run comprehensive extraction
            result = self.route_extractor.run()
            
            # Check that all extraction methods were called
            self.route_extractor._extract_sitemap_routes.assert_called_once()
            self.route_extractor._extract_robots_routes.assert_called_once()
            self.route_extractor._extract_crawled_routes.assert_called_once()
            self.route_extractor._extract_api_routes.assert_called_once()
            self.route_extractor._categorize_routes.assert_called_once()
            self.route_extractor._generate_route_report.assert_called_once()
            
            # Check result structure
            expected_keys = ['all_routes', 'sitemap_routes', 'robots_routes', 
                           'crawled_routes', 'api_routes', 'static_routes', 'dynamic_routes']
            
            for key in expected_keys:
                self.assertIn(key, result)
                self.assertIsInstance(result[key], set)


def run_route_extractor_demo():
    """Run a demonstration of the RouteExtractor capabilities"""
    print(Fore.BLUE + "=== Route Extractor Demo ===" + Style.RESET_ALL)
    
    # Create a mock scanner for demonstration
    mock_scanner = Mock()
    mock_scanner.target_url = "https://example.com"
    mock_scanner.timeout = 10
    mock_scanner.verbose = True
    mock_scanner.max_threads = 5
    mock_scanner.discovered_urls = [
        "https://example.com/page1",
        "https://example.com/page2",
        "https://example.com/api/v1/users",
        "https://example.com/admin"
    ]
    mock_scanner.session = Mock()
    
    # Initialize route extractor
    route_extractor = RouteExtractor(mock_scanner)
    
    print(Fore.CYAN + "Route Extractor initialized with:" + Style.RESET_ALL)
    print(f"  Target URL: {route_extractor.target_url}")
    print(f"  Timeout: {route_extractor.timeout}")
    print(f"  Max Threads: {route_extractor.max_threads}")
    print(f"  Verbose: {route_extractor.verbose}")
    
    print(Fore.CYAN + "\nSitemap locations configured:" + Style.RESET_ALL)
    for location in route_extractor.sitemap_locations:
        print(f"  - {location}")
    
    print(Fore.CYAN + "\nRoute patterns configured:" + Style.RESET_ALL)
    for category, patterns in route_extractor.route_patterns.items():
        print(f"  {category}: {len(patterns)} patterns")
    
    print(Fore.CYAN + "\nIgnore extensions configured:" + Style.RESET_ALL)
    print(f"  {len(route_extractor.ignore_extensions)} extensions to ignore")
    
    print(Fore.GREEN + "\nRoute Extractor is ready for comprehensive route extraction!" + Style.RESET_ALL)


if __name__ == "__main__":
    # Run the demo
    run_route_extractor_demo()
    
    # Run tests
    unittest.main(verbosity=2) 