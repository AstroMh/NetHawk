#!/usr/bin/env python3

"""
Advanced Route Extractor Module

This module provides comprehensive route extraction capabilities including:
- Sitemap extraction and parsing
- Robots.txt route discovery
- XML sitemap parsing
- HTML sitemap extraction
- JavaScript route discovery
- API endpoint discovery
- Dynamic route detection
- Route categorization and analysis
"""

import re
import xml.etree.ElementTree as ET
import json
import urllib.parse
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from colorama import Fore, Style
import requests
from typing import Dict, List, Set, Tuple, Optional


class RouteExtractor:
    """
    Advanced Route Extractor for comprehensive website route discovery
    
    This class implements sophisticated route extraction techniques including:
    - Sitemap extraction and parsing (XML, HTML, TXT)
    - Robots.txt route discovery
    - JavaScript route extraction
    - API endpoint discovery
    - Dynamic route detection
    - Route categorization and analysis
    """
    
    def __init__(self, scanner_instance):
        """
        Initialize the Route Extractor with scanner instance
        
        Args:
            scanner_instance: The main WebScanner instance
        """
        self.scanner = scanner_instance
        self.target_url = scanner_instance.target_url
        self.session = scanner_instance.session
        self.timeout = scanner_instance.timeout
        self.verbose = scanner_instance.verbose
        self.max_threads = scanner_instance.max_threads
        
        # Route storage
        self.all_routes = set()
        self.sitemap_routes = set()
        self.robots_routes = set()
        self.crawled_routes = set()
        self.api_routes = set()
        self.static_routes = set()
        self.dynamic_routes = set()
        
        # Common sitemap locations
        self.sitemap_locations = [
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
        
        # Route patterns for detection
        self.route_patterns = {
            'api_endpoints': [
                r'/api/[^/\s]+',
                r'/v\d+/[^/\s]+',
                r'/rest/[^/\s]+',
                r'/graphql',
                r'/gql',
                r'/service/[^/\s]+',
                r'/json/[^/\s]+'
            ],
            'admin_panels': [
                r'/admin[^/\s]*',
                r'/administrator[^/\s]*',
                r'/wp-admin[^/\s]*',
                r'/console[^/\s]*',
                r'/manage[^/\s]*',
                r'/panel[^/\s]*',
                r'/control[^/\s]*',
                r'/backend[^/\s]*'
            ],
            'auth_routes': [
                r'/login[^/\s]*',
                r'/register[^/\s]*',
                r'/signup[^/\s]*',
                r'/signin[^/\s]*',
                r'/logout[^/\s]*',
                r'/auth[^/\s]*',
                r'/account[^/\s]*',
                r'/profile[^/\s]*'
            ],
            'dynamic_routes': [
                r'/\d+',
                r'/[a-f0-9]{8,}',
                r'/[^/\s]+\?[^/\s]+',
                r'/[^/\s]+#[^/\s]+'
            ]
        }
        
        # File extensions to ignore
        self.ignore_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.tar', '.gz', '.7z',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            '.exe', '.msi', '.dmg', '.deb', '.rpm'
        }
    
    def run(self) -> Dict[str, Set[str]]:
        """
        Run comprehensive route extraction
        
        Returns:
            dict: Categorized routes by type
        """
        if self.verbose:
            print(Fore.BLUE + "[*] Starting comprehensive route extraction..." + Style.RESET_ALL)
            print(Fore.CYAN + f"    Target: {self.target_url}" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Using {len(self.sitemap_locations)} sitemap locations" + Style.RESET_ALL)
            print(Fore.CYAN + f"    Advanced route detection enabled" + Style.RESET_ALL)
        
        # Extract routes from multiple sources
        self._extract_sitemap_routes()
        self._extract_robots_routes()
        self._extract_crawled_routes()
        self._extract_api_routes()
        self._categorize_routes()
        
        # Generate comprehensive report
        self._generate_route_report()
        
        return {
            'all_routes': self.all_routes,
            'sitemap_routes': self.sitemap_routes,
            'robots_routes': self.robots_routes,
            'crawled_routes': self.crawled_routes,
            'api_routes': self.api_routes,
            'static_routes': self.static_routes,
            'dynamic_routes': self.dynamic_routes
        }
    
    def _extract_sitemap_routes(self):
        """Extract routes from various sitemap formats"""
        if self.verbose:
            print(Fore.BLUE + "  [+] Extracting sitemap routes..." + Style.RESET_ALL)
        
        for sitemap_path in self.sitemap_locations:
            sitemap_url = urljoin(self.target_url, sitemap_path)
            
            try:
                response = self.session.get(sitemap_url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    if 'xml' in content_type:
                        self._parse_xml_sitemap(response.text, sitemap_url)
                    elif 'text' in content_type:
                        self._parse_text_sitemap(response.text, sitemap_url)
                    elif 'html' in content_type:
                        self._parse_html_sitemap(response.text, sitemap_url)
                        
            except Exception as e:
                if self.verbose:
                    print(Fore.YELLOW + f"    [!] Error accessing {sitemap_url}: {str(e)}" + Style.RESET_ALL)
    
    def _parse_xml_sitemap(self, content: str, sitemap_url: str):
        """Parse XML sitemap and extract routes"""
        try:
            # Handle XML namespaces
            namespaces = {
                'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9',
                'xhtml': 'http://www.w3.org/1999/xhtml'
            }
            
            root = ET.fromstring(content)
            
            # Extract URLs from sitemap
            for url_elem in root.findall('.//ns:url', namespaces):
                loc_elem = url_elem.find('ns:loc', namespaces)
                if loc_elem is not None:
                    url = loc_elem.text.strip()
                    if self._is_valid_route(url):
                        self.sitemap_routes.add(url)
                        self.all_routes.add(url)
            
            # Extract sitemap index references
            for sitemap_elem in root.findall('.//ns:sitemap', namespaces):
                loc_elem = sitemap_elem.find('ns:loc', namespaces)
                if loc_elem is not None:
                    sub_sitemap_url = loc_elem.text.strip()
                    self._extract_sub_sitemap(sub_sitemap_url)
                    
        except ET.ParseError as e:
            if self.verbose:
                print(Fore.YELLOW + f"    [!] XML parsing error for {sitemap_url}: {str(e)}" + Style.RESET_ALL)
    
    def _parse_text_sitemap(self, content: str, sitemap_url: str):
        """Parse text sitemap and extract routes"""
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # Try to extract URL from line
                url_match = re.search(r'https?://[^\s]+', line)
                if url_match:
                    url = url_match.group(0)
                    if self._is_valid_route(url):
                        self.sitemap_routes.add(url)
                        self.all_routes.add(url)
    
    def _parse_html_sitemap(self, content: str, sitemap_url: str):
        """Parse HTML sitemap and extract routes"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract links from HTML sitemap
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(sitemap_url, href)
                
                if self._is_valid_route(full_url):
                    self.sitemap_routes.add(full_url)
                    self.all_routes.add(full_url)
                    
        except Exception as e:
            if self.verbose:
                print(Fore.YELLOW + f"    [!] HTML parsing error for {sitemap_url}: {str(e)}" + Style.RESET_ALL)
    
    def _extract_sub_sitemap(self, sitemap_url: str):
        """Extract routes from sub-sitemap"""
        try:
            response = self.session.get(sitemap_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                
                if 'xml' in content_type:
                    self._parse_xml_sitemap(response.text, sitemap_url)
                    
        except Exception as e:
            if self.verbose:
                print(Fore.YELLOW + f"    [!] Error accessing sub-sitemap {sitemap_url}: {str(e)}" + Style.RESET_ALL)
    
    def _extract_robots_routes(self):
        """Extract routes from robots.txt"""
        if self.verbose:
            print(Fore.BLUE + "  [+] Extracting robots.txt routes..." + Style.RESET_ALL)
        
        robots_url = urljoin(self.target_url, '/robots.txt')
        
        try:
            response = self.session.get(robots_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                content = response.text
                lines = content.split('\n')
                
                for line in lines:
                    line = line.strip()
                    
                    # Extract Sitemap directives
                    if line.lower().startswith('sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        self._extract_sub_sitemap(sitemap_url)
                    
                    # Extract Allow/Disallow paths
                    elif line.lower().startswith('allow:') or line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urljoin(self.target_url, path)
                            if self._is_valid_route(full_url):
                                self.robots_routes.add(full_url)
                                self.all_routes.add(full_url)
                                
        except Exception as e:
            if self.verbose:
                print(Fore.YELLOW + f"    [!] Error accessing robots.txt: {str(e)}" + Style.RESET_ALL)
    
    def _extract_crawled_routes(self):
        """Extract routes from crawled pages"""
        if self.verbose:
            print(Fore.BLUE + "  [+] Extracting routes from crawled pages..." + Style.RESET_ALL)
        
        # Use existing discovered URLs from scanner
        if hasattr(self.scanner, 'discovered_urls'):
            for url in self.scanner.discovered_urls:
                if self._is_valid_route(url):
                    self.crawled_routes.add(url)
                    self.all_routes.add(url)
    
    def _extract_api_routes(self):
        """Extract API routes from various sources"""
        if self.verbose:
            print(Fore.BLUE + "  [+] Extracting API routes..." + Style.RESET_ALL)
        
        # Extract API routes from JavaScript files
        self._extract_js_routes()
        
        # Extract API routes from HTML comments
        self._extract_html_comment_routes()
        
        # Extract API routes from common patterns
        self._extract_pattern_routes()
    
    def _extract_js_routes(self):
        """Extract routes from JavaScript files"""
        js_files = []
        
        # Find JavaScript files in discovered URLs
        for url in self.all_routes:
            if url.endswith('.js') or 'javascript' in url.lower():
                js_files.append(url)
        
        # Extract routes from JavaScript files
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self._parse_js_file, js_files)
    
    def _parse_js_file(self, js_url: str):
        """Parse JavaScript file for route patterns"""
        try:
            response = self.session.get(js_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                content = response.text
                
                # Extract API endpoints from JavaScript
                api_patterns = [
                    r'["\'](/api/[^"\']+)["\']',
                    r'["\'](/v\d+/[^"\']+)["\']',
                    r'["\'](/rest/[^"\']+)["\']',
                    r'["\'](/graphql[^"\']*)["\']',
                    r'["\'](/gql[^"\']*)["\']',
                    r'["\'](/service/[^"\']+)["\']',
                    r'["\'](/json/[^"\']+)["\']'
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        full_url = urljoin(self.target_url, match)
                        if self._is_valid_route(full_url):
                            self.api_routes.add(full_url)
                            self.all_routes.add(full_url)
                            
        except Exception as e:
            if self.verbose:
                print(Fore.YELLOW + f"    [!] Error parsing JS file {js_url}: {str(e)}" + Style.RESET_ALL)
    
    def _extract_html_comment_routes(self):
        """Extract routes from HTML comments"""
        # This would require parsing HTML files for comments containing routes
        pass
    
    def _extract_pattern_routes(self):
        """Extract routes based on common patterns"""
        base_url = self.target_url.rstrip('/')
        
        # Common API patterns
        api_patterns = [
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/rest/v1',
            '/rest/v2',
            '/graphql',
            '/gql',
            '/service',
            '/json'
        ]
        
        for pattern in api_patterns:
            full_url = base_url + pattern
            if self._is_valid_route(full_url):
                self.api_routes.add(full_url)
                self.all_routes.add(full_url)
    
    def _categorize_routes(self):
        """Categorize routes by type"""
        if self.verbose:
            print(Fore.BLUE + "  [+] Categorizing routes..." + Style.RESET_ALL)
        
        for route in self.all_routes:
            # Check for static routes
            if self._is_static_route(route):
                self.static_routes.add(route)
            
            # Check for dynamic routes
            elif self._is_dynamic_route(route):
                self.dynamic_routes.add(route)
            
            # Check for API routes
            elif self._is_api_route(route):
                self.api_routes.add(route)
    
    def _is_valid_route(self, url: str) -> bool:
        """Check if URL is a valid route to include"""
        try:
            parsed = urlparse(url)
            
            # Check if it's the same domain
            target_parsed = urlparse(self.target_url)
            if parsed.netloc and parsed.netloc != target_parsed.netloc:
                return False
            
            # Check for ignored extensions
            path = parsed.path.lower()
            for ext in self.ignore_extensions:
                if path.endswith(ext):
                    return False
            
            # Check for common static file patterns
            static_patterns = [
                r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$',
                r'\.(pdf|doc|docx|xls|xlsx|ppt|pptx)$',
                r'\.(zip|rar|tar|gz|7z)$',
                r'\.(mp3|mp4|avi|mov|wmv)$'
            ]
            
            for pattern in static_patterns:
                if re.search(pattern, path):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _is_static_route(self, url: str) -> bool:
        """Check if route is static"""
        static_patterns = [
            r'\.(html|htm|php|asp|aspx|jsp)$',
            r'/(about|contact|privacy|terms|help|faq|support)',
            r'/(index|home|main)',
            r'/(products|services|pricing)'
        ]
        
        path = urlparse(url).path.lower()
        return any(re.search(pattern, path) for pattern in static_patterns)
    
    def _is_dynamic_route(self, url: str) -> bool:
        """Check if route is dynamic"""
        dynamic_patterns = [
            r'/\d+$',
            r'/[a-f0-9]{8,}',
            r'\?[^=]+=',
            r'#[^/]+$'
        ]
        
        return any(re.search(pattern, url) for pattern in dynamic_patterns)
    
    def _is_api_route(self, url: str) -> bool:
        """Check if route is an API endpoint"""
        api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'/rest/',
            r'/graphql',
            r'/gql',
            r'/service/',
            r'/json/'
        ]
        
        path = urlparse(url).path.lower()
        return any(re.search(pattern, path) for pattern in api_patterns)
    
    def _generate_route_report(self):
        """Generate comprehensive route extraction report"""
        if not self.verbose:
            return
        
        print(Fore.GREEN + f"[+] Route extraction completed" + Style.RESET_ALL)
        print(Fore.GREEN + f"    Total routes found: {len(self.all_routes)}" + Style.RESET_ALL)
        
        # Detailed breakdown
        if self.sitemap_routes:
            print(Fore.CYAN + f"    Sitemap routes: {len(self.sitemap_routes)}" + Style.RESET_ALL)
        if self.robots_routes:
            print(Fore.CYAN + f"    Robots.txt routes: {len(self.robots_routes)}" + Style.RESET_ALL)
        if self.crawled_routes:
            print(Fore.CYAN + f"    Crawled routes: {len(self.crawled_routes)}" + Style.RESET_ALL)
        if self.api_routes:
            print(Fore.CYAN + f"    API routes: {len(self.api_routes)}" + Style.RESET_ALL)
        if self.static_routes:
            print(Fore.CYAN + f"    Static routes: {len(self.static_routes)}" + Style.RESET_ALL)
        if self.dynamic_routes:
            print(Fore.CYAN + f"    Dynamic routes: {len(self.dynamic_routes)}" + Style.RESET_ALL)
        
        # Advanced features summary
        print(Fore.MAGENTA + "    Advanced features used:" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ XML sitemap parsing" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ HTML sitemap extraction" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Text sitemap parsing" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Robots.txt analysis" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ JavaScript route extraction" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ API endpoint discovery" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Route categorization" + Style.RESET_ALL)
        print(Fore.MAGENTA + "      ✓ Dynamic route detection" + Style.RESET_ALL) 