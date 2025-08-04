#!/usr/bin/env python3

import urllib.parse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from termcolor import colored

def discover_urls(scanner):
    """
    Crawl the website to discover URLs.
    
    Args:
        scanner: The WebScanner instance
        
    Returns:
        list: Discovered URLs
    """
    scanner.discovered_urls = []
    to_visit = [scanner.target_url]
    visited = set()
    max_urls = 500  # Limit to avoid crawling the entire internet
    
    def extract_urls(url):
        """Extract URLs from a webpage"""
        try:
            response = scanner.session.get(url, timeout=scanner.timeout, verify=False)
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return []
            
            soup = BeautifulSoup(response.text, 'html.parser')
            new_urls = []
            
            # Extract links from <a> tags
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(url, href)
                
                # Filter URLs to stay within the same domain
                parsed_url = urllib.parse.urlparse(full_url)
                base_parsed = urllib.parse.urlparse(scanner.base_url)
                
                if parsed_url.netloc == base_parsed.netloc:
                    # Remove fragments
                    full_url = full_url.split('#')[0]
                    new_urls.append(full_url)
            
            # Extract URLs from <script>, <link>, <img> tags
            for tag in soup.find_all(['script', 'link', 'img']):
                if tag.has_attr('src'):
                    src = tag['src']
                    full_url = urljoin(url, src)
                    parsed_url = urllib.parse.urlparse(full_url)
                    base_parsed = urllib.parse.urlparse(scanner.base_url)
                    
                    if parsed_url.netloc == base_parsed.netloc:
                        new_urls.append(full_url)
                elif tag.name == 'link' and tag.has_attr('href'):
                    href = tag['href']
                    full_url = urljoin(url, href)
                    parsed_url = urllib.parse.urlparse(full_url)
                    base_parsed = urllib.parse.urlparse(scanner.base_url)
                    
                    if parsed_url.netloc == base_parsed.netloc:
                        new_urls.append(full_url)
            
            return list(set(new_urls))
            
        except Exception as e:
            if scanner.verbose:
                scanner.logger.error(f"Error fetching {url}: {str(e)}")
            return []
    
    # Breadth-first search to discover URLs
    while to_visit and len(visited) < max_urls:
        # Process URLs in batches for efficiency
        batch_size = min(scanner.max_threads, len(to_visit))
        current_batch = to_visit[:batch_size]
        to_visit = to_visit[batch_size:]
        
        # Extract new URLs from current batch
        with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
            new_urls = list(executor.map(extract_urls, current_batch))
        
        # Add current batch to visited and discovered_urls
        for url in current_batch:
            visited.add(url)
            scanner.discovered_urls.append(url)
            
        # Add new URLs to to_visit queue if not already processed
        for url_list in new_urls:
            for url in url_list:
                if url not in visited and url not in to_visit:
                    to_visit.append(url)
    
    # Remove duplicates while maintaining order
    scanner.discovered_urls = list(dict.fromkeys(scanner.discovered_urls))
    
    # Categorize URLs by types and patterns for better analysis
    categorized_urls = {
        "static_resources": [],
        "api_endpoints": [],
        "forms": [],
        "authenticated_areas": [],
        "admin_areas": []
    }
    
    for url in scanner.discovered_urls:
        # Static resources
        if any(ext in url.lower() for ext in ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.ttf']):
            categorized_urls["static_resources"].append(url)
        
        # API endpoints
        elif any(pattern in url.lower() for pattern in ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql', '/gql', '/service', '/json']):
            categorized_urls["api_endpoints"].append(url)
        
        # Forms
        elif any(pattern in url.lower() for pattern in ['/login', '/register', '/signup', '/contact', '/form', '/subscribe', '/search']):
            categorized_urls["forms"].append(url)
        
        # Authenticated areas
        elif any(pattern in url.lower() for pattern in ['/account', '/profile', '/dashboard', '/user', '/settings', '/my-']):
            categorized_urls["authenticated_areas"].append(url)
        
        # Admin areas
        elif any(pattern in url.lower() for pattern in ['/admin', '/administrator', '/wp-admin', '/console', '/manage', '/panel', '/control', '/backend']):
            categorized_urls["admin_areas"].append(url)
    
    # Provide a summary of the categorized URLs if verbose mode is enabled
    if scanner.verbose:
        scanner.logger.info(f"Discovered {len(scanner.discovered_urls)} URLs:")
        for category, urls in categorized_urls.items():
            if urls:
                scanner.logger.info(f"  {category.replace('_', ' ').title()}: {len(urls)}")
    
    return scanner.discovered_urls 