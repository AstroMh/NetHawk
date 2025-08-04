#!/usr/bin/env python3

import os
import time
import requests
import concurrent.futures
from urllib.parse import urljoin, urlparse
from termcolor import colored

def brute_force_directories(scanner_instance):
    """
    Brute force directories and files on the target website.
    
    Args:
        scanner_instance: The main WebScanner instance
        
    Returns:
        list: Discovered directories
    """
    target_url = scanner_instance.target_url
    session = scanner_instance.session
    timeout = scanner_instance.timeout
    verbose = scanner_instance.verbose
    max_threads = scanner_instance.max_threads
    
    # Get base URL
    base_url = scanner_instance._get_base_url()
    
    # List of common directories and files to check
    # This is a small list, in production, use a larger wordlist
    common_paths = [
        # Common directories
        'admin/', 'administrator/', 'backup/', 'backups/', 'css/', 'data/',
        'images/', 'img/', 'js/', 'media/', 'scripts/', 'static/', 'temp/',
        'tmp/', 'content/', 'assets/', 'uploads/', 'api/', 'dashboard/',
        'login/', 'wp-admin/', 'wp-content/', 'wp-includes/', 'download/',
        '.git/', '.svn/', 'config/', 'admin/login/', 'admin/admin/',
        'admin/account/', 'admin/admin_login/', 'admin/cp/', 'admin/home/',
        'phpMyAdmin/', 'phpmyadmin/', 'PMA/', 'forum/', 'bbs/', 'cache/',
        'webmail/', 'mail/', 'database/', 'db/', 'install/', 'setup/',
        'administrator/index.php', 'administrator/login.php', 'system/',
        'old/', 'new/', 'files/', 'dev/', 'test/', 'demo/', 'sql/', 'server/',
        'logs/', 'bin/', 'tools/', 'cgi-bin/', 'private/', 'robots.txt',
        '.htaccess', 
        
        # Common files
        'index.php', 'index.html', 'index.htm', 'default.php', 'default.html',
        'default.htm', 'info.php', 'phpinfo.php', 'test.php', 'config.php',
        'configuration.php', 'config.inc.php', 'settings.php', 'setup.php',
        'admin.php', 'wp-login.php', 'log.txt', 'logs.txt', 'error.log',
        'debug.log', 'backup.sql', 'backup.zip', 'backup.tar.gz', 'backup.gz',
        'db.sql', 'db.zip', 'db.tar.gz', 'db.gz', 'database.sql', 'users.sql',
        'dump.sql', 'data.sql', 'stats.php', 'server-status', 'server-info'
    ]
    
    # Load a custom wordlist if available
    wordlist_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                 'utils', 'wordlists', 'directories.txt')
    
    try:
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                wordlist_paths = f.read().splitlines()
                # Remove empty lines and comments
                wordlist_paths = [line for line in wordlist_paths if line and not line.startswith('#')]
                common_paths.extend(wordlist_paths)
            
            # Remove duplicates while preserving order
            common_paths = list(dict.fromkeys(common_paths))
            
            if verbose:
                print(colored(f"[*] Loaded {len(wordlist_paths)} paths from wordlist", 'blue'))
    except Exception as e:
        if verbose:
            print(colored(f"[!] Error loading wordlist: {str(e)}", 'yellow'))
    
    discovered = []
    
    # Function to check a single path
    def check_path(path):
        url = urljoin(base_url, path)
        
        try:
            # Add a random delay to avoid detection
            time.sleep(0.1)
            
            # Send request
            response = session.get(url, timeout=timeout, allow_redirects=False)
            
            # Check if the path exists based on status code
            if response.status_code < 400:  # 200 OK, 301, 302, 307 redirects
                path_data = {
                    'url': url,
                    'status_code': response.status_code,
                    'size': len(response.content),
                    'path': path
                }
                
                if verbose:
                    print(colored(f"[+] Found: {url} ({response.status_code})", 'green'))
                
                return path_data
            
            # Some servers might return 403 Forbidden for existing directories
            elif response.status_code == 403:  # Forbidden
                path_data = {
                    'url': url,
                    'status_code': response.status_code,
                    'size': len(response.content),
                    'path': path,
                    'note': 'Access Forbidden - Resource likely exists'
                }
                
                if verbose:
                    print(colored(f"[+] Found (Forbidden): {url}", 'yellow'))
                
                return path_data
            
            return None
            
        except requests.exceptions.RequestException:
            return None
    
    print(colored("[*] Starting directory bruteforce...", 'blue'))
    print(colored(f"[*] Checking {len(common_paths)} paths on {base_url}...", 'blue'))
    
    # Use ThreadPoolExecutor for parallel processing
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_path = {executor.submit(check_path, path): path for path in common_paths}
        
        for future in concurrent.futures.as_completed(future_to_path):
            path = future_to_path[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
                    discovered.append(result)
            except Exception as e:
                if verbose:
                    print(colored(f"[!] Error checking {path}: {str(e)}", 'red'))
    
    print(colored(f"[+] Directory bruteforce completed. Found {len(results)} resources.", 'green'))
    
    # Store in scanner instance
    scanner_instance.directories = discovered
    
    return discovered 