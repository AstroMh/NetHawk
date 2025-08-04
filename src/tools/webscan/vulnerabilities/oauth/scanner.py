#!/usr/bin/env python3

import re
import json
import base64
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style
from bs4 import BeautifulSoup

class OAuthScanner:
    """Scanner for detecting OAuth and OpenID Connect vulnerabilities"""
    
    def __init__(self, scanner_instance):
        """
        Initialize the OAuth Scanner with a reference to the main scanner instance
        
        Args:
            scanner_instance: The main WebScanner instance
        """
        self.scanner = scanner_instance
        self.target_url = scanner_instance.target_url
        self.session = scanner_instance.session
        self.timeout = scanner_instance.timeout
        self.verbose = scanner_instance.verbose
        self.max_threads = scanner_instance.max_threads
        self.vulnerabilities = []
        self.discovered_urls = scanner_instance.discovered_urls
        self.oauth_vulnerabilities = []  # Initialize empty list to store OAuth vulnerabilities
        
        # Patterns to detect OAuth endpoints and parameters
        self.oauth_patterns = [
            # OAuth authorization endpoints
            r'(?i)/oauth/authorize',
            r'(?i)/oauth2/auth',
            r'(?i)/oauth/token',
            r'(?i)/oauth2/token',
            r'(?i)/oauth/access_token',
            r'(?i)/authorize',
            r'(?i)/auth',
            r'(?i)/token',
            # OpenID Connect endpoints
            r'(?i)/oidc/authorize',
            r'(?i)/oidc/token',
            r'(?i)/oidc',
            r'(?i)/.well-known/openid-configuration',
            # Common OAuth parameters in URLs
            r'(?i)[?&]client_id=',
            r'(?i)[?&]redirect_uri=',
            r'(?i)[?&]response_type=',
            r'(?i)[?&]scope=',
            r'(?i)[?&]state=',
            r'(?i)[?&]code=',
            r'(?i)[?&]token=',
            r'(?i)[?&]id_token=',
            r'(?i)[?&]access_token='
        ]
        
        # Common OAuth configuration patterns in HTML/JS
        self.oauth_config_patterns = [
            r'(?i)client_id[\s]*[=:][\s]*["\']([^"\']+)["\']',
            r'(?i)client_secret[\s]*[=:][\s]*["\']([^"\']+)["\']',
            r'(?i)redirect_uri[\s]*[=:][\s]*["\']([^"\']+)["\']',
            r'(?i)auth_uri[\s]*[=:][\s]*["\']([^"\']+)["\']',
            r'(?i)token_uri[\s]*[=:][\s]*["\']([^"\']+)["\']'
        ]
    
    def run(self):
        """Run the OAuth scanner on all discovered URLs"""
        if self.verbose:
            print(Fore.BLUE + "[*] Starting OAuth vulnerability scanner..." + Style.RESET_ALL)

        # Check for OAuth endpoints and potential vulnerabilities
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            list(executor.map(self.scan_url, self.discovered_urls))
            
        if self.verbose:
            print(Fore.BLUE + f"[*] OAuth scanner completed. Found {len(self.vulnerabilities)} vulnerabilities." + Style.RESET_ALL)
            
        return self.vulnerabilities
        
    def scan_url(self, url):
        """
        Scan a single URL for OAuth vulnerabilities
        
        Args:
            url (str): URL to scan
        """
        try:
            if self.verbose:
                print(Fore.BLUE + f"  [+] Scanning {url} for OAuth issues" + Style.RESET_ALL)
                
            # Check if the URL itself matches any OAuth patterns
            is_oauth_endpoint = any(re.search(pattern, url) for pattern in self.oauth_patterns)
            
            # Get the page content
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                content = response.text
                
                # Parse the HTML content
                soup = BeautifulSoup(content, 'html.parser')
                
                # Look for OAuth endpoints in HTML links, scripts, etc.
                self.find_oauth_endpoints(url, soup)
                
                # Check for OAuth configuration leaks in page source
                self.check_oauth_config_leaks(url, content)
                
                # If this is an OAuth endpoint, perform specific tests
                if is_oauth_endpoint:
                    self.test_oauth_endpoint(url, response)
                    
                # Check for CSRF vulnerability in OAuth flows
                self.test_oauth_csrf(url, soup)
                
                # Check for open redirect in redirect_uri
                self.test_redirect_uri_validation(url)
                
                # Check for missing state parameter
                self.test_missing_state(url, content)
                
            except Exception as e:
                if self.verbose:
                    print(Fore.YELLOW + f"  [!] Error fetching {url}: {str(e)}" + Style.RESET_ALL)
                    
        except Exception as e:
            if self.verbose:
                print(Fore.RED + f"  [-] Error scanning {url} for OAuth issues: {str(e)}" + Style.RESET_ALL)
            
    def find_oauth_endpoints(self, base_url, soup):
        """
        Find OAuth endpoints in HTML content
        
        Args:
            base_url (str): The base URL being scanned
            soup (BeautifulSoup): Parsed HTML content
        """
        # Check all links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = self._make_absolute_url(base_url, href)
            
            if any(re.search(pattern, full_url) for pattern in self.oauth_patterns):
                if self.verbose:
                    print(Fore.BLUE + f"  [+] Found OAuth related link: {full_url}" + Style.RESET_ALL)
                    
                # Add to discovered URLs for further scanning
                if full_url not in self.discovered_urls:
                    self.discovered_urls.append(full_url)
                    
        # Check form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            full_url = self._make_absolute_url(base_url, action)
            
            if any(re.search(pattern, full_url) for pattern in self.oauth_patterns):
                if self.verbose:
                    print(Fore.BLUE + f"  [+] Found OAuth related form action: {full_url}" + Style.RESET_ALL)
                    
                # Add to discovered URLs for further scanning
                if full_url not in self.discovered_urls:
                    self.discovered_urls.append(full_url)
        
        # Check script sources for OAuth libraries
        oauth_libraries = ['oauth', 'auth0', 'openid', 'okta', 'keycloak']
        for script in soup.find_all('script', src=True):
            src = script['src']
            if any(lib in src.lower() for lib in oauth_libraries):
                if self.verbose:
                    print(Fore.BLUE + f"  [+] Found OAuth related script: {src}" + Style.RESET_ALL)
    
    def check_oauth_config_leaks(self, url, content):
        """
        Check for leaked OAuth configuration in page source
        
        Args:
            url (str): The URL being scanned
            content (str): The page content
        """
        for pattern in self.oauth_config_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if 'client_secret' in pattern.lower():
                    self.add_vulnerability(url, "OAuth client secret exposed", 
                                         f"OAuth client secret found in page source: '{match}'",
                                         "Critical", 90, "CWE-798", 
                                         ["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
                                         remediation="Never expose OAuth client secrets in client-side code. Store secrets server-side only.")
                elif 'client_id' in pattern.lower():
                    # Client ID alone is usually not a vulnerability, but we note it
                    if self.verbose:
                        print(Fore.BLUE + f"  [+] Found OAuth client ID: {match}" + Style.RESET_ALL)
    
    def test_oauth_endpoint(self, url, response):
        """
        Test an OAuth endpoint for vulnerabilities
        
        Args:
            url (str): The OAuth endpoint URL
            response (Response): The HTTP response from the endpoint
        """
        # Parse URL parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Test for insecure transport
        if parsed_url.scheme != 'https':
            self.add_vulnerability(url, "OAuth over insecure transport", 
                                 "OAuth flows should only use HTTPS to protect tokens and authorization codes from interception",
                                 "High", 80, "CWE-319", 
                                 ["https://oauth.net/2/"],
                                 remediation="Use HTTPS for all OAuth endpoints and redirects")
        
        # Check for client_id without client_secret (implicit flow)
        if 'client_id' in query_params and 'code' in query_params and url.lower().endswith('/token'):
            # This might be a token endpoint that doesn't require client_secret
            self.test_token_endpoint_security(url)
            
        # Check for redirect_uri validation
        if 'redirect_uri' in query_params:
            redirect_uri = query_params['redirect_uri'][0]
            self.test_redirect_uri_validation(url)
            
        # Check for response_type parameter
        if 'response_type' in query_params:
            response_type = query_params['response_type'][0]
            
            # Test for implicit flow (less secure than authorization code flow)
            if response_type == 'token':
                self.add_vulnerability(url, "OAuth implicit flow in use", 
                                     "The OAuth implicit flow (response_type=token) is less secure than the authorization code flow",
                                     "Medium", 60, "CWE-345", 
                                     ["https://oauth.net/2/grant-types/implicit/"],
                                     remediation="Consider using authorization code flow with PKCE instead of implicit flow")
                
        # Check for missing state parameter
        if ('code' in query_params or 'token' in query_params) and 'state' not in query_params:
            self.add_vulnerability(url, "OAuth missing state parameter", 
                                 "The OAuth flow does not use the 'state' parameter, which is required to prevent CSRF attacks",
                                 "Medium", 70, "CWE-352", 
                                 ["https://auth0.com/docs/protocols/state-parameters"],
                                 remediation="Always include a unique, non-guessable state parameter in OAuth requests")
    
    def test_token_endpoint_security(self, url):
        """
        Test the token endpoint for security issues
        
        Args:
            url (str): The token endpoint URL
        """
        try:
            # Try to get a token without client_secret
            data = {
                'grant_type': 'authorization_code',
                'client_id': 'test_client_id',
                'code': 'invalid_code',
                'redirect_uri': 'https://example.com/callback'
            }
            
            response = self.session.post(url, data=data, timeout=self.timeout)
            
            # Check if the response is just a 401/400 or if it reveals information
            if response.status_code != 401 and response.status_code != 400:
                # The endpoint might not be properly validating client authentication
                self.add_vulnerability(url, "OAuth token endpoint without client authentication", 
                                     "The OAuth token endpoint may not be properly validating client credentials",
                                     "High", 75, "CWE-287", 
                                     ["https://oauth.net/2/grant-types/authorization-code/"],
                                     remediation="Require client authentication for token endpoints using client_secret or other methods")
        except Exception as e:
            if self.verbose:
                print(Fore.YELLOW + f"  [!] Error testing token endpoint: {str(e)}" + Style.RESET_ALL)
    
    def test_redirect_uri_validation(self, url):
        """
        Test if the authorization server properly validates redirect_uri
        
        Args:
            url (str): The URL to test
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if 'redirect_uri' not in query_params:
            return
            
        original_redirect_uri = query_params['redirect_uri'][0]
        
        try:
            # Try malicious redirect URIs
            malicious_redirect_uris = [
                'https://attacker.com',
                'https://example.com@attacker.com',
                'https://attacker.com/callback',
                original_redirect_uri + '.attacker.com',
                'javascript:alert(document.domain)'
            ]
            
            for malicious_uri in malicious_redirect_uris:
                # Replace the redirect_uri in the URL
                modified_url = re.sub(
                    r'redirect_uri=[^&]+', 
                    f'redirect_uri={urllib.parse.quote(malicious_uri)}', 
                    url
                )
                
                response = self.session.get(modified_url, timeout=self.timeout, allow_redirects=False)
                
                # If we don't get an error (400/401), the server might be accepting arbitrary redirect URIs
                if response.status_code == 200 or response.status_code == 302:
                    self.add_vulnerability(url, "OAuth redirect_uri not properly validated", 
                                         f"The authorization server may accept arbitrary redirect URIs, which can lead to authorization code/token theft",
                                         "Critical", 85, "CWE-601", 
                                         ["https://oauth.net/2/oauth-best-practice/"],
                                         remediation="Validate redirect_uri against a whitelist of allowed URIs. Require exact matching, not just prefix or domain matching.")
                    return
                    
        except Exception as e:
            if self.verbose:
                print(Fore.YELLOW + f"  [!] Error testing redirect_uri validation: {str(e)}" + Style.RESET_ALL)
    
    def test_oauth_csrf(self, url, soup):
        """
        Test for CSRF vulnerability in OAuth flows
        
        Args:
            url (str): The URL to test
            soup (BeautifulSoup): Parsed HTML content
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Check if this is an OAuth authorization endpoint
        if any(re.search(r'(?i)/oauth.*?/auth', url) for pattern in self.oauth_patterns):
            # Check if the state parameter is used
            if 'state' not in query_params:
                self.add_vulnerability(url, "OAuth authorization endpoint without state parameter", 
                                     "The OAuth authorization endpoint does not use the 'state' parameter, making it vulnerable to CSRF attacks",
                                     "High", 75, "CWE-352", 
                                     ["https://auth0.com/docs/protocols/state-parameters"],
                                     remediation="Implement the state parameter in all OAuth authorization requests. The value should be unpredictable and tied to the user's session.")
                
        # Check for OAuth login buttons without CSRF protection
        login_buttons = soup.find_all('a', href=True) + soup.find_all('button') + soup.find_all('input', {'type': 'button'})
        for button in login_buttons:
            if button.name == 'a':
                href = button.get('href', '')
            else:
                href = button.get('onclick', '')
                
            # Check if this is an OAuth login button
            if 'oauth' in str(button).lower() or 'login with' in str(button).lower() or 'sign in with' in str(button).lower():
                # Check if there's a state parameter in the href or onclick
                if href and 'state=' not in href.lower():
                    self.add_vulnerability(url, "OAuth login without CSRF protection", 
                                         "The OAuth login functionality does not include a state parameter, making it vulnerable to CSRF attacks",
                                         "Medium", 65, "CWE-352", 
                                         ["https://tools.ietf.org/html/rfc6749#section-10.12"],
                                         remediation="Implement the state parameter in all OAuth login links. Generate a unique state value for each user session.")
    
    def test_missing_state(self, url, content):
        """
        Test for missing state parameter in OAuth implementations
        
        Args:
            url (str): The URL to test
            content (str): The page content
        """
        # Check if the page contains OAuth-related functionality
        if re.search(r'oauth|openid|auth0|okta|keycloak', content, re.IGNORECASE):
            # Search for OAuth implementation without state parameter
            oauth_params = re.findall(r'(?i)(client_id|response_type|redirect_uri|scope|access_token|id_token)[\s]*[=:][\s]*["\']([^"\']+)["\']', content)
            has_oauth_params = len(oauth_params) > 0
            
            # Check if state parameter is missing
            has_state = re.search(r'(?i)state[\s]*[=:][\s]*["\']([^"\']+)["\']', content) is not None
            
            if has_oauth_params and not has_state:
                self.add_vulnerability(url, "OAuth implementation missing state parameter", 
                                     "The OAuth implementation does not appear to use the state parameter, making it vulnerable to CSRF attacks",
                                     "Medium", 65, "CWE-352", 
                                     ["https://auth0.com/docs/protocols/state-parameters"],
                                     remediation="Implement the state parameter in all OAuth flows to prevent CSRF attacks. The state value should be unpredictable and tied to the user's session.")
    
    def _make_absolute_url(self, base_url, relative_url):
        """Convert a relative URL to an absolute URL"""
        if relative_url.startswith('http://') or relative_url.startswith('https://'):
            return relative_url
        else:
            return urllib.parse.urljoin(base_url, relative_url)
            
    def add_vulnerability(self, url, name, description, severity, risk_score, cwe, references, remediation):
        """Add a vulnerability to the list"""
        vuln = {
            'type': 'OAuth',
            'name': name,
            'url': url,
            'severity': severity,
            'risk_score': risk_score,
            'description': description,
            'evidence': f"URL: {url}",
            'parameter': 'OAuth Flow',
            'cwe': cwe,
            'references': references,
            'remediation': remediation
        }
        
        self.vulnerabilities.append(vuln)
        
        if self.verbose:
            print(Fore.RED + f"[!] Found {severity} OAuth vulnerability at {url}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"    {name}: {description}" + Style.RESET_ALL) 