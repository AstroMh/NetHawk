#!/usr/bin/env python3

import socket
import dns.resolver
import concurrent.futures
from urllib.parse import urlparse
from termcolor import colored

def enumerate_subdomains(scanner):
    """
    Enumerate subdomains of the target domain using DNS queries.
    
    Args:
        scanner: The WebScanner instance
        
    Returns:
        list: Discovered subdomains
    """
    subdomains = []
    
    # Extract base domain from target URL
    parsed_url = urlparse(scanner.target_url)
    base_domain = parsed_url.netloc
    
    # Remove 'www.' if present
    if base_domain.startswith('www.'):
        base_domain = base_domain[4:]
    
    # Common subdomain wordlist for enumeration
    common_subdomains = [
        'www', 'mail', 'ftp', 'webmail', 'login', 'admin', 'test',
        'dev', 'staging', 'stage', 'app', 'api', 'server', 'cloud',
        'blog', 'shop', 'forum', 'support', 'help', 'portal', 'beta',
        'secure', 'mobile', 'vpn', 'mx', 'autodiscover', 'autoconfig',
        'ns1', 'ns2', 'dns', 'dns1', 'dns2', 'db', 'database', 'mysql',
        'smtp', 'pop', 'proxy', 'exchange', 'gateway', 'remote',
        'docker', 'jenkins', 'gitlab', 'git', 'svn', 'demo', 'cdn',
        'images', 'img', 'media', 'static', 'assets', 'files', 'docs',
        'status', 'intranet', 'internal', 'wifi', 'guest', 'account',
        'signup', 'login', 'auth', 'sso', 'oauth', 'analytics', 'monitor',
        'kibana', 'graphite', 'grafana', 'prometheus', 'metrics',
        'webdisk', 'backup', 'storage', 's3'
    ]
    
    # Only try basic subdomain enumeration in normal mode
    # Use a smaller subset of common subdomains to avoid being too slow
    if not scanner.verbose:
        common_subdomains = common_subdomains[:20]
    
    scanner.logger.info(f"Enumerating subdomains for {base_domain}...")
    
    def check_subdomain(subdomain):
        """Check if a subdomain exists and can be resolved"""
        full_domain = f"{subdomain}.{base_domain}"
        try:
            # Try to resolve the domain
            ip_addresses = []
            
            # Try to get A records
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                for rdata in answers:
                    ip_addresses.append(rdata.address)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            
            # If we found IP addresses, the subdomain exists
            if ip_addresses:
                return {
                    'domain': full_domain,
                    'ip_addresses': ip_addresses,
                    'type': 'A'
                }
            
            # Try to get CNAME records if no A records were found
            try:
                answers = dns.resolver.resolve(full_domain, 'CNAME')
                cname_records = []
                for rdata in answers:
                    cname_records.append(str(rdata.target))
                
                if cname_records:
                    return {
                        'domain': full_domain,
                        'cname_records': cname_records,
                        'type': 'CNAME'
                    }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            
            return None
        except Exception as e:
            if scanner.verbose:
                scanner.logger.debug(f"Error checking subdomain {full_domain}: {str(e)}")
            return None
    
    # Use ThreadPoolExecutor for faster subdomain enumeration
    with concurrent.futures.ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
        results = executor.map(check_subdomain, common_subdomains)
    
    # Filter out None results and add to subdomains list
    for result in results:
        if result:
            subdomains.append(result)
            if scanner.verbose:
                if result['type'] == 'A':
                    scanner.logger.info(f"Found subdomain: {result['domain']} ({', '.join(result['ip_addresses'])})")
                else:
                    scanner.logger.info(f"Found subdomain: {result['domain']} (CNAME: {', '.join(result['cname_records'])})")
    
    # Also try to get subdomains from certificate transparency logs
    try:
        import requests
        # Use crt.sh to find subdomains from certificate transparency logs
        url = f"https://crt.sh/?q=%.{base_domain}&output=json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                ct_subdomains = set()
                
                for entry in data:
                    # Extract the subdomain from the certificate
                    name_value = entry.get('name_value', '')
                    
                    # Split on newlines and handle wildcard domains
                    domains = name_value.split('\n')
                    for domain in domains:
                        if '*' in domain:
                            # Skip wildcard domains
                            continue
                        
                        # Make sure it's a subdomain of our base domain
                        if domain.endswith(f".{base_domain}") and domain != base_domain:
                            ct_subdomains.add(domain)
                
                # Add certificate transparency findings to our subdomain list
                for subdomain in ct_subdomains:
                    if not any(entry['domain'] == subdomain for entry in subdomains):
                        # Try to resolve the IP for this subdomain
                        try:
                            ip_addresses = socket.gethostbyname_ex(subdomain)[2]
                            subdomains.append({
                                'domain': subdomain,
                                'ip_addresses': ip_addresses,
                                'type': 'CT',  # Certificate Transparency
                                'source': 'crt.sh'
                            })
                            
                            if scanner.verbose:
                                scanner.logger.info(f"Found subdomain (CT): {subdomain} ({', '.join(ip_addresses)})")
                        except socket.gaierror:
                            # Can't resolve IP, but still include the subdomain
                            subdomains.append({
                                'domain': subdomain,
                                'ip_addresses': [],
                                'type': 'CT',
                                'source': 'crt.sh'
                            })
                            
                            if scanner.verbose:
                                scanner.logger.info(f"Found subdomain (CT): {subdomain} (No IP)")
            except ValueError:
                if scanner.verbose:
                    scanner.logger.debug("Error parsing JSON from crt.sh")
    except Exception as e:
        if scanner.verbose:
            scanner.logger.debug(f"Error querying certificate transparency logs: {str(e)}")
    
    # Update the scanner's subdomains
    scanner.subdomains = subdomains
    
    if subdomains:
        scanner.logger.info(f"Found {len(subdomains)} subdomains")
    else:
        scanner.logger.info("No subdomains found")
    
    return subdomains 