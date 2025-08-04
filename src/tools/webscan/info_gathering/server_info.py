#!/usr/bin/env python3

import socket
import urllib.parse
import requests
from termcolor import colored

def gather_server_info(scanner):
    """
    Gather basic information about the target server.
    
    Args:
        scanner: The WebScanner instance
        
    Returns:
        dict: Server information
    """
    server_info = {
        "server": "Unknown",
        "technologies": [],
        "ip_address": "Unknown",
        "headers": {}
    }
    
    try:
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout, verify=False)
        
        parsed_url = urllib.parse.urlparse(scanner.target_url)
        hostname = parsed_url.netloc
        
        try:
            ip_address = socket.gethostbyname(hostname)
            server_info["ip_address"] = ip_address
        except socket.gaierror:
            server_info["ip_address"] = "Unknown"
        
        # Extract server header and other headers
        if response.headers:
            server_info["headers"] = dict(response.headers)
            
            if "Server" in response.headers:
                server_info["server"] = response.headers["Server"]
            
            # Check for various technology indicators
            tech_indicators = {
                "PHP": ["X-Powered-By: PHP", "PHPSESSID"],
                "ASP.NET": ["X-AspNet-Version", "ASP.NET", ".NET"],
                "Django": ["csrftoken", "django"],
                "Ruby on Rails": ["_rails_session"],
                "jQuery": ["jquery"],
                "React": ["react"],
                "Angular": ["angular"],
                "Bootstrap": ["bootstrap"],
                "WordPress": ["wp-content", "wp-includes"],
                "Apache": ["apache"],
                "Nginx": ["nginx"],
                "IIS": ["IIS"],
                "CloudFlare": ["cloudflare"],
                "AWS": ["aws", "amazon"],
                "Akamai": ["akamai"]
            }
            
            # Check headers and response content for technology indicators
            response_text = response.text.lower()
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in str(response.headers).lower() or indicator.lower() in response_text:
                        if tech not in server_info["technologies"]:
                            server_info["technologies"].append(tech)
            
        # Print server information
        if scanner.verbose:
            scanner.logger.info(f"Server: {server_info['server']}")
            scanner.logger.info(f"IP Address: {server_info['ip_address']}")
            scanner.logger.info(f"Technologies: {', '.join(server_info['technologies'])}")
            
            scanner.logger.info("HTTP Headers:")
            for header, value in server_info["headers"].items():
                scanner.logger.info(f"  {header}: {value}")
            
    except requests.exceptions.RequestException as e:
        scanner.logger.error(f"Error gathering server information: {str(e)}")
    
    return server_info 