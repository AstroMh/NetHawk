#!/usr/bin/env python3

import re
import json
from bs4 import BeautifulSoup
from termcolor import colored

def detect_tech_stack(scanner):
    """
    Detect technologies used by the target website.
    
    Args:
        scanner: The WebScanner instance
        
    Returns:
        dict: Detected technologies
    """
    tech_stack = {
        "frameworks": [],
        "languages": [],
        "servers": [],
        "cms": [],
        "javascript_libraries": [],
        "analytics": [],
        "hosting": [],
        "security": []
    }
    
    try:
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout, verify=False)
        content = response.text
        headers = response.headers
        
        # Check server information first
        if scanner.server_info.get("server"):
            server = scanner.server_info["server"]
            if "apache" in server.lower():
                tech_stack["servers"].append("Apache")
            elif "nginx" in server.lower():
                tech_stack["servers"].append("Nginx")
            elif "iis" in server.lower():
                tech_stack["servers"].append("IIS")
            elif "lighttpd" in server.lower():
                tech_stack["servers"].append("LightHTTPD")
            
        # Check headers for technologies
        if "X-Powered-By" in headers:
            powered_by = headers["X-Powered-By"]
            if "php" in powered_by.lower():
                tech_stack["languages"].append("PHP")
            elif "asp.net" in powered_by.lower():
                tech_stack["languages"].append("ASP.NET")
                tech_stack["frameworks"].append("ASP.NET")
            elif "express" in powered_by.lower():
                tech_stack["frameworks"].append("Express.js")
                tech_stack["languages"].append("JavaScript (Node.js)")
        
        # Parse HTML content with BeautifulSoup
        soup = BeautifulSoup(content, 'html.parser')
        
        # Check for JavaScript libraries
        js_libraries = {
            "jQuery": ["jquery", "jQuery"],
            "React": ["react.js", "react-dom", "reactdom"],
            "Angular": ["angular", "ng-app", "ng-controller"],
            "Vue.js": ["vue.js", "vue.min.js"],
            "Bootstrap": ["bootstrap.js", "bootstrap.min.js", "bootstrap.css"],
            "Modernizr": ["modernizr"],
            "Lodash": ["lodash.js", "lodash.min.js", "_"],
            "MooTools": ["mootools"],
            "Prototype": ["prototype.js"],
            "D3.js": ["d3.js", "d3.min.js"],
            "Chart.js": ["chart.js", "chart.min.js"],
            "Three.js": ["three.js", "three.min.js"]
        }
        
        # Check script tags
        for script in soup.find_all("script", src=True):
            src = script["src"].lower()
            for lib, patterns in js_libraries.items():
                if any(pattern.lower() in src for pattern in patterns):
                    if lib not in tech_stack["javascript_libraries"]:
                        tech_stack["javascript_libraries"].append(lib)
        
        # Check for inline scripts that might reveal technologies
        for script in soup.find_all("script"):
            script_text = script.get_text().lower()
            for lib, patterns in js_libraries.items():
                if any(pattern.lower() in script_text for pattern in patterns):
                    if lib not in tech_stack["javascript_libraries"]:
                        tech_stack["javascript_libraries"].append(lib)
        
        # Check for CMS signatures
        cms_signatures = {
            "WordPress": ["wp-content", "wp-includes", "wp-admin", "wordpress"],
            "Drupal": ["drupal", "drupal.js", "drupal.min.js", "drupal.settings"],
            "Joomla": ["joomla", "com_content", "com_users"],
            "Magento": ["magento", "Mage.Cookies", "mage/cookies.js"],
            "Shopify": ["shopify", ".myshopify.com"],
            "WooCommerce": ["woocommerce", "wc-checkout", "wc-cart"],
            "Ghost": ["ghost", "ghost-sdk", "ghost.js"],
            "Squarespace": ["squarespace", "static.squarespace.com"],
            "Wix": ["wix.com", "static.wixstatic.com"],
            "TYPO3": ["typo3", "typo3temp", "typo3conf"]
        }
        
        page_text = str(soup).lower()
        for cms, patterns in cms_signatures.items():
            if any(pattern.lower() in page_text for pattern in patterns):
                if cms not in tech_stack["cms"]:
                    tech_stack["cms"].append(cms)
        
        # Check for analytics tools
        analytics_tools = {
            "Google Analytics": ["google-analytics.com", "ga('create'", "analytics.js", "gtag"],
            "Matomo/Piwik": ["matomo", "piwik"],
            "Hotjar": ["hotjar", "hj.q", "hjSetting"],
            "Mixpanel": ["mixpanel"],
            "Kissmetrics": ["kissmetrics", "KM.identify"],
            "Adobe Analytics": ["adobe analytics", "omniture"]
        }
        
        for tool, patterns in analytics_tools.items():
            if any(pattern.lower() in page_text for pattern in patterns):
                if tool not in tech_stack["analytics"]:
                    tech_stack["analytics"].append(tool)
        
        # Check for hosting platforms
        hosting_platforms = {
            "AWS": ["amazonaws.com", "aws-region", "aws.amazon.com"],
            "Cloudflare": ["cloudflare", "cdnjs.cloudflare.com"],
            "Google Cloud": ["googleusercontent.com", "storage.googleapis.com"],
            "Heroku": ["herokuapp.com", "heroku-app"],
            "Netlify": ["netlify", "netlify.app"],
            "Vercel": ["vercel.app", "now.sh", "vercel-analytics"],
            "GitHub Pages": ["github.io", "github.com/pages"],
            "Akamai": ["akamai", "akamaiedge", "akamaihd.net"]
        }
        
        for platform, patterns in hosting_platforms.items():
            if any(pattern.lower() in page_text for pattern in patterns) or any(pattern.lower() in str(headers) for pattern in patterns):
                if platform not in tech_stack["hosting"]:
                    tech_stack["hosting"].append(platform)
        
        # Check for security tools
        security_tools = {
            "Cloudflare": ["cloudflare", "__cf", "cf-ray", "cf-cache-status"],
            "Sucuri": ["sucuri", "sucuri-firewall"],
            "ModSecurity": ["modsecurity"],
            "Imperva": ["imperva", "incapsula"],
            "Akamai": ["akamai"],
            "AWS WAF": ["aws-waf", "awswaf"]
        }
        
        for tool, patterns in security_tools.items():
            if any(pattern.lower() in str(headers) for pattern in patterns):
                if tool not in tech_stack["security"]:
                    tech_stack["security"].append(tool)
        
        # Update the scanner's technology stack
        scanner.technology_stack = tech_stack
        
        # Log detected technologies
        if scanner.verbose or len(tech_stack["frameworks"]) > 0 or len(tech_stack["cms"]) > 0:
            scanner.logger.info("Detected technologies:")
            for category, technologies in tech_stack.items():
                if technologies:
                    scanner.logger.info(f"  {category.capitalize()}: {', '.join(technologies)}")
                    
    except Exception as e:
        scanner.logger.error(f"Error detecting technology stack: {str(e)}")
    
    # Remove empty categories before returning
    filtered_tech_stack = {k: v for k, v in tech_stack.items() if v}
    
    # If everything is empty, convert to a list or keep an empty dict
    if not filtered_tech_stack:
        return []
    
    return filtered_tech_stack 