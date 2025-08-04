#!/usr/bin/env python3

import csv
import json
import os
from datetime import datetime
from termcolor import colored

def generate_report(scanner, report_format="json", output_dir="reports"):
    """
    Generate a report of scan findings.
    
    Args:
        scanner: The WebScanner instance
        report_format (str): The format of the report. Options: json, html, csv
        output_dir (str): Directory to save the report
        
    Returns:
        str: Path to the generated report
    """
    # Create reports directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # Prepare report data
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    target_domain = scanner.target_url.replace("http://", "").replace("https://", "").split("/")[0]
    report_name = f"{target_domain}_{timestamp}"
    
    # Get vulnerability descriptions
    vuln_descriptions = _get_vulnerability_descriptions()
    
    # Initialize summary statistics
    total_urls = len(scanner.discovered_urls)
    total_forms = len(scanner.forms)
    
    # Consolidate all vulnerabilities into the main vulnerabilities list
    # This ensures all vulnerabilities from all scanners are included in the report
    all_vulnerabilities = []
    
    # Add vulnerabilities from the main list
    all_vulnerabilities.extend(scanner.vulnerabilities)
    
    # Add vulnerabilities from specific scanners if they're not already in the main list
    specialized_collections = [
        scanner.xss_vulnerabilities,
        scanner.sqli_vulnerabilities,
        scanner.open_redirect_vulnerabilities,
        scanner.lfi_vulnerabilities,
        scanner.csrf_vulnerabilities,
        scanner.command_injection_vulnerabilities,
        scanner.rce_vulnerabilities,
        scanner.cors_vulnerabilities,
        scanner.ssl_tls_vulnerabilities,
        scanner.missing_headers,
        scanner.deserialization_vulnerabilities,
        scanner.xxe_vulnerabilities,
        scanner.ssrf_vulnerabilities,
        scanner.csp_vulnerabilities,
        scanner.ssti_vulnerabilities,
        scanner.idor_vulnerabilities,
        scanner.oauth_vulnerabilities,
        scanner.jwt_vulnerabilities,
        scanner.crlf_vulnerabilities,
        scanner.http_request_smuggling_vulnerabilities
    ]
    
    # Make sure we don't have duplicates
    for collection in specialized_collections:
        for vuln in collection:
            # Check if this vulnerability is already in the main list
            # We consider it a duplicate if it has the same type, URL, and evidence
            is_duplicate = False
            for existing_vuln in all_vulnerabilities:
                if (vuln.get('type') == existing_vuln.get('type') and 
                    vuln.get('url') == existing_vuln.get('url') and 
                    vuln.get('evidence') == existing_vuln.get('evidence')):
                    is_duplicate = True
                    break
            
            # If it's not a duplicate, add it to our consolidated list
            if not is_duplicate:
                all_vulnerabilities.append(vuln)
    
    total_vulns = len(all_vulnerabilities)
    
    # Count vulnerabilities by severity
    vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    vuln_types = {}
    
    # Process vulnerabilities with their descriptions and details
    processed_vulns = []
    
    # Process all vulnerabilities found
    for vuln in all_vulnerabilities:
        vuln_type = vuln.get('type', 'Unknown')
        
        if vuln_type in vuln_descriptions:
            severity = vuln_descriptions[vuln_type]["severity"]
            risk_score = vuln_descriptions[vuln_type]["risk_score"]
        else:
            severity = vuln.get('severity', 'info').lower()
            risk_score = {
                'critical': 90,
                'high': 70,
                'medium': 50,
                'low': 30,
                'info': 10
            }.get(severity, 10)
        
        processed_vuln = {
            "type": vuln_type,
            "severity": severity,
            "risk_score": risk_score,
            "url": vuln.get("url", ""),
            "parameters": vuln.get("parameter", ""),
            "payload": vuln.get("payload", ""),
            "evidence": vuln.get("evidence", ""),
            "details": vuln_descriptions.get(vuln_type, {
                "description": "No detailed description available",
                "impact": "Unknown impact",
                "remediation": "Contact security team for remediation steps",
                "cwe": "Unknown",
                "references": []
            })
        }
        
        processed_vulns.append(processed_vuln)
        vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    # Sort vulnerabilities by risk score (descending)
    processed_vulns.sort(key=lambda x: x["risk_score"], reverse=True)
    
    # Build report data structure
    tech_stack = scanner.tech_stack
    
    # Ensure tech_stack is a dictionary before including in report_data
    if isinstance(tech_stack, list):
        tech_stack = {"detected_technologies": tech_stack}
    
    report_data = {
        "scan_info": {
            "target": scanner.target_url,
            "start_time": scanner.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration": str(datetime.now() - scanner.start_time),
            "scanned_urls": total_urls,
            "forms_analyzed": total_forms
        },
        "server_info": scanner.server_info,
        "technology_stack": tech_stack,
        "statistics": {
            "total_vulnerabilities": total_vulns,
            "vulnerability_counts": vuln_counts,
            "vulnerability_types": vuln_types
        },
        "vulnerabilities": processed_vulns
    }
    
    # Generate report in the specified format
    if report_format.lower() == "json":
        report_path = os.path.join(output_dir, f"{report_name}.json")
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=4)
            
    elif report_format.lower() == "html":
        report_path = os.path.join(output_dir, f"{report_name}.html")
        _generate_html_report(report_path, report_data, vuln_descriptions)
            
    elif report_format.lower() == "csv":
        report_path = os.path.join(output_dir, f"{report_name}.csv")
        _generate_csv_report(report_path, report_data)
            
    else:  # Default to JSON if format is invalid
        report_path = os.path.join(output_dir, f"{report_name}.json")
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=4)
    
    print(colored(f"[+] Report generated: {report_path}", 'green'))
    return report_path

def _get_vulnerability_descriptions():
    """
    Return detailed descriptions for each vulnerability type.
    
    Returns:
        dict: Dictionary of vulnerability types with their descriptions, impacts, etc.
    """
    return {
        "XSS": {
            "severity": "high",
            "risk_score": 75,
            "description": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users, bypassing the same-origin policy. This can lead to session hijacking, credential theft, or delivery of malware.",
            "impact": "Attackers can steal cookies, session tokens, or other sensitive information; modify webpage content; redirect users to malicious sites; or perform actions on behalf of the victim.",
            "remediation": "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers, employ frameworks that automatically escape output, and validate all user inputs against a whitelist of allowed values.",
            "cwe": "CWE-79",
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting"
            ]
        },
        "SQL Injection": {
            "severity": "critical",
            "risk_score": 95,
            "description": "SQL Injection occurs when hostile data is inserted into SQL statements, potentially allowing attackers to view, modify, or delete data they are not normally able to access.",
            "impact": "Complete database compromise, data theft, data manipulation, authentication bypass, and in some cases, server compromise through command execution.",
            "remediation": "Use parameterized queries or prepared statements. Never build SQL commands by concatenating strings containing user input. Implement the principle of least privilege for database accounts. Employ input validation and ORM frameworks.",
            "cwe": "CWE-89",
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ]
        },
        "Open Redirect": {
            "severity": "medium",
            "risk_score": 45,
            "description": "Open Redirect vulnerabilities occur when a web application accepts untrusted input that can cause it to redirect users to arbitrary external domains, potentially facilitating phishing attacks.",
            "impact": "Enables phishing attacks by redirecting users to malicious sites that may steal credentials or distribute malware while appearing to come from a trusted source.",
            "remediation": "Implement a whitelist of allowed redirect URLs or domains. Avoid passing the full target URL in a parameter; instead, use an identifier that maps to a server-side list of allowed URLs.",
            "cwe": "CWE-601",
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/601.html"
            ]
        },
        "CSRF": {
            "severity": "medium",
            "risk_score": 55,
            "description": "Cross-Site Request Forgery (CSRF) tricks users into performing actions on a web application in which they are authenticated, by executing unwanted actions without their knowledge.",
            "impact": "Attackers can perform unauthorized actions on behalf of authenticated users, such as changing account settings, making purchases, or transferring funds.",
            "remediation": "Implement anti-CSRF tokens for all state-changing operations. Verify the Origin/Referer header for sensitive actions. Use SameSite cookies and require confirmation for sensitive actions.",
            "cwe": "CWE-352",
            "references": [
                "https://owasp.org/www-community/attacks/csrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
            ]
        },
        "Command Injection": {
            "severity": "critical",
            "risk_score": 90,
            "description": "Command Injection occurs when an application passes unsafe user-supplied data to a system shell. This allows attackers to execute arbitrary OS commands on the host system.",
            "impact": "Complete system compromise, including data theft, system modification, installation of backdoors, or use of the server for further attacks.",
            "remediation": "Avoid calling OS commands directly. Use APIs instead of system calls when possible. If OS commands are necessary, implement strict input validation and use allowlists of permitted values.",
            "cwe": "CWE-77",
            "references": [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
            ]
        },
        "LFI": {
            "severity": "high",
            "risk_score": 80,
            "description": "Local File Inclusion (LFI) allows attackers to include files on a server through the web browser, potentially exposing sensitive data or executing malicious code.",
            "impact": "Access to sensitive files such as configuration files, logs, or application source code, which may contain credentials or API keys. When combined with other vulnerabilities, it may lead to remote code execution.",
            "remediation": "Avoid passing user-supplied filenames to file operations. If unavoidable, implement strict input validation, use allowlists, and ensure files are in the expected directory.",
            "cwe": "CWE-22",
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                "https://cwe.mitre.org/data/definitions/22.html"
            ]
        },
        "RCE": {
            "severity": "critical",
            "risk_score": 95,
            "description": "Remote Code Execution (RCE) allows attackers to execute malicious code on the victim's machine, usually through vulnerabilities in applications, upload functionality, or deserialization issues.",
            "impact": "Complete system compromise, data theft, lateral movement within the network, deployment of ransomware, or creation of persistent backdoors.",
            "remediation": "Apply regular security updates to all software. Implement proper input validation and sanitization. Restrict file upload functionality and use content type validation. Avoid using unsafe deserialization of user inputs.",
            "cwe": "CWE-94",
            "references": [
                "https://cwe.mitre.org/data/definitions/94.html",
                "https://owasp.org/www-community/vulnerabilities/Unsafe_Code_Injection"
            ]
        },
        "CORS": {
            "severity": "medium",
            "risk_score": 60,
            "description": "Cross-Origin Resource Sharing (CORS) misconfigurations can allow malicious websites to interact with your API or website in ways that should not be allowed, potentially leading to data theft.",
            "impact": "Information leakage, unauthorized access to sensitive data, and potential credential theft when combined with other vulnerabilities.",
            "remediation": "Configure CORS headers to only allow trusted domains. Avoid using wildcard origins for sensitive endpoints. Set appropriate values for Access-Control-Allow-Credentials and other CORS headers.",
            "cwe": "CWE-942",
            "references": [
                "https://portswigger.net/web-security/cors",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html"
            ]
        },
        "SSL/TLS": {
            "severity": "medium",
            "risk_score": 50,
            "description": "SSL/TLS vulnerabilities include weak cipher suites, protocol versions, certificate issues, or known cryptographic flaws that can compromise the secure communication channel.",
            "impact": "Man-in-the-middle attacks, information disclosure, or complete bypass of encryption, allowing attackers to view or modify sensitive data in transit.",
            "remediation": "Configure servers to use modern, secure TLS protocol versions and cipher suites. Implement HSTS. Regularly update SSL libraries and ensure proper certificate validation.",
            "cwe": "CWE-295",
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                "https://www.ssllabs.com/projects/best-practices/"
            ]
        },
        "Missing HTTP Security Headers": {
            "severity": "low",
            "risk_score": 35,
            "description": "HTTP security headers provide an additional layer of defense against various attacks by instructing browsers on how to handle website content. Missing security headers can expose the application to attacks that could otherwise be prevented.",
            "impact": "Depending on the missing headers, impacts may include clickjacking, XSS, information disclosure, or data theft via code injection.",
            "remediation": "Implement appropriate security headers like Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, and Referrer-Policy.",
            "cwe": "CWE-693",
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                "https://owasp.org/www-project-secure-headers/"
            ]
        },
        "Deserialization": {
            "severity": "critical",
            "risk_score": 85,
            "description": "Insecure Deserialization occurs when an application deserializes untrusted data without proper validation, potentially allowing attackers to manipulate serialized objects to achieve code execution, bypass authentication, or perform denial of service attacks.",
            "impact": "Remote code execution, authentication bypass, object and data structure manipulation, denial of service, and in many cases complete system compromise.",
            "remediation": "Avoid deserializing data from untrusted sources. If unavoidable, implement integrity checks, type checks, and proper validation. Use serialization formats that don't allow code execution (like JSON). Consider using runtime application self-protection (RASP) technologies.",
            "cwe": "CWE-502",
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
                "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
                "https://portswigger.net/web-security/deserialization"
            ]
        },
        "CSP": {
            "severity": "medium",
            "risk_score": 45,
            "description": "Content Security Policy (CSP) misconfigurations or missing policies can allow execution of malicious scripts, enable clickjacking, or permit other client-side attacks that CSP is designed to prevent.",
            "impact": "Cross-site scripting (XSS), data exfiltration, and other client-side attacks that could be prevented with proper CSP implementation.",
            "remediation": "Implement a strict Content Security Policy that follows the principle of least privilege. Avoid unsafe-inline and unsafe-eval. Use nonces or hashes for inline scripts when necessary. Regularly test and update CSP rules.",
            "cwe": "CWE-1021",
            "references": [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                "https://content-security-policy.com/"
            ]
        },
        "SSL Certificate Issues": {
            "severity": "medium",
            "risk_score": 55,
            "description": "Problems with SSL certificates, such as expiration, mismatched domain names, self-signed certificates, or untrusted certificate authorities, can compromise the security of encrypted communications.",
            "impact": "Loss of trust by users, browser security warnings, potential for man-in-the-middle attacks, and information disclosure.",
            "remediation": "Use certificates from trusted certificate authorities. Configure certificates correctly with proper domain names. Implement automatic certificate renewal. Use modern cryptographic algorithms and key lengths.",
            "cwe": "CWE-295",
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                "https://www.ssllabs.com/projects/best-practices/"
            ]
        },
        "Heartbleed": {
            "severity": "critical",
            "risk_score": 90,
            "description": "Heartbleed is a serious vulnerability in the OpenSSL cryptographic software library that allows attackers to read memory from vulnerable systems, potentially exposing sensitive data like private keys and passwords.",
            "impact": "Exposure of sensitive information including private keys, passwords, and other secrets stored in memory, potentially enabling further attacks.",
            "remediation": "Update OpenSSL to a patched version. Regenerate all SSL certificates and private keys. Force password changes for all users after remediation.",
            "cwe": "CWE-126",
            "references": [
                "https://heartbleed.com/",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160",
                "https://www.synopsys.com/software-integrity/security-testing/fuzz-testing/defensics/ssl-tls-protocol-test-suites/heartbleed-test-tool.html"
            ]
        },
        "SSRF": {
            "severity": "high",
            "risk_score": 75,
            "description": "Server-Side Request Forgery (SSRF) allows attackers to induce the server-side application to make requests to unintended locations, potentially bypassing network access controls and accessing internal services.",
            "impact": "Access to internal services that shouldn't be publicly accessible, data exfiltration, port scanning of internal networks, and in some cases, remote code execution.",
            "remediation": "Implement strict input validation and allowlists for URLs and domain names. Use a server-side proxy for HTTP requests. Disable unused URL schemas. Configure firewall rules to restrict outbound connections from the server.",
            "cwe": "CWE-918",
            "references": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://portswigger.net/web-security/ssrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
            ]
        },
        "XXE": {
            "severity": "high",
            "risk_score": 80,
            "description": "XML External Entity (XXE) attacks occur when XML input containing a reference to an external entity is processed by a weakly configured XML parser, leading to disclosure of confidential data or server-side request forgery.",
            "impact": "Disclosure of sensitive files, server-side request forgery, denial of service, and potentially remote code execution in certain circumstances.",
            "remediation": "Disable XML external entity and DTD processing in XML parsers. Use less complex data formats like JSON. Patch or upgrade XML parsers. Implement server-side input validation and sanitize user-supplied XML.",
            "cwe": "CWE-611",
            "references": [
                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/xxe"
            ]
        },
        "Directory Traversal": {
            "severity": "high",
            "risk_score": 75,
            "description": "Directory traversal (also known as path traversal) allows attackers to access files and directories stored outside the intended directory by manipulating variables that reference files with dot-dot-slash (../) sequences or similar techniques.",
            "impact": "Unauthorized access to sensitive files, including configuration files, password files, and other critical system files, potentially leading to information disclosure or system compromise.",
            "remediation": "Validate and sanitize user input for directory traversal sequences. Use proper access controls and sandboxing. Implement a whitelist of allowed files or directories. Avoid passing user input directly to file system operations.",
            "cwe": "CWE-22",
            "references": [
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://portswigger.net/web-security/file-path-traversal",
                "https://cwe.mitre.org/data/definitions/22.html"
            ]
        },
        "Remote Code Execution (RCE)": {
            "severity": "critical",
            "risk_score": 95,
            "description": "Remote Code Execution (RCE) allows attackers to execute malicious code on the victim's machine, usually through vulnerabilities in applications, upload functionality, or deserialization issues.",
            "impact": "Complete system compromise, data theft, lateral movement within the network, deployment of ransomware, or creation of persistent backdoors.",
            "remediation": "Apply regular security updates to all software. Implement proper input validation and sanitization. Restrict file upload functionality and use content type validation. Avoid using unsafe deserialization of user inputs.",
            "cwe": "CWE-94",
            "references": [
                "https://cwe.mitre.org/data/definitions/94.html",
                "https://owasp.org/www-community/vulnerabilities/Unsafe_Code_Injection"
            ]
        },
        "SSTI": {
            "severity": "high",
            "risk_score": 80,
            "description": "Server-Side Template Injection (SSTI) occurs when user input is embedded directly into server-side templates, allowing attackers to inject malicious template code that can lead to remote code execution, file system access, and other server-side attacks.",
            "impact": "Remote code execution, server-side file read/write operations, access to sensitive information, and complete compromise of the application or hosting environment.",
            "remediation": "Never allow user input to be directly used in template syntax. Implement proper input validation and sanitization. Use sandboxed templating environments. Consider using template systems that have security features built-in.",
            "cwe": "CWE-94",
            "references": [
                "https://portswigger.net/research/server-side-template-injection",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
                "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection"
            ]
        },
        "IDOR": {
            "severity": "high",
            "risk_score": 75,
            "description": "Insecure Direct Object Reference vulnerabilities allow attackers to access or modify unauthorized resources by manipulating object references.",
            "impact": "Unauthorized access to sensitive data or system compromise.",
            "remediation": "Implement proper access controls and validation for object references. Use whitelists or allowlists for object access.",
            "cwe": "CWE-639",
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Insecure_Direct_Object_Reference",
                "https://cwe.mitre.org/data/definitions/639.html"
            ]
        },
        "OAuth": {
            "severity": "high",
            "risk_score": 70,
            "description": "OAuth vulnerabilities occur when the implementation of the OAuth protocol is flawed, allowing attackers to steal tokens, forge requests, or bypass authentication.",
            "impact": "Unauthorized access to protected resources, account takeover, identity theft, and data breaches.",
            "remediation": "Implement proper OAuth flows, validate redirect URIs, use the state parameter to prevent CSRF, implement PKCE for public clients, and validate tokens properly.",
            "cwe": "CWE-352",
            "references": [
                "https://oauth.net/2/",
                "https://tools.ietf.org/html/rfc6749",
                "https://portswigger.net/web-security/oauth"
            ]
        },
        "JWT": {
            "severity": "high",
            "risk_score": 75,
            "description": "JSON Web Token (JWT) vulnerabilities occur when the implementation of JWT authentication is flawed, allowing attackers to forge tokens, bypass signature verification, or exploit weak cryptographic keys.",
            "impact": "Authentication bypass, unauthorized access to protected resources, privilege escalation, and impersonation of other users.",
            "remediation": "Implement proper token validation, use strong encryption keys, validate all claims including expiration, and avoid using the 'none' algorithm. Ensure the server properly validates signatures and doesn't accept tokens with manipulated headers.",
            "cwe": "CWE-347",
            "references": [
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                "https://portswigger.net/web-security/jwt"
            ]
        },
        "CRLF Injection": {
            "severity": "medium",
            "risk_score": 60,
            "description": "CRLF (Carriage Return Line Feed) Injection vulnerabilities occur when an attacker can inject CR and LF characters into HTTP responses, allowing header splitting and potentially leading to cross-site scripting, cache poisoning, or cookie-based attacks.",
            "impact": "HTTP response splitting, cross-site scripting, cache poisoning, cookie manipulation, and HTTP response header injection.",
            "remediation": "Implement proper input validation and output encoding. Filter or encode CR and LF characters (\\r, \\n) in user input. Use libraries that handle HTTP headers safely and prevent header splitting.",
            "cwe": "CWE-113",
            "references": [
                "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                "https://portswigger.net/kb/issues/00200200_http-response-header-injection",
                "https://cwe.mitre.org/data/definitions/113.html"
            ]
        },
        "HTTP Request Smuggling": {
            "severity": "high",
            "risk_score": 80,
            "description": "HTTP Request Smuggling vulnerabilities exploit inconsistencies in how front-end and back-end servers parse HTTP requests, allowing attackers to 'smuggle' malicious requests that bypass security controls.",
            "impact": "Web cache poisoning, bypassing security controls, gaining unauthorized access to sensitive data, session hijacking, and credential stealing.",
            "remediation": "Ensure consistent HTTP request parsing between front-end and back-end servers. Validate Content-Length and Transfer-Encoding headers properly. Use HTTP/2 where possible, as it has more strict parsing rules.",
            "cwe": "CWE-444",
            "references": [
                "https://portswigger.net/web-security/request-smuggling",
                "https://owasp.org/www-community/attacks/HTTP_Request_Smuggling",
                "https://cwe.mitre.org/data/definitions/444.html"
            ]
        }
    }

def _generate_csv_report(report_path, report_data):
    """
    Generate a CSV report of vulnerabilities.
    
    Args:
        report_path (str): Path to write the CSV report to
        report_data (dict): Data to include in the report
    """
    with open(report_path, 'w', newline='') as csvfile:
        # Get server information and technology stack
        server_info = report_data.get('server_info', {})
        tech_stack = report_data.get('technology_stack', {})
        
        # Ensure tech_stack is a dictionary to prevent "'list' object has no attribute 'items'" error
        if isinstance(tech_stack, list):
            # Convert list to dictionary with a default category
            tech_stack = {"detected_technologies": tech_stack}
            
        writer = csv.writer(csvfile)
        
        # Report Header
        writer.writerow(['NetHawk Penetration Test Report'])
        writer.writerow([''])
        
        # Target Information Section
        writer.writerow(['TARGET INFORMATION'])
        writer.writerow(['Target URL', report_data['scan_info']['target']])
        writer.writerow(['Scan Start Time', report_data['scan_info']['start_time']])
        writer.writerow(['Scan Duration', report_data['scan_info']['scan_duration']])
        writer.writerow(['URLs Scanned', report_data['scan_info']['scanned_urls']])
        writer.writerow(['Forms Analyzed', report_data['scan_info']['forms_analyzed']])
        writer.writerow(['Total Vulnerabilities', report_data['statistics']['total_vulnerabilities']])
        writer.writerow([''])
        
        # Server Information Section
        writer.writerow(['SERVER INFORMATION'])
        writer.writerow(['IP Address', server_info.get('ip_address', 'Unknown')])
        writer.writerow(['Server Type', server_info.get('server', 'Unknown')])
        writer.writerow(['Host', report_data['scan_info']['target'].replace("http://", "").replace("https://", "").split("/")[0]])
        writer.writerow(['Protocol', report_data['scan_info']['target'].split("://")[0].upper()])
        
        # Add more detailed server information
        writer.writerow(['Operating System', server_info.get('os', 'Unknown')])
        writer.writerow(['Server Software', server_info.get('server_software', 'Unknown')])
        writer.writerow(['Server Version', server_info.get('server_version', 'Unknown')])
        writer.writerow(['Web Framework', server_info.get('framework', 'Unknown')])
        
        # Add DNS information if available
        if 'dns_records' in server_info:
            writer.writerow(['DNS Records', 'See below'])
            for record_type, values in server_info.get('dns_records', {}).items():
                if isinstance(values, list):
                    writer.writerow([f'  {record_type}', ', '.join(str(v) for v in values)])
                else:
                    writer.writerow([f'  {record_type}', str(values)])
                    
        writer.writerow(['Technologies Detected', ', '.join(server_info.get('technologies', ['None detected']))])
        writer.writerow([''])
        
        # HTTP Headers Section
        writer.writerow(['HTTP HEADERS'])
        writer.writerow(['Header Name', 'Value', 'Security Implications'])
        
        # Important security headers to check
        security_headers = {
            "Content-Security-Policy": "Helps prevent XSS and other code injection attacks",
            "X-XSS-Protection": "Provides protection against some types of XSS attacks",
            "X-Content-Type-Options": "Prevents MIME-type sniffing attacks",
            "X-Frame-Options": "Prevents clickjacking attacks",
            "Strict-Transport-Security": "Enforces secure (HTTPS) connections",
            "Referrer-Policy": "Controls how much referrer information should be included with requests",
            "Permissions-Policy": "Controls which browser features can be used (formerly Feature-Policy)"
        }
        
        # First list any security headers that are present
        headers = server_info.get('headers', {})
        for header, implication in security_headers.items():
            if header in headers:
                writer.writerow([header, headers[header], implication])
            else:
                writer.writerow([header, 'MISSING - Security risk', implication])
        
        # List all other headers
        for header_name, header_value in headers.items():
            if header_name not in security_headers:
                writer.writerow([header_name, header_value, ''])
        
        writer.writerow([''])
        
        # Technology Stack Section
        writer.writerow(['TECHNOLOGY STACK INFORMATION'])
        if tech_stack:
            for category, technologies in tech_stack.items():
                category_display = category.replace('_', ' ').capitalize()
                
                if isinstance(technologies, list) and technologies:
                    # Handle both string items and dictionary items with versions
                    tech_items = []
                    for item in technologies:
                        if isinstance(item, dict):
                            name = item.get('name', 'Unknown')
                            version = item.get('version', 'Unknown version')
                            tech_items.append(f"{name} ({version})")
                        else:
                            tech_items.append(str(item))
                    
                    writer.writerow([category_display, ', '.join(tech_items)])
                else:
                    writer.writerow([category_display, 'None detected'])
        else:
            writer.writerow(['Detected Technologies', 'None detected'])
            
        writer.writerow([''])
        
        # Vulnerability Summary Section
        writer.writerow(['VULNERABILITY SUMMARY'])
        writer.writerow(['Severity', 'Count', 'Risk Level'])
        severity_risk = {
            'critical': 'Immediate action required',
            'high': 'Urgent attention needed',
            'medium': 'Should be addressed soon',
            'low': 'Remediate when possible',
            'info': 'Informational finding'
        }
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = report_data['statistics']['vulnerability_counts'].get(severity, 0)
            risk = severity_risk.get(severity)
            writer.writerow([severity.capitalize(), count, risk])
        writer.writerow([''])
        
        # Vulnerability Types Section
        writer.writerow(['VULNERABILITY TYPES'])
        writer.writerow(['Type', 'Count', 'Highest Severity'])
        for vuln_type, count in report_data['statistics']['vulnerability_types'].items():
            # Find highest severity for this vulnerability type
            highest_severity = "Info"
            highest_score = 0
            
            for vuln in report_data['vulnerabilities']:
                if vuln.get('type') == vuln_type:
                    score = vuln.get('risk_score', 0)
                    if score > highest_score:
                        highest_score = score
                        highest_severity = vuln.get('severity', 'Info').capitalize()
                        
            writer.writerow([vuln_type, count, highest_severity])
        writer.writerow([''])
        
        # Vulnerability Details Section
        writer.writerow(['VULNERABILITY DETAILS'])
        writer.writerow(['Type', 'Severity', 'Risk Score', 'URL', 'Method', 'Parameter', 'Payload', 'Evidence', 'Description', 'Impact', 'Remediation', 'CWE', 'References'])
        
        for vuln in report_data['vulnerabilities']:
            details = vuln.get('details', {})
            references = '; '.join(details.get('references', []))
            
            writer.writerow([
                vuln.get('type', ''),
                vuln.get('severity', '').capitalize(),
                vuln.get('risk_score', ''),
                vuln.get('url', ''),
                vuln.get('method', 'GET'),
                vuln.get('parameter', vuln.get('parameters', '')),
                vuln.get('payload', ''),
                vuln.get('evidence', ''),
                details.get('description', ''),
                details.get('impact', ''),
                details.get('remediation', ''),
                details.get('cwe', ''),
                references
            ])

def _generate_html_report(report_path, report_data, vuln_descriptions):
    """
    Generate an HTML report of vulnerabilities.
    
    Args:
        report_path (str): Path to write the HTML report to
        report_data (dict): Data to include in the report
        vuln_descriptions (dict): Descriptions for various vulnerability types
    """
    # Get server information
    server_info = report_data.get('server_info', {})
    tech_stack = report_data.get('technology_stack', {})
    
    # Ensure tech_stack is a dictionary to prevent "'list' object has no attribute 'items'" error
    if isinstance(tech_stack, list):
        # Convert list to dictionary with a default category
        tech_stack = {"detected_technologies": tech_stack}
    
    # Get current date for report
    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetHawk Penetration Test Report for {report_data['scan_info']['target']}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3, h4 {{
            color: #2c3e50;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .summary, .server-info, .tech-info, .network-info, .section {{
            background-color: #f8f9fa;
            border-left: 4px solid #4285f4;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }}
        .tech-info {{
            background-color: #f0f8ff;
            border-left: 4px solid #4285f4;
        }}
        .network-info {{
            background-color: #f0fff0;
            border-left: 4px solid #20c997;
        }}
        .vulnerability {{
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 15px;
        }}
        .critical {{
            border-left: 5px solid #dc3545;
        }}
        .high {{
            border-left: 5px solid #fd7e14;
        }}
        .medium {{
            border-left: 5px solid #ffc107;
        }}
        .low {{
            border-left: 5px solid #20c997;
        }}
        .info {{
            border-left: 5px solid #0dcaf0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        .method-item {{
            margin-bottom: 10px;
            padding: 5px;
            background-color: #f8f9fa;
            border-radius: 4px;
        }}
        .references {{
            margin-top: 10px;
        }}
        .references a {{
            display: block;
            margin-bottom: 5px;
            color: #0366d6;
            text-decoration: none;
        }}
        .references a:hover {{
            text-decoration: underline;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            border-bottom: 2px solid #4285f4;
            padding-bottom: 10px;
        }}
        .logo {{
            font-size: 24px;
            font-weight: bold;
            color: #4285f4;
        }}
        .report-meta {{
            text-align: right;
            font-size: 14px;
        }}
        .severity-count {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            margin-right: 5px;
        }}
        .critical-bg {{
            background-color: #dc3545;
        }}
        .high-bg {{
            background-color: #fd7e14;
        }}
        .medium-bg {{
            background-color: #ffc107;
            color: #333;
        }}
        .low-bg {{
            background-color: #20c997;
        }}
        .info-bg {{
            background-color: #0dcaf0;
        }}
        .recommendation {{
            background-color: #fffdeb;
            border-left: 4px solid #ffd54f;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }}
        .severity-legend {{
            display: flex;
            justify-content: flex-start;
            margin-bottom: 20px;
        }}
        .severity-item {{
            display: flex;
            align-items: center;
            margin-right: 15px;
        }}
        .severity-color {{
            width: 16px;
            height: 16px;
            margin-right: 5px;
            display: inline-block;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            background-color: #e9ecef;
            margin-right: 5px;
            font-size: 12px;
        }}
        .code {{
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 8px;
            border-radius: 4px;
        }}
        .header-table {{
            width: 100%;
            margin-bottom: 10px;
        }}
        .header-table td {{
            vertical-align: top;
            padding: 4px 8px;
            border: none;
        }}
        .header-table tr {{
            border: none;
        }}
        .header-name {{
            font-weight: bold;
            width: 30%;
        }}
        .pie-chart-container {{
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
        }}
        .half-section {{
            width: 48%;
            display: inline-block;
            vertical-align: top;
            margin-right: 2%;
        }}
        .tech-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-top: 10px;
        }}
        .tech-card {{
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
        }}
        .tech-card h4 {{
            margin-top: 0;
            color: #4285f4;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }}
        .security-header {{
            background-color: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 5px 10px;
            margin-bottom: 10px;
        }}
        .missing-header {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 5px 10px;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                NetHawk
            </div>
            <div class="report-meta">
                <p><strong>Report Generated:</strong> {current_date}</p>
                <p><strong>Target:</strong> {report_data['scan_info']['target']}</p>
            </div>
        </div>
        
        <h1>Web Application Penetration Test Report</h1>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>This report details the findings of an automated security assessment performed on {report_data['scan_info']['target']}. The assessment identified {report_data['statistics']['total_vulnerabilities']} potential security vulnerabilities that may put the application at risk.</p>
            
            <div class="severity-legend">
                <div class="severity-item">
                    <div class="severity-color" style="background-color: #dc3545;"></div>
                    <div>Critical: {report_data['statistics']['vulnerability_counts'].get('critical', 0)}</div>
                </div>
                <div class="severity-item">
                    <div class="severity-color" style="background-color: #fd7e14;"></div>
                    <div>High: {report_data['statistics']['vulnerability_counts'].get('high', 0)}</div>
                </div>
                <div class="severity-item">
                    <div class="severity-color" style="background-color: #ffc107;"></div>
                    <div>Medium: {report_data['statistics']['vulnerability_counts'].get('medium', 0)}</div>
                </div>
                <div class="severity-item">
                    <div class="severity-color" style="background-color: #20c997;"></div>
                    <div>Low: {report_data['statistics']['vulnerability_counts'].get('low', 0)}</div>
                </div>
                <div class="severity-item">
                    <div class="severity-color" style="background-color: #0dcaf0;"></div>
                    <div>Info: {report_data['statistics']['vulnerability_counts'].get('info', 0)}</div>
                </div>
            </div>
            
            <div class="pie-chart-container">
                <div style="width: 400px; height: 200px;">
                    <canvas id="vulnerabilityChart" width="400" height="200"></canvas>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Scope of Assessment</h2>
            <table>
                <tr>
                    <th>Target URL</th>
                    <td>{report_data['scan_info']['target']}</td>
                </tr>
                <tr>
                    <th>Scan Start Time</th>
                    <td>{report_data['scan_info']['start_time']}</td>
                </tr>
                <tr>
                    <th>Scan Duration</th>
                    <td>{report_data['scan_info']['scan_duration']}</td>
                </tr>
                <tr>
                    <th>URLs Scanned</th>
                    <td>{report_data['scan_info']['scanned_urls']}</td>
                </tr>
                <tr>
                    <th>Forms Analyzed</th>
                    <td>{report_data['scan_info']['forms_analyzed']}</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Target Reconnaissance</h2>
            
            <div class="network-info">
                <h3>Network Information</h3>
                <table>
                    <tr>
                        <th>Host</th>
                        <td>{report_data['scan_info']['target'].replace("http://", "").replace("https://", "").split("/")[0]}</td>
                    </tr>
                    <tr>
                        <th>IP Address</th>
                        <td>{server_info.get('ip_address', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <th>Server Type</th>
                        <td>{server_info.get('server', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <th>Protocol</th>
                        <td>{report_data['scan_info']['target'].split("://")[0].upper()}</td>
                    </tr>
                    <tr>
                        <th>Operating System</th>
                        <td>{server_info.get('os', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <th>Server Software</th>
                        <td>{server_info.get('server_software', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <th>Server Version</th>
                        <td>{server_info.get('server_version', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <th>Web Framework</th>
                        <td>{server_info.get('framework', 'Unknown')}</td>
                    </tr>
                </table>
                
                {
                ''.join([
                f"""
                <h4>DNS Records</h4>
                <table>
                {''.join([
                    f"""
                    <tr>
                        <th>{record_type}</th>
                        <td>{'<br>'.join(str(v) for v in values) if isinstance(values, list) else str(values)}</td>
                    </tr>
                    """ for record_type, values in server_info.get('dns_records', {}).items()
                ])}
                </table>
                """ if 'dns_records' in server_info and server_info['dns_records'] else ''
                ])
                }
            </div>
            
            <div class="server-info">
                <h3>HTTP Headers Analysis</h3>
                <p>The following headers were identified during the scan. Security-related headers are highlighted when missing or misconfigured.</p>
                
                <table class="header-table">
                    <tr>
                        <th>Header Name</th>
                        <th>Value</th>
                        <th>Security Implications</th>
                    </tr>
"""
    
    # Security headers to check
    important_security_headers = {
        "Content-Security-Policy": "Helps prevent XSS and other code injection attacks",
        "X-XSS-Protection": "Provides protection against some types of XSS attacks",
        "X-Content-Type-Options": "Prevents MIME-type sniffing attacks",
        "X-Frame-Options": "Prevents clickjacking attacks",
        "Strict-Transport-Security": "Enforces secure (HTTPS) connections",
        "Referrer-Policy": "Controls how much referrer information should be included with requests",
        "Permissions-Policy": "Controls which browser features can be used (formerly Feature-Policy)"
    }
    
    # Add HTTP headers with security impact information
    headers = server_info.get('headers', {})
    for header_name, header_value in headers.items():
        security_impact = ""
        header_class = ""
        
        # Check if it's a security header and provide relevant information
        if header_name in important_security_headers:
            security_impact = important_security_headers[header_name]
            header_class = "security-header"
        
        html_content += f"""
                    <tr class="{header_class}">
                        <td class="header-name">{header_name}</td>
                        <td>{header_value}</td>
                        <td>{security_impact}</td>
                    </tr>"""
    
    # Check for missing security headers
    for header_name, impact in important_security_headers.items():
        if header_name not in headers:
            html_content += f"""
                    <tr class="missing-header">
                        <td class="header-name">{header_name}</td>
                        <td><em>Missing</em></td>
                        <td>{impact} - <strong>Missing security header</strong></td>
                    </tr>"""
    
    html_content += """
                </table>
            </div>
            
            <div class="tech-info">
                <h3>Technology Stack Analysis</h3>
                <p>The following technologies were detected during the scan. This information can be used to identify potential vulnerabilities specific to the software stack.</p>
                
                <div class="tech-grid">
"""

    # Create a card for each technology category
    if tech_stack:
        if isinstance(tech_stack, dict):
            for category, items in tech_stack.items():
                if items:
                    category_display = category.replace("_", " ").capitalize()
                    html_content += f"""
                            <div class="tech-card">
                                <h4>{category_display}</h4>
                                <ul>
    """
                    # Handle both string items and dictionary items with versions
                    for item in items:
                        if isinstance(item, dict):
                            name = item.get('name', 'Unknown')
                            version = item.get('version', 'Unknown version')
                            html_content += f"""
                                    <li>{name} ({version})</li>"""
                        else:
                            html_content += f"""
                                    <li>{item}</li>"""
                    html_content += """
                                </ul>
                            </div>
    """
        elif isinstance(tech_stack, list):
            html_content += f"""
                    <div class="tech-card">
                        <h4>Detected Technologies</h4>
                        <ul>
            """
            for item in tech_stack:
                if isinstance(item, dict):
                    name = item.get('name', 'Unknown')
                    version = item.get('version', 'Unknown version')
                    html_content += f"""
                            <li>{name} ({version})</li>"""
                else:
                    html_content += f"""
                            <li>{item}</li>"""
            html_content += """
                        </ul>
                    </div>
            """
        
    # If no technologies were detected, add a note
    if not tech_stack or (isinstance(tech_stack, dict) and all(len(items) == 0 for category, items in tech_stack.items())) or (isinstance(tech_stack, list) and len(tech_stack) == 0):
        html_content += """
                    <div class="tech-card">
                        <h4>No technologies detected</h4>
                        <p>The scanner could not definitively identify technologies in use. Manual reconnaissance might be required.</p>
                    </div>
"""

    html_content += """
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Scan Methods Performed</h2>
            <div class="method-item">
                <h3>🔍 Information Gathering</h3>
                <ul>
                    <li>Server Information Analysis</li>
                    <li>Technology Stack Detection</li>
                    <li>Subdomain Enumeration</li>
                </ul>
            </div>
            
            <div class="method-item">
                <h3>🕸️ Crawling & Discovery</h3>
                <ul>
                    <li>URL Discovery</li>
                    <li>Form Detection</li>
                    <li>Directory Bruteforce</li>
                </ul>
            </div>
            
            <div class="method-item">
                <h3>🔒 Security Configuration Analysis</h3>
                <ul>
                    <li>HTTP Security Headers Check</li>
                    <li>SSL/TLS Configuration Analysis</li>
                    <li>Content Security Policy (CSP) Evaluation</li>
                    <li>Cross-Origin Resource Sharing (CORS) Analysis</li>
                </ul>
            </div>
            
            <div class="method-item">
                <h3>⚠️ Vulnerability Scanning</h3>
                <ul>
                    <li>Cross-Site Scripting (XSS) Detection</li>
                    <li>SQL Injection Testing</li>
                    <li>Command Injection Analysis</li>
                    <li>Local File Inclusion (LFI) Testing</li>
                    <li>Remote Code Execution (RCE) Testing</li>
                    <li>Cross-Site Request Forgery (CSRF) Detection</li>
                    <li>Open Redirect Analysis</li>
                    <li>Insecure Deserialization Detection</li>
                    <li>XML External Entity (XXE) Testing</li>
                    <li>Server-Side Request Forgery (SSRF) Analysis</li>
                    <li>Insecure Direct Object References (IDOR) Testing</li>
                    <li>Server-Side Template Injection (SSTI) Testing</li>
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>Vulnerability Summary</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                    <th>Risk Level</th>
                </tr>
                <tr>
                    <td>Critical</td>
                    <td>{report_data['statistics']['vulnerability_counts'].get('critical', 0)}</td>
                    <td>
                        <div class="severity-count critical-bg">
                            Immediate action required
                        </div>
                    </td>
                </tr>
                <tr>
                    <td>High</td>
                    <td>{report_data['statistics']['vulnerability_counts'].get('high', 0)}</td>
                    <td>
                        <div class="severity-count high-bg">
                            Urgent attention needed
                        </div>
                    </td>
                </tr>
                <tr>
                    <td>Medium</td>
                    <td>{report_data['statistics']['vulnerability_counts'].get('medium', 0)}</td>
                    <td>
                        <div class="severity-count medium-bg">
                            Should be addressed soon
                        </div>
                    </td>
                </tr>
                <tr>
                    <td>Low</td>
                    <td>{report_data['statistics']['vulnerability_counts'].get('low', 0)}</td>
                    <td>
                        <div class="severity-count low-bg">
                            Remediate when possible
                        </div>
                    </td>
                </tr>
                <tr>
                    <td>Info</td>
                    <td>{report_data['statistics']['vulnerability_counts'].get('info', 0)}</td>
                    <td>
                        <div class="severity-count info-bg">
                            Informational finding
                        </div>
                    </td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Vulnerabilities by Type</h2>
            <table>
                <tr>
                    <th>Vulnerability Type</th>
                    <th>Count</th>
                    <th>Highest Severity</th>
                </tr>
    """
    
    # Add vulnerability types information
    for vuln_type, count in report_data['statistics']['vulnerability_types'].items():
        # Find highest severity for this vulnerability type
        highest_severity = "Info"
        highest_score = 0
        
        for vuln in report_data['vulnerabilities']:
            if vuln.get('type') == vuln_type:
                score = vuln.get('risk_score', 0)
                if score > highest_score:
                    highest_score = score
                    highest_severity = vuln.get('severity', 'Info').capitalize()
        
        severity_class = highest_severity.lower() + "-bg"
        
        html_content += f"""
            <tr>
                <td>{vuln_type}</td>
                <td>{count}</td>
                <td><div class="severity-count {severity_class}">{highest_severity}</div></td>
            </tr>"""
    
    html_content += """
        </table>
        </div>
        
        <div class="section">
            <h2>Detailed Findings</h2>
    """
    
    # Group vulnerabilities by severity
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    for severity in severity_order:
        severity_vulns = [v for v in report_data['vulnerabilities'] if v.get('severity', '').lower() == severity]
        
        if not severity_vulns:
            continue
            
        html_content += f"""
            <h3>{severity.capitalize()} Severity Vulnerabilities</h3>
        """
        
        # Add each vulnerability to the report
        for vuln in severity_vulns:
            vuln_type = vuln.get('type', 'Unknown')
            details = vuln.get('details', {})
            
            html_content += f"""
            <div class="vulnerability {severity}">
                <h3>{vuln_type}</h3>
                <table>
                    <tr>
                        <th>URL</th>
                        <td>{vuln.get('url', '')}</td>
                    </tr>
                    <tr>
                        <th>Method</th>
                        <td>{vuln.get('method', 'GET')}</td>
                    </tr>
                    <tr>
                        <th>Parameter</th>
                        <td>{vuln.get('parameter', vuln.get('parameters', ''))}</td>
                    </tr>
                    <tr>
                        <th>Severity</th>
                        <td><div class="severity-count {severity}-bg">{severity.capitalize()}</div></td>
                    </tr>
                    <tr>
                        <th>Risk Score</th>
                        <td>{vuln.get('risk_score', '')}</td>
                    </tr>
                </table>
                
                <h4>Description</h4>
                <p>{details.get('description', 'No description available')}</p>
                
                <h4>Evidence</h4>
                <div class="code">{vuln.get('evidence', 'No evidence available')}</div>
                
                <h4>Payload Used</h4>
                <div class="code">{vuln.get('payload', 'No payload information available')}</div>
                
                <h4>Impact</h4>
                <p>{details.get('impact', 'No impact information available')}</p>
                
                <h4>Remediation</h4>
                <div class="recommendation">
                    <p>{details.get('remediation', 'No remediation information available')}</p>
                </div>
                
                <h4>CWE</h4>
                <p><span class="badge">{details.get('cwe', 'No CWE information available')}</span></p>
                
                <h4>References</h4>
                <div class="references">
            """
            
            for ref in details.get('references', []):
                html_content += f"<a href='{ref}' target='_blank'>{ref}</a>"
                
            if not details.get('references'):
                html_content += "<p>No references available</p>"
                
            html_content += """
                </div>
            </div>
            """
    
    html_content += """
        </div>
        
        <div class="section">
            <h2>Security Recommendations</h2>
            <div class="recommendation">
                <h3>Critical Priorities</h3>
                <ul>
"""
    
    # Generate recommendations based on vulnerability types
    critical_recs = []
    high_recs = []
    medium_recs = []
    
    vuln_types = report_data['statistics']['vulnerability_types'].keys()
    
    # Add recommendations based on vulnerability types found
    for vuln_type in vuln_types:
        if vuln_type in vuln_descriptions:
            severity = vuln_descriptions[vuln_type]["severity"]
            remediation = vuln_descriptions[vuln_type]["remediation"]
            
            rec = f"<li><strong>{vuln_type}:</strong> {remediation}</li>"
            
            if severity == "critical":
                critical_recs.append(rec)
            elif severity == "high":
                high_recs.append(rec)
            elif severity == "medium":
                medium_recs.append(rec)
    
    # If no critical recommendations, add a default message
    if not critical_recs:
        html_content += """
                    <li>No critical vulnerabilities were detected.</li>
"""
    else:
        for rec in critical_recs:
            html_content += f"""
                    {rec}
"""
            
    html_content += """
                </ul>
            </div>
            
            <div class="recommendation">
                <h3>High Priorities</h3>
                <ul>
"""
    
    # If no high recommendations, add a default message
    if not high_recs:
        html_content += """
                    <li>No high severity vulnerabilities were detected.</li>
"""
    else:
        for rec in high_recs:
            html_content += f"""
                    {rec}
"""
            
    html_content += """
                </ul>
            </div>
            
            <div class="recommendation">
                <h3>Medium Priorities</h3>
                <ul>
"""
    
    # If no medium recommendations, add a default message
    if not medium_recs:
        html_content += """
                    <li>No medium severity vulnerabilities were detected.</li>
"""
    else:
        for rec in medium_recs:
            html_content += f"""
                    {rec}
"""
            
    html_content += """
                </ul>
            </div>
            
            <div class="recommendation">
                <h3>General Security Best Practices</h3>
                <ul>
                    <li><strong>Keep systems updated:</strong> Regularly update all software, frameworks, and libraries to patch known vulnerabilities.</li>
                    <li><strong>Implement a Web Application Firewall (WAF):</strong> A WAF can provide an additional layer of security against common web attacks.</li>
                    <li><strong>Use strong authentication:</strong> Implement multi-factor authentication for sensitive areas of the application.</li>
                    <li><strong>Follow the principle of least privilege:</strong> Ensure that users and systems have only the minimum necessary permissions.</li>
                    <li><strong>Perform regular security testing:</strong> Conduct penetration tests and security assessments on a regular basis.</li>
                </ul>
            </div>
        </div>
        
        <div class="summary">
            <h2>Report Information</h2>
            <p><strong>Generated:</strong> """ + current_date + """</p>
            <p><strong>Tool:</strong> NetHawk Web Vulnerability Scanner</p>
            <p><small>This report was automatically generated. Findings should be verified by a security professional before remediation.</small></p>
        </div>
    </div>
    
    <!-- Include Chart.js for pie chart -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // Create a pie chart of vulnerability severity distribution
        const ctx = document.getElementById('vulnerabilityChart').getContext('2d');
        const vulnerabilityChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [
                        """ + str(report_data['statistics']['vulnerability_counts'].get('critical', 0)) + """,
                        """ + str(report_data['statistics']['vulnerability_counts'].get('high', 0)) + """,
                        """ + str(report_data['statistics']['vulnerability_counts'].get('medium', 0)) + """,
                        """ + str(report_data['statistics']['vulnerability_counts'].get('low', 0)) + """,
                        """ + str(report_data['statistics']['vulnerability_counts'].get('info', 0)) + """
                    ],
                    backgroundColor: [
                        '#dc3545', // Critical
                        '#fd7e14', // High
                        '#ffc107', // Medium
                        '#20c997', // Low
                        '#0dcaf0'  // Info
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Vulnerability Severity Distribution'
                    }
                }
            }
        });
    </script>
</body>
</html>
    """
    
    with open(report_path, 'w') as f:
        f.write(html_content) 