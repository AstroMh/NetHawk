#!/usr/bin/env python3

def check_security_headers(scanner):
    """
    Check for missing or misconfigured HTTP security headers.
    
    Args:
        scanner: The WebScanner instance
        
    Returns:
        dict: Results of the security headers check with vulnerabilities found
    """
    # Make a request to the target URL
    try:
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout, verify=False)
        headers = response.headers
    except Exception as e:
        if scanner.verbose:
            scanner.logger.error(f"Error checking security headers: {str(e)}")
        return {'status': 'error', 'message': str(e)}
    
    # Headers to check and their recommended values
    security_headers = {
        'Strict-Transport-Security': {
            'description': 'HTTP Strict Transport Security (HSTS)',
            'recommended': 'max-age=31536000; includeSubDomains',
            'risk_score': 7,
            'cwe': 'CWE-319',
            'resources': ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html'],
            'remediation': 'Implement HSTS with a max-age of at least one year and includeSubDomains directive.'
        },
        'Content-Security-Policy': {
            'description': 'Content Security Policy (CSP)',
            'recommended': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'",
            'risk_score': 6,
            'cwe': 'CWE-1021',
            'resources': ['https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'],
            'remediation': 'Implement a strict CSP that restricts the sources from which content can be loaded.'
        },
        'X-Frame-Options': {
            'description': 'X-Frame-Options',
            'recommended': 'DENY or SAMEORIGIN',
            'risk_score': 5,
            'cwe': 'CWE-1021',
            'resources': ['https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html'],
            'remediation': 'Add X-Frame-Options header with DENY or SAMEORIGIN value to prevent clickjacking.'
        },
        'X-Content-Type-Options': {
            'description': 'X-Content-Type-Options',
            'recommended': 'nosniff',
            'risk_score': 4,
            'cwe': 'CWE-430',
            'resources': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
            'remediation': 'Add X-Content-Type-Options header with nosniff value to prevent MIME type sniffing.'
        },
        'Referrer-Policy': {
            'description': 'Referrer Policy',
            'recommended': 'no-referrer, strict-origin, or strict-origin-when-cross-origin',
            'risk_score': 3,
            'cwe': 'CWE-200',
            'resources': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
            'remediation': 'Implement a restrictive Referrer-Policy to control information leakage.'
        },
        'Permissions-Policy': {
            'description': 'Permissions Policy',
            'recommended': 'camera=(), microphone=(), geolocation=(), payment=()',
            'risk_score': 3,
            'cwe': 'CWE-693',
            'resources': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy'],
            'remediation': 'Implement a Permissions-Policy to restrict browser features.'
        },
        'X-XSS-Protection': {
            'description': 'X-XSS-Protection',
            'recommended': '1; mode=block',
            'risk_score': 3,
            'cwe': 'CWE-79',
            'resources': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'],
            'remediation': 'Add X-XSS-Protection header with "1; mode=block" value (though modern browsers rely on CSP instead).'
        },
        'Cache-Control': {
            'description': 'Cache Control for sensitive pages',
            'recommended': 'no-store, max-age=0',
            'risk_score': 4,
            'cwe': 'CWE-525',
            'resources': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control'],
            'remediation': 'Set Cache-Control headers to prevent caching of sensitive data.'
        }
    }
    
    # Additional headers to check
    server_headers = {
        'Server': {
            'description': 'Server header revealing software info',
            'risk_score': 3,
            'cwe': 'CWE-200',
            'resources': ['https://owasp.org/www-community/security_misconfiguration'],
            'remediation': 'Configure the server to not reveal version information in the Server header.'
        },
        'X-Powered-By': {
            'description': 'X-Powered-By header revealing tech stack',
            'risk_score': 3,
            'cwe': 'CWE-200',
            'resources': ['https://owasp.org/www-community/security_misconfiguration'],
            'remediation': 'Remove the X-Powered-By header to avoid exposing technology information.'
        },
        'X-AspNet-Version': {
            'description': 'X-AspNet-Version header revealing ASP.NET version',
            'risk_score': 3,
            'cwe': 'CWE-200',
            'resources': ['https://owasp.org/www-community/security_misconfiguration'],
            'remediation': 'Remove the X-AspNet-Version header to avoid exposing technology information.'
        }
    }
    
    # Initialize results
    header_results = {
        'missing_headers': [],
        'misconfigured_headers': [],
        'info_disclosure_headers': [],
        'headers_found': {}
    }
    
    # Check for missing security headers
    for header, config in security_headers.items():
        header_found = False
        # Handle case-insensitive header names
        for response_header in headers:
            if response_header.lower() == header.lower():
                header_found = True
                header_value = headers[response_header]
                header_results['headers_found'][header] = header_value
                
                # Check if the header is configured correctly
                if header.lower() == 'strict-transport-security':
                    if 'max-age=' not in header_value.lower() or int(header_value.split('max-age=')[1].split(';')[0]) < 31536000:
                        header_results['misconfigured_headers'].append({
                            'header': header,
                            'value': header_value,
                            'issue': 'HSTS max-age is less than recommended 1 year',
                            'recommendation': config['recommended'],
                            'risk_score': config['risk_score'],
                            'cwe': config['cwe'],
                            'resources': config['resources'],
                            'remediation': config['remediation']
                        })
                
                elif header.lower() == 'content-security-policy':
                    if "default-src 'none'" in header_value or "default-src *" in header_value or "script-src *" in header_value:
                        header_results['misconfigured_headers'].append({
                            'header': header,
                            'value': header_value,
                            'issue': 'CSP policy is too permissive',
                            'recommendation': config['recommended'],
                            'risk_score': config['risk_score'],
                            'cwe': config['cwe'],
                            'resources': config['resources'],
                            'remediation': config['remediation']
                        })
                
                elif header.lower() == 'x-frame-options':
                    if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                        header_results['misconfigured_headers'].append({
                            'header': header,
                            'value': header_value,
                            'issue': 'X-Frame-Options should be set to DENY or SAMEORIGIN',
                            'recommendation': config['recommended'],
                            'risk_score': config['risk_score'],
                            'cwe': config['cwe'],
                            'resources': config['resources'],
                            'remediation': config['remediation']
                        })
                
                break
        
        if not header_found:
            header_results['missing_headers'].append({
                'header': header,
                'description': config['description'],
                'recommendation': config['recommended'],
                'risk_score': config['risk_score'],
                'cwe': config['cwe'],
                'resources': config['resources'],
                'remediation': config['remediation']
            })
    
    # Check information disclosure headers
    for header, config in server_headers.items():
        for response_header in headers:
            if response_header.lower() == header.lower():
                header_value = headers[response_header]
                header_results['info_disclosure_headers'].append({
                    'header': header,
                    'value': header_value,
                    'description': config['description'],
                    'risk_score': config['risk_score'],
                    'cwe': config['cwe'],
                    'resources': config['resources'],
                    'remediation': config['remediation']
                })
                break
    
    # Log results if verbose
    if scanner.verbose:
        scanner.logger.info(f"Security headers analysis completed:")
        if header_results['missing_headers']:
            scanner.logger.warning(f"  Missing security headers: {len(header_results['missing_headers'])}")
        if header_results['misconfigured_headers']:
            scanner.logger.warning(f"  Misconfigured security headers: {len(header_results['misconfigured_headers'])}")
        if header_results['info_disclosure_headers']:
            scanner.logger.warning(f"  Information disclosure headers: {len(header_results['info_disclosure_headers'])}")
    
    # Add to vulnerabilities if any issues found
    if header_results['missing_headers'] or header_results['misconfigured_headers']:
        for missing in header_results['missing_headers']:
            scanner.add_vulnerability(
                name=f"Missing {missing['header']} Header",
                url=scanner.target_url,
                severity="Medium" if missing['risk_score'] >= 5 else "Low",
                risk_score=missing['risk_score'],
                description=f"The application does not set the {missing['header']} security header. {missing['description']}",
                recommendation=missing['remediation'],
                cwe=missing['cwe'],
                references=missing['resources'],
                details=missing
            )
        
        for misconf in header_results['misconfigured_headers']:
            scanner.add_vulnerability(
                name=f"Misconfigured {misconf['header']} Header",
                url=scanner.target_url,
                severity="Medium" if misconf['risk_score'] >= 5 else "Low",
                risk_score=misconf['risk_score'],
                description=f"The {misconf['header']} header is not configured securely. Current value: {misconf['value']}",
                recommendation=misconf['remediation'],
                cwe=misconf['cwe'],
                references=misconf['resources'],
                details=misconf
            )
        
        for info in header_results['info_disclosure_headers']:
            scanner.add_vulnerability(
                name=f"Information Disclosure in {info['header']} Header",
                url=scanner.target_url,
                severity="Low",
                risk_score=info['risk_score'],
                description=f"The {info['header']} header reveals sensitive information: {info['value']}",
                recommendation=info['remediation'],
                cwe=info['cwe'],
                references=info['resources'],
                details=info
            )
    
    return header_results 