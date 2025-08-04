# Advanced CSRF Scanner Module

## Overview

The Advanced CSRF Scanner is a comprehensive Cross-Site Request Forgery (CSRF) vulnerability detection system that implements cutting-edge techniques for identifying various types of CSRF vulnerabilities and protection mechanisms in web applications.

## Features

### Core Capabilities

- **Token-based CSRF Protection Analysis**: Comprehensive analysis of CSRF tokens in forms, cookies, and headers
- **Header-based CSRF Protection Detection**: Identifies header-based CSRF protection mechanisms
- **Cookie-based CSRF Protection Validation**: Analyzes cookie-based CSRF protection
- **SameSite Cookie Analysis**: Detects SameSite cookie CSRF protection
- **Weak Token Detection**: Identifies weak or predictable CSRF tokens
- **Attack Vector Analysis**: Determines the most likely attack vectors for forms
- **Severity Assessment**: Comprehensive severity assessment based on form functionality
- **Comprehensive Recommendations**: Detailed recommendations for CSRF protection implementation

### CSRF Vulnerability Types Detected

1. **Missing Protection**: Forms without any CSRF protection mechanisms
2. **Weak Protection**: Forms with weak or bypassable CSRF protection
3. **Predictable Tokens**: CSRF tokens that are predictable or easily guessable
4. **Static Tokens**: CSRF tokens that don't change between sessions
5. **Insufficient Validation**: Forms with inadequate token validation
6. **Header Bypass**: Forms vulnerable to header-based attacks
7. **Cookie Bypass**: Forms vulnerable to cookie-based attacks
8. **SameSite Bypass**: Forms vulnerable to SameSite cookie bypasses

## Protection Mechanisms Analyzed

### Token-based Protection
- **Field Analysis**: Checks form fields for CSRF tokens
- **Cookie Analysis**: Analyzes cookies for CSRF tokens
- **Header Analysis**: Examines response headers for CSRF tokens
- **Parameter Analysis**: Checks URL parameters for CSRF tokens

### Header-based Protection
- **Header Validation**: Validates security headers
- **Origin Check**: Verifies Origin header validation
- **Referer Check**: Analyzes Referer header validation
- **Custom Header Analysis**: Examines custom CSRF headers

### Cookie-based Protection
- **SameSite Analysis**: Analyzes SameSite cookie attributes
- **Secure Flag**: Checks for secure cookie flags
- **HttpOnly Flag**: Validates HttpOnly cookie attributes
- **Domain Validation**: Verifies cookie domain restrictions

### Advanced Protection Patterns
- **Double Submit Cookie**: Detects Double Submit Cookie pattern
- **Synchronizer Token**: Identifies Synchronizer Token pattern
- **Custom Token Patterns**: Analyzes custom token implementations
- **State Parameter Verification**: Validates state parameters

## CSRF Token Patterns

### Field Names
- csrf, token, nonce, xsrf, verify, authenticity
- security, form_token, request_token, session_token
- anti_csrf, csrf_token, xsrf_token, form_token
- request_token, session_token, authenticity_token
- security_token, form_security, request_security

### Cookie Names
- csrf, token, xsrf, nonce, authenticity
- security, form_token, request_token, session_token
- anti_csrf, csrf_token, xsrf_token, form_token
- request_token, session_token, authenticity_token
- security_token, form_security, request_security

### Header Names
- X-CSRF-Token, X-XSRF-Token, X-Requested-With
- X-CSRF-Header, X-Anti-CSRF, X-Security-Token
- X-Form-Token, X-Request-Token, X-Session-Token
- X-Authenticity-Token, X-Security-Header

### Parameter Names
- csrf, token, nonce, xsrf, verify, authenticity
- security, form_token, request_token, session_token
- anti_csrf, csrf_token, xsrf_token, form_token
- request_token, session_token, authenticity_token
- security_token, form_security, request_security

## Attack Vectors

### Form Submission
- **POST Request**: Form submission via POST method
- **GET Request**: Form submission via GET method
- **PUT Request**: Form submission via PUT method
- **DELETE Request**: Form submission via DELETE method

### AJAX Request
- **XMLHttpRequest**: AJAX requests without CSRF protection
- **Fetch Request**: Fetch API requests without CSRF protection
- **Axios Request**: Axios requests without CSRF protection

### API Endpoint
- **REST API**: REST API endpoints without CSRF protection
- **GraphQL API**: GraphQL API endpoints without CSRF protection
- **SOAP API**: SOAP API endpoints without CSRF protection

### File Upload
- **Multipart Form**: File upload forms without CSRF protection
- **File Upload API**: File upload APIs without CSRF protection

### State Change
- **Password Change**: Password change operations without CSRF protection
- **Email Change**: Email change operations without CSRF protection
- **Profile Update**: Profile update operations without CSRF protection

### Privileged Action
- **Admin Action**: Administrative actions without CSRF protection
- **User Creation**: User creation operations without CSRF protection
- **Role Change**: Role change operations without CSRF protection

## Vulnerability Patterns

### Missing Token Patterns
- `<form[^>]*>.*?</form>` - Form without CSRF token
- `<input[^>]*type=["\']submit["\'][^>]*>` - Submit input without protection
- `<button[^>]*type=["\']submit["\'][^>]*>` - Submit button without protection

### Weak Token Patterns
- `<input[^>]*name=["\'][^"\']*(csrf|token|nonce)[^"\']*["\'][^>]*>` - Weak token field
- `<input[^>]*value=["\'][^"\']*["\'][^>]*>` - Token with weak value

### Predictable Token Patterns
- `<input[^>]*value=["\'][0-9]+["\'][^>]*>` - Numeric token
- `<input[^>]*value=["\'][a-zA-Z0-9]{8,}["\'][^>]*>` - Short alphanumeric token

### Static Token Patterns
- `<input[^>]*value=["\'][^"\']*["\'][^>]*>` - Static token value
- `<input[^>]*value=["\'][^"\']*["\'][^>]*>` - Unchanging token

## Severity Levels

### Critical
- Password change operations without CSRF protection
- Email change operations without CSRF protection
- Administrative actions without CSRF protection
- User creation operations without CSRF protection
- Role change operations without CSRF protection

### High
- State-changing operations without CSRF protection
- Form submissions via POST/PUT/DELETE without protection
- File upload operations without CSRF protection
- AJAX requests without CSRF protection

### Medium
- Forms with weak or bypassable CSRF protection
- Predictable or static CSRF tokens
- Insufficient token validation
- Missing security headers

### Low
- Forms with basic CSRF protection
- Non-critical operations without protection
- Informational security issues

## Usage

```python
from src.tools.webscan.vulnerabilities.csrf import CSRFScanner

# Initialize scanner with web scanner instance
csrf_scanner = CSRFScanner(scanner_instance)

# Run comprehensive CSRF scan
vulnerabilities_found = csrf_scanner.run()
```

## Configuration

The scanner can be configured through the main web scanner instance:

- `verbose`: Enable detailed output
- `timeout`: Request timeout
- `session`: HTTP session object
- `target_url`: Target URL for scanning
- `forms`: List of discovered forms to test
- `max_threads`: Maximum number of threads for parallel testing

## Output

The scanner provides comprehensive vulnerability reports including:

- Vulnerability type and subtype
- Severity level
- URL affected
- Form details (action, method, inputs)
- Detailed description
- Evidence description
- Protection analysis results
- Attack vector information
- Comprehensive recommendations

## Advanced Features

### Comprehensive Testing
- Tests multiple protection mechanisms simultaneously
- Uses threading for improved performance
- Implements pattern-based detection
- Provides detailed vulnerability analysis

### Evidence Collection
- Detailed CSRF token analysis
- Protection mechanism identification
- Weak token detection
- Attack vector identification

### Real-time Validation
- Immediate vulnerability confirmation
- Comprehensive evidence analysis
- Severity assessment
- Risk evaluation

### Protection Analysis
- Token-based protection analysis
- Header-based protection detection
- Cookie-based protection validation
- SameSite cookie analysis
- Weak token detection

## Security Considerations

- All tests are designed for security assessment purposes only
- Use only on authorized systems
- Follow responsible disclosure practices
- Respect rate limiting and server resources
- Comply with applicable laws and regulations

## Contributing

When adding new protection mechanisms or attack vectors:

1. Test thoroughly in controlled environments
2. Document the protection mechanism
3. Include evidence collection methods
4. Update severity assessment logic
5. Add appropriate pattern detection

## License

This module is part of the NetHawk project and follows the same licensing terms. 