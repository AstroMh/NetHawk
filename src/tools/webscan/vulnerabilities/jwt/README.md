# Advanced JWT Scanner Module

## Overview

The Advanced JWT Scanner is a comprehensive JSON Web Token (JWT) vulnerability detection system that implements cutting-edge techniques for identifying various types of JWT vulnerabilities and cryptographic weaknesses in web applications.

## Features

### Core Capabilities

- **Algorithm Confusion Detection**: Identifies algorithm switching attacks (RS256/HS256)
- **None Algorithm Testing**: Detects 'none' algorithm vulnerabilities
- **Weak Secret Detection**: Identifies weak or predictable secret keys
- **Signature Stripping Analysis**: Detects signature verification bypasses
- **Expired Token Validation**: Tests if expired tokens are still accepted
- **Token Tampering Detection**: Identifies payload manipulation vulnerabilities
- **Header Injection Testing**: Detects malicious header injection
- **Payload Manipulation Analysis**: Tests for unauthorized payload modifications
- **Key Confusion Attacks**: Advanced cryptographic attack detection
- **Token Replay Detection**: Identifies token replay vulnerabilities
- **Timing-based Attacks**: Sophisticated timing analysis
- **Comprehensive Cryptographic Testing**: Advanced cryptographic weakness detection

### JWT Vulnerability Types Detected

1. **Algorithm Confusion**: RS256/HS256 algorithm switching attacks
2. **None Algorithm**: 'none' algorithm vulnerability
3. **Weak Secret**: Weak or predictable secret keys
4. **Signature Stripping**: Signature verification bypass
5. **Expired Token**: Expired tokens still accepted
6. **Token Tampering**: Unauthorized payload modifications
7. **Header Injection**: Malicious header injection
8. **Payload Manipulation**: Unauthorized payload changes
9. **Key Confusion**: Advanced cryptographic attacks
10. **Token Replay**: Token reuse vulnerabilities
11. **Timing Attack**: Timing-based cryptographic attacks

## JWT Token Detection Patterns

### Authorization Headers
- `Authorization: Bearer <token>`
- `Authorization: JWT <token>`
- `X-Auth-Token: <token>`
- `X-JWT-Token: <token>`

### Cookies
- `jwt=<token>`
- `token=<token>`
- `access_token=<token>`
- `auth_token=<token>`
- `session_token=<token>`
- `bearer_token=<token>`

### URL Parameters
- `?jwt=<token>`
- `?token=<token>`
- `?access_token=<token>`
- `?auth_token=<token>`
- `?bearer=<token>`

### Response Body
- `"token": "<token>"`
- `"jwt": "<token>"`
- `"access_token": "<token>"`
- `"auth_token": "<token>"`

## Weak Secrets Database

### Common Words
- secret, key, private, password, admin, root, user
- token, auth, jwt, api, app, web, server, client

### Common Combinations
- jwt_secret, jwt_key, api_secret, api_key
- token_secret, token_key, app_secret, app_key
- secret_key, private_key, auth_secret, auth_key

### Weak Passwords
- 123456, 123456789, password, qwerty
- abcdef, abc123, 123abc, admin123, root123

### Short Secrets
- a, ab, abc, abcd, abcde, abcdef, abcdefg
- 1, 12, 123, 1234, 12345, 123456, 1234567

### Default Secrets
- changeme, default, secret123, key123
- private123, password123, admin123, root123

## JWT Algorithms and Vulnerabilities

### Symmetric Algorithms
- **HS256**: HMAC with SHA-256
  - Vulnerabilities: weak_secret, key_rotation
- **HS384**: HMAC with SHA-384
  - Vulnerabilities: weak_secret, key_rotation
- **HS512**: HMAC with SHA-512
  - Vulnerabilities: weak_secret, key_rotation

### Asymmetric Algorithms
- **RS256**: RSA with SHA-256
  - Vulnerabilities: algorithm_confusion, key_exposure
- **RS384**: RSA with SHA-384
  - Vulnerabilities: algorithm_confusion, key_exposure
- **RS512**: RSA with SHA-512
  - Vulnerabilities: algorithm_confusion, key_exposure
- **ES256**: ECDSA with SHA-256
  - Vulnerabilities: algorithm_confusion, key_exposure
- **ES384**: ECDSA with SHA-384
  - Vulnerabilities: algorithm_confusion, key_exposure
- **ES512**: ECDSA with SHA-512
  - Vulnerabilities: algorithm_confusion, key_exposure

### None Algorithm
- **none**: No signature
  - Vulnerabilities: signature_bypass, critical

## Vulnerability Types and Severity

### Critical Severity
- **Algorithm Confusion**: Algorithm switching attacks (RS256/HS256)
- **None Algorithm**: 'none' algorithm vulnerability
- **Signature Stripping**: Signature verification bypass
- **Key Confusion**: Advanced cryptographic attacks

### High Severity
- **Weak Secret**: Weak or predictable secret keys
- **Token Tampering**: Unauthorized payload modifications
- **Header Injection**: Malicious header injection
- **Payload Manipulation**: Unauthorized payload changes

### Medium Severity
- **Expired Token**: Expired tokens still accepted
- **Token Replay**: Token reuse vulnerabilities

### Low Severity
- **Timing Attack**: Timing-based cryptographic attacks

## Advanced Testing Techniques

### Algorithm Confusion Testing
- Detects when servers accept HS256 tokens for RS256 endpoints
- Tests algorithm switching vulnerabilities
- Identifies cryptographic implementation flaws

### None Algorithm Testing
- Tests multiple variations: none, None, NONE, nOnE
- Detects servers that accept unsigned tokens
- Identifies critical signature bypass vulnerabilities

### Weak Secret Detection
- Tests comprehensive database of weak secrets
- Covers common words, combinations, passwords
- Includes short secrets and default values

### Signature Stripping Analysis
- Tests if servers accept tokens without signatures
- Detects signature verification bypasses
- Identifies critical authentication flaws

### Expired Token Validation
- Tests if expired tokens are still accepted
- Modifies expiration timestamps
- Detects time validation weaknesses

### Token Tampering Detection
- Tests payload claim modifications
- Attempts to escalate privileges
- Detects unauthorized payload changes

### Header Injection Testing
- Tests malicious header injection
- Attempts path traversal in headers
- Detects header processing vulnerabilities

### Payload Manipulation Analysis
- Tests various payload modifications
- Attempts privilege escalation
- Detects unauthorized payload changes

## Usage

```python
from src.tools.webscan.vulnerabilities.jwt import JWTScanner

# Initialize scanner with web scanner instance
jwt_scanner = JWTScanner(scanner_instance)

# Run comprehensive JWT scan
vulnerabilities_found = jwt_scanner.run()
```

## Configuration

The scanner can be configured through the main web scanner instance:

- `verbose`: Enable detailed output
- `timeout`: Request timeout
- `session`: HTTP session object
- `target_url`: Target URL for scanning
- `discovered_urls`: List of discovered URLs to test
- `max_threads`: Maximum number of threads for parallel testing

## Output

The scanner provides comprehensive vulnerability reports including:

- Vulnerability type and subtype
- Severity level and risk score
- URL affected
- JWT token evidence (masked for security)
- Detailed description
- CWE references
- Comprehensive remediation recommendations

## Advanced Features

### Comprehensive Testing
- Tests multiple vulnerability types simultaneously
- Uses threading for improved performance
- Implements advanced cryptographic analysis
- Provides detailed vulnerability analysis

### Evidence Collection
- Detailed JWT token analysis
- Cryptographic weakness identification
- Algorithm vulnerability detection
- Comprehensive security assessment

### Real-time Validation
- Immediate vulnerability confirmation
- Comprehensive evidence analysis
- Severity assessment
- Risk evaluation

### Cryptographic Analysis
- Algorithm confusion detection
- Weak secret identification
- Signature verification testing
- Advanced cryptographic testing

## Security Considerations

- All tests are designed for security assessment purposes only
- Use only on authorized systems
- Follow responsible disclosure practices
- Respect rate limiting and server resources
- Comply with applicable laws and regulations

## Contributing

When adding new vulnerability types or testing techniques:

1. Test thoroughly in controlled environments
2. Document the vulnerability type
3. Include evidence collection methods
4. Update severity assessment logic
5. Add appropriate cryptographic testing

## License

This module is part of the NetHawk project and follows the same licensing terms. 