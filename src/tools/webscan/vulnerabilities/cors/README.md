# Advanced CORS Scanner Module

## Overview

The Advanced CORS Scanner is a comprehensive Cross-Origin Resource Sharing (CORS) vulnerability detection system that implements cutting-edge techniques for identifying various types of CORS misconfigurations in web applications.

## Features

### Core Capabilities

- **Origin Reflection Detection**: Identifies when malicious origins are reflected in CORS headers
- **Wildcard Misconfiguration Analysis**: Detects dangerous wildcard (*) CORS configurations
- **Null Origin Vulnerability Testing**: Tests for null origin vulnerabilities
- **Domain Confusion Attack Detection**: Identifies domain confusion attacks
- **Subdomain Takeover Analysis**: Detects subdomain takeover opportunities via CORS
- **Protocol Downgrade Detection**: Identifies protocol downgrade attacks
- **Credential Exposure Analysis**: Tests for credential exposure via CORS
- **Method and Header Exposure Testing**: Detects dangerous HTTP methods and sensitive headers
- **Preflight Request Analysis**: Comprehensive preflight request testing
- **Timing-based Attack Detection**: Identifies potential timing-based CORS attacks

### CORS Vulnerability Types Detected

1. **Origin Reflection**: Malicious origins reflected in Access-Control-Allow-Origin
2. **Wildcard Misconfigurations**: Dangerous wildcard (*) configurations
3. **Null Origin Vulnerabilities**: Null origin with credentials
4. **Domain Confusion**: Domain confusion attacks
5. **Subdomain Takeover**: Subdomain takeover via CORS
6. **Protocol Downgrade**: Protocol downgrade attacks
7. **Credential Exposure**: Credential exposure via CORS
8. **Method Exposure**: Dangerous HTTP methods exposed
9. **Header Exposure**: Sensitive headers exposed
10. **Preflight Vulnerabilities**: Preflight request vulnerabilities
11. **Timing Attacks**: Timing-based CORS attacks

## Attack Vectors

### Origin Reflection Attacks
- Tests malicious origins for reflection in CORS headers
- Detects when attacker-controlled origins are reflected
- Identifies credential exposure with reflected origins

### Wildcard Misconfigurations
- Detects wildcard (*) Access-Control-Allow-Origin
- Identifies wildcard patterns with credentials
- Tests various wildcard configurations

### Null Origin Vulnerabilities
- Tests null origin variants (null, NULL, Null)
- Detects null origin with credentials
- Identifies null origin confusion attacks

### Domain Confusion Attacks
- Tests domain confusion patterns
- Detects subdomain takeover opportunities
- Identifies domain manipulation attacks

### Protocol Downgrade Attacks
- Tests HTTP vs HTTPS protocol confusion
- Detects protocol manipulation attacks
- Identifies insecure protocol configurations

### Credential Exposure
- Tests for Access-Control-Allow-Credentials: true
- Detects credential exposure with malicious origins
- Identifies sensitive data exposure

### Method and Header Exposure
- Tests for dangerous HTTP methods (PUT, DELETE, PATCH, TRACE, CONNECT)
- Detects sensitive header exposure
- Identifies over-permissive CORS configurations

## CORS Headers Analyzed

### Origin Control Headers
- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Origin-Response`

### Credential Control Headers
- `Access-Control-Allow-Credentials`
- `Access-Control-Allow-Credentials-Response`

### Method Control Headers
- `Access-Control-Allow-Methods`
- `Access-Control-Request-Method`

### Header Control Headers
- `Access-Control-Allow-Headers`
- `Access-Control-Request-Headers`
- `Access-Control-Expose-Headers`

### Timing Control Headers
- `Access-Control-Max-Age`
- `Access-Control-Request-Private-Network`

### Preflight Control Headers
- `Access-Control-Preflight-Response`
- `Access-Control-Preflight-Request`

## Malicious Domains Tested

### Basic Attack Domains
- evil.com
- attacker.com
- malicious.com
- hacker.com
- phishing.com

### Domain Confusion Domains
- null.evil.com
- evil.com.target.com
- target.com.evil.com
- subdomain.evil.com
- www.evil.com

### Subdomain Takeover Domains
- api.evil.com
- admin.evil.com
- dev.evil.com
- test.evil.com
- staging.evil.com

### Protocol Manipulation Domains
- http://evil.com
- https://evil.com
- ftp://evil.com
- file://evil.com
- data://evil.com

### Null Origin Variants
- null
- NULL
- Null
- null.com
- null.evil.com

### Wildcard Variants
- *
- *.evil.com
- *.target.com
- *.com
- *.org

## Vulnerability Patterns

### Wildcard Patterns
- `^\*$` - Exact wildcard
- `^\*\.` - Wildcard subdomain
- `\.\*$` - Wildcard suffix
- `^\*\.\*$` - Double wildcard

### Null Patterns
- `^null$` - Exact null
- `^NULL$` - Uppercase null
- `^Null$` - Title case null

### Reflection Patterns
- `^https?://[^/]+$` - HTTP/HTTPS origin
- `^https?://[^/]+/$` - HTTP/HTTPS origin with trailing slash

### Domain Confusion Patterns
- `\.evil\.com$` - Evil domain suffix
- `\.attacker\.com$` - Attacker domain suffix
- `\.malicious\.com$` - Malicious domain suffix

## Severity Levels

### Critical
- Origin reflection with credentials
- Wildcard origin with credentials
- Credential exposure with malicious origins

### High
- Origin reflection without credentials
- Null origin with credentials
- Domain confusion attacks
- Subdomain takeover via CORS
- Preflight request vulnerabilities

### Medium
- Wildcard origin without credentials
- Null origin without credentials
- Protocol downgrade attacks
- Method exposure vulnerabilities
- Header exposure vulnerabilities

### Low
- Timing-based attacks
- Non-critical misconfigurations

## Usage

```python
from src.tools.webscan.vulnerabilities.cors import CORSScanner

# Initialize scanner with web scanner instance
cors_scanner = CORSScanner(scanner_instance)

# Run comprehensive CORS scan
vulnerabilities_found = cors_scanner.run()
```

## Configuration

The scanner can be configured through the main web scanner instance:

- `verbose`: Enable detailed output
- `timeout`: Request timeout
- `session`: HTTP session object
- `target_url`: Target URL for scanning
- `discovered_urls`: List of discovered URLs to test

## Output

The scanner provides comprehensive vulnerability reports including:

- Vulnerability type and subtype
- Severity level
- URL affected
- Detailed description
- Evidence description
- Credential exposure status
- Attack vector information
- Pattern matching details

## Advanced Features

### Comprehensive Testing
- Tests multiple attack vectors simultaneously
- Uses threading for improved performance
- Implements pattern-based detection
- Provides detailed vulnerability analysis

### Evidence Collection
- Detailed CORS header analysis
- Pattern matching evidence
- Credential exposure detection
- Attack vector identification

### Real-time Validation
- Immediate vulnerability confirmation
- Comprehensive evidence analysis
- Severity assessment
- Risk evaluation

## Security Considerations

- All tests are designed for security assessment purposes only
- Use only on authorized systems
- Follow responsible disclosure practices
- Respect rate limiting and server resources
- Comply with applicable laws and regulations

## Contributing

When adding new attack vectors or techniques:

1. Test thoroughly in controlled environments
2. Document the attack technique
3. Include evidence collection methods
4. Update severity assessment logic
5. Add appropriate pattern detection

## License

This module is part of the NetHawk project and follows the same licensing terms. 