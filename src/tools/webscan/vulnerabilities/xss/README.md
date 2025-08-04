# Advanced XSS Scanner Module

## Overview

The Advanced XSS Scanner is a comprehensive Cross-Site Scripting (XSS) vulnerability detection system that implements cutting-edge techniques for identifying various types of XSS vulnerabilities in web applications.

## Features

### Core Capabilities

- **Context-Aware Detection**: Automatically determines the context of input fields and applies appropriate payloads
- **Advanced Filter Bypass**: Implements sophisticated techniques to bypass common WAF and filter systems
- **Multi-Encoding Support**: Tests payloads with various encoding methods (HTML, URL, Unicode, etc.)
- **Polyglot Payloads**: Uses universal payloads that work across multiple contexts
- **Real-time Validation**: Validates vulnerabilities in real-time with comprehensive evidence collection

### XSS Types Detected

1. **Reflected XSS**: Detects non-persistent XSS vulnerabilities
2. **Stored XSS**: Identifies persistent XSS vulnerabilities
3. **DOM-based XSS**: Detects client-side XSS vulnerabilities
4. **Context-Specific XSS**: HTML, JavaScript, CSS, XML, and URL contexts

### Advanced Techniques

#### Filter Bypass Methods
- Case manipulation (mixed case)
- HTML entity encoding
- Unicode encoding
- Double encoding
- Null byte injection
- Polyglot payloads

#### WAF Bypass Detection
- Cloudflare bypass techniques
- ModSecurity bypass methods
- Imperva bypass strategies
- F5 ASM bypass techniques
- Akamai bypass methods

#### CSP Bypass Detection
- Unsafe-inline directive detection
- Unsafe-eval directive detection
- Data URI bypass techniques
- Nonce bypass attempts
- Hash bypass attempts

## Payload Categories

### Basic Payloads
- Standard script tags
- JavaScript alert functions
- Cookie and location access
- User agent detection

### Advanced Bypass Payloads
- HTML5 entity bypass
- Unicode encoding bypass
- Mixed case manipulation
- Double encoding techniques
- Polyglot universal payloads

### Context-Specific Payloads

#### HTML Context
- Script tag injection
- Event handler injection
- SVG vector injection
- Image vector injection
- Iframe injection

#### JavaScript Context
- String concatenation
- Template literal injection
- Eval function injection
- Function constructor injection
- Dynamic import injection

#### CSS Context
- Expression injection
- URL function injection
- Behavior property injection
- Import rule injection

#### XML Context
- CDATA section injection
- XML processing instruction injection
- SVG namespace injection
- MathML namespace injection

#### URL Context
- JavaScript protocol injection
- Data URI injection
- VBScript protocol injection
- Void function injection

## Detection Patterns

### Script Tags
- `<script[^>]*>.*?</script>`
- `<script[^>]*>`
- `</script>`

### JavaScript Protocols
- `javascript:`
- `vbscript:`
- `data:text/javascript`
- `data:application/javascript`

### Data URIs
- `data:text/html`
- `data:image/svg+xml`
- `data:application/xml`
- `data:text/xml`

### Event Handlers
- `on\w+\s*=`
- `onload\s*=`
- `onerror\s*=`
- `onmouseover\s*=`
- `onfocus\s*=`
- `onblur\s*=`
- `onchange\s*=`
- `onsubmit\s*=`
- `onkeydown\s*=`
- `onkeyup\s*=`
- `onkeypress\s*=`

### Dangerous Tags
- `<svg[^>]*>`
- `<img[^>]*>`
- `<iframe[^>]*>`
- `<object[^>]*>`
- `<embed[^>]*>`
- `<video[^>]*>`
- `<audio[^>]*>`
- `<details[^>]*>`
- `<math[^>]*>`
- `<xml[^>]*>`

### CSS Expressions
- `expression\s*\(`
- `url\s*\(\s*javascript:`
- `behavior\s*:\s*url\s*\(`

### DOM Manipulation
- `document\.write\s*\(`
- `document\.writeln\s*\(`
- `innerHTML\s*=`
- `outerHTML\s*=`
- `insertAdjacentHTML\s*\(`
- `eval\s*\(`
- `Function\s*\(`
- `setTimeout\s*\(`
- `setInterval\s*\(`

## Severity Levels

### Critical
- Direct script execution
- JavaScript protocol injection
- Data URI injection
- Eval function injection
- DOM manipulation functions

### High
- Event handler injection
- Expression injection
- URL function injection
- VBScript injection

### Medium
- Event handler attributes
- JavaScript protocol
- Data URI protocols
- Expression functions

### Low
- Basic script injection
- Simple event handlers
- Non-executable payloads

## Usage

```python
from src.tools.webscan.vulnerabilities.xss import XSSScanner

# Initialize scanner with web scanner instance
xss_scanner = XSSScanner(scanner_instance)

# Run comprehensive XSS scan
vulnerabilities_found = xss_scanner.run()
```

## Configuration

The scanner can be configured through the main web scanner instance:

- `verbose`: Enable detailed output
- `timeout`: Request timeout
- `max_threads`: Maximum concurrent threads
- `session`: HTTP session object

## Output

The scanner provides comprehensive vulnerability reports including:

- Vulnerability type and subtype
- Severity level
- Context information
- Payload used
- Evidence description
- Response details
- Timestamp
- Payload category

## Advanced Features

### Context Detection
- Analyzes input field attributes
- Determines appropriate payloads
- Validates payloads for context
- Generates context-specific variants

### Evidence Collection
- Direct payload reflection
- Encoded payload variants
- Pattern-based detection
- Context-specific indicators
- WAF/CSP bypass evidence
- Encoding bypass evidence

### Real-time Validation
- Immediate vulnerability confirmation
- Comprehensive evidence analysis
- Severity assessment
- Risk evaluation

## Security Considerations

- All payloads are designed for testing purposes only
- Use only on authorized systems
- Follow responsible disclosure practices
- Respect rate limiting and server resources
- Comply with applicable laws and regulations

## Contributing

When adding new payloads or techniques:

1. Test thoroughly in controlled environments
2. Document the bypass technique
3. Include evidence collection methods
4. Update severity assessment logic
5. Add appropriate context detection

## License

This module is part of the NetHawk project and follows the same licensing terms. 