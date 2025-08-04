#!/usr/bin/env python3

# Import vulnerability scanners
from src.tools.webscan.vulnerabilities.rce import RCEScanner
from src.tools.webscan.vulnerabilities.command_injection import CommandInjectionScanner
from src.tools.webscan.vulnerabilities.sqli import SQLIScanner
from src.tools.webscan.vulnerabilities.xss import XSSScanner
from src.tools.webscan.vulnerabilities.lfi import LFIScanner
from src.tools.webscan.vulnerabilities.open_redirect import OpenRedirectScanner
from src.tools.webscan.vulnerabilities.idor import IDORScanner
from src.tools.webscan.vulnerabilities.ssti import SSTIScanner

# Add more imports as vulnerability scanners are implemented
# from src.tools.webscan.vulnerabilities.csrf import CSRFScanner
# from src.tools.webscan.vulnerabilities.cors import CORSScanner
# from src.tools.webscan.vulnerabilities.ssrf import SSRFScanner
# from src.tools.webscan.vulnerabilities.xxe import XXEScanner
# etc.

# Export all vulnerability scanner classes
__all__ = [
    'RCEScanner',
    'CommandInjectionScanner',
    'SQLIScanner',
    'XSSScanner',
    'LFIScanner',
    'OpenRedirectScanner',
    'IDORScanner',
    'SSTIScanner',
    # Add more scanners as they are implemented
    # 'CSRFScanner',
    # 'CORSScanner',
    # 'SSRFScanner',
    # 'XXEScanner',
]

# This file is intentionally empty to make this directory a Python package.
