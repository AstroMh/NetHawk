#!/usr/bin/env python3

from src.tools.webscan.vulnerabilities.xxe.scanner import XXEScanner
from src.tools.webscan.vulnerabilities.xxe.utils import (
    generate_xxe_payloads,
    create_evil_dtd,
    analyze_xxe_response,
    generate_xxe_report
)

__all__ = [
    'XXEScanner',
    'generate_xxe_payloads',
    'create_evil_dtd',
    'analyze_xxe_response',
    'generate_xxe_report'
]
