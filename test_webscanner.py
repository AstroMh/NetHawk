#!/usr/bin/env python3

from src.tools.webscan.core.scanner import WebScanner

if __name__ == "__main__":
    scanner = WebScanner("https://example.com")
    report_path = scanner.run()
    print(f"Test completed. Report saved to: {report_path}") 