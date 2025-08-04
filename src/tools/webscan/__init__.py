#!/usr/bin/env python3

import os

try:
    from src.tools.webscan.core.scanner import WebScanner
    # Export the WebScanner class
    __all__ = ['WebScanner']
except ImportError:
    # If the import fails, provide a placeholder for the WebScanner class
    WebScanner = None
    __all__ = []

def check_webscan_requirements():
    """
    Verify that all requirements for the web scanner are installed.
    
    Returns:
        bool: True if all requirements are installed, False otherwise
    """
    from termcolor import colored
    
    requirements_met = True
    
    # Basic requirements
    try:
        import requests
    except ImportError:
        requirements_met = False
        print(colored("\n[!] ", 'red') + "Module 'requests' is not installed.")
        print(colored("[!] ", 'yellow') + "Install it with: 'pip install requests'")
    
    try:
        import concurrent.futures
    except ImportError:
        requirements_met = False
        print(colored("\n[!] ", 'red') + "Module 'concurrent.futures' is not installed.")
        print(colored("[!] ", 'yellow') + "Install it with: 'pip install futures'")
    
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        requirements_met = False
        print(colored("\n[!] ", 'red') + "Module 'beautifulsoup4' is not installed.")
        print(colored("[!] ", 'yellow') + "Install it with: 'pip install beautifulsoup4'")
    
    # Database requirements
    try:
        import sqlalchemy
    except ImportError:
        # This is not a critical error, but show a warning
        print(colored("\n[!] ", 'yellow') + "Module 'sqlalchemy' is not installed.")
        print(colored("[!] ", 'yellow') + "Database features will not be available.")
        print(colored("[!] ", 'yellow') + "Install it with: 'pip install sqlalchemy'")
    
    try:
        import psycopg2
    except ImportError:
        # This is not a critical error, but show a warning
        print(colored("\n[!] ", 'yellow') + "Module 'psycopg2' is not installed.")
        print(colored("[!] ", 'yellow') + "PostgreSQL database features will not be available.")
        print(colored("[!] ", 'yellow') + "Install it with: 'pip install psycopg2-binary'")
    
    # Verify that necessary internal modules exist
    try:
        # Check that scanner.py exists
        scanner_path = os.path.join(os.path.dirname(__file__), "core", "scanner.py")
        if not os.path.isfile(scanner_path):
            requirements_met = False
            print(colored("\n[!] ", 'red') + "File 'scanner.py' is not found in the expected path.")
            print(colored("[!] ", 'yellow') + "Verify that the project structure is correct.")
    except Exception as e:
        requirements_met = False
        print(colored("\n[!] ", 'red') + f"Error checking file structure: {str(e)}")
    
    return requirements_met

# This file is intentionally empty to make this directory a Python package.
