#!/usr/bin/env python

import sys
import os

print(f"Python version: {sys.version}")
print(f"Current working directory: {os.getcwd()}")
print(f"Python path: {sys.path}")

try:
    import termcolor
    print("termcolor is available")
except ImportError:
    print("termcolor is NOT available")

try:
    import scapy
    print("scapy is available")
except ImportError:
    print("scapy is NOT available")

try:
    from src.logos.logo import Logo
    print("Logo module is available")
except ImportError as e:
    print(f"Logo module is NOT available: {str(e)}") 