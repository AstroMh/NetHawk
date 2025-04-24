#!/usr/bin/env python

import importlib
from termcolor import colored

def check_dependency(module_name, package_name=None):
    """
    Check if a dependency is installed.
    
    Args:
        module_name: The name of the module to import
        package_name: The name of the package to suggest installing (if different from module_name)
        
    Returns:
        bool: Whether the dependency is installed
    """
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        if package_name is None:
            package_name = module_name
        print(colored(f"\n[!] {module_name} is not installed.", 'red'))
        print(colored(f"[!] This feature requires {module_name} to be installed.", 'yellow'))
        print(colored(f"[!] Please install it with: 'pip install {package_name}'", 'yellow'))
        return False

def check_all_dependencies():
    """
    Check all required dependencies for the NetHawk toolkit.
    
    Returns:
        dict: A dictionary with module names as keys and boolean availability as values
    """
    dependencies = {
        "core": {
            "termcolor": True,  # If we're running this, termcolor is already imported
            "scapy": check_dependency("scapy"),
        },
        "optional": {
            "netfilterqueue": check_dependency("netfilterqueue"),
            "keyboard": check_dependency("keyboard"),
            "pynput": check_dependency("pynput"),
        }
    }
    
    return dependencies 