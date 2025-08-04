#!/usr/bin/env python3

import os
import sys
from termcolor import colored

def check_directory_structure():
    """
    Verify that the required directory structure for webscan exists
    
    Returns:
        bool: True if the structure is correct, False otherwise
    """
    # Current directory where this script is located
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Required directory structure
    required_dirs = [
        "core",
        "database",
        "vulnerabilities",
        "crawlers",
        "info_gathering",
        "reporting",
        "utils"
    ]
    
    # Critical files
    required_files = [
        "core/scanner.py",
        "core/__init__.py",
        "database/db_connector.py",
        "database/db_service.py",
        "database/__init__.py",
        "__init__.py"
    ]
    
    # Check directories
    missing_dirs = []
    for directory in required_dirs:
        dir_path = os.path.join(current_dir, directory)
        if not os.path.isdir(dir_path):
            missing_dirs.append(directory)
    
    # Check files
    missing_files = []
    for file in required_files:
        file_path = os.path.join(current_dir, file)
        if not os.path.isfile(file_path):
            missing_files.append(file)
    
    # Show results
    if missing_dirs or missing_files:
        print(colored("\n[!] ", 'red') + "Problems found with the webscan module structure:")
        
        if missing_dirs:
            print(colored("\n[!] ", 'yellow') + "Missing directories:")
            for directory in missing_dirs:
                print(colored(f"    - {directory}", 'yellow'))
        
        if missing_files:
            print(colored("\n[!] ", 'yellow') + "Missing files:")
            for file in missing_files:
                print(colored(f"    - {file}", 'yellow'))
        
        print(colored("\n[!] ", 'yellow') + "This may cause issues when running the web scanner.")
        return False
    else:
        print(colored("\n[+] ", 'green') + "The webscan module structure appears correct.")
        return True

def verify_database_structure():
    """
    Verify the database structure is correct
    """
    try:
        # First try to import just the Base
        try:
            from src.tools.webscan.database.db_connector import Base
        except ImportError:
            print(colored("[!] ", 'red') + "Could not import database models. Make sure SQLAlchemy is installed.")
            print(colored("[!] ", 'yellow') + "Install SQLAlchemy with: pip install sqlalchemy")
            return False
        
        # Then try to import ModuleStructure
        try:
            from src.tools.webscan.database.db_connector import ModuleStructure
            print(colored("[+] ", 'green') + "Database structure includes the module_structure table.")
            return True
        except (ImportError, AttributeError):
            print(colored("[!] ", 'yellow') + "ModuleStructure not found in database models.")
            print(colored("[!] ", 'yellow') + "Some features may not be available.")
            # Return True because this is a non-critical issue
            return True
            
    except Exception as e:
        print(colored("[!] ", 'red') + f"Error verifying database structure: {str(e)}")
        return False

if __name__ == "__main__":
    print(colored("\n[*] ", 'blue') + "Verifying webscan module structure...")
    
    # Check directory structure
    dirs_ok = check_directory_structure()
    
    # Check database structure
    db_ok = verify_database_structure()
    
    if dirs_ok and db_ok:
        print(colored("\n[+] ", 'green') + "The webscan module appears to be correctly configured.")
        sys.exit(0)
    else:
        print(colored("\n[!] ", 'red') + "Problems were found with the webscan module.")
        print(colored("[!] ", 'yellow') + "Please fix the issues before using the web scanner.")
        sys.exit(1) 