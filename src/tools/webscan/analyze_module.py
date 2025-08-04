#!/usr/bin/env python3

import os
import sys
import argparse
import json
from termcolor import colored

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from src.tools.webscan.database.db_service import DBService

def analyze_module_structure(module_path=None, db_uri=None, verbose=False):
    """
    Analyze the webscan module structure and save it to the database
    
    Args:
        module_path (str): Path to the module directory. If None, uses the current directory.
        db_uri (str): Database URI. If None, uses environment variable or default.
        verbose (bool): Whether to print verbose output.
        
    Returns:
        bool: True if successful, False otherwise
    """
    # If no path provided, use the current directory
    if not module_path:
        module_path = os.path.dirname(os.path.abspath(__file__))
    
    print(colored("[*] ", 'blue') + f"Analyzing module structure at {module_path}")
    
    try:
        # Initialize database service
        db = DBService(db_uri)
        
        # Save module structure
        root_module = db.save_module_structure(module_path)
        
        if verbose and root_module:
            print(colored("[+] ", 'green') + f"Root module ID: {root_module.id}")
            print(colored("[+] ", 'green') + f"Root module name: {root_module.name}")
            print(colored("[+] ", 'green') + f"Root module path: {root_module.path}")
            print(colored("[+] ", 'green') + f"Root module description: {root_module.description}")
        
        print(colored("[+] ", 'green') + "Module structure analysis completed and saved to database")
        
        # Close database connection
        db.close()
        
        return True
    except Exception as e:
        print(colored("[!] ", 'red') + f"Error analyzing module structure: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def list_module_structure(output_format="text", db_uri=None):
    """
    List the module structure from the database
    
    Args:
        output_format (str): Output format ('text' or 'json')
        db_uri (str): Database URI. If None, uses environment variable or default.
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Initialize database service
        db = DBService(db_uri)
        
        # Get module structure
        modules = db.get_module_structure()
        
        if not modules:
            print(colored("[!] ", 'yellow') + "No module structure found in the database")
            return False
        
        if output_format == "json":
            # Print as JSON
            print(json.dumps(modules, indent=2))
        else:
            # Print as text
            for module in modules:
                _print_module_structure(module)
        
        # Close database connection
        db.close()
        
        return True
    except Exception as e:
        print(colored("[!] ", 'red') + f"Error listing module structure: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def _print_module_structure(module, indent=0):
    """
    Print module structure in a hierarchical format
    
    Args:
        module (dict): Module structure dict
        indent (int): Indentation level
    """
    # Determine color based on type
    color = 'blue' if module['type'] == 'directory' else 'white'
    
    # Format the module information
    module_info = f"{' ' * indent}{'├─ ' if indent > 0 else ''}{module['name']}"
    
    # Add additional info based on type
    if module['type'] == 'file':
        file_info = []
        if module['file_type']:
            file_info.append(f"{module['file_type']}")
        if module['line_count']:
            file_info.append(f"{module['line_count']} lines")
        if module['is_executable']:
            file_info.append("executable")
        
        if file_info:
            module_info += f" ({', '.join(file_info)})"
    else:
        module_info += f" ({len(module['children'])} items)"
    
    # Print the module information
    print(colored(module_info, color))
    
    # Print description with indentation
    if module['description']:
        desc_indent = indent + 4
        print(colored(f"{' ' * desc_indent}└─ {module['description']}", 'dark_grey'))
    
    # Print children
    for child in module['children']:
        _print_module_structure(child, indent + 4)

def main():
    """Main function to run the module analyzer"""
    parser = argparse.ArgumentParser(description="NetHawk WebScan Module Structure Analyzer")
    parser.add_argument("--path", help="Path to the module directory to analyze")
    parser.add_argument("--uri", help="PostgreSQL connection URI (postgresql://username:password@host:port/dbname)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--list", action="store_true", help="List module structure from database")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format for listing (text or json)")
    args = parser.parse_args()
    
    # Use URI from command line or environment variable
    db_uri = args.uri or os.environ.get("NETHAWK_DB_URI")
    
    if not db_uri:
        print(colored("[!] ", 'yellow') + "No database URI provided. Using default: postgresql://postgres:postgres@localhost:5432/nethawk")
        db_uri = "postgresql://postgres:postgres@localhost:5432/nethawk"
    
    # Check if we're listing or analyzing
    if args.list:
        success = list_module_structure(args.format, db_uri)
    else:
        # Get the module path
        module_path = args.path
        
        # Run the module analyzer
        success = analyze_module_structure(module_path, db_uri, args.verbose)
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main() 