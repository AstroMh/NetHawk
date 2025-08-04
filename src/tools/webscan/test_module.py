#!/usr/bin/env python3

import os
import sys
import json

def analyze_module_structure(module_path=None, verbose=False):
    """
    Simple function to analyze the module structure
    
    Args:
        module_path (str): Path to the module directory
        verbose (bool): Whether to print verbose output
    """
    # If no path is provided, use the current directory
    if not module_path:
        module_path = os.path.dirname(os.path.abspath(__file__))
    
    print(f"Analyzing module structure at {module_path}")
    
    # Get the directory structure
    structure = get_directory_structure(module_path)
    
    # Print as JSON
    print(json.dumps(structure, indent=2))
    
    return True

def get_directory_structure(path):
    """
    Get the directory structure as a nested dictionary
    
    Args:
        path (str): Path to the directory
    
    Returns:
        dict: Directory structure
    """
    result = {
        "name": os.path.basename(path),
        "path": path,
        "type": "directory" if os.path.isdir(path) else "file",
        "children": []
    }
    
    if os.path.isdir(path):
        # Count subdirectories and files
        subdirs = []
        files = []
        
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if item.startswith('.') or item.startswith('__pycache__'):
                continue
                
            if os.path.isdir(item_path):
                subdirs.append(item)
            else:
                files.append(item)
        
        result["description"] = f"Directory containing {len(subdirs)} subdirectories and {len(files)} files"
        
        # Add children
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if item.startswith('.') or item.startswith('__pycache__'):
                continue
                
            result["children"].append(get_directory_structure(item_path))
    else:
        # Add file information
        _, ext = os.path.splitext(path)
        file_type = ext.lstrip('.') if ext else None
        
        # Count lines in file
        line_count = None
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = sum(1 for _ in f)
        except Exception:
            pass
        
        # Check if file is executable
        is_executable = os.access(path, os.X_OK)
        
        result["file_type"] = file_type
        result["line_count"] = line_count
        result["is_executable"] = is_executable
        
        # Add file description
        if file_type == 'py':
            result["description"] = "Python module file"
        elif file_type == 'md':
            result["description"] = "Documentation file"
        elif file_type in ['txt', 'csv', 'json', 'yaml', 'yml']:
            result["description"] = f"{file_type.upper()} data file"
        else:
            result["description"] = f"{file_type} file" if file_type else "Unknown file type"
    
    return result

if __name__ == "__main__":
    # Get module path from command line
    module_path = sys.argv[1] if len(sys.argv) > 1 else None
    
    # Run the module analyzer
    analyze_module_structure(module_path, verbose=True) 