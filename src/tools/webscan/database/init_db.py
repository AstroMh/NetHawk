#!/usr/bin/env python3

import os
import sys
import argparse
from termcolor import colored

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from src.tools.webscan.database.db_connector import DatabaseConnection, Base

def init_database(db_uri=None):
    """
    Initialize the PostgreSQL database by creating all required tables.
    
    Args:
        db_uri (str): PostgreSQL connection URI
    """
    print(colored("[*] ", 'blue') + "Initializing NetHawk database...")
    
    try:
        # Create database connection
        db = DatabaseConnection(db_uri)
        
        # Create tables
        print(colored("[*] ", 'blue') + "Creating database tables...")
        Base.metadata.create_all(db.engine)
        
        print(colored("[+] ", 'green') + "Database initialization completed successfully!")
        print(colored("[+] ", 'green') + f"Database URI: {db_uri or os.environ.get('NETHAWK_DB_URI', 'postgresql://postgres:postgres@localhost:5432/nethawk')}")
        
        # Close the connection
        db.close()
        
        return True
    except Exception as e:
        print(colored("[!] ", 'red') + f"Error initializing database: {str(e)}")
        return False

# Verificar que todas las dependencias para la base de datos estén instaladas
# Check that all database dependencies are installed
def check_db_dependencies():
    """
    Check if all database dependencies are installed
    
    Returns:
        bool: True if all dependencies are installed, False otherwise
    """
    dependencies_met = True
    
    try:
        import sqlalchemy
    except ImportError:
        dependencies_met = False
        print(colored("[!] ", 'red') + "SQLAlchemy is not installed.")
        print(colored("[!] ", 'yellow') + "Please install it with: 'pip install sqlalchemy'")
    
    try:
        import psycopg2
    except ImportError:
        dependencies_met = False
        print(colored("[!] ", 'red') + "psycopg2 is not installed.")
        print(colored("[!] ", 'yellow') + "Please install it with: 'pip install psycopg2-binary'")
    
    return dependencies_met

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetHawk Database Initialization Tool")
    parser.add_argument("--uri", help="PostgreSQL connection URI (postgresql://username:password@host:port/dbname)")
    args = parser.parse_args()
    
    # Verificar dependencias de base de datos
    if not check_db_dependencies():
        print(colored("[!] ", 'red') + "Missing database dependencies. Please install them before proceeding.")
        sys.exit(1)
    
    # Use URI from command line or environment variable
    db_uri = args.uri or os.environ.get("NETHAWK_DB_URI")
    
    if not db_uri:
        print(colored("[!] ", 'yellow') + "No database URI provided. Using default: postgresql://postgres:postgres@localhost:5432/nethawk")
        db_uri = "postgresql://postgres:postgres@localhost:5432/nethawk"
    
    # Initialize the database
    success = init_database(db_uri)
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1) 