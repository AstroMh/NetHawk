# NetHawk WebScan Module Structure

This document provides an overview of the WebScan module structure and functionality.

## Core Module

- **Path**: `src/tools/webscan/core`
- **Description**: Core functionality for the web vulnerability scanner.
- **Files**:
  - `scanner.py`: Main WebScanner class that orchestrates the scanning process.
  - `__init__.py`: Package initialization file.

## Database Module

- **Path**: `src/tools/webscan/database`
- **Description**: Database integration for storing scan results and module information.
- **Files**:
  - `db_connector.py`: Database models and connection management.
  - `db_service.py`: Service layer for database operations.
  - `init_db.py`: Database initialization script.
  - `README.md`: Database usage documentation.

## Vulnerabilities Module

- **Path**: `src/tools/webscan/vulnerabilities`
- **Description**: Contains scanners for various vulnerability types.
- **Submodules**:
  - `xss`: Cross-Site Scripting vulnerability detection.
  - `sqli`: SQL Injection vulnerability detection.
  - `csrf`: Cross-Site Request Forgery vulnerability detection.
  - `open_redirect`: Open Redirect vulnerability detection.
  - `lfi`: Local File Inclusion vulnerability detection.
  - `command_injection`: Command Injection vulnerability detection.
  - `rce`: Remote Code Execution vulnerability detection.
  - `cors`: Cross-Origin Resource Sharing vulnerability detection.
  - `idor`: Insecure Direct Object Reference vulnerability detection.
  - `ssti`: Server-Side Template Injection vulnerability detection.
  - `ssrf`: Server-Side Request Forgery vulnerability detection.
  - `xxe`: XML External Entity vulnerability detection.
  - `jwt`: JSON Web Token vulnerability detection.
  - `oauth`: OAuth vulnerability detection.
  - `crlf`: CRLF Injection vulnerability detection.
  - `request_smuggling`: HTTP Request Smuggling vulnerability detection.
  - `deserialization`: Insecure Deserialization vulnerability detection.
  - `headers`: HTTP Security Headers checking.
  - `ssl_tls`: SSL/TLS configuration checking.
  - `csp`: Content Security Policy checking.

## Crawlers Module

- **Path**: `src/tools/webscan/crawlers`
- **Description**: Tools for crawling websites and discovering content.
- **Files**:
  - `url_crawler.py`: Discovers URLs on the target website.
  - `form_finder.py`: Identifies and extracts forms from web pages.
  - `directory_brute.py`: Brute-forces directories on the target site.

## Information Gathering Module

- **Path**: `src/tools/webscan/info_gathering`
- **Description**: Tools for gathering information about the target.
- **Files**:
  - `server_info.py`: Gathers information about the server.
  - `tech_detection.py`: Detects technologies used by the target.
  - `subdomain_enum.py`: Enumerates subdomains of the target.

## Reporting Module

- **Path**: `src/tools/webscan/reporting`
- **Description**: Generates scan reports in various formats.
- **Files**:
  - `report_generator.py`: Generates scan reports in HTML, PDF, or JSON format.

## Utils Module

- **Path**: `src/tools/webscan/utils`
- **Description**: Utility functions and resources for the scanner.
- **Submodules**:
  - `wordlists`: Contains wordlists for brute-forcing and testing.

## Module Analysis

A new feature has been added to analyze and document the WebScan module structure:

- **File**: `src/tools/webscan/analyze_module.py`
- **Description**: Script to analyze the WebScan module structure and store it in the database.
- **Usage**:
  ```
  python src/tools/webscan/analyze_module.py [--path PATH] [--uri URI] [--list] [--format {text,json}] [-v]
  ```
- **Options**:
  - `--path`: Path to the module directory to analyze (default: current directory)
  - `--uri`: PostgreSQL connection URI
  - `--list`: List module structure from database
  - `--format`: Output format for listing (text or json)
  - `-v, --verbose`: Enable verbose output

The module structure is stored in the `module_structure` table in the database, which contains information about directories, files, their relationships, and descriptions. 