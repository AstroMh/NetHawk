# NetHawk Database Integration

This module provides PostgreSQL database integration for the NetHawk web vulnerability scanner, allowing scan results to be stored persistently in a relational database.

## Features

- Store scan information including target URL, timestamps, and scan statistics
- Save server information and technology stack details
- Record all discovered vulnerabilities with detailed information
- Support for all vulnerability types scanned by NetHawk
- Query functionality to retrieve past scan results

## Requirements

- PostgreSQL database server (version 10 or later recommended)
- Python packages:
  - SQLAlchemy (2.0.0 or later)
  - psycopg2-binary (2.9.5 or later)

These dependencies are included in the main NetHawk requirements.txt file.

## Setup Instructions

### 1. Install PostgreSQL

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
```

#### macOS (using Homebrew):
```bash
brew install postgresql
brew services start postgresql
```

#### Windows:
Download and install from: https://www.postgresql.org/download/windows/

### 2. Create Database

```bash
sudo -u postgres psql
```

In the PostgreSQL prompt, create a database and user:
```sql
CREATE DATABASE nethawk;
CREATE USER nethawk_user WITH ENCRYPTED PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE nethawk TO nethawk_user;
\q
```

### 3. Initialize the Database

Use the provided initialization script:

```bash
cd /path/to/NetHawk
python -m src.tools.webscan.database.init_db --uri "postgresql://nethawk_user:your_secure_password@localhost:5432/nethawk"
```

Alternatively, you can set the database URI as an environment variable:

```bash
export NETHAWK_DB_URI="postgresql://nethawk_user:your_secure_password@localhost:5432/nethawk"
python -m src.tools.webscan.database.init_db
```

## Usage

You can specify the database URI when running scans through the NetHawk menu interface, or by setting the `NETHAWK_DB_URI` environment variable.

### Connection URI Format

The PostgreSQL connection URI follows this format:
```
postgresql://username:password@host:port/dbname
```

Example:
```
postgresql://nethawk_user:your_secure_password@localhost:5432/nethawk
```

## Database Schema

The database includes the following main tables:

- `scans`: Contains base scan information
- `server_info`: Server details for each scan
- `technology_stack`: Detected technologies
- Vulnerability tables (one for each vulnerability type):
  - `xss_vulnerabilities`
  - `sqli_vulnerabilities`
  - `open_redirect_vulnerabilities`
  - `lfi_vulnerabilities`
  - `csrf_vulnerabilities`
  - `command_injection_vulnerabilities`
  - `rce_vulnerabilities`
  - `cors_vulnerabilities`
  - `ssl_tls_vulnerabilities`
  - `missing_header_vulnerabilities`
  - `deserialization_vulnerabilities`
  - `xxe_vulnerabilities`
  - `ssrf_vulnerabilities`
  - `csp_vulnerabilities`
  - `ssti_vulnerabilities`
  - `idor_vulnerabilities`

## Accessing Scan Results Directly

You can also query the database directly using standard SQL tools:

```sql
-- Get list of scans
SELECT id, target_url, start_time, scan_duration FROM scans ORDER BY start_time DESC;

-- Get vulnerabilities for a specific scan
SELECT v.type, v.severity, v.url, v.parameter, v.evidence 
FROM xss_vulnerabilities v
WHERE v.scan_id = 1
ORDER BY v.risk_score DESC;
```

## Using the Python API

The database integration includes a Python API for direct access:

```python
from src.tools.webscan.database import DBService

# Connect to database
db = DBService("postgresql://nethawk_user:your_secure_password@localhost:5432/nethawk")

# Get recent scans
recent_scans = db.get_latest_scans(limit=5)

# Get vulnerabilities for a scan
scan_id = 1
vulnerabilities = db.get_vulnerabilities_by_scan(scan_id)

# Close the connection when done
db.close()
``` 