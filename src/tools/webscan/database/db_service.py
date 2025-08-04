#!/usr/bin/env python3

import json
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError
from .db_connector import (
    DatabaseConnection, Scan, ServerInfo, TechnologyStack,
    XSSVulnerability, SQLiVulnerability, OpenRedirectVulnerability,
    LFIVulnerability, CSRFVulnerability, CommandInjectionVulnerability,
    RCEVulnerability, CORSVulnerability, SSLTLSVulnerability,
    MissingHeaderVulnerability, DeserializationVulnerability,
    XXEVulnerability, SSRFVulnerability, CSPVulnerability,
    SSTIVulnerability, IDORVulnerability, ModuleStructure
)
import os

class DBService:
    """Service for handling database operations"""
    
    def __init__(self, db_uri=None):
        """
        Initialize database service
        
        Args:
            db_uri (str): PostgreSQL connection URI
        """
        self.db = DatabaseConnection(db_uri)
        # Ensure tables exist
        self.db.create_tables()
    
    def create_scan(self, scanner):
        """
        Create a scan record in the database
        
        Args:
            scanner: WebScanner instance
            
        Returns:
            Scan: The created scan record
        """
        try:
            scan = Scan(
                target_url=scanner.target_url,
                start_time=scanner.start_time,
                scanned_urls=len(scanner.discovered_urls),
                forms_analyzed=len(scanner.forms)
            )
            
            self.db.session.add(scan)
            self.db.session.commit()
            return scan
        except SQLAlchemyError as e:
            self.db.session.rollback()
            raise e
    
    def complete_scan(self, scan, scanner):
        """
        Update the scan record when the scan is completed
        
        Args:
            scan: Scan record to update
            scanner: WebScanner instance
        """
        try:
            scan.end_time = datetime.now()
            scan.scan_duration = str(datetime.now() - scanner.start_time)
            scan.scanned_urls = len(scanner.discovered_urls)
            scan.forms_analyzed = len(scanner.forms)
            
            self.db.session.commit()
        except SQLAlchemyError as e:
            self.db.session.rollback()
            raise e
    
    def save_server_info(self, scan_id, server_info):
        """
        Save server information
        
        Args:
            scan_id (int): ID of the scan
            server_info (dict): Server information dict
        
        Returns:
            ServerInfo: The created server info record
        """
        try:
            # Convert dict fields to JSON strings
            headers_json = json.dumps(server_info.get('headers', {}))
            dns_records_json = json.dumps(server_info.get('dns_records', {}))
            
            # Create server info record
            server_info_record = ServerInfo(
                scan_id=scan_id,
                ip_address=server_info.get('ip_address'),
                server=server_info.get('server'),
                server_software=server_info.get('server_software'),
                server_version=server_info.get('server_version'),
                os=server_info.get('os'),
                framework=server_info.get('framework'),
                headers=headers_json,
                dns_records=dns_records_json
            )
            
            self.db.session.add(server_info_record)
            self.db.session.commit()
            return server_info_record
        except SQLAlchemyError as e:
            self.db.session.rollback()
            raise e
    
    def save_tech_stack(self, scan_id, tech_stack):
        """
        Save technology stack information
        
        Args:
            scan_id (int): ID of the scan
            tech_stack (dict): Technology stack dict
        """
        try:
            # Handle both dict and list formats
            if isinstance(tech_stack, list):
                for item in tech_stack:
                    if isinstance(item, dict):
                        tech_record = TechnologyStack(
                            scan_id=scan_id,
                            category='detected_technologies',
                            name=item.get('name', 'Unknown'),
                            version=item.get('version')
                        )
                    else:
                        tech_record = TechnologyStack(
                            scan_id=scan_id,
                            category='detected_technologies',
                            name=str(item),
                            version=None
                        )
                    self.db.session.add(tech_record)
            else:
                # Handle dict format
                for category, technologies in tech_stack.items():
                    for item in technologies:
                        if isinstance(item, dict):
                            tech_record = TechnologyStack(
                                scan_id=scan_id,
                                category=category,
                                name=item.get('name', 'Unknown'),
                                version=item.get('version')
                            )
                        else:
                            tech_record = TechnologyStack(
                                scan_id=scan_id,
                                category=category,
                                name=str(item),
                                version=None
                            )
                        self.db.session.add(tech_record)
            
            self.db.session.commit()
        except SQLAlchemyError as e:
            self.db.session.rollback()
            raise e
    
    def save_single_vulnerability_type(self, scan_id, vuln_key, vulnerabilities, description=""):
        """
        Save a specific type of vulnerabilities to the database immediately
        
        Args:
            scan_id (int): ID of the scan
            vuln_key (str): Vulnerability type key (e.g., 'xss', 'sqli')
            vulnerabilities (list): List of vulnerability dictionaries
            description (str): Description of the vulnerability type
            
        Returns:
            int: Number of vulnerabilities saved
        """
        vuln_type_mapping = {
            'xss': 'XSS',
            'sqli': 'SQL Injection',
            'open_redirect': 'Open Redirect',
            'lfi': 'LFI',
            'csrf': 'CSRF',
            'command_injection': 'Command Injection',
            'rce': 'RCE',
            'cors': 'CORS',
            'ssl_tls': 'SSL/TLS',
            'missing_headers': 'Missing HTTP Security Headers',
            'deserialization': 'Deserialization',
            'xxe': 'XXE',
            'ssrf': 'SSRF',
            'csp': 'CSP',
            'ssti': 'SSTI',
            'idor': 'IDOR'
        }
        
        # Get the proper vulnerability type name
        vuln_type = vuln_type_mapping.get(vuln_key, vuln_key.upper())
        
        # Save each vulnerability
        count = 0
        for vulnerability in vulnerabilities:
            try:
                self.save_vulnerability(vuln_type, scan_id, vulnerability, 
                                       {vuln_type: {'description': description}})
                count += 1
            except Exception as e:
                print(f"Failed to save {vuln_type} vulnerability: {str(e)}")
                
        return count
    
    def save_vulnerability(self, vuln_type, scan_id, vulnerability, vuln_descriptions=None):
        """
        Save a vulnerability to the database
        
        Args:
            vuln_type (str): Type of vulnerability (e.g., 'XSS', 'SQLi')
            scan_id (int): ID of the scan
            vulnerability (dict): Vulnerability information
            vuln_descriptions (dict): Dictionary of vulnerability descriptions
            
        Returns:
            The created vulnerability record
        """
        try:
            # Get vulnerability description if available
            description_data = {}
            if vuln_descriptions and vuln_type in vuln_descriptions:
                description_data = vuln_descriptions[vuln_type]
            
            # Get severity and risk score
            severity = vulnerability.get('severity', description_data.get('severity', 'medium'))
            risk_score = vulnerability.get('risk_score', description_data.get('risk_score', 50))
            
            # Create base vulnerability data
            base_data = {
                'scan_id': scan_id,
                'type': vuln_type,
                'severity': severity,
                'risk_score': risk_score,
                'url': vulnerability.get('url', ''),
                'method': vulnerability.get('method', 'GET'),
                'parameter': vulnerability.get('parameter', vulnerability.get('parameters', '')),
                'payload': vulnerability.get('payload', ''),
                'evidence': vulnerability.get('evidence', ''),
                'description': description_data.get('description', ''),
                'impact': description_data.get('impact', ''),
                'remediation': description_data.get('remediation', ''),
                'cwe': description_data.get('cwe', '')
            }
            
            # Create the appropriate vulnerability object based on type
            vuln_record = None
            
            if vuln_type == 'XSS':
                vuln_record = XSSVulnerability(
                    **base_data,
                    is_reflected=vulnerability.get('is_reflected', True),
                    context=vulnerability.get('context', '')
                )
            elif vuln_type == 'SQL Injection':
                vuln_record = SQLiVulnerability(
                    **base_data,
                    database_type=vulnerability.get('database_type', ''),
                    is_blind=vulnerability.get('is_blind', False)
                )
            elif vuln_type == 'Open Redirect':
                vuln_record = OpenRedirectVulnerability(
                    **base_data,
                    redirect_url=vulnerability.get('redirect_url', '')
                )
            elif vuln_type == 'LFI':
                vuln_record = LFIVulnerability(
                    **base_data,
                    accessed_file=vulnerability.get('accessed_file', '')
                )
            elif vuln_type == 'CSRF':
                vuln_record = CSRFVulnerability(
                    **base_data,
                    form_action=vulnerability.get('form_action', '')
                )
            elif vuln_type == 'Command Injection':
                vuln_record = CommandInjectionVulnerability(
                    **base_data,
                    os_command=vulnerability.get('os_command', '')
                )
            elif vuln_type == 'RCE':
                vuln_record = RCEVulnerability(
                    **base_data,
                    execution_method=vulnerability.get('execution_method', '')
                )
            elif vuln_type == 'CORS':
                vuln_record = CORSVulnerability(
                    **base_data,
                    allow_origin=vulnerability.get('allow_origin', ''),
                    allow_credentials=vulnerability.get('allow_credentials', False)
                )
            elif vuln_type == 'SSL/TLS':
                vuln_record = SSLTLSVulnerability(
                    **base_data,
                    protocol_version=vulnerability.get('protocol_version', ''),
                    cipher_suite=vulnerability.get('cipher_suite', '')
                )
            elif vuln_type == 'Missing HTTP Security Headers':
                vuln_record = MissingHeaderVulnerability(
                    **base_data,
                    header_name=vulnerability.get('header_name', '')
                )
            elif vuln_type == 'Deserialization':
                vuln_record = DeserializationVulnerability(
                    **base_data,
                    serialization_format=vulnerability.get('serialization_format', '')
                )
            elif vuln_type == 'XXE':
                vuln_record = XXEVulnerability(
                    **base_data,
                    entity_name=vulnerability.get('entity_name', '')
                )
            elif vuln_type == 'SSRF':
                vuln_record = SSRFVulnerability(
                    **base_data,
                    target_url=vulnerability.get('target_url', '')
                )
            elif vuln_type == 'CSP':
                vuln_record = CSPVulnerability(
                    **base_data,
                    directive=vulnerability.get('directive', ''),
                    issue=vulnerability.get('issue', '')
                )
            elif vuln_type == 'SSTI':
                vuln_record = SSTIVulnerability(
                    **base_data,
                    template_engine=vulnerability.get('template_engine', '')
                )
            elif vuln_type == 'IDOR':
                vuln_record = IDORVulnerability(
                    **base_data,
                    original_id=vulnerability.get('original_id', ''),
                    accessed_id=vulnerability.get('accessed_id', '')
                )
            
            if vuln_record:
                self.db.session.add(vuln_record)
                self.db.session.commit()
                return vuln_record
            
            return None
        except SQLAlchemyError as e:
            self.db.session.rollback()
            raise e
    
    def save_vulnerabilities(self, scan_id, scanner, vuln_descriptions=None):
        """
        Save all vulnerabilities from a scan
        
        Args:
            scan_id (int): ID of the scan
            scanner: WebScanner instance
            vuln_descriptions (dict): Dictionary of vulnerability descriptions
        """
        # Process all vulnerability collections
        collections = [
            ('XSS', scanner.xss_vulnerabilities),
            ('SQL Injection', scanner.sqli_vulnerabilities),
            ('Open Redirect', scanner.open_redirect_vulnerabilities),
            ('LFI', scanner.lfi_vulnerabilities),
            ('CSRF', scanner.csrf_vulnerabilities),
            ('Command Injection', scanner.command_injection_vulnerabilities),
            ('RCE', scanner.rce_vulnerabilities),
            ('CORS', scanner.cors_vulnerabilities),
            ('SSL/TLS', scanner.ssl_tls_vulnerabilities),
            ('Missing HTTP Security Headers', scanner.missing_headers),
            ('Deserialization', scanner.deserialization_vulnerabilities),
            ('XXE', scanner.xxe_vulnerabilities),
            ('SSRF', scanner.ssrf_vulnerabilities),
            ('CSP', scanner.csp_vulnerabilities),
            ('SSTI', scanner.ssti_vulnerabilities),
            ('IDOR', scanner.idor_vulnerabilities)
        ]
        
        try:
            for vuln_type, collection in collections:
                for vulnerability in collection:
                    self.save_vulnerability(vuln_type, scan_id, vulnerability, vuln_descriptions)
            
            # Also process the main vulnerabilities list
            for vulnerability in scanner.vulnerabilities:
                vuln_type = vulnerability.get('type', 'Unknown')
                self.save_vulnerability(vuln_type, scan_id, vulnerability, vuln_descriptions)
        except SQLAlchemyError as e:
            self.db.session.rollback()
            raise e
    
    def get_scan_by_id(self, scan_id):
        """
        Get a scan by ID
        
        Args:
            scan_id (int): ID of the scan
            
        Returns:
            Scan: The scan record
        """
        return self.db.session.query(Scan).filter(Scan.id == scan_id).first()
    
    def get_scans_by_target(self, target_url):
        """
        Get all scans for a target URL
        
        Args:
            target_url (str): Target URL
            
        Returns:
            list: List of scan records
        """
        return self.db.session.query(Scan).filter(Scan.target_url.like(f"%{target_url}%")).all()
    
    def get_latest_scans(self, limit=10):
        """
        Get the latest scans
        
        Args:
            limit (int): Maximum number of scans to return
            
        Returns:
            list: List of scan records
        """
        return self.db.session.query(Scan).order_by(Scan.start_time.desc()).limit(limit).all()
    
    def get_vulnerabilities_by_scan(self, scan_id):
        """
        Get all vulnerabilities for a scan
        
        Args:
            scan_id (int): ID of the scan
            
        Returns:
            dict: Dictionary of vulnerability lists by type
        """
        # Query all vulnerability types for this scan
        vulns = {
            'XSS': self.db.session.query(XSSVulnerability).filter(XSSVulnerability.scan_id == scan_id).all(),
            'SQL Injection': self.db.session.query(SQLiVulnerability).filter(SQLiVulnerability.scan_id == scan_id).all(),
            'Open Redirect': self.db.session.query(OpenRedirectVulnerability).filter(OpenRedirectVulnerability.scan_id == scan_id).all(),
            'LFI': self.db.session.query(LFIVulnerability).filter(LFIVulnerability.scan_id == scan_id).all(),
            'CSRF': self.db.session.query(CSRFVulnerability).filter(CSRFVulnerability.scan_id == scan_id).all(),
            'Command Injection': self.db.session.query(CommandInjectionVulnerability).filter(CommandInjectionVulnerability.scan_id == scan_id).all(),
            'RCE': self.db.session.query(RCEVulnerability).filter(RCEVulnerability.scan_id == scan_id).all(),
            'CORS': self.db.session.query(CORSVulnerability).filter(CORSVulnerability.scan_id == scan_id).all(),
            'SSL/TLS': self.db.session.query(SSLTLSVulnerability).filter(SSLTLSVulnerability.scan_id == scan_id).all(),
            'Missing HTTP Security Headers': self.db.session.query(MissingHeaderVulnerability).filter(MissingHeaderVulnerability.scan_id == scan_id).all(),
            'Deserialization': self.db.session.query(DeserializationVulnerability).filter(DeserializationVulnerability.scan_id == scan_id).all(),
            'XXE': self.db.session.query(XXEVulnerability).filter(XXEVulnerability.scan_id == scan_id).all(),
            'SSRF': self.db.session.query(SSRFVulnerability).filter(SSRFVulnerability.scan_id == scan_id).all(),
            'CSP': self.db.session.query(CSPVulnerability).filter(CSPVulnerability.scan_id == scan_id).all(),
            'SSTI': self.db.session.query(SSTIVulnerability).filter(SSTIVulnerability.scan_id == scan_id).all(),
            'IDOR': self.db.session.query(IDORVulnerability).filter(IDORVulnerability.scan_id == scan_id).all()
        }
        
        # Remove empty lists
        return {k: v for k, v in vulns.items() if v}
    
    def get_tech_stack_by_scan(self, scan_id):
        """
        Get technology stack for a scan
        
        Args:
            scan_id (int): ID of the scan
            
        Returns:
            dict: Dictionary of technologies by category
        """
        tech_records = self.db.session.query(TechnologyStack).filter(TechnologyStack.scan_id == scan_id).all()
        
        # Group by category
        tech_stack = {}
        for record in tech_records:
            if record.category not in tech_stack:
                tech_stack[record.category] = []
            
            if record.version:
                tech_stack[record.category].append({
                    'name': record.name,
                    'version': record.version
                })
            else:
                tech_stack[record.category].append(record.name)
        
        return tech_stack
    
    def get_server_info_by_scan(self, scan_id):
        """
        Get server information for a specific scan
        
        Args:
            scan_id (int): ID of the scan
            
        Returns:
            dict: Server information
        """
        try:
            server_info = self.db.session.query(ServerInfo).filter_by(scan_id=scan_id).first()
            
            if not server_info:
                return None
            
            # Convert JSON strings back to dicts
            headers = json.loads(server_info.headers) if server_info.headers else {}
            dns_records = json.loads(server_info.dns_records) if server_info.dns_records else {}
        
        return {
                'ip_address': server_info.ip_address,
                'server': server_info.server,
                'server_software': server_info.server_software,
                'server_version': server_info.server_version,
                'os': server_info.os,
                'framework': server_info.framework,
            'headers': headers,
            'dns_records': dns_records
            }
        except SQLAlchemyError as e:
            print(f"Error retrieving server info: {str(e)}")
            return None

    def save_module_structure(self, module_path, parent_id=None):
        """
        Save module structure information (directories and files)
        
        Args:
            module_path (str): Path to the module directory
            parent_id (int): ID of the parent module in the database
            
        Returns:
            ModuleStructure: The created module record
        """
        try:
            # Get the base name of the current path
            name = os.path.basename(module_path)
            
            # Check if this is a file or directory
            is_file = os.path.isfile(module_path)
            
            # Calculate file properties if it's a file
            line_count = None
            file_type = None
            is_executable = False
            
            if is_file:
                # Get file extension for file_type
                _, ext = os.path.splitext(module_path)
                file_type = ext.lstrip('.') if ext else None
                
                # Count the number of lines
                try:
                    with open(module_path, 'r', encoding='utf-8', errors='ignore') as f:
                        line_count = sum(1 for _ in f)
                except Exception:
                    line_count = None
                
                # Check if file is executable
                is_executable = os.access(module_path, os.X_OK)
            
            # Create module record
            module_record = ModuleStructure(
                parent_id=parent_id,
                name=name,
                path=module_path,
                type='file' if is_file else 'directory',
                file_type=file_type,
                line_count=line_count,
                is_executable=is_executable
            )
            
            # Description based on file type and directory content
            if is_file:
                if file_type == 'py':
                    module_record.description = "Python module file"
                elif file_type == 'md':
                    module_record.description = "Documentation file"
                elif file_type in ['txt', 'csv', 'json', 'yaml', 'yml']:
                    module_record.description = f"{file_type.upper()} data file"
                else:
                    module_record.description = f"{file_type} file" if file_type else "Unknown file type"
            else:
                subdirs = [name for name in os.listdir(module_path) 
                          if os.path.isdir(os.path.join(module_path, name))]
                files = [name for name in os.listdir(module_path) 
                        if os.path.isfile(os.path.join(module_path, name))]
                
                module_record.description = f"Directory containing {len(subdirs)} subdirectories and {len(files)} files"
            
            self.db.session.add(module_record)
            self.db.session.commit()
            
            # If it's a directory, process all its children
            if not is_file:
                for item in os.listdir(module_path):
                    item_path = os.path.join(module_path, item)
                    # Skip __pycache__ directories and hidden files/directories
                    if os.path.basename(item_path).startswith('__pycache__') or os.path.basename(item_path).startswith('.'):
                        continue
                    self.save_module_structure(item_path, module_record.id)
            
            return module_record
        except SQLAlchemyError as e:
            self.db.session.rollback()
            raise e
        except Exception as e:
            print(f"Error saving module structure for {module_path}: {str(e)}")
            return None
    
    def get_module_structure(self, root_path=None):
        """
        Get the module structure from the database
        
        Args:
            root_path (str): Filter by root path
            
        Returns:
            list: List of module structure records in a hierarchical format
        """
        try:
            if root_path:
                # Find the root module by path
                root_module = self.db.session.query(ModuleStructure).filter_by(path=root_path).first()
                if not root_module:
                    return []
                
                # Get the hierarchical structure
                return self._build_module_hierarchy(root_module.id)
            else:
                # Get all root modules (with no parent)
                root_modules = self.db.session.query(ModuleStructure).filter_by(parent_id=None).all()
                result = []
                
                for root in root_modules:
                    result.append(self._build_module_hierarchy(root.id))
                
                return result
        except SQLAlchemyError as e:
            print(f"Error retrieving module structure: {str(e)}")
            return []
    
    def _build_module_hierarchy(self, module_id):
        """
        Build a hierarchical structure from the module records
        
        Args:
            module_id (int): ID of the root module
            
        Returns:
            dict: Hierarchical representation of the module structure
        """
        module = self.db.session.query(ModuleStructure).get(module_id)
        if not module:
            return None
        
        # Convert module to dict
        module_dict = {
            'id': module.id,
            'name': module.name,
            'path': module.path,
            'type': module.type,
            'description': module.description,
            'file_type': module.file_type,
            'is_executable': module.is_executable,
            'line_count': module.line_count,
            'children': []
        }
        
        # Get children
        children = self.db.session.query(ModuleStructure).filter_by(parent_id=module.id).all()
        
        for child in children:
            child_dict = self._build_module_hierarchy(child.id)
            if child_dict:
                module_dict['children'].append(child_dict)
        
        return module_dict
    
    def close(self):
        """Close the database connection"""
        self.db.close() 