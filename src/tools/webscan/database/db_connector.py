#!/usr/bin/env python3

import os
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

# Base class for all models
Base = declarative_base()

class Scan(Base):
    """Base scan model that contains common scan information"""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    target_url = Column(String(255), nullable=False)
    start_time = Column(DateTime, default=datetime.now)
    end_time = Column(DateTime, nullable=True)
    scan_duration = Column(String(50), nullable=True)
    scanned_urls = Column(Integer, default=0)
    forms_analyzed = Column(Integer, default=0)
    
    # Relationships
    xss_vulnerabilities = relationship("XSSVulnerability", back_populates="scan", cascade="all, delete-orphan")
    sqli_vulnerabilities = relationship("SQLiVulnerability", back_populates="scan", cascade="all, delete-orphan")
    open_redirect_vulnerabilities = relationship("OpenRedirectVulnerability", back_populates="scan", cascade="all, delete-orphan")
    lfi_vulnerabilities = relationship("LFIVulnerability", back_populates="scan", cascade="all, delete-orphan")
    csrf_vulnerabilities = relationship("CSRFVulnerability", back_populates="scan", cascade="all, delete-orphan")
    command_injection_vulnerabilities = relationship("CommandInjectionVulnerability", back_populates="scan", cascade="all, delete-orphan")
    rce_vulnerabilities = relationship("RCEVulnerability", back_populates="scan", cascade="all, delete-orphan")
    cors_vulnerabilities = relationship("CORSVulnerability", back_populates="scan", cascade="all, delete-orphan")
    ssrf_vulnerabilities = relationship("SSRFVulnerability", back_populates="scan", cascade="all, delete-orphan")
    xxe_vulnerabilities = relationship("XXEVulnerability", back_populates="scan", cascade="all, delete-orphan")
    deserialization_vulnerabilities = relationship("DeserializationVulnerability", back_populates="scan", cascade="all, delete-orphan")
    csp_vulnerabilities = relationship("CSPVulnerability", back_populates="scan", cascade="all, delete-orphan")
    ssti_vulnerabilities = relationship("SSTIVulnerability", back_populates="scan", cascade="all, delete-orphan")
    idor_vulnerabilities = relationship("IDORVulnerability", back_populates="scan", cascade="all, delete-orphan")
    ssl_tls_vulnerabilities = relationship("SSLTLSVulnerability", back_populates="scan", cascade="all, delete-orphan")
    missing_headers = relationship("MissingHeaderVulnerability", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan(id={self.id}, target_url='{self.target_url}', start_time='{self.start_time}')>"


class BaseVulnerability:
    """Mixin for common vulnerability fields"""
    id = Column(Integer, primary_key=True)
    type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    risk_score = Column(Integer, nullable=False)
    url = Column(String(255), nullable=False)
    method = Column(String(10), default="GET")
    parameter = Column(String(255), nullable=True)
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    cwe = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=datetime.now)

# Define all vulnerability models
class XSSVulnerability(Base, BaseVulnerability):
    __tablename__ = 'xss_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="xss_vulnerabilities")
    is_reflected = Column(Boolean, default=True)
    context = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<XSSVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"

class SQLiVulnerability(Base, BaseVulnerability):
    __tablename__ = 'sqli_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="sqli_vulnerabilities")
    database_type = Column(String(100), nullable=True)
    is_blind = Column(Boolean, default=False)
    
    def __repr__(self):
        return f"<SQLiVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"

class OpenRedirectVulnerability(Base, BaseVulnerability):
    __tablename__ = 'open_redirect_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="open_redirect_vulnerabilities")
    redirect_url = Column(String(255), nullable=True)
    
    def __repr__(self):
        return f"<OpenRedirectVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"

class LFIVulnerability(Base, BaseVulnerability):
    __tablename__ = 'lfi_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="lfi_vulnerabilities")
    accessed_file = Column(String(255), nullable=True)
    
    def __repr__(self):
        return f"<LFIVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"

class CSRFVulnerability(Base, BaseVulnerability):
    __tablename__ = 'csrf_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="csrf_vulnerabilities")
    form_action = Column(String(255), nullable=True)
    
    def __repr__(self):
        return f"<CSRFVulnerability(id={self.id}, url='{self.url}')>"

class CommandInjectionVulnerability(Base, BaseVulnerability):
    __tablename__ = 'command_injection_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="command_injection_vulnerabilities")
    os_command = Column(String(255), nullable=True)
    
    def __repr__(self):
        return f"<CommandInjectionVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"

class RCEVulnerability(Base, BaseVulnerability):
    __tablename__ = 'rce_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="rce_vulnerabilities")
    execution_method = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<RCEVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"

class CORSVulnerability(Base, BaseVulnerability):
    __tablename__ = 'cors_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="cors_vulnerabilities")
    allow_origin = Column(String(255), nullable=True)
    allow_credentials = Column(Boolean, nullable=True)
    
    def __repr__(self):
        return f"<CORSVulnerability(id={self.id}, url='{self.url}')>"

class SSLTLSVulnerability(Base, BaseVulnerability):
    __tablename__ = 'ssl_tls_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="ssl_tls_vulnerabilities")
    protocol_version = Column(String(50), nullable=True)
    cipher_suite = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<SSLTLSVulnerability(id={self.id}, url='{self.url}')>"

class MissingHeaderVulnerability(Base, BaseVulnerability):
    __tablename__ = 'missing_header_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="missing_headers")
    header_name = Column(String(100), nullable=False)
    
    def __repr__(self):
        return f"<MissingHeaderVulnerability(id={self.id}, url='{self.url}', header_name='{self.header_name}')>"

class DeserializationVulnerability(Base, BaseVulnerability):
    __tablename__ = 'deserialization_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="deserialization_vulnerabilities")
    serialization_format = Column(String(50), nullable=True)
    
    def __repr__(self):
        return f"<DeserializationVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"

class XXEVulnerability(Base, BaseVulnerability):
    __tablename__ = 'xxe_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="xxe_vulnerabilities")
    entity_name = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<XXEVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"

class SSRFVulnerability(Base, BaseVulnerability):
    __tablename__ = 'ssrf_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="ssrf_vulnerabilities")
    target_url = Column(String(255), nullable=True)
    
    def __repr__(self):
        return f"<SSRFVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"

class CSPVulnerability(Base, BaseVulnerability):
    __tablename__ = 'csp_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="csp_vulnerabilities")
    directive = Column(String(100), nullable=True)
    issue = Column(String(255), nullable=True)
    
    def __repr__(self):
        return f"<CSPVulnerability(id={self.id}, url='{self.url}')>"

class SSTIVulnerability(Base, BaseVulnerability):
    __tablename__ = 'ssti_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="ssti_vulnerabilities")
    template_engine = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<SSTIVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"

class IDORVulnerability(Base, BaseVulnerability):
    __tablename__ = 'idor_vulnerabilities'
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    scan = relationship("Scan", back_populates="idor_vulnerabilities")
    original_id = Column(String(100), nullable=True)
    accessed_id = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<IDORVulnerability(id={self.id}, url='{self.url}', parameter='{self.parameter}')>"


class ServerInfo(Base):
    __tablename__ = 'server_info'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    ip_address = Column(String(50), nullable=True)
    server = Column(String(100), nullable=True)
    server_software = Column(String(100), nullable=True)
    server_version = Column(String(50), nullable=True)
    os = Column(String(50), nullable=True)
    framework = Column(String(100), nullable=True)
    headers = Column(Text, nullable=True)  # JSON string
    dns_records = Column(Text, nullable=True)  # JSON string
    
    def __repr__(self):
        return f"<ServerInfo(id={self.id}, ip_address='{self.ip_address}', server='{self.server}')>"


class TechnologyStack(Base):
    __tablename__ = 'technology_stack'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    category = Column(String(100), nullable=False)
    name = Column(String(100), nullable=False)
    version = Column(String(50), nullable=True)
    
    def __repr__(self):
        return f"<TechnologyStack(id={self.id}, category='{self.category}', name='{self.name}')>"

class ModuleStructure(Base):
    __tablename__ = 'module_structure'
    
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, ForeignKey('module_structure.id'), nullable=True)
    name = Column(String(255), nullable=False)
    path = Column(String(500), nullable=False)
    type = Column(String(50), nullable=False)  # 'directory' or 'file'
    description = Column(Text, nullable=True)
    file_type = Column(String(50), nullable=True)  # For files only: 'python', 'json', etc.
    is_executable = Column(Boolean, default=False)
    line_count = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Self-referential relationship
    children = relationship("ModuleStructure", 
                           backref=relationship.backref('parent', remote_side=[id]),
                           cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ModuleStructure(id={self.id}, name='{self.name}', type='{self.type}')>"

# Database connection class
class DatabaseConnection:
    """Database connection manager for NetHawk"""
    
    def __init__(self, db_uri=None):
        """
        Initialize database connection
        
        Args:
            db_uri (str): PostgreSQL connection URI in format postgresql://username:password@host:port/dbname
        """
        if db_uri is None:
            # Default to environment variable or use a default local connection
            db_uri = os.environ.get('NETHAWK_DB_URI', 'postgresql://postgres:postgres@localhost:5432/nethawk')
        
        self.engine = create_engine(db_uri)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
    
    def create_tables(self):
        """Create all database tables if they don't exist"""
        Base.metadata.create_all(self.engine)
    
    def close(self):
        """Close the database connection"""
        self.session.close() 