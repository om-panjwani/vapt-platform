import enum
import uuid
from datetime import datetime
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship, Column, JSON
from sqlalchemy import Enum as SQLEnum, Text, Index
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON


class ProjectStatus(str, enum.Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class HostStatus(str, enum.Enum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class PortState(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, enum.Enum):
    CONFIRMED = "confirmed"
    NEEDS_VALIDATION = "needs_validation"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"


class ConfidenceLevel(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Project(SQLModel, table=True):
    __tablename__ = "projects"
    __table_args__ = (
        Index("ix_projects_name", "name"),
        Index("ix_projects_created_at", "created_at"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    name: str = Field(max_length=255, index=True)
    description: Optional[str] = Field(default=None, sa_column=Column(Text))
    status: ProjectStatus = Field(default=ProjectStatus.ACTIVE, sa_column=Column(SQLEnum(ProjectStatus)))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = Field(default=None)

    targets: List["Target"] = Relationship(back_populates="project", cascade_delete=True)
    scans: List["ScanJob"] = Relationship(back_populates="project", cascade_delete=True)
    findings: List["Finding"] = Relationship(back_populates="project", cascade_delete=True)
    reports: List["Report"] = Relationship(back_populates="project", cascade_delete=True)


class Target(SQLModel, table=True):
    __tablename__ = "targets"
    __table_args__ = (
        Index("ix_targets_project_id", "project_id"),
        Index("ix_targets_host", "host"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    project_id: int = Field(foreign_key="projects.id", index=True)
    host: str = Field(max_length=255, index=True)
    host_type: str = Field(default="ip", max_length=50)
    allowed_ports: str = Field(default="1-65535", max_length=500)
    excluded_ports: Optional[str] = Field(default=None, max_length=500)
    scope_notes: Optional[str] = Field(default=None, sa_column=Column(Text))
    is_authorized: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    project: Project = Relationship(back_populates="targets")
    hosts: List["Host"] = Relationship(back_populates="target", cascade_delete=True)
    scans: List["ScanJob"] = Relationship(back_populates="target", cascade_delete=True)


class ScanJob(SQLModel, table=True):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_project_id", "project_id"),
        Index("ix_scan_jobs_target_id", "target_id"),
        Index("ix_scan_jobs_status", "status"),
        Index("ix_scan_jobs_started_at", "started_at"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    project_id: int = Field(foreign_key="projects.id", index=True)
    target_id: int = Field(foreign_key="targets.id", index=True)
    name: str = Field(max_length=255)
    scan_type: str = Field(default="tcp_connect", max_length=50)
    port_range: str = Field(default="1-65535", max_length=500)
    nse_scripts: Optional[str] = Field(default=None, max_length=1000)
    arguments: Optional[str] = Field(default=None, max_length=1000)
    status: ScanStatus = Field(default=ScanStatus.PENDING, sa_column=Column(SQLEnum(ScanStatus)))
    progress: int = Field(default=0, ge=0, le=100)
    current_task: Optional[str] = Field(default=None, max_length=255)
    error_message: Optional[str] = Field(default=None, sa_column=Column(Text))
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    project: Project = Relationship(back_populates="scans")
    target: Target = Relationship(back_populates="scans")
    hosts: List["Host"] = Relationship(back_populates="scan_job", cascade_delete=True)
    nse_results: List["NSEResult"] = Relationship(back_populates="scan_job", cascade_delete=True)


class Host(SQLModel, table=True):
    __tablename__ = "hosts"
    __table_args__ = (
        Index("ix_hosts_scan_job_id", "scan_job_id"),
        Index("ix_hosts_target_id", "target_id"),
        Index("ix_hosts_ip", "ip"),
        Index("ix_hosts_status", "status"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    scan_job_id: int = Field(foreign_key="scan_jobs.id", index=True)
    target_id: int = Field(foreign_key="targets.id", index=True)
    ip: str = Field(max_length=45, index=True)
    hostname: Optional[str] = Field(default=None, max_length=255)
    mac_address: Optional[str] = Field(default=None, max_length=17)
    vendor: Optional[str] = Field(default=None, max_length=255)
    os_name: Optional[str] = Field(default=None, max_length=255)
    os_accuracy: Optional[int] = Field(default=None, ge=0, le=100)
    status: HostStatus = Field(default=HostStatus.UNKNOWN, sa_column=Column(SQLEnum(HostStatus)))
    response_time: Optional[float] = Field(default=None)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    scan_job: ScanJob = Relationship(back_populates="hosts")
    target: Target = Relationship(back_populates="hosts")
    ports: List["Port"] = Relationship(back_populates="host", cascade_delete=True)
    nse_results: List["NSEResult"] = Relationship(back_populates="host", cascade_delete=True)


class Port(SQLModel, table=True):
    __tablename__ = "ports"
    __table_args__ = (
        Index("ix_ports_host_id", "host_id"),
        Index("ix_ports_port_number", "port"),
        Index("ix_ports_state", "state"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    host_id: int = Field(foreign_key="hosts.id", index=True)
    port: int = Field(index=True)
    protocol: str = Field(default="tcp", max_length=10)
    state: PortState = Field(default=PortState.OPEN, sa_column=Column(SQLEnum(PortState)))
    service_name: Optional[str] = Field(default=None, max_length=100)
    service_version: Optional[str] = Field(default=None, max_length=255)
    service_product: Optional[str] = Field(default=None, max_length=255)
    service_extrainfo: Optional[str] = Field(default=None, max_length=255)
    service_cpe: Optional[str] = Field(default=None, max_length=255)
    confidence: int = Field(default=0, ge=0, le=100)
    reason: Optional[str] = Field(default=None, max_length=100)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)

    host: Host = Relationship(back_populates="ports")
    services: List["Service"] = Relationship(back_populates="port", cascade_delete=True)
    findings: List["Finding"] = Relationship(back_populates="port", cascade_delete=True)


class Service(SQLModel, table=True):
    __tablename__ = "services"
    __table_args__ = (
        Index("ix_services_port_id", "port_id"),
        Index("ix_services_name", "name"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    port_id: int = Field(foreign_key="ports.id", index=True)
    name: str = Field(max_length=100, index=True)
    version: Optional[str] = Field(default=None, max_length=100)
    product: Optional[str] = Field(default=None, max_length=255)
    extrainfo: Optional[str] = Field(default=None, max_length=255)
    cpe: Optional[str] = Field(default=None, max_length=255)
    fingerprint_method: Optional[str] = Field(default=None, max_length=100)
    confidence: int = Field(default=0, ge=0, le=100)
    banner: Optional[str] = Field(default=None, sa_column=Column(Text))
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    port: Port = Relationship(back_populates="services")
    vulnerabilities: List["Vulnerability"] = Relationship(back_populates="service", cascade_delete=True)


class Vulnerability(SQLModel, table=True):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vulnerabilities_cve_id", "cve_id"),
        Index("ix_vulnerabilities_service_id", "service_id"),
        Index("ix_vulnerabilities_severity", "severity"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    service_id: int = Field(foreign_key="services.id", index=True)
    cve_id: Optional[str] = Field(default=None, max_length=20, index=True)
    title: str = Field(max_length=500)
    description: Optional[str] = Field(default=None, sa_column=Column(Text))
    severity: FindingSeverity = Field(default=FindingSeverity.INFORMATIONAL, sa_column=Column(SQLEnum(FindingSeverity)))
    cvss_score: Optional[float] = Field(default=None, ge=0, le=10)
    cvss_vector: Optional[str] = Field(default=None, max_length=100)
    affected_versions: Optional[str] = Field(default=None, max_length=500)
    fixed_version: Optional[str] = Field(default=None, max_length=100)
    references: Optional[List[str]] = Field(default=None, sa_column=Column(SQLiteJSON))
    remediation: Optional[str] = Field(default=None, sa_column=Column(Text))
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.LOW, sa_column=Column(SQLEnum(ConfidenceLevel)))
    detection_source: str = Field(default="nmap", max_length=100)
    published_date: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    service: Service = Relationship(back_populates="vulnerabilities")
    findings: List["Finding"] = Relationship(back_populates="vulnerability", cascade_delete=True)


class Finding(SQLModel, table=True):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_project_id", "project_id"),
        Index("ix_findings_host_id", "host_id"),
        Index("ix_findings_port_id", "port_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_created_at", "created_at"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    project_id: int = Field(foreign_key="projects.id", index=True)
    host_id: Optional[int] = Field(default=None, foreign_key="hosts.id", index=True)
    port_id: Optional[int] = Field(default=None, foreign_key="ports.id", index=True)
    vulnerability_id: Optional[int] = Field(default=None, foreign_key="vulnerabilities.id", index=True)
    title: str = Field(max_length=500)
    description: Optional[str] = Field(default=None, sa_column=Column(Text))
    category: str = Field(max_length=100, index=True)
    severity: FindingSeverity = Field(default=FindingSeverity.INFORMATIONAL, sa_column=Column(SQLEnum(FindingSeverity)))
    cvss_score: Optional[float] = Field(default=None, ge=0, le=10)
    evidence: Optional[str] = Field(default=None, sa_column=Column(Text))
    remediation: Optional[str] = Field(default=None, sa_column=Column(Text))
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.LOW, sa_column=Column(SQLEnum(ConfidenceLevel)))
    status: FindingStatus = Field(default=FindingStatus.NEEDS_VALIDATION, sa_column=Column(SQLEnum(FindingStatus)))
    detection_source: str = Field(default="automated", max_length=100)
    references: Optional[List[str]] = Field(default=None, sa_column=Column(SQLiteJSON))
    tags: Optional[List[str]] = Field(default=None, sa_column=Column(SQLiteJSON))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    validated_at: Optional[datetime] = Field(default=None)
    validated_by: Optional[str] = Field(default=None, max_length=100)

    project: Project = Relationship(back_populates="findings")
    host: Optional[Host] = Relationship()
    port: Optional[Port] = Relationship()
    vulnerability: Optional[Vulnerability] = Relationship(back_populates="findings")


class NSEResult(SQLModel, table=True):
    __tablename__ = "nse_results"
    __table_args__ = (
        Index("ix_nse_results_scan_job_id", "scan_job_id"),
        Index("ix_nse_results_host_id", "host_id"),
        Index("ix_nse_results_script", "script_name"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    scan_job_id: int = Field(foreign_key="scan_jobs.id", index=True)
    host_id: int = Field(foreign_key="hosts.id", index=True)
    port_id: Optional[int] = Field(default=None, foreign_key="ports.id", index=True)
    script_name: str = Field(max_length=100, index=True)
    script_category: Optional[str] = Field(default=None, max_length=50)
    output: Optional[str] = Field(default=None, sa_column=Column(Text))
    severity: Optional[FindingSeverity] = Field(default=None, sa_column=Column(SQLEnum(FindingSeverity)))
    executed_at: datetime = Field(default_factory=datetime.utcnow)

    scan_job: ScanJob = Relationship(back_populates="nse_results")
    host: Host = Relationship(back_populates="nse_results")
    port: Optional[Port] = Relationship()


class Report(SQLModel, table=True):
    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_project_id", "project_id"),
        Index("ix_reports_generated_at", "generated_at"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    project_id: int = Field(foreign_key="projects.id", index=True)
    name: str = Field(max_length=255)
    format: str = Field(default="html", max_length=20)
    file_path: Optional[str] = Field(default=None, max_length=500)
    status: str = Field(default="generating", max_length=50)
    error_message: Optional[str] = Field(default=None, sa_column=Column(Text))
    generated_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    project: Project = Relationship(back_populates="reports")


class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_timestamp", "timestamp"),
        Index("ix_audit_logs_action", "action"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    user_id: Optional[str] = Field(default=None, max_length=100)
    action: str = Field(max_length=100, index=True)
    resource_type: str = Field(max_length=50)
    resource_id: Optional[str] = Field(default=None, max_length=100)
    details: Optional[str] = Field(default=None, sa_column=Column(SQLiteJSON))
    ip_address: Optional[str] = Field(default=None, max_length=45)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)