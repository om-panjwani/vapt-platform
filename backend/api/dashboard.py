from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from datetime import datetime, timedelta

from database import get_db_session
from database.crud import project_crud, finding_crud, scan_job_crud
from database.models import Project, Finding, FindingSeverity, ScanJob, ScanStatus, Host, HostStatus, Port, PortState
from vulnerability_engine.findings import findings_engine
from backend.logging_config import get_logger

router = APIRouter()
logger = get_logger(__name__)


class DashboardStats(BaseModel):
    total_projects: int
    active_projects: int
    total_hosts: int
    total_open_ports: int
    total_services: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    informational_findings: int
    recent_scans: int
    running_scans: int


class ProjectSummary(BaseModel):
    id: int
    uuid: str
    name: str
    status: str
    targets_count: int
    scans_count: int
    findings_count: int
    critical_count: int
    high_count: int
    created_at: str


class RecentActivity(BaseModel):
    type: str
    description: str
    timestamp: str
    project_id: Optional[int] = None
    project_name: Optional[str] = None


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    session: AsyncSession = Depends(get_db_session),
):
    total_projects = await project_crud.count(session)
    active_projects = await project_crud.count(session, filters={"status": "active"})

    total_hosts_result = await session.execute(select(func.count(Host.id)))
    total_hosts = total_hosts_result.scalar_one()

    open_ports_result = await session.execute(
        select(func.count(Port.id)).where(Port.state == PortState.OPEN)
    )
    total_open_ports = open_ports_result.scalar_one()

    total_services_result = await session.execute(select(func.count(Host.id)))
    total_services = total_services_result.scalar_one()

    all_findings = await finding_crud.list(session, limit=10000)
    severity_counts = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    recent_scans_result = await session.execute(
        select(func.count(ScanJob.id)).where(
            ScanJob.started_at >= datetime.utcnow() - timedelta(days=7)
        )
    )
    recent_scans = recent_scans_result.scalar_one()

    running_scans_result = await session.execute(
        select(func.count(ScanJob.id)).where(ScanJob.status == ScanStatus.RUNNING)
    )
    running_scans = running_scans_result.scalar_one()

    return DashboardStats(
        total_projects=total_projects,
        active_projects=active_projects,
        total_hosts=total_hosts,
        total_open_ports=total_open_ports,
        total_services=total_services,
        total_findings=len(all_findings),
        critical_findings=severity_counts.get(FindingSeverity.CRITICAL, 0),
        high_findings=severity_counts.get(FindingSeverity.HIGH, 0),
        medium_findings=severity_counts.get(FindingSeverity.MEDIUM, 0),
        low_findings=severity_counts.get(FindingSeverity.LOW, 0),
        informational_findings=severity_counts.get(FindingSeverity.INFORMATIONAL, 0),
        recent_scans=recent_scans,
        running_scans=running_scans,
    )


@router.get("/projects", response_model=List[ProjectSummary])
async def get_project_summaries(
    limit: int = Query(10, ge=1, le=50),
    session: AsyncSession = Depends(get_db_session),
):
    projects = await project_crud.list(session, limit=limit, filters={"status": "active"})
    summaries = []

    for project in projects:
        severity_counts = await finding_crud.get_severity_counts(session, project.id)
        targets_count = await project_crud._count_targets(session, project.id)
        scans_count = await project_crud._count_scans(session, project.id)
        findings_count = await project_crud._count_findings(session, project.id)

        summaries.append(ProjectSummary(
            id=project.id,
            uuid=project.uuid,
            name=project.name,
            status=project.status.value,
            targets_count=targets_count,
            scans_count=scans_count,
            findings_count=findings_count,
            critical_count=severity_counts.get(FindingSeverity.CRITICAL, 0),
            high_count=severity_counts.get(FindingSeverity.HIGH, 0),
            created_at=project.created_at.isoformat(),
        ))

    return summaries


@router.get("/projects/{project_id}/stats")
async def get_project_dashboard_stats(
    project_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    stats = await findings_engine.get_dashboard_stats(project_id)
    return stats


@router.get("/activity", response_model=List[RecentActivity])
async def get_recent_activity(
    limit: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_db_session),
):
    activities = []

    recent_scans = await scan_job_crud.list(
        session, limit=limit, filters={}
    )
    for scan in recent_scans:
        project = await project_crud.get(session, scan.project_id)
        activities.append(RecentActivity(
            type="scan",
            description=f"Scan '{scan.name}' {scan.status.value}",
            timestamp=scan.updated_at.isoformat(),
            project_id=scan.project_id,
            project_name=project.name if project else None,
        ))

    recent_findings = await finding_crud.list(session, limit=limit)
    for finding in recent_findings:
        project = await project_crud.get(session, finding.project_id)
        activities.append(RecentActivity(
            type="finding",
            description=f"Finding: {finding.title} ({finding.severity.value})",
            timestamp=finding.created_at.isoformat(),
            project_id=finding.project_id,
            project_name=project.name if project else None,
        ))

    activities.sort(key=lambda x: x.timestamp, reverse=True)
    return activities[:limit]