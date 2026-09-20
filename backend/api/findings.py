from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from datetime import datetime

from database import get_db_session
from database.crud import finding_crud, project_crud
from database.models import Finding, FindingSeverity, FindingStatus, ConfidenceLevel
from backend.logging_config import get_logger, audit_logger

router = APIRouter()
logger = get_logger(__name__)


class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    confidence: Optional[ConfidenceLevel] = None
    severity: Optional[FindingSeverity] = None
    remediation: Optional[str] = None
    tags: Optional[List[str]] = None


class FindingResponse(BaseModel):
    id: int
    uuid: str
    project_id: int
    host_id: Optional[int]
    port_id: Optional[int]
    vulnerability_id: Optional[int]
    title: str
    description: Optional[str]
    category: str
    severity: FindingSeverity
    cvss_score: Optional[float]
    evidence: Optional[str]
    remediation: Optional[str]
    confidence: ConfidenceLevel
    status: FindingStatus
    detection_source: str
    references: Optional[List[str]]
    tags: Optional[List[str]]
    created_at: str
    updated_at: str
    validated_at: Optional[str]
    validated_by: Optional[str]

    class Config:
        from_attributes = True


class FindingDetailResponse(FindingResponse):
    host_ip: Optional[str] = None
    port_number: Optional[int] = None
    cve_id: Optional[str] = None


@router.get("/projects/{project_id}/findings", response_model=List[FindingResponse])
async def list_findings(
    project_id: int,
    severity: Optional[FindingSeverity] = None,
    status: Optional[FindingStatus] = None,
    category: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = await finding_crud.get_by_project(
        session, project_id, severity=severity, status=status, skip=skip, limit=limit
    )

    if category:
        findings = [f for f in findings if f.category == category]

    return findings


@router.get("/findings/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(
    finding_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    finding = await finding_crud.get(session, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    host_ip = finding.host.ip if finding.host else None
    port_number = finding.port.port if finding.port else None
    cve_id = finding.vulnerability.cve_id if finding.vulnerability else None

    response = FindingDetailResponse.model_validate(finding)
    response.host_ip = host_ip
    response.port_number = port_number
    response.cve_id = cve_id
    return response


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: int,
    finding_in: FindingUpdate,
    session: AsyncSession = Depends(get_db_session),
):
    finding = await finding_crud.get(session, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    update_data = finding_in.model_dump(exclude_unset=True)
    if "status" in update_data and update_data["status"] == FindingStatus.CONFIRMED:
        update_data["validated_at"] = datetime.utcnow()
        update_data["validated_by"] = "api_user"

    finding = await finding_crud.update(session, finding, update_data)
    audit_logger.log_finding_updated(finding_id, finding.project_id, update_data)
    logger.info("finding_updated", finding_id=finding_id, changes=update_data)
    return finding


@router.get("/projects/{project_id}/findings/stats")
async def get_finding_stats(
    project_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    severity_counts = await finding_crud.get_severity_counts(session, project_id)
    status_counts = await finding_crud.get_status_counts(session, project_id)

    return {
        "severity": {k.value: v for k, v in severity_counts.items()},
        "status": {k.value: v for k, v in status_counts.items()},
        "total": sum(severity_counts.values()),
    }