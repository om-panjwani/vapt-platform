from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from datetime import datetime

from database import get_db_session
from database.crud import scan_job_crud, target_crud, project_crud
from database.models import ScanJob, ScanStatus
from scanner.scan_manager import scan_manager
from backend.logging_config import get_logger, audit_logger

router = APIRouter()
logger = get_logger(__name__)


class ScanCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    target_id: int
    scan_type: str = Field(default="tcp_connect", max_length=50)
    port_range: str = Field(default="1-65535", max_length=500)
    nse_scripts: Optional[str] = Field(None, max_length=1000)
    arguments: Optional[str] = Field(None, max_length=1000)


class ScanResponse(BaseModel):
    id: int
    uuid: str
    project_id: int
    target_id: int
    name: str
    scan_type: str
    port_range: str
    nse_scripts: Optional[str]
    arguments: Optional[str]
    status: ScanStatus
    progress: int
    current_task: Optional[str]
    error_message: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class ScanDetailResponse(ScanResponse):
    hosts_count: int


@router.post("/projects/{project_id}/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    project_id: int,
    scan_in: ScanCreate,
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    target = await target_crud.get(session, scan_in.target_id)
    if not target or target.project_id != project_id:
        raise HTTPException(status_code=404, detail="Target not found in project")

    scan = ScanJob(
        project_id=project_id,
        target_id=scan_in.target_id,
        name=scan_in.name,
        scan_type=scan_in.scan_type,
        port_range=scan_in.port_range,
        nse_scripts=scan_in.nse_scripts,
        arguments=scan_in.arguments,
    )
    scan = await scan_job_crud.create(session, scan)
    logger.info("scan_created", scan_id=scan.id, name=scan.name, project_id=project_id)
    return scan


@router.get("/projects/{project_id}/scans", response_model=List[ScanResponse])
async def list_scans(
    project_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[ScanStatus] = None,
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    filters = {"project_id": project_id}
    if status:
        filters["status"] = status
    scans = await scan_job_crud.list(session, skip=skip, limit=limit, filters=filters)
    return scans


@router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    result = await scan_job_crud.get_with_details(session, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.post("/scans/{scan_id}/start", response_model=ScanResponse)
async def start_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db_session),
):
    scan = await scan_job_crud.get(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != ScanStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Scan is not in PENDING status (current: {scan.status.value})")

    target = await target_crud.get(session, scan.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if not target.is_authorized:
        raise HTTPException(status_code=403, detail="Target is not authorized for scanning")

    success = await scan_manager.start_scan(scan_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to start scan")

    scan = await scan_job_crud.get(session, scan_id)
    audit_logger.log_scan_started(scan_id, target.host)
    logger.info("scan_started", scan_id=scan_id, target=target.host)
    return scan


@router.post("/scans/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    scan = await scan_job_crud.get(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan in {scan.status.value} status")

    success = await scan_manager.cancel_scan(scan_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to cancel scan")

    scan = await scan_job_crud.get(session, scan_id)
    logger.info("scan_cancelled", scan_id=scan_id)
    return scan


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    scan = await scan_job_crud.get(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await scan_job_crud.delete(session, scan_id)
    logger.info("scan_deleted", scan_id=scan_id)