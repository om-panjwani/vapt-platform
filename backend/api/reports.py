from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from fastapi.responses import FileResponse

from database import get_db_session
from database.crud import report_crud, project_crud
from database.models import Report
from backend.logging_config import get_logger, audit_logger

router = APIRouter()
logger = get_logger(__name__)


class ReportCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    format: str = Field(default="html", pattern="^(html|pdf)$")
    executive_summary: Optional[str] = None
    methodology: Optional[str] = None


class ReportResponse(BaseModel):
    id: int
    uuid: str
    project_id: int
    name: str
    format: str
    file_path: Optional[str]
    status: str
    error_message: Optional[str]
    generated_at: Optional[str]
    created_at: str

    class Config:
        from_attributes = True


async def generate_report_task(
    report_id: int,
    project_id: int,
    format: str,
    executive_summary: Optional[str],
    methodology: Optional[str],
):
    from reports.generator import report_generator
    from database import get_db_session
    async with get_db_session() as session:
        try:
            await report_generator.generate_report(
                project_id=project_id,
                name=f"Report {report_id}",
                format=format,
                executive_summary=executive_summary,
                methodology=methodology,
            )
            audit_logger.log_report_generated(report_id, project_id, format)
        except Exception as e:
            logger.error("report_generation_failed", report_id=report_id, error=str(e))


@router.post("/projects/{project_id}/reports", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def create_report(
    project_id: int,
    report_in: ReportCreate,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    report = Report(
        project_id=project_id,
        name=report_in.name,
        format=report_in.format,
        status="pending",
    )
    session.add(report)
    await session.flush()

    background_tasks.add_task(
        generate_report_task,
        report.id,
        project_id,
        report_in.format,
        report_in.executive_summary,
        report_in.methodology,
    )

    logger.info("report_queued", report_id=report.id, project_id=project_id)
    return report


@router.get("/projects/{project_id}/reports", response_model=List[ReportResponse])
async def list_reports(
    project_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    reports = await report_crud.get_by_project(session, project_id)
    return reports


@router.get("/reports/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    report = await report_crud.get(session, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    report = await report_crud.get(session, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.status != "completed":
        raise HTTPException(status_code=400, detail="Report not ready")

    if not report.file_path:
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(
        path=report.file_path,
        filename=f"{report.name}.{report.format}",
        media_type="application/pdf" if report.format == "pdf" else "text/html",
    )


@router.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    report = await report_crud.get(session, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.file_path:
        from pathlib import Path
        Path(report.file_path).unlink(missing_ok=True)

    await report_crud.delete(session, report_id)
    logger.info("report_deleted", report_id=report_id)