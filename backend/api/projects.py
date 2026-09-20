from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from database import get_db_session
from database.crud import project_crud
from database.models import Project, ProjectStatus
from backend.logging_config import get_logger

router = APIRouter()
logger = get_logger(__name__)


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[ProjectStatus] = None


class ProjectResponse(BaseModel):
    id: int
    uuid: str
    name: str
    description: Optional[str]
    status: ProjectStatus
    created_at: str
    updated_at: str
    completed_at: Optional[str]

    class Config:
        from_attributes = True


class ProjectDetailResponse(ProjectResponse):
    targets_count: int
    scans_count: int
    findings_count: int


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project_in: ProjectCreate,
    session: AsyncSession = Depends(get_db_session),
):
    project = Project(name=project_in.name, description=project_in.description)
    project = await project_crud.create(session, project)
    logger.info("project_created", project_id=project.id, name=project.name)
    return project


@router.get("", response_model=List[ProjectResponse])
async def list_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[ProjectStatus] = None,
    session: AsyncSession = Depends(get_db_session),
):
    filters = {"status": status} if status else None
    projects = await project_crud.list(session, skip=skip, limit=limit, filters=filters)
    return projects


@router.get("/{project_id}", response_model=ProjectDetailResponse)
async def get_project(
    project_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    result = await project_crud.get_with_counts(session, project_id)
    if not result:
        raise HTTPException(status_code=404, detail="Project not found")
    return result


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: int,
    project_in: ProjectUpdate,
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    update_data = project_in.model_dump(exclude_unset=True)
    project = await project_crud.update(session, project, update_data)
    logger.info("project_updated", project_id=project_id)
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    await project_crud.delete(session, project_id)
    logger.info("project_deleted", project_id=project_id)