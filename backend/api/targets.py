from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from database import get_db_session
from database.crud import target_crud, project_crud
from database.models import Target
from backend.logging_config import get_logger

router = APIRouter()
logger = get_logger(__name__)


class TargetCreate(BaseModel):
    host: str = Field(..., min_length=1, max_length=255)
    host_type: str = Field(default="ip", max_length=50)
    allowed_ports: str = Field(default="1-65535", max_length=500)
    excluded_ports: Optional[str] = Field(None, max_length=500)
    scope_notes: Optional[str] = None
    is_authorized: bool = True


class TargetUpdate(BaseModel):
    host: Optional[str] = Field(None, min_length=1, max_length=255)
    host_type: Optional[str] = Field(None, max_length=50)
    allowed_ports: Optional[str] = Field(None, max_length=500)
    excluded_ports: Optional[str] = Field(None, max_length=500)
    scope_notes: Optional[str] = None
    is_authorized: Optional[bool] = None


class TargetResponse(BaseModel):
    id: int
    uuid: str
    project_id: int
    host: str
    host_type: str
    allowed_ports: str
    excluded_ports: Optional[str]
    scope_notes: Optional[str]
    is_authorized: bool
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.post("/projects/{project_id}/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(
    project_id: int,
    target_in: TargetCreate,
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    target = Target(
        project_id=project_id,
        host=target_in.host,
        host_type=target_in.host_type,
        allowed_ports=target_in.allowed_ports,
        excluded_ports=target_in.excluded_ports,
        scope_notes=target_in.scope_notes,
        is_authorized=target_in.is_authorized,
    )
    target = await target_crud.create(session, target)
    logger.info("target_created", target_id=target.id, host=target.host, project_id=project_id)
    return target


@router.get("/projects/{project_id}/targets", response_model=List[TargetResponse])
async def list_targets(
    project_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_db_session),
):
    project = await project_crud.get(session, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    targets = await target_crud.get_by_project(session, project_id, skip=skip, limit=limit)
    return targets


@router.get("/targets/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    target = await target_crud.get(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.patch("/targets/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: int,
    target_in: TargetUpdate,
    session: AsyncSession = Depends(get_db_session),
):
    target = await target_crud.get(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    update_data = target_in.model_dump(exclude_unset=True)
    target = await target_crud.update(session, target, update_data)
    logger.info("target_updated", target_id=target_id)
    return target


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    target = await target_crud.get(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    await target_crud.delete(session, target_id)
    logger.info("target_deleted", target_id=target_id)