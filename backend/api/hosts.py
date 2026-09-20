from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from database import get_db_session
from database.crud import host_crud, port_crud, service_crud, scan_job_crud
from database.models import Host, HostStatus, Port, PortState, Service
from backend.logging_config import get_logger

router = APIRouter()
logger = get_logger(__name__)


class PortResponse(BaseModel):
    id: int
    uuid: str
    port: int
    protocol: str
    state: PortState
    service_name: Optional[str]
    service_version: Optional[str]
    service_product: Optional[str]
    service_extrainfo: Optional[str]
    service_cpe: Optional[str]
    confidence: int
    reason: Optional[str]

    class Config:
        from_attributes = True


class ServiceResponse(BaseModel):
    id: int
    uuid: str
    name: str
    version: Optional[str]
    product: Optional[str]
    extrainfo: Optional[str]
    cpe: Optional[str]
    fingerprint_method: Optional[str]
    confidence: int
    banner: Optional[str]

    class Config:
        from_attributes = True


class HostResponse(BaseModel):
    id: int
    uuid: str
    scan_job_id: int
    target_id: int
    ip: str
    hostname: Optional[str]
    mac_address: Optional[str]
    vendor: Optional[str]
    os_name: Optional[str]
    os_accuracy: Optional[int]
    status: HostStatus
    response_time: Optional[float]
    discovered_at: str
    ports: List[PortResponse] = []
    services: List[ServiceResponse] = []

    class Config:
        from_attributes = True


@router.get("/scans/{scan_id}/hosts", response_model=List[HostResponse])
async def list_hosts(
    scan_id: int,
    status: Optional[HostStatus] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_db_session),
):
    scan = await scan_job_crud.get(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    hosts = await host_crud.get_by_scan(session, scan_id, skip=skip, limit=limit)
    if status:
        hosts = [h for h in hosts if h.status == status]

    result = []
    for host in hosts:
        ports = await port_crud.get_by_host(session, host.id)
        host_ports = []
        host_services = []
        for port in ports:
            host_ports.append(PortResponse.model_validate(port))
            services = await service_crud.get_by_port(session, port.id)
            for service in services:
                host_services.append(ServiceResponse.model_validate(service))

        host_data = HostResponse.model_validate(host)
        host_data.ports = host_ports
        host_data.services = host_services
        result.append(host_data)

    return result


@router.get("/hosts/{host_id}", response_model=HostResponse)
async def get_host(
    host_id: int,
    session: AsyncSession = Depends(get_db_session),
):
    host = await host_crud.get(session, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    ports = await port_crud.get_by_host(session, host.id)
    host_ports = []
    host_services = []
    for port in ports:
        host_ports.append(PortResponse.model_validate(port))
        services = await service_crud.get_by_port(session, port.id)
        for service in services:
            host_services.append(ServiceResponse.model_validate(service))

    host_data = HostResponse.model_validate(host)
    host_data.ports = host_ports
    host_data.services = host_services
    return host_data