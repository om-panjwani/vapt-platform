from datetime import datetime
from typing import List, Optional, Sequence, TypeVar, Generic
from uuid import UUID
from sqlalchemy import select, func, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel

from database.models import (
    Project,
    Target,
    ScanJob,
    Host,
    Port,
    Service,
    Vulnerability,
    Finding,
    NSEResult,
    Report,
    AuditLog,
    ProjectStatus,
    ScanStatus,
    HostStatus,
    PortState,
    FindingSeverity,
    FindingStatus,
    ConfidenceLevel,
)

ModelType = TypeVar("ModelType", bound=SQLModel)


class CRUDBase(Generic[ModelType]):
    def __init__(self, model: type[ModelType]):
        self.model = model

    async def get(self, session: AsyncSession, id: int) -> Optional[ModelType]:
        return await session.get(self.model, id)

    async def get_by_uuid(self, session: AsyncSession, uuid: str) -> Optional[ModelType]:
        result = await session.execute(select(self.model).where(self.model.uuid == uuid))
        return result.scalar_one_or_none()

    async def list(
        self,
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[dict] = None,
    ) -> Sequence[ModelType]:
        query = select(self.model).offset(skip).limit(limit)
        if filters:
            for key, value in filters.items():
                if hasattr(self.model, key):
                    query = query.where(getattr(self.model, key) == value)
        result = await session.execute(query)
        return result.scalars().all()

    async def count(self, session: AsyncSession, filters: Optional[dict] = None) -> int:
        query = select(func.count(self.model.id))
        if filters:
            for key, value in filters.items():
                if hasattr(self.model, key):
                    query = query.where(getattr(self.model, key) == value)
        result = await session.execute(query)
        return result.scalar_one()

    async def create(self, session: AsyncSession, obj_in: ModelType) -> ModelType:
        session.add(obj_in)
        await session.flush()
        await session.refresh(obj_in)
        return obj_in

    async def update(
        self, session: AsyncSession, db_obj: ModelType, obj_in: dict
    ) -> ModelType:
        for field, value in obj_in.items():
            if hasattr(db_obj, field):
                setattr(db_obj, field, value)
        if hasattr(db_obj, "updated_at"):
            db_obj.updated_at = datetime.utcnow()
        session.add(db_obj)
        await session.flush()
        await session.refresh(db_obj)
        return db_obj

    async def delete(self, session: AsyncSession, id: int) -> bool:
        obj = await session.get(self.model, id)
        if obj:
            await session.delete(obj)
            return True
        return False


class ProjectCRUD(CRUDBase[Project]):
    async def get_with_counts(self, session: AsyncSession, id: int) -> Optional[dict]:
        project = await self.get(session, id)
        if not project:
            return None
        return {
            "project": project,
            "targets_count": await self._count_targets(session, id),
            "scans_count": await self._count_scans(session, id),
            "findings_count": await self._count_findings(session, id),
        }

    async def _count_targets(self, session: AsyncSession, project_id: int) -> int:
        result = await session.execute(
            select(func.count(Target.id)).where(Target.project_id == project_id)
        )
        return result.scalar_one()

    async def _count_scans(self, session: AsyncSession, project_id: int) -> int:
        result = await session.execute(
            select(func.count(ScanJob.id)).where(ScanJob.project_id == project_id)
        )
        return result.scalar_one()

    async def _count_findings(self, session: AsyncSession, project_id: int) -> int:
        result = await session.execute(
            select(func.count(Finding.id)).where(Finding.project_id == project_id)
        )
        return result.scalar_one()


class TargetCRUD(CRUDBase[Target]):
    async def get_by_project(
        self, session: AsyncSession, project_id: int, skip: int = 0, limit: int = 100
    ) -> Sequence[Target]:
        result = await session.execute(
            select(Target).where(Target.project_id == project_id).offset(skip).limit(limit)
        )
        return result.scalars().all()


class ScanJobCRUD(CRUDBase[ScanJob]):
    async def get_with_details(self, session: AsyncSession, id: int) -> Optional[dict]:
        scan = await self.get(session, id)
        if not scan:
            return None
        hosts_count = await self._count_hosts(session, id)
        return {
            "scan": scan,
            "hosts_count": hosts_count,
        }

    async def _count_hosts(self, session: AsyncSession, scan_job_id: int) -> int:
        result = await session.execute(
            select(func.count(Host.id)).where(Host.scan_job_id == scan_job_id)
        )
        return result.scalar_one()

    async def update_progress(
        self, session: AsyncSession, scan_id: int, progress: int, task: Optional[str] = None
    ) -> Optional[ScanJob]:
        scan = await self.get(session, scan_id)
        if not scan:
            return None
        scan.progress = progress
        if task:
            scan.current_task = task
        session.add(scan)
        await session.flush()
        await session.refresh(scan)
        return scan

    async def mark_completed(
        self, session: AsyncSession, scan_id: int, error: Optional[str] = None
    ) -> Optional[ScanJob]:
        scan = await self.get(session, scan_id)
        if not scan:
            return None
        scan.status = ScanStatus.COMPLETED if not error else ScanStatus.FAILED
        scan.completed_at = datetime.utcnow()
        scan.progress = 100
        if error:
            scan.error_message = error
        session.add(scan)
        await session.flush()
        await session.refresh(scan)
        return scan


class HostCRUD(CRUDBase[Host]):
    async def get_by_scan(
        self, session: AsyncSession, scan_job_id: int, skip: int = 0, limit: int = 100
    ) -> Sequence[Host]:
        result = await session.execute(
            select(Host)
            .where(Host.scan_job_id == scan_job_id)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_up_hosts(self, session: AsyncSession, scan_job_id: int) -> Sequence[Host]:
        result = await session.execute(
            select(Host).where(
                Host.scan_job_id == scan_job_id, Host.status == HostStatus.UP
            )
        )
        return result.scalars().all()


class PortCRUD(CRUDBase[Port]):
    async def get_open_ports(self, session: AsyncSession, host_id: int) -> Sequence[Port]:
        result = await session.execute(
            select(Port).where(Port.host_id == host_id, Port.state == PortState.OPEN)
        )
        return result.scalars().all()

    async def get_by_host(
        self, session: AsyncSession, host_id: int, skip: int = 0, limit: int = 100
    ) -> Sequence[Port]:
        result = await session.execute(
            select(Port).where(Port.host_id == host_id).offset(skip).limit(limit)
        )
        return result.scalars().all()


class ServiceCRUD(CRUDBase[Service]):
    async def get_by_port(self, session: AsyncSession, port_id: int) -> Sequence[Service]:
        result = await session.execute(
            select(Service).where(Service.port_id == port_id)
        )
        return result.scalars().all()


class VulnerabilityCRUD(CRUDBase[Vulnerability]):
    async def get_by_service(
        self, session: AsyncSession, service_id: int
    ) -> Sequence[Vulnerability]:
        result = await session.execute(
            select(Vulnerability).where(Vulnerability.service_id == service_id)
        )
        return result.scalars().all()

    async def get_by_cve(self, session: AsyncSession, cve_id: str) -> Sequence[Vulnerability]:
        result = await session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        )
        return result.scalars().all()


class FindingCRUD(CRUDBase[Finding]):
    async def get_by_project(
        self,
        session: AsyncSession,
        project_id: int,
        severity: Optional[FindingSeverity] = None,
        status: Optional[FindingStatus] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> Sequence[Finding]:
        query = select(Finding).where(Finding.project_id == project_id)
        if severity:
            query = query.where(Finding.severity == severity)
        if status:
            query = query.where(Finding.status == status)
        query = query.order_by(Finding.severity.desc(), Finding.created_at.desc())
        query = query.offset(skip).limit(limit)
        result = await session.execute(query)
        return result.scalars().all()

    async def get_severity_counts(self, session: AsyncSession, project_id: int) -> dict:
        result = await session.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.project_id == project_id)
            .group_by(Finding.severity)
        )
        counts = {severity: 0 for severity in FindingSeverity}
        for severity, count in result.all():
            counts[severity] = count
        return counts

    async def get_status_counts(self, session: AsyncSession, project_id: int) -> dict:
        result = await session.execute(
            select(Finding.status, func.count(Finding.id))
            .where(Finding.project_id == project_id)
            .group_by(Finding.status)
        )
        counts = {status: 0 for status in FindingStatus}
        for status, count in result.all():
            counts[status] = count
        return counts


class NSEResultCRUD(CRUDBase[NSEResult]):
    async def get_by_scan(
        self, session: AsyncSession, scan_job_id: int
    ) -> Sequence[NSEResult]:
        result = await session.execute(
            select(NSEResult).where(NSEResult.scan_job_id == scan_job_id)
        )
        return result.scalars().all()


class ReportCRUD(CRUDBase[Report]):
    async def get_by_project(
        self, session: AsyncSession, project_id: int
    ) -> Sequence[Report]:
        result = await session.execute(
            select(Report)
            .where(Report.project_id == project_id)
            .order_by(Report.created_at.desc())
        )
        return result.scalars().all()


class AuditLogCRUD(CRUDBase[AuditLog]):
    async def log(
        self,
        session: AsyncSession,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        log = AuditLog(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            details=details,
            ip_address=ip_address,
        )
        session.add(log)
        await session.flush()
        await session.refresh(log)
        return log


project_crud = ProjectCRUD(Project)
target_crud = TargetCRUD(Target)
scan_job_crud = ScanJobCRUD(ScanJob)
host_crud = HostCRUD(Host)
port_crud = PortCRUD(Port)
service_crud = ServiceCRUD(Service)
vulnerability_crud = VulnerabilityCRUD(Vulnerability)
finding_crud = FindingCRUD(Finding)
nse_result_crud = NSEResultCRUD(NSEResult)
report_crud = ReportCRUD(Report)
audit_log_crud = AuditLogCRUD(AuditLog)