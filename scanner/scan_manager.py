import asyncio
import logging
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from database import get_db_session
from database.crud import (
    scan_job_crud,
    host_crud,
    port_crud,
    service_crud,
    nse_result_crud,
    target_crud,
)
from database.models import (
    ScanJob,
    Host,
    Port,
    Service,
    NSEResult,
    ScanStatus,
    HostStatus,
    PortState,
)
from scanner.nmap_scanner import NmapScanner, ScanTarget, ScanResult

logger = logging.getLogger(__name__)


class ScanManager:
    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
        self._running_scans: dict[int, asyncio.Task] = {}
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def start_scan(
        self,
        scan_job_id: int,
        progress_callback: Optional[callable] = None,
    ) -> bool:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)

        async with get_db_session() as session:
            scan_job = await scan_job_crud.get(session, scan_job_id)
            if not scan_job:
                logger.error(f"Scan job {scan_job_id} not found")
                return False

            if scan_job.status != ScanStatus.PENDING:
                logger.warning(f"Scan job {scan_job_id} is not in PENDING status")
                return False

            target = await target_crud.get(session, scan_job.target_id)
            if not target:
                logger.error(f"Target {scan_job.target_id} not found")
                return False

            scan_job.status = ScanStatus.RUNNING
            scan_job.started_at = datetime.utcnow()
            scan_job.progress = 0
            scan_job.current_task = "Initializing scan"
            session.add(scan_job)
            await session.flush()

        task = asyncio.create_task(self._run_scan(scan_job_id, target, progress_callback))
        self._running_scans[scan_job_id] = task
        task.add_done_callback(lambda t: self._running_scans.pop(scan_job_id, None))
        return True

    async def _run_scan(
        self,
        scan_job_id: int,
        target,
        progress_callback: Optional[callable] = None,
    ) -> None:
        async with self._semaphore:
            try:
                await self._execute_scan(scan_job_id, target, progress_callback)
            except Exception as e:
                logger.exception(f"Scan {scan_job_id} failed")
                async with get_db_session() as session:
                    await scan_job_crud.mark_completed(session, scan_job_id, error=str(e))

    async def _execute_scan(
        self,
        scan_job_id: int,
        target,
        progress_callback: Optional[callable] = None,
    ) -> None:
        scanner = NmapScanner()
        scan_target = ScanTarget(
            host=target.host,
            ports=target.allowed_ports or "1-65535",
            excluded_ports=target.excluded_ports,
        )

        nse_scripts = None
        if target.scan_jobs:
            for job in target.scan_jobs:
                if job.id == scan_job_id and job.nse_scripts:
                    nse_scripts = [s.strip() for s in job.nse_scripts.split(",") if s.strip()]
                    break

        async def update_progress(progress: int, task: str):
            async with get_db_session() as session:
                await scan_job_crud.update_progress(session, scan_job_id, progress, task)
            if progress_callback:
                await progress_callback(scan_job_id, progress, task)

        await update_progress(10, "Starting host discovery")

        result = await scanner.scan(
            target=scan_target,
            scan_type="tcp_connect",
            enable_service_detection=True,
            enable_os_detection=False,
            nse_scripts=nse_scripts,
        )

        await update_progress(50, "Processing results")

        async with get_db_session() as session:
            await self._store_results(session, scan_job_id, target.id, result)

        await update_progress(90, "Correlating vulnerabilities")

        async with get_db_session() as session:
            from vulnerability_engine.correlation import correlate_vulnerabilities
            await correlate_vulnerabilities(session, scan_job_id)

        await update_progress(100, "Scan completed")

        async with get_db_session() as session:
            await scan_job_crud.mark_completed(session, scan_job_id)

    async def _store_results(
        self,
        session,
        scan_job_id: int,
        target_id: int,
        result: ScanResult,
    ) -> None:
        for host_info in result.targets:
            host = Host(
                scan_job_id=scan_job_id,
                target_id=target_id,
                ip=host_info.ip,
                hostname=host_info.hostname,
                mac_address=host_info.mac_address,
                vendor=host_info.vendor,
                os_name=host_info.os_name,
                os_accuracy=host_info.os_accuracy,
                status=HostStatus.UP,
                response_time=host_info.response_time,
            )
            session.add(host)
            await session.flush()

            for port_info in host_info.ports:
                if port_info.state.lower() != "open":
                    continue

                port = Port(
                    host_id=host.id,
                    port=port_info.port,
                    protocol=port_info.protocol,
                    state=PortState(port_info.state.upper()) if port_info.state.upper() in PortState.__members__ else PortState.OPEN,
                    service_name=port_info.service_name,
                    service_version=port_info.service_version,
                    service_product=port_info.service_product,
                    service_extrainfo=port_info.service_extrainfo,
                    service_cpe=port_info.service_cpe,
                    confidence=port_info.confidence,
                    reason=port_info.reason,
                )
                session.add(port)
                await session.flush()

                if port_info.service_name:
                    service = Service(
                        port_id=port.id,
                        name=port_info.service_name,
                        version=port_info.service_version,
                        product=port_info.service_product,
                        extrainfo=port_info.service_extrainfo,
                        cpe=port_info.service_cpe,
                        fingerprint_method="nmap",
                        confidence=port_info.confidence,
                    )
                    session.add(port)
                    session.add(service)

        for nse in result.nse_results:
            host_result = await session.execute(
                Host.__table__.select().where(Host.ip == nse.host)
            )
            host = host_result.scalar_one_or_none()
            if not host:
                continue

            port_id = None
            if nse.port:
                port_result = await session.execute(
                    Port.__table__.select().where(
                        Port.host_id == host.id, Port.port == nse.port
                    )
                )
                port = port_result.scalar_one_or_none()
                if port:
                    port_id = port.id

            nse_result = NSEResult(
                scan_job_id=scan_job_id,
                host_id=host.id,
                port_id=port_id,
                script_name=nse.script_name,
                script_category=nse.script_category,
                output=nse.output,
                severity=nse.severity,
            )
            session.add(nse_result)

    async def cancel_scan(self, scan_job_id: int) -> bool:
        if scan_job_id in self._running_scans:
            task = self._running_scans[scan_job_id]
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            async with get_db_session() as session:
                await scan_job_crud.update(session, scan_job_id, {
                    "status": ScanStatus.CANCELLED,
                    "completed_at": datetime.utcnow(),
                    "error_message": "Cancelled by user",
                })
            return True
        return False

    async def get_running_scans(self) -> List[int]:
        return list(self._running_scans.keys())


scan_manager = ScanManager()