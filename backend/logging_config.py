import logging
import sys
from pathlib import Path
from typing import Any, Dict

import structlog
from backend.config import get_settings

settings = get_settings()


def setup_logging() -> None:
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    shared_processors = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if settings.LOG_FORMAT == "json":
        processors = shared_processors + [structlog.processors.JSONRenderer()]
    else:
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True)
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    log_file = Path(settings.LOG_FILE)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    file_handler.setFormatter(logging.Formatter("%(message)s"))

    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)
    root_logger.setLevel(log_level)

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)


class AuditLogger:
    def __init__(self, logger_name: str = "audit"):
        self.logger = get_logger(logger_name)

    def log_action(
        self,
        action: str,
        resource_type: str,
        resource_id: str = None,
        user_id: str = None,
        details: Dict[str, Any] = None,
        ip_address: str = None,
        success: bool = True,
    ) -> None:
        self.logger.info(
            "audit_log",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            details=details or {},
            ip_address=ip_address,
            success=success,
        )

    def log_scan_started(self, scan_id: int, target: str, user_id: str = None) -> None:
        self.log_action(
            action="scan_started",
            resource_type="scan",
            resource_id=str(scan_id),
            user_id=user_id,
            details={"target": target},
        )

    def log_scan_completed(self, scan_id: int, target: str, findings_count: int, user_id: str = None) -> None:
        self.log_action(
            action="scan_completed",
            resource_type="scan",
            resource_id=str(scan_id),
            user_id=user_id,
            details={"target": target, "findings_count": findings_count},
        )

    def log_scan_failed(self, scan_id: int, target: str, error: str, user_id: str = None) -> None:
        self.log_action(
            action="scan_failed",
            resource_type="scan",
            resource_id=str(scan_id),
            user_id=user_id,
            details={"target": target, "error": error},
            success=False,
        )

    def log_report_generated(self, report_id: int, project_id: int, format: str, user_id: str = None) -> None:
        self.log_action(
            action="report_generated",
            resource_type="report",
            resource_id=str(report_id),
            user_id=user_id,
            details={"project_id": project_id, "format": format},
        )

    def log_finding_updated(self, finding_id: int, project_id: int, changes: Dict, user_id: str = None) -> None:
        self.log_action(
            action="finding_updated",
            resource_type="finding",
            resource_id=str(finding_id),
            user_id=user_id,
            details={"project_id": project_id, "changes": changes},
        )

    def log_target_created(self, target_id: int, project_id: int, host: str, user_id: str = None) -> None:
        self.log_action(
            action="target_created",
            resource_type="target",
            resource_id=str(target_id),
            user_id=user_id,
            details={"project_id": project_id, "host": host},
        )


audit_logger = AuditLogger()