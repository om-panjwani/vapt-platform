from functools import lru_cache
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "VAPT Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = Field(default="vapt-platform-secret-key-min-32-chars-for-development-only", min_length=32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/vapt.db"
    DATABASE_ECHO: bool = False

    # Scanner
    NMAP_PATH: str = "/usr/bin/nmap"
    DEFAULT_SCAN_TIMEOUT: int = 300
    MAX_CONCURRENT_SCANS: int = 3
    ALLOWED_NSE_SCRIPTS: str = "http-enum,http-title,http-methods,ssl-cert,smb-protocols,ssh2-enum-algos,dns-zone-transfer,ftp-anon,smtp-commands"

    # Security
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60

    # Reporting
    REPORT_OUTPUT_DIR: str = "./reports/output"
    REPORT_TEMPLATE_DIR: str = "./reports/templates"

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_FILE: str = "./logs/vapt.log"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    @property
    def allowed_nse_scripts_list(self) -> List[str]:
        return [s.strip() for s in self.ALLOWED_NSE_SCRIPTS.split(",") if s.strip()]

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()