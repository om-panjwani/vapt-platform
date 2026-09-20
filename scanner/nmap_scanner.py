import asyncio
import logging
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from backend.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


@dataclass
class ScanTarget:
    host: str
    ports: str = "1-65535"
    excluded_ports: Optional[str] = None


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    service_product: Optional[str] = None
    service_extrainfo: Optional[str] = None
    service_cpe: Optional[str] = None
    confidence: int = 0
    reason: Optional[str] = None


@dataclass
class HostInfo:
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_name: Optional[str] = None
    os_accuracy: Optional[int] = None
    status: str = "unknown"
    response_time: Optional[float] = None
    ports: List[PortInfo] = field(default_factory=list)


@dataclass
class NSEResult:
    host: str
    port: Optional[int]
    script_name: str
    script_category: Optional[str]
    output: str
    severity: Optional[str] = None


@dataclass
class ScanResult:
    targets: List[HostInfo]
    nse_results: List[NSEResult]
    scan_duration: float
    command: str
    started_at: datetime
    completed_at: datetime
    error: Optional[str] = None


class NmapScanner:
    SAFE_SCAN_TYPES = {
        "tcp_connect": "-sT",
        "tcp_syn": "-sS",
        "udp": "-sU",
    }

    SAFE_OPTIONS = {
        "service_detection": "-sV",
        "version_intensity": "--version-intensity",
        "os_detection": "-O",
        "traceroute": "--traceroute",
        "no_ping": "-Pn",
        "fast_scan": "-F",
        "top_ports": "--top-ports",
    }

    ALLOWED_NSE_CATEGORIES = {
        "safe",
        "discovery",
        "version",
        "vuln",
    }

    DANGEROUS_NSE_CATEGORIES = {
        "exploit",
        "brute",
        "dos",
        "fuzzer",
        "intrusive",
    }

    def __init__(
        self,
        nmap_path: Optional[str] = None,
        timeout: Optional[int] = None,
        allowed_scripts: Optional[List[str]] = None,
    ):
        self.nmap_path = nmap_path or settings.NMAP_PATH
        self.timeout = timeout or settings.DEFAULT_SCAN_TIMEOUT
        self.allowed_scripts = allowed_scripts or settings.allowed_nse_scripts_list
        self._validate_nmap()

    def _validate_nmap(self) -> None:
        try:
            result = subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Nmap not found or not executable: {self.nmap_path}")
            logger.info(f"Nmap validated: {result.stdout.split(chr(10))[0]}")
        except FileNotFoundError:
            raise RuntimeError(f"Nmap not found at: {self.nmap_path}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Nmap version check timed out")

    def _validate_target(self, target: ScanTarget) -> bool:
        if not target.host or not target.host.strip():
            return False
        return True

    def _validate_ports(self, ports: str) -> bool:
        port_pattern = re.compile(r'^(\d{1,5}(-\d{1,5})?)(,\d{1,5}(-\d{1,5})?)*$')
        if not port_pattern.match(ports):
            return False
        for part in ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start < 1 or end > 65535 or start > end:
                    return False
            else:
                port = int(part)
                if port < 1 or port > 65535:
                    return False
        return True

    def _build_command(
        self,
        target: ScanTarget,
        scan_type: str = "tcp_connect",
        enable_service_detection: bool = True,
        enable_os_detection: bool = False,
        nse_scripts: Optional[List[str]] = None,
        extra_args: Optional[str] = None,
    ) -> List[str]:
        cmd = [self.nmap_path]

        cmd.append("-n")
        cmd.append("-oX")
        cmd.append("-")

        if scan_type in self.SAFE_SCAN_TYPES:
            cmd.append(self.SAFE_SCAN_TYPES[scan_type])
        else:
            cmd.append(self.SAFE_SCAN_TYPES["tcp_connect"])

        if enable_service_detection:
            cmd.append("-sV")
            cmd.append("--version-intensity")
            cmd.append("7")

        if enable_os_detection:
            cmd.append("-O")

        if target.ports and self._validate_ports(target.ports):
            cmd.append("-p")
            cmd.append(target.ports)

        if target.excluded_ports and self._validate_ports(target.excluded_ports):
            cmd.append("--exclude-ports")
            cmd.append(target.excluded_ports)

        cmd.append("-Pn")

        if nse_scripts:
            safe_scripts = [s for s in nse_scripts if s in self.allowed_scripts]
            if safe_scripts:
                cmd.append("--script")
                cmd.append(",".join(safe_scripts))

        if extra_args:
            extra_parts = shlex.split(extra_args)
            safe_extra = []
            for part in extra_parts:
                if not any(dangerous in part for dangerous in ["-sS", "-sT", "-sU", "-O", "-A", "--script"]):
                    safe_extra.append(part)
            cmd.extend(safe_extra)

        cmd.append(target.host)

        return cmd

    async def scan(
        self,
        target: ScanTarget,
        scan_type: str = "tcp_connect",
        enable_service_detection: bool = True,
        enable_os_detection: bool = False,
        nse_scripts: Optional[List[str]] = None,
        extra_args: Optional[str] = None,
        progress_callback: Optional[callable] = None,
    ) -> ScanResult:
        if not self._validate_target(target):
            raise ValueError("Invalid target")

        command = self._build_command(
            target=target,
            scan_type=scan_type,
            enable_service_detection=enable_service_detection,
            enable_os_detection=enable_os_detection,
            nse_scripts=nse_scripts,
            extra_args=extra_args,
        )

        logger.info(f"Starting scan: {' '.join(command)}")
        started_at = datetime.utcnow()

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise RuntimeError(f"Scan timed out after {self.timeout} seconds")

            completed_at = datetime.utcnow()
            scan_duration = (completed_at - started_at).total_seconds()

            if process.returncode not in (0, 1):
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Scan failed: {error_msg}")
                return ScanResult(
                    targets=[],
                    nse_results=[],
                    scan_duration=scan_duration,
                    command=" ".join(command),
                    started_at=started_at,
                    completed_at=completed_at,
                    error=error_msg,
                )

            xml_output = stdout.decode()
            hosts, nse_results = self._parse_xml(xml_output)

            logger.info(f"Scan completed in {scan_duration:.2f}s, found {len(hosts)} hosts")
            return ScanResult(
                targets=hosts,
                nse_results=nse_results,
                scan_duration=scan_duration,
                command=" ".join(command),
                started_at=started_at,
                completed_at=completed_at,
            )

        except Exception as e:
            completed_at = datetime.utcnow()
            scan_duration = (completed_at - started_at).total_seconds()
            logger.exception("Scan error")
            return ScanResult(
                targets=[],
                nse_results=[],
                scan_duration=scan_duration,
                command=" ".join(command),
                started_at=started_at,
                completed_at=completed_at,
                error=str(e),
            )

    def _parse_xml(self, xml_output: str) -> Tuple[List[HostInfo], List[NSEResult]]:
        hosts = []
        nse_results = []

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return hosts, nse_results

        for host_elem in root.findall("host"):
            host_info = self._parse_host(host_elem)
            if host_info:
                hosts.append(host_info)

            for port_elem in host_elem.findall("ports/port"):
                nse_results.extend(self._parse_nse_scripts(host_info.ip, port_elem))

        return hosts, nse_results

    def _parse_host(self, host_elem: ET.Element) -> Optional[HostInfo]:
        status_elem = host_elem.find("status")
        if status_elem is None or status_elem.get("state") != "up":
            return None

        address_elem = host_elem.find("address[@addrtype='ipv4']")
        if address_elem is None:
            address_elem = host_elem.find("address[@addrtype='ipv6']")
        if address_elem is None:
            return None

        ip = address_elem.get("addr", "")
        hostname = None
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")

        mac_address = None
        vendor = None
        mac_elem = host_elem.find("address[@addrtype='mac']")
        if mac_elem is not None:
            mac_address = mac_elem.get("addr")
            vendor = mac_elem.get("vendor")

        os_name = None
        os_accuracy = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name")
                os_accuracy = int(osmatch.get("accuracy", 0))

        response_time = None
        times_elem = host_elem.find("times")
        if times_elem is not None:
            response_time = float(times_elem.get("srtt", 0)) / 1000.0

        ports = []
        for port_elem in host_elem.findall("ports/port"):
            port_info = self._parse_port(port_elem)
            if port_info:
                ports.append(port_info)

        return HostInfo(
            ip=ip,
            hostname=hostname,
            mac_address=mac_address,
            vendor=vendor,
            os_name=os_name,
            os_accuracy=os_accuracy,
            status="up",
            response_time=response_time,
            ports=ports,
        )

    def _parse_port(self, port_elem: ET.Element) -> Optional[PortInfo]:
        port_id = port_elem.get("portid")
        protocol = port_elem.get("protocol", "tcp")
        if not port_id:
            return None

        state_elem = port_elem.find("state")
        state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

        service_elem = port_elem.find("service")
        service_name = None
        service_version = None
        service_product = None
        service_extrainfo = None
        service_cpe = None
        confidence = 0

        if service_elem is not None:
            service_name = service_elem.get("name")
            service_version = service_elem.get("version")
            service_product = service_elem.get("product")
            service_extrainfo = service_elem.get("extrainfo")
            confidence = int(service_elem.get("conf", "0"))
            cpe_elem = service_elem.find("cpe")
            if cpe_elem is not None:
                service_cpe = cpe_elem.text

        reason_elem = port_elem.find("reason")
        reason = reason_elem.get("reason") if reason_elem is not None else None

        return PortInfo(
            port=int(port_id),
            protocol=protocol,
            state=state,
            service_name=service_name,
            service_version=service_version,
            service_product=service_product,
            service_extrainfo=service_extrainfo,
            service_cpe=service_cpe,
            confidence=confidence,
            reason=reason,
        )

    def _parse_nse_scripts(self, host_ip: str, port_elem: ET.Element) -> List[NSEResult]:
        results = []
        port_id = port_elem.get("portid")
        port = int(port_id) if port_id else None

        for script_elem in port_elem.findall("script"):
            script_name = script_elem.get("id", "")
            output = script_elem.get("output", "")
            results.append(
                NSEResult(
                    host=host_ip,
                    port=port,
                    script_name=script_name,
                    script_category=None,
                    output=output,
                )
            )

        hostscript_elem = port_elem.find("../hostscript")
        if hostscript_elem is not None:
            for script_elem in hostscript_elem.findall("script"):
                script_name = script_elem.get("id", "")
                output = script_elem.get("output", "")
                results.append(
                    NSEResult(
                        host=host_ip,
                        port=None,
                        script_name=script_name,
                        script_category=None,
                        output=output,
                    )
                )

        return results

    def validate_scan_scope(self, target: ScanTarget, authorized_targets: List[str]) -> bool:
        for auth_target in authorized_targets:
            if self._target_matches(target.host, auth_target):
                return True
        return False

    def _target_matches(self, target: str, authorized: str) -> bool:
        if "/" in authorized:
            import ipaddress
            try:
                target_ip = ipaddress.ip_address(target)
                auth_network = ipaddress.ip_network(authorized, strict=False)
                return target_ip in auth_network
            except ValueError:
                pass
        return target == authorized


async def run_scan(
    target: str,
    ports: str = "1-65535",
    scan_type: str = "tcp_connect",
    nse_scripts: Optional[List[str]] = None,
) -> ScanResult:
    scanner = NmapScanner()
    scan_target = ScanTarget(host=target, ports=ports)
    return await scanner.scan(
        target=scan_target,
        scan_type=scan_type,
        nse_scripts=nse_scripts,
    )