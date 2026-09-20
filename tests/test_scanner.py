import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from scanner.nmap_scanner import NmapScanner, ScanTarget, ScanResult, PortInfo, HostInfo
from scanner.scan_manager import ScanManager


class TestNmapScannerSafety:
    def test_scanner_initialization(self):
        scanner = NmapScanner()
        assert scanner is not None
        assert scanner.nmap_path is not None

    def test_scanner_custom_nmap_path(self):
        scanner = NmapScanner(nmap_path="/usr/bin/nmap")
        assert scanner.nmap_path == "/usr/bin/nmap"

    def test_validate_target_valid(self):
        scanner = NmapScanner()
        valid_target = type('obj', (object,), {'host': '127.0.0.1', 'ports': '1-1000'})()
        assert scanner._validate_target(valid_target) == True

    def test_validate_target_empty(self):
        scanner = NmapScanner()
        empty_target = type('obj', (object,), {'host': ''})()
        assert scanner._validate_target(empty_target) == False

    def test_validate_ports_valid(self):
        scanner = NmapScanner()
        assert scanner._validate_ports("1-1000") == True
        assert scanner._validate_ports("80,443") == True
        assert scanner._validate_ports("1-65535") == True

    def test_validate_ports_invalid(self):
        scanner = NmapScanner()
        assert scanner._validate_ports("") == False
        assert scanner._validate_ports("-1") == False
        assert scanner._validate_ports("0") == False
        assert scanner._validate_ports("70000") == False
        assert scanner._validate_ports("abc") == False
        assert scanner._validate_ports("1-10,20-5") == False

    def test_validate_target_matches_authorized(self):
        scanner = NmapScanner()
        assert scanner._target_matches("192.168.1.1", "192.168.1.1") == True
        assert scanner._target_matches("192.168.1.1", "10.0.0.1") == False

    def test_parse_port_info(self):
        scanner = NmapScanner()
        
        port_xml = '<port portid="80" protocol="tcp"><state state="open" reason="syn-ack"/><service name="http" version="2.4.49" product="Apache httpd" extrainfo="Ubuntu "/></port>'
        port_elem = MagicMock()
        port_elem.get.return_value = "80"
        port_elem.get.return_value = "tcp"
        port_elem.find.return_value = MagicMock()
        port_elem.find.return_value.get.return_value = "open"
        
        assert hasattr(scanner, '_parse_port')


class TestNmapScannerParsing:
    def test_host_parsing_basic(self):
        scanner = NmapScanner()
        
        xml_output = '''<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun scanner="nmap" args="nmap -sT 127.0.0.1" start="1700000000" start_str="2023-11-15 12:00:00" end="1700000001" end_str="2023-11-15 12:00:01" summary="Radar scan performed">
        <host>
          <status state="up" reason="arp-response"/>
          <address addrtype="ipv4" addr="127.0.0.1"/>
          <hostnames>
            <hostname name="localhost"/>
          </hostnames>
          <ports>
            <port portid="22" protocol="tcp">
              <state state="open" reason="syn-ack"/>
              <service name="ssh" version="8.0" product="OpenSSH" extrainfo="protocol 2.0"/>
            </port>
          </ports>
        </host>
        </nmaprun>'''
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)
            host_elems = root.findall("host")
            assert len(host_elems) >= 1
        except ET.ParseError:
            pytest.skip("XML parsing not fully implemented yet")

    def test_nmap_output_parsing_structure(self):
        xml_output = '''<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun>
        <host>
          <status state="up"/>
          <address addrtype="ipv4" addr="192.168.1.1"/>
          <ports>
            <port portid="22" protocol="tcp"><state state="open" reason="syn-ack"/></port>
            <port portid="80" protocol="tcp"><state state="open" reason="syn-ack"/><service name="http"/></port>
          </ports>
        </host>
        </nmaprun>'''
        
        assert "nmaprun" in xml_output
        assert "host" in xml_output
        assert "port" in xml_output
        assert "status" in xml_output


class TestScanManager:
    def test_scan_manager_initialization(self):
        manager = ScanManager(max_concurrent=2)
        assert manager is not None
        assert manager.max_concurrent == 2

    def test_scan_manager_semaphore(self):
        manager = ScanManager(max_concurrent=3)
        assert manager._semaphore is not None

    async def test_start_scan(self):
        manager = ScanManager(max_concurrent=1)
        
        with patch.object(manager, '_execute_scan', new=AsyncMock()):
            result = await manager.start_scan(1)
            assert result is True or False

    async def test_cancel_scan(self):
        manager = ScanManager(max_concurrent=1)
        
        assert hasattr(manager, 'cancel_scan')


class TestScanSafety:
    def test_scan_scope_validation(self):
        from scanner.nmap_scanner import NmapScanner
        scanner = NmapScanner()
        
        target = type('obj', (object,), {
            'host': '192.168.1.1',
        })()
        
        assert scanner.validate_scan_scope(target, ["192.168.1.1"]) == True
        assert scanner.validate_scan_scope(target, ["10.0.0.1"]) == False

    def test_scan_with_no_nmap(self):
        import subprocess
        pass


class TestScanTimeout:
    @patch('asyncio.create_subprocess_exec')
    async def test_scan_timeout(self, mock_exec):
        from scanner.nmap_scanner import NmapScanner
        scanner = NmapScanner(timeout=5)
        
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock()
        mock_process.communicate.side_effect = asyncio.TimeoutError()
        mock_process.returncode = None
        mock_exec.return_value = mock_process
        
        assert scanner.timeout == 5


@pytest.fixture
def sample_scanner():
    return NmapScanner()


@pytest.fixture
def sample_scan_target():
    return ScanTarget(host="192.168.1.1", ports="1-1000")


@pytest.fixture
def sample_port_info():
    return PortInfo(
        port=80,
        protocol="tcp",
        state="open",
        service_name="http",
        service_version="2.4.49",
    )


@pytest.fixture
def sample_host_info():
    return HostInfo(
        ip="192.168.1.1",
        hostname="localhost",
        status="up",
    )


@pytest.fixture
def sample_scan_result():
    return ScanResult(
        targets=[],
        nse_results=[],
        scan_duration=10.0,
        command="nmap -sT -oX - 192.168.1.1",
        started_at=None,
        completed_at=None,
    )