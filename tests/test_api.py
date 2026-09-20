import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from backend.config import get_settings, Settings
from backend.main import create_app


@pytest.fixture
def client():
    settings = get_settings()
    app = create_app()
    return TestClient(app)


@pytest.fixture
async async def db_session():
    engine = create_async_engine(
        "sqlite+aiosqlite:///./test_vapt.db",
        echo=False,
        future=True,
    )
    
    async with engine.begin() as conn:
        from database.models import SQLModel
        await conn.run_sync(SQLModel.metadata.create_all)
    
    async_session_factory = sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    async with async_session_factory() as session:
        yield session
    
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)


class TestHealthEndpoint:
    def test_health_check(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"


class TestProjectEndpoints:
    def test_create_project(self, client):
        project_data = {
            "name": "External Network Assessment",
            "description": "Q1 2024 external network penetration test"
        }
        response = client.post("/api/v1/projects", json=project_data)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "External Network Assessment"
        assert "uuid" in data
        assert "created_at" in data
    
    def test_create_project_missing_name(self, client):
        response = client.post("/api/v1/projects", json={"description": "No name"})
        assert response.status_code == 422
    
    def test_list_projects(self, client):
        response = client.get("/api/v1/projects")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_get_project(self, client):
        create_data = {"name": "Test Project"}
        create_resp = client.post("/api/v1/projects", json=create_data)
        project_id = create_resp.json()["id"]
        
        response = client.get(f"/api/v1/projects/{project_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Project"
        assert "uuid" in data
    
    def test_update_project(self, client):
        create_data = {"name": "Project to Update"}
        create_resp = client.post("/api/v1/projects", json=create_data)
        project_id = create_resp.json()["id"]
        
        update_data = {"name": "Updated Project Name"}
        response = client.patch(f"/api/v1/projects/{project_id}", json=update_data)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Project Name"
    
    def test_delete_project(self, client):
        create_data = {"name": "Project to Delete"}
        create_resp = client.post("/api/v1/projects", json=create_data)
        project_id = create_resp.json()["id"]
        
        response = client.delete(f"/api/v1/projects/{project_id}")
        assert response.status_code == 204
        
        get_resp = client.get(f"/api/v1/projects/{project_id}")
        assert get_resp.status_code == 404


class TestTargetEndpoints:
    def test_create_target(self, client):
        create_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = create_resp.json()["id"]
        
        target_data = {
            "host": "192.168.1.1",
            "host_type": "ip",
            "allowed_ports": "1-1000",
            "scope_notes": "Internal network segment"
        }
        response = client.post(f"/api/v1/projects/{project_id}/targets", json=target_data)
        assert response.status_code == 201
        data = response.json()
        assert data["host"] == "192.168.1.1"
        assert data["project_id"] == project_id
        assert "uuid" in data
    
    def test_list_targets(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        client.post(f"/api/v1/projects/{project_id}/targets", json={
            "host": "192.168.1.1",
            "host_type": "ip",
        })
        
        response = client.get(f"/api/v1/projects/{project_id}/targets")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
    
    def test_get_target(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        create_resp = client.post(f"/api/v1/projects/{project_id}/targets", json={
            "host": "10.0.0.1",
        })
        target_id = create_resp.json()["id"]
        
        response = client.get(f"/api/v1/targets/{target_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["host"] == "10.0.0.1"


class TestScanEndpoints:
    def test_create_scan(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        target_resp = client.post(f"/api/v1/projects/{project_id}/targets", json={
            "host": "192.168.1.0/24",
        })
        target_id = target_resp.json()["id"]
        
        scan_data = {
            "name": "Full TCP Connect Scan",
            "target_id": target_id,
            "scan_type": "tcp_connect",
            "port_range": "1-1000",
            "nse_scripts": "http-enum,http-title",
        }
        response = client.post(f"/api/v1/projects/{project_id}/scans", json=scan_data)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Full TCP Connect Scan"
        assert data["status"] == "pending"
        assert "uuid" in data
        assert data["progress"] == 0
    
    def test_create_scan_invalid_target(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        scan_data = {
            "name": "Scan with Bad Target",
            "target_id": 9999,
        }
        response = client.post(f"/api/v1/projects/{project_id}/scans", json=scan_data)
        assert response.status_code == 404
    
    def test_list_scans(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        target_resp = client.post(f"/api/v1/projects/{project_id}/targets", json={
            "host": "192.168.1.0/24",
        })
        
        client.post(f"/api/v1/projects/{project_id}/scans", json={
            "name": "Test Scan",
            "target_id": target_resp.json()["id"],
        })
        
        response = client.get(f"/api/v1/projects/{project_id}/scans")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
    
    def test_get_scan(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        target_resp = client.post(f"/api/v1/projects/{project_id}/targets", json={
            "host": "192.168.1.0/24",
        })
        target_id = target_resp.json()["id"]
        
        scan_resp = client.post(f"/api/v1/projects/{project_id}/scans", json={
            "name": "Test Scan",
            "target_id": target_id,
        })
        scan_id = scan_resp.json()["id"]
        
        response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Scan"


class TestFindingsEndpoints:
    def test_list_findings(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        response = client.get(f"/api/v1/projects/{project_id}/findings")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_list_findings_with_filters(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        response = client.get(f"/api/v1/projects/{project_id}/findings?severity=critical")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_get_finding(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        response = client.get(f"/api/v1/projects/{project_id}/findings")
        data = response.json()
        assert isinstance(data, list)
        if data:
            finding_id = data[0]["id"]
            response = client.get(f"/api/v1/findings/{finding_id}")
            assert response.status_code == 200


class TestReportsEndpoints:
    def test_create_report(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        response = client.post(f"/api/v1/projects/{project_id}/reports", json={
            "name": "Q1 Assessment Report",
            "format": "html",
        })
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Q1 Assessment Report"
        assert data["format"] == "html"
        assert data["status"] in ["pending", "generating", "completed"]
        assert "uuid" in data
    
    def test_list_reports(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        client.post(f"/api/v1/projects/{project_id}/reports", json={
            "name": "Test Report",
            "format": "html",
        })
        
        response = client.get(f"/api/v1/projects/{project_id}/reports")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
    
    def test_get_report(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        create_resp = client.post(f"/api/v1/projects/{project_id}/reports", json={
            "name": "Test Report",
            "format": "html",
        })
        report_id = create_resp.json()["id"]
        
        response = client.get(f"/api/v1/reports/{report_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Report"
    
    def test_download_report(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        create_resp = client.post(f"/api/v1/projects/{project_id}/reports", json={
            "name": "Test Report",
            "format": "html",
        })
        report_id = create_resp.json()["id"]
        
        response = client.get(f"/api/v1/reports/{report_id}/download")
        assert response.status_code in [200, 404]


class TestDashboardEndpoints:
    def test_get_dashboard_stats(self, client):
        response = client.get("/api/v1/stats")
        assert response.status_code == 200
        data = response.json()
        assert hasattr(data, 'total_projects') or isinstance(data, dict)
    
    def test_get_project_summaries(self, client):
        response = client.get("/api/v1/projects")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_get_project_dashboard_stats(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        response = client.get(f"/api/v1/projects/{project_id}/stats")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)


class TestErrorHandling:
    def test_404_project_not_found(self, client):
        response = client.get("/api/v1/projects/9999")
        assert response.status_code == 404
    
    def test_404_target_not_found(self, client):
        response = client.get("/api/v1/targets/9999")
        assert response.status_code == 404
    
    def test_404_scan_not_found(self, client):
        response = client.get("/api/v1/scans/9999")
        assert response.status_code == 404
    
    def test_404_finding_not_found(self, client):
        response = client.get("/api/v1/findings/9999")
        assert response.status_code == 404
    
    def test_404_report_not_found(self, client):
        response = client.get("/api/v1/reports/9999")
        assert response.status_code == 404
    
    def test_400_invalid_scan_status(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        target_resp = client.post(f"/api/v1/projects/{project_id}/targets", json={
            "host": "192.168.1.0/24",
        })
        target_id = target_resp.json()["id"]
        
        response = client.post(f"/api/v1/scans/9999/start")
        assert response.status_code == 404
    
    def test_403_unauthorized_target(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        target_resp = client.post(f"/api/v1/projects/{project_id}/targets", json={
            "host": "192.168.1.0/24",
            "is_authorized": False,
        })
        target_id = target_resp.json()["id"]
        
        scan_resp = client.post(f"/api/v1/projects/{project_id}/scans", json={
            "name": "Unauthorized Scan",
            "target_id": target_id,
        })
        scan_id = scan_resp.json()["id"]
        
        response = client.post(f"/api/v1/scans/{scan_id}/start")
        assert response.status_code in [400, 403]


class TestAPIValidation:
    def test_project_name_required(self, client):
        response = client.post("/api/v1/projects", json={"description": "No name"})
        assert response.status_code == 422
    
    def test_target_host_required(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        
        response = client.post(f"/api/v1/projects/{project_id}/targets", json={})
        assert response.status_code == 422
    
    def test_scan_name_required(self, client):
        project_resp = client.post("/api/v1/projects", json={"name": "Test Project"})
        project_id = project_resp.json()["id"]
        target_resp = client.post(f"/api/v1/projects/{project_id}/targets", json={"host": "192.168.1.0/24"})
        target_id = target_resp.json()["id"]
        
        response = client.post(f"/api/v1/projects/{project_id}/scans", json={"target_id": target_id})
        assert response.status_code == 422