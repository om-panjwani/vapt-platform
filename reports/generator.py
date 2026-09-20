import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.config import get_settings
from database import get_db_session
from database.crud import (
    project_crud,
    finding_crud,
    host_crud,
    port_crud,
    service_crud,
    scan_job_crud,
    target_crud,
    report_crud,
)
from database.models import (
    Project,
    Finding,
    FindingSeverity,
    ScanJob,
    Host,
    Port,
    Service,
    Target,
    Report,
)

settings = get_settings()
logger = logging.getLogger(__name__)

SEVERITY_ORDER = [
    FindingSeverity.CRITICAL,
    FindingSeverity.HIGH,
    FindingSeverity.MEDIUM,
    FindingSeverity.LOW,
    FindingSeverity.INFORMATIONAL,
]

SEVERITY_COLORS = {
    FindingSeverity.CRITICAL: "#dc2626",
    FindingSeverity.HIGH: "#ea580c",
    FindingSeverity.MEDIUM: "#d97706",
    FindingSeverity.LOW: "#2563eb",
    FindingSeverity.INFORMATIONAL: "#64748b",
}


class ReportGenerator:
    def __init__(self, template_dir: Optional[str] = None, output_dir: Optional[str] = None):
        self.template_dir = Path(template_dir or settings.REPORT_TEMPLATE_DIR)
        self.output_dir = Path(output_dir or settings.REPORT_OUTPUT_DIR)
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._ensure_templates()

    def _ensure_templates(self) -> None:
        html_template = self.template_dir / "report.html"
        if not html_template.exists():
            html_template.write_text(self._get_default_html_template())

    def _get_default_html_template(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report.title }} - Security Assessment Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #1e293b; background: #fff; }
        .page { max-width: 8.5in; margin: 0 auto; padding: 1in; }
        @media print { .page { padding: 0.5in; } .no-print { display: none; } }
        header { border-bottom: 3px solid #1e293b; padding-bottom: 1rem; margin-bottom: 2rem; }
        h1 { font-size: 2rem; font-weight: 700; color: #1e293b; }
        h2 { font-size: 1.5rem; font-weight: 600; color: #1e293b; margin-top: 2rem; margin-bottom: 1rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.5rem; }
        h3 { font-size: 1.125rem; font-weight: 600; color: #334155; margin-top: 1.5rem; margin-bottom: 0.5rem; }
        .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .meta-item { background: #f8fafc; padding: 1rem; border-radius: 0.5rem; border: 1px solid #e2e8f0; }
        .meta-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: #64748b; letter-spacing: 0.05em; }
        .meta-value { font-size: 1rem; font-weight: 500; color: #1e293b; margin-top: 0.25rem; }
        .severity-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
        .severity-critical { background: #fef2f2; color: #dc2626; }
        .severity-high { background: #fff7ed; color: #ea580c; }
        .severity-medium { background: #fffbeb; color: #d97706; }
        .severity-low { background: #eff6ff; color: #2563eb; }
        .severity-informational { background: #f1f5f9; color: #64748b; }
        .finding { background: #fff; border: 1px solid #e2e8f0; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1.5rem; }
        .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.5rem; }
        .finding-title { font-size: 1.125rem; font-weight: 600; color: #1e293b; }
        .finding-meta { display: flex; gap: 1rem; font-size: 0.875rem; color: #64748b; flex-wrap: wrap; }
        .finding-section { margin-top: 1rem; }
        .finding-section-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: #64748b; letter-spacing: 0.05em; }
        .finding-section-content { margin-top: 0.5rem; white-space: pre-wrap; font-family: inherit; }
        .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: #fff; border: 1px solid #e2e8f0; border-radius: 0.5rem; padding: 1rem; text-align: center; }
        .stat-value { font-size: 2rem; font-weight: 700; }
        .stat-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: #64748b; }
        .stat-critical { color: #dc2626; }
        .stat-high { color: #ea580c; }
        .stat-medium { color: #d97706; }
        .stat-low { color: #2563eb; }
        .stat-info { color: #64748b; }
        .host-summary { width: 100%; border-collapse: collapse; margin-bottom: 2rem; font-size: 0.875rem; }
        .host-summary th, .host-summary td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
        .host-summary th { background: #f8fafc; font-weight: 600; color: #334155; }
        .host-summary tr:hover { background: #f8fafc; }
        .toc { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 2rem; }
        .toc ul { list-style: none; }
        .toc li { padding: 0.25rem 0; }
        .toc a { color: #334155; text-decoration: none; }
        .toc a:hover { text-decoration: underline; }
        .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e2e8f0; font-size: 0.75rem; color: #64748b; text-align: center; }
        .disclaimer { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 0.5rem; padding: 1rem; margin-bottom: 2rem; font-size: 0.875rem; }
        .executive-summary { background: #f0f9ff; border: 1px solid #bae6fd; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 2rem; }
        .methodology { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 2rem; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; font-size: 0.875rem; }
        th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f8fafc; font-weight: 600; }
    </style>
</head>
<body>
    <div class="page">
        <header>
            <h1>{{ report.title }}</h1>
            <p style="color: #64748b; margin-top: 0.5rem;">Security Assessment Report</p>
        </header>

        <div class="disclaimer">
            <strong>CONFIDENTIAL</strong> - This report contains sensitive security information. Distribution should be limited to authorized personnel only.
        </div>

        <div class="meta-grid">
            <div class="meta-item">
                <div class="meta-label">Project</div>
                <div class="meta-value">{{ project.name }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Assessment Date</div>
                <div class="meta-value">{{ report.generated_at.strftime('%B %d, %Y') }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Report ID</div>
                <div class="meta-value">{{ report.uuid[:8] }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Classification</div>
                <div class="meta-value">Confidential</div>
            </div>
        </div>

        <div class="toc">
            <h2>Table of Contents</h2>
            <ul>
                <li><a href="#executive-summary">1. Executive Summary</a></li>
                <li><a href="#scope">2. Assessment Scope</a></li>
                <li><a href="#methodology">3. Methodology</a></li>
                <li><a href="#target-inventory">4. Target Inventory</a></li>
                <li><a href="#findings-summary">5. Findings Summary</a></li>
                <li><a href="#detailed-findings">6. Detailed Findings</a></li>
                <li><a href="#remediation">7. Remediation Recommendations</a></li>
                <li><a href="#limitations">8. Limitations</a></li>
            </ul>
        </div>

        <section id="executive-summary">
            <h2>1. Executive Summary</h2>
            <div class="executive-summary">
                <p>{{ report.executive_summary | safe }}</p>
            </div>

            <h3>Key Statistics</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value stat-critical">{{ stats.severity_counts.critical }}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value stat-high">{{ stats.severity_counts.high }}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value stat-medium">{{ stats.severity_counts.medium }}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value stat-low">{{ stats.severity_counts.low }}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value stat-info">{{ stats.severity_counts.informational }}</div>
                    <div class="stat-label">Informational</div>
                </div>
            </div>
        </section>

        <section id="scope">
            <h2>2. Assessment Scope</h2>
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">Targets in Scope</div>
                    <div class="meta-value">{{ targets | length }}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scans Performed</div>
                    <div class="meta-value">{{ scans | length }}</div>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Type</th>
                        <th>Allowed Ports</th>
                        <th>Scope Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {% for target in targets %}
                    <tr>
                        <td>{{ target.host }}</td>
                        <td>{{ target.host_type }}</td>
                        <td>{{ target.allowed_ports }}</td>
                        <td>{{ target.scope_notes or 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>

        <section id="methodology">
            <h2>3. Methodology</h2>
            <div class="methodology">
                {{ report.methodology | safe }}
            </div>
        </section>

        <section id="target-inventory">
            <h2>4. Target Inventory</h2>
            <h3>Discovered Hosts</h3>
            <table class="host-summary">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>Open Ports</th>
                        <th>Services</th>
                    </tr>
                </thead>
                <tbody>
                    {% for host in hosts %}
                    <tr>
                        <td>{{ host.ip }}</td>
                        <td>{{ host.hostname or 'N/A' }}</td>
                        <td>{{ host.os_name or 'Unknown' }}</td>
                        <td>{{ host.open_ports_count }}</td>
                        <td>{{ host.services_count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>

            <h3>Discovered Services</h3>
            <table>
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Product</th>
                    </tr>
                </thead>
                <tbody>
                    {% for service in services %}
                    <tr>
                        <td>{{ service.host_ip }}</td>
                        <td>{{ service.port }}</td>
                        <td>{{ service.protocol }}</td>
                        <td>{{ service.name }}</td>
                        <td>{{ service.version or 'Unknown' }}</td>
                        <td>{{ service.product or 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>

        <section id="findings-summary">
            <h2>5. Findings Summary</h2>
            <p>Total findings: {{ findings | length }}</p>
            <p>Breakdown by severity:</p>
            <ul>
                {% for severity in severity_order %}
                {% set count = severity_counts.get(severity, 0) %}
                {% if count > 0 %}
                <li><span class="severity-badge severity-{{ severity.value }}">{{ severity.value.capitalize() }}</span>: {{ count }}</li>
                {% endif %}
                {% endfor %}
            </ul>
        </section>

        <section id="detailed-findings">
            <h2>6. Detailed Findings</h2>
            {% for finding in findings %}
            <div class="finding">
                <div class="finding-header">
                    <h3 class="finding-title">{{ finding.title }}</h3>
                    <span class="severity-badge severity-{{ finding.severity.value }}">{{ finding.severity.value.capitalize() }}</span>
                </div>
                <div class="finding-meta">
                    <span>Host: {{ finding.host_ip or 'N/A' }}</span>
                    <span>Port: {{ finding.port or 'N/A' }}</span>
                    <span>Category: {{ finding.category }}</span>
                    <span>Confidence: {{ finding.confidence.value.capitalize() }}</span>
                    <span>Status: {{ finding.status.value.replace('_', ' ').capitalize() }}</span>
                </div>

                <div class="finding-section">
                    <div class="finding-section-label">Description</div>
                    <div class="finding-section-content">{{ finding.description }}</div>
                </div>

                {% if finding.evidence %}
                <div class="finding-section">
                    <div class="finding-section-label">Evidence</div>
                    <div class="finding-section-content">{{ finding.evidence }}</div>
                </div>
                {% endif %}

                {% if finding.cve_id %}
                <div class="finding-section">
                    <div class="finding-section-label">CVE Reference</div>
                    <div class="finding-section-content">{{ finding.cve_id }} (CVSS: {{ finding.cvss_score or 'N/A' }})</div>
                </div>
                {% endif %}

                <div class="finding-section">
                    <div class="finding-section-label">Remediation</div>
                    <div class="finding-section-content">{{ finding.remediation or 'No specific remediation provided.' }}</div>
                </div>

                {% if finding.references %}
                <div class="finding-section">
                    <div class="finding-section-label">References</div>
                    <div class="finding-section-content">
                        {% for ref in finding.references %}
                        <div>{{ ref }}</div>
                        {% endfor %}
                    </div>
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </section>

        <section id="remediation">
            <h2>7. Remediation Recommendations</h2>
            <p>Prioritize remediation based on severity and business impact:</p>
            <ol>
                <li><strong>Critical/High:</strong> Address immediately. These pose immediate risk of compromise.</li>
                <li><strong>Medium:</strong> Schedule remediation within 30 days.</li>
                <li><strong>Low:</strong> Address during next maintenance window.</li>
                <li><strong>Informational:</strong> Review for defense-in-depth improvements.</li>
            </ol>
            <p>Consider implementing a vulnerability management program with regular scanning, patch management, and configuration review.</p>
        </section>

        <section id="limitations">
            <h2>8. Limitations</h2>
            <ul>
                <li>This assessment represents a point-in-time snapshot of the target environment.</li>
                <li>Automated vulnerability detection may produce false positives; manual validation is recommended.</li>
                <li>Only authorized targets within defined scope were assessed.</li>
                <li>Zero-day vulnerabilities and unknown attack vectors are not covered.</li>
                <li>Internal network segmentation and host-based controls were not evaluated.</li>
                <li>Social engineering, physical security, and wireless assessments were not in scope.</li>
            </ul>
        </section>

        <div class="footer">
            <p>Generated by VAPT Platform v{{ app_version }} on {{ report.generated_at.strftime('%Y-%m-%d %H:%M UTC') }}</p>
            <p>Report ID: {{ report.uuid }}</p>
        </div>
    </div>
</body>
</html>"""

    async def generate_report(
        self,
        project_id: int,
        name: str,
        format: str = "html",
        executive_summary: Optional[str] = None,
        methodology: Optional[str] = None,
    ) -> Report:
        async with get_db_session() as session:
            project = await project_crud.get(session, project_id)
            if not project:
                raise ValueError(f"Project {project_id} not found")

            report_record = Report(
                project_id=project_id,
                name=name,
                format=format,
                status="generating",
            )
            session.add(report_record)
            await session.flush()

            try:
                report_data = await self._collect_report_data(session, project_id)

                if format == "html":
                    file_path = await self._generate_html(report_record, project, report_data, executive_summary, methodology)
                elif format == "pdf":
                    file_path = await self._generate_pdf(report_record, project, report_data, executive_summary, methodology)
                else:
                    raise ValueError(f"Unsupported format: {format}")

                report_record.file_path = str(file_path)
                report_record.status = "completed"
                report_record.generated_at = datetime.utcnow()
                session.add(report_record)
                await session.flush()

                logger.info(f"Report generated: {file_path}")
                return report_record

            except Exception as e:
                report_record.status = "failed"
                report_record.error_message = str(e)
                session.add(report_record)
                await session.flush()
                logger.exception("Report generation failed")
                raise

    async def _collect_report_data(self, session, project_id: int) -> Dict:
        findings = await finding_crud.get_by_project(session, project_id)
        severity_counts = await finding_crud.get_severity_counts(session, project_id)

        targets = await target_crud.get_by_project(session, project_id)
        scans = await scan_job_crud.list(session, filters={"project_id": project_id})

        all_hosts = []
        all_services = []
        for target in targets:
            for scan in scans:
                if scan.target_id == target.id and scan.status == ScanStatus.COMPLETED:
                    hosts = await host_crud.get_by_scan(session, scan.id)
                    for host in hosts:
                        ports = await port_crud.get_open_ports(session, host.id)
                        host_data = {
                            "ip": host.ip,
                            "hostname": host.hostname,
                            "os_name": host.os_name,
                            "open_ports_count": len(ports),
                            "services_count": 0,
                        }
                        for port in ports:
                            services = await service_crud.get_by_port(session, port.id)
                            host_data["services_count"] += len(services)
                            for service in services:
                                all_services.append({
                                    "host_ip": host.ip,
                                    "port": port.port,
                                    "protocol": port.protocol,
                                    "name": service.name,
                                    "version": service.version,
                                    "product": service.product,
                                })
                        all_hosts.append(host_data)

        return {
            "findings": findings,
            "severity_counts": severity_counts,
            "targets": targets,
            "scans": scans,
            "hosts": all_hosts,
            "services": all_services,
        }

    async def _generate_html(
        self,
        report_record: Report,
        project: Project,
        report_data: Dict,
        executive_summary: Optional[str],
        methodology: Optional[str],
    ) -> Path:
        template = self.jinja_env.get_template("report.html")

        findings_data = []
        for f in report_data["findings"]:
            findings_data.append({
                "title": f.title,
                "description": f.description,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "status": f.status,
                "host_ip": f.host.ip if f.host else "N/A",
                "port": f.port.port if f.port else "N/A",
                "evidence": f.evidence,
                "cve_id": f.vulnerability.cve_id if f.vulnerability else None,
                "cvss_score": f.cvss_score,
                "remediation": f.remediation,
                "references": f.references,
            })

        html_content = template.render(
            report=report_record,
            project=project,
            stats=report_data,
            findings=findings_data,
            targets=report_data["targets"],
            scans=report_data["scans"],
            hosts=report_data["hosts"],
            services=report_data["services"],
            severity_order=SEVERITY_ORDER,
            executive_summary=executive_summary or self._generate_executive_summary(report_data),
            methodology=methodology or self._get_default_methodology(),
            app_version=settings.APP_VERSION,
        )

        file_name = f"report_{report_record.uuid}.html"
        file_path = self.output_dir / file_name
        file_path.write_text(html_content)
        return file_path

    async def _generate_pdf(
        self,
        report_record: Report,
        project: Project,
        report_data: Dict,
        executive_summary: Optional[str],
        methodology: Optional[str],
    ) -> Path:
        template = self.jinja_env.get_template("report.html")

        findings_data = []
        for f in report_data["findings"]:
            findings_data.append({
                "title": f.title,
                "description": f.description,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "status": f.status,
                "host_ip": f.host.ip if f.host else "N/A",
                "port": f.port.port if f.port else "N/A",
                "evidence": f.evidence,
                "cve_id": f.vulnerability.cve_id if f.vulnerability else None,
                "cvss_score": f.cvss_score,
                "remediation": f.remediation,
                "references": f.references,
            })

        html_content = template.render(
            report=report_record,
            project=project,
            stats=report_data,
            findings=findings_data,
            targets=report_data["targets"],
            scans=report_data["scans"],
            hosts=report_data["hosts"],
            services=report_data["services"],
            severity_order=SEVERITY_ORDER,
            executive_summary=executive_summary or self._generate_executive_summary(report_data),
            methodology=methodology or self._get_default_methodology(),
            app_version=settings.APP_VERSION,
        )

        file_name = f"report_{report_record.uuid}.pdf"
        file_path = self.output_dir / file_name

        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(str(file_path))
        except ImportError:
            file_path.write_text(html_content)

        report_record.status = "completed"
        report_record.generated_at = datetime.utcnow()
        return file_path

    def _generate_executive_summary(self, report_data: Dict) -> str:
        total_findings = len(report_data["findings"])
        critical = report_data["severity_counts"].get(FindingSeverity.CRITICAL, 0)
        high = report_data["severity_counts"].get(FindingSeverity.HIGH, 0)
        medium = report_data["severity_counts"].get(FindingSeverity.MEDIUM, 0)
        low = report_data["severity_counts"].get(FindingSeverity.LOW, 0)
        info = report_data["severity_counts"].get(FindingSeverity.INFORMATIONAL, 0)

        hosts_count = len(report_data["hosts"])
        services_count = len(report_data["services"])

        summary = f"""
        <p>This report presents the results of a security assessment conducted against <strong>{hosts_count} hosts</strong> with <strong>{services_count} discovered services</strong>.</p>
        <p>The assessment identified a total of <strong>{total_findings} findings</strong> across the following severity levels:</p>
        <ul>
            <li><span class="severity-badge severity-critical">Critical</span>: {critical}</li>
            <li><span class="severity-badge severity-high">High</span>: {high}</li>
            <li><span class="severity-badge severity-medium">Medium</span>: {medium}</li>
            <li><span class="severity-badge severity-low">Low</span>: {low}</li>
            <li><span class="severity-badge severity-informational">Informational</span>: {info}</li>
        </ul>
        """
        if critical > 0 or high > 0:
            summary += "<p><strong>Immediate action is required</strong> to address critical and high-severity findings that pose significant risk to the organization.</p>"
        elif medium > 0:
            summary += "<p><strong>Timely remediation</strong> of medium-severity findings is recommended to reduce the attack surface.</p>"
        else:
            summary += "<p>The assessment did not reveal critical or high-severity vulnerabilities. Continue regular security monitoring and maintenance.</p>"

        return summary

    def _get_default_methodology(self) -> str:
        return """
        <h3>Assessment Methodology</h3>
        <p>This assessment was conducted using the VAPT Platform, following industry-standard methodologies:</p>
        <ol>
            <li><strong>Reconnaissance & Discovery:</strong> Network mapping, host discovery, and service enumeration using Nmap.</li>
            <li><strong>Vulnerability Identification:</strong> Automated correlation of discovered services and versions against a curated CVE database.</li>
            <li><strong>Configuration Review:</strong> Analysis of service configurations for security misconfigurations using Nmap NSE scripts.</li>
            <li><strong>Manual Validation:</strong> Findings are marked for manual validation to reduce false positives.</li>
        </ol>
        <h3>Tools Used</h3>
        <ul>
            <li>Nmap for network scanning and service enumeration</li>
            <li>Nmap NSE scripts for configuration checks</li>
            <li>Local CVE database for vulnerability correlation</li>
        </ul>
        <h3>Scope Limitations</h3>
        <p>This assessment was limited to the defined scope and authorized targets. No exploitation, privilege escalation, or post-exploitation activities were performed.</p>
        """


report_generator = ReportGenerator()