"""Report Generation Agent: produces PDF/HTML/JSON incident reports.

Includes: executive summary, timeline, MITRE mapping, recommendations.
"""
import io
import json
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _summary(incidents: list[dict]) -> dict:
    by_level = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for incident in incidents:
        level = incident.get("threat_level", "Low")
        by_level[level] = by_level.get(level, 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_incidents": len(incidents),
        "by_threat_level": by_level,
    }


def _timeline(incidents: list[dict]) -> list[dict]:
    events = []
    for incident in incidents:
        for finding in incident.get("findings", []):
            events.append({
                "ip": incident.get("ip"),
                "attack_type": finding.get("attack_type"),
                "severity": finding.get("severity"),
                "evidence": finding.get("evidence"),
            })
    return events


def build_report_data(incidents: list[dict]) -> dict:
    return {
        "executive_summary": _summary(incidents),
        "timeline": _timeline(incidents),
        "incidents": incidents,
    }


def to_json(incidents: list[dict]) -> str:
    return json.dumps(build_report_data(incidents), indent=2, default=str)


def to_html(incidents: list[dict]) -> str:
    data = build_report_data(incidents)
    rows = "".join(
        f"<tr><td>{i['priority']}</td><td>{i['threat_level']}</td><td>{i['risk_score']}</td>"
        f"<td>{i.get('ip') or i.get('username') or '-'}</td>"
        f"<td>{', '.join(i['attack_types'])}</td>"
        f"<td>{', '.join(sorted({m['technique_id'] for m in i['mitre_techniques']}))}</td>"
        f"<td>{', '.join(i['recommended_actions'])}</td></tr>"
        for i in incidents
    )
    summary = data["executive_summary"]
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SecureOrch Incident Report</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 0.9rem; }}
th {{ background: #f0f0f0; }}
</style></head>
<body>
<h1>SecureOrch Incident Report</h1>
<p>Generated: {summary['generated_at']}</p>
<h2>Executive Summary</h2>
<p>Total incidents: {summary['total_incidents']}</p>
<ul>
{''.join(f"<li>{level}: {count}</li>" for level, count in summary['by_threat_level'].items())}
</ul>
<h2>Incidents</h2>
<table>
<tr><th>Priority</th><th>Threat Level</th><th>Risk Score</th><th>IP/User</th>
<th>Attack Types</th><th>MITRE</th><th>Recommended Actions</th></tr>
{rows}
</table>
</body></html>"""


def to_pdf(incidents: list[dict]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [Paragraph("SecureOrch Incident Report", styles["Title"]), Spacer(1, 12)]

    data = build_report_data(incidents)
    summary = data["executive_summary"]
    elements.append(Paragraph(f"Generated: {summary['generated_at']}", styles["Normal"]))
    elements.append(Paragraph(f"Total incidents: {summary['total_incidents']}", styles["Normal"]))
    for level, count in summary["by_threat_level"].items():
        elements.append(Paragraph(f"{level}: {count}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    table_data = [["Priority", "Threat Level", "Risk", "IP/User", "Attack Types", "MITRE", "Actions"]]
    for incident in incidents:
        table_data.append([
            incident["priority"],
            incident["threat_level"],
            str(incident["risk_score"]),
            incident.get("ip") or incident.get("username") or "-",
            ", ".join(incident["attack_types"]),
            ", ".join(sorted({m["technique_id"] for m in incident["mitre_techniques"]})),
            ", ".join(incident["recommended_actions"]),
        ])

    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(table)

    doc.build(elements)
    return buffer.getvalue()
