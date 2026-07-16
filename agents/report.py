"""Report Generation Agent: produces PDF/HTML/JSON incident reports.

Includes: executive summary, timeline, MITRE mapping, recommendations.
"""
import io
import json
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
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
<html><head><meta charset="utf-8"><title>SentinelMAS Incident Report</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 0.9rem; }}
th {{ background: #f0f0f0; }}
</style></head>
<body>
<h1>SentinelMAS Incident Report</h1>
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


_CELL_STYLE = ParagraphStyle("cell", fontName="Helvetica", fontSize=7.5, leading=9.5)
_HEADER_STYLE = ParagraphStyle("header", fontName="Helvetica-Bold", fontSize=8, leading=10,
                                textColor=colors.black)

# Column widths (points) for a landscape letter page with 0.4in margins
# (usable width ~734pt). Long cells (Attack Types/MITRE/Actions) get most of
# the room and wrap via Paragraph instead of overflowing off the page.
_COL_WIDTHS = [42, 60, 34, 82, 160, 140, 196]
_COL_HEADERS = ["Priority", "Threat\nLevel", "Risk", "IP / User", "Attack Types", "MITRE", "Recommended Actions"]


def to_pdf(incidents: list[dict]) -> bytes:
    buffer = io.BytesIO()
    margin = 0.4 * 72
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(letter),
        leftMargin=margin, rightMargin=margin, topMargin=margin, bottomMargin=margin,
    )
    styles = getSampleStyleSheet()
    elements = [Paragraph("SentinelMAS Incident Report", styles["Title"]), Spacer(1, 12)]

    data = build_report_data(incidents)
    summary = data["executive_summary"]
    elements.append(Paragraph(f"Generated: {summary['generated_at']}", styles["Normal"]))
    elements.append(Paragraph(f"Total incidents: {summary['total_incidents']}", styles["Normal"]))
    for level, count in summary["by_threat_level"].items():
        elements.append(Paragraph(f"{level}: {count}", styles["Normal"]))
    elements.append(Spacer(1, 14))

    def cell(text: str, style=_CELL_STYLE) -> Paragraph:
        return Paragraph(str(text), style)

    table_data = [[cell(h, _HEADER_STYLE) for h in _COL_HEADERS]]
    for incident in incidents:
        table_data.append([
            cell(incident["priority"]),
            cell(incident["threat_level"]),
            cell(incident["risk_score"]),
            cell(incident.get("ip") or incident.get("username") or "-"),
            cell(", ".join(incident["attack_types"])),
            cell(", ".join(sorted({m["technique_id"] for m in incident["mitre_techniques"]}))),
            cell(", ".join(incident["recommended_actions"])),
        ])

    table = Table(table_data, colWidths=_COL_WIDTHS, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(table)

    doc.build(elements)
    return buffer.getvalue()
