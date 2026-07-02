"""Report Generation Agent: JSON / HTML / PDF output."""
import json

from agents import report
from agents.orchestrator import run_pipeline
from tests.synthetic import generate_entries


def _incidents(n=400):
    return run_pipeline(generate_entries(n))["incidents"]


def test_json_report_is_valid_and_structured():
    incidents = _incidents()
    data = json.loads(report.to_json(incidents))
    assert set(data) == {"executive_summary", "timeline", "incidents"}
    summary = data["executive_summary"]
    assert summary["total_incidents"] == len(incidents)
    assert set(summary["by_threat_level"]) == {"Critical", "High", "Medium", "Low"}


def test_html_report_contains_table_and_summary():
    html = report.to_html(_incidents())
    assert "<table>" in html
    assert "Executive Summary" in html
    assert "SecureOrch Incident Report" in html


def test_pdf_report_has_valid_header():
    pdf = report.to_pdf(_incidents())
    assert isinstance(pdf, bytes)
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 1000


def test_reports_handle_empty_incident_list():
    assert json.loads(report.to_json([]))["executive_summary"]["total_incidents"] == 0
    assert "<table>" in report.to_html([])
    assert report.to_pdf([])[:4] == b"%PDF"
