"""Log Analysis Agent: rule-based attack detection."""
import uuid

from agents.log_analysis import (
    BRUTE_FORCE_THRESHOLD,
    SCAN_DISTINCT_PATH_THRESHOLD,
    detect_patterns,
)


def _entry(event, ip=None, username=None):
    return {
        "id": str(uuid.uuid4()), "timestamp": None, "ip": ip,
        "username": username, "event": event, "severity": "info", "source": "test",
    }


def _types(findings):
    return {f["attack_type"] for f in findings}


def test_brute_force_requires_threshold_failed_logins():
    entries = [_entry("Failed password for root", "203.0.113.1", "root")
               for _ in range(BRUTE_FORCE_THRESHOLD)]
    findings = detect_patterns(entries)
    assert "brute_force" in _types(findings)


def test_below_threshold_is_failed_login_not_brute_force():
    entries = [_entry("Failed password for root", "203.0.113.1", "root")]
    findings = detect_patterns(entries)
    types = _types(findings)
    assert "failed_login" in types
    assert "brute_force" not in types


def test_sql_injection_detected():
    findings = detect_patterns([_entry("GET /p?id=1' OR '1'='1", "203.0.113.2")])
    assert "sql_injection" in _types(findings)


def test_xss_detected_even_url_encoded():
    # %3Cscript%3E decodes to <script> — detection runs on the decoded event.
    findings = detect_patterns([_entry("GET /s?q=%3Cscript%3Ealert(1)%3C/script%3E", "203.0.113.3")])
    assert "xss" in _types(findings)


def test_privilege_escalation_detected():
    findings = detect_patterns([_entry("sudo su - root", "203.0.113.4", "root")])
    assert "privilege_escalation" in _types(findings)


def test_port_scan_needs_distinct_paths():
    entries = [_entry(f"GET /path{i} -> 404", "203.0.113.5")
               for i in range(SCAN_DISTINCT_PATH_THRESHOLD)]
    findings = detect_patterns(entries)
    assert "port_scan" in _types(findings)


def test_benign_traffic_produces_no_findings():
    entries = [_entry("GET / -> 200", "198.18.0.1") for _ in range(5)]
    assert detect_patterns(entries) == []


def test_findings_carry_evidence_and_ids():
    findings = detect_patterns([_entry("GET /p?id=1' OR '1'='1", "203.0.113.2")])
    f = findings[0]
    assert f["evidence"]
    assert f["ip"] == "203.0.113.2"
    assert isinstance(f["entry_ids"], list) and f["entry_ids"]
