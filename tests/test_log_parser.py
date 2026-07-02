"""Log Parsing Agent: format detection and normalization to the common schema."""
from agents.log_parser import detect_and_parse

COMMON_KEYS = {"id", "timestamp", "ip", "username", "event", "severity", "source"}


def _b(text: str) -> bytes:
    return text.encode("utf-8")


def test_csv_parsing_maps_aliased_columns():
    csv = "time,src_ip,user,action,severity\n2026-07-01,10.0.0.9,jdoe,login,low\n"
    entries = detect_and_parse("events.csv", _b(csv))
    assert len(entries) == 1
    e = entries[0]
    assert COMMON_KEYS <= set(e)
    assert e["ip"] == "10.0.0.9"
    assert e["username"] == "jdoe"
    assert e["event"] == "login"


def test_json_parsing_accepts_logs_wrapper():
    payload = '{"logs": [{"src_ip": "1.2.3.4", "user": "root", "event_type": "sudo"}]}'
    entries = detect_and_parse("data.json", _b(payload))
    assert len(entries) == 1
    assert entries[0]["ip"] == "1.2.3.4"
    assert entries[0]["event"] == "sudo"


def test_apache_access_log_extracts_method_path_status():
    line = '203.0.113.5 - - [01/Jul/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 128'
    entries = detect_and_parse("sample_apache_access.log", _b(line))
    assert len(entries) == 1
    e = entries[0]
    assert e["ip"] == "203.0.113.5"
    assert "GET /admin -> 404" == e["event"]
    assert e["severity"] == "medium"  # 4xx


def test_linux_auth_log_extracts_user_and_ip():
    line = "Jul  1 10:00:00 host sshd[123]: Failed password for root from 203.0.113.9 port 22 ssh2"
    entries = detect_and_parse("sample_linux_auth.log", _b(line))
    assert len(entries) == 1
    e = entries[0]
    assert e["username"] == "root"
    assert e["ip"] == "203.0.113.9"
    assert e["severity"] == "medium"


def test_plain_txt_fallback_still_extracts_ip():
    entries = detect_and_parse("notes.txt", _b("connection from 8.8.8.8 refused"))
    assert len(entries) == 1
    assert entries[0]["ip"] == "8.8.8.8"


def test_every_entry_has_unique_id():
    csv = "ip,event\n1.1.1.1,a\n2.2.2.2,b\n3.3.3.3,c\n"
    entries = detect_and_parse("x.csv", _b(csv))
    assert len({e["id"] for e in entries}) == len(entries) == 3
