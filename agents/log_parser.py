"""Log Parsing Agent: normalizes CSV/JSON/TXT/Apache/Linux auth logs into a common schema.

Common schema per entry: timestamp, ip, username, event, severity, source
"""
import csv
import io
import json
import re
import uuid
from datetime import datetime, timezone

APACHE_COMBINED_RE = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+)'
)

LINUX_AUTH_RE = re.compile(
    r'^(?P<time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
    r'(?P<proc>\w+)(\[\d+\])?:\s+(?P<msg>.*)$'
)

LINUX_AUTH_USER_IP_RE = re.compile(
    r'(Failed|Accepted|Invalid user) (password for )?(invalid user )?(?P<user>\S+)'
    r'.*from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)


def _base_entry(source: str) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": None,
        "ip": None,
        "username": None,
        "event": None,
        "severity": "info",
        "source": source,
    }


def parse_csv(content: str, filename: str) -> list[dict]:
    entries = []
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        entry = _base_entry(filename)
        lower = {k.lower().strip(): v for k, v in row.items()}
        entry["timestamp"] = lower.get("timestamp") or lower.get("time") or lower.get("date")
        entry["ip"] = lower.get("ip") or lower.get("src_ip") or lower.get("source_ip")
        entry["username"] = lower.get("username") or lower.get("user")
        entry["event"] = lower.get("event") or lower.get("event_type") or lower.get("action")
        entry["severity"] = lower.get("severity", "info") or "info"
        entries.append(entry)
    return entries


def parse_json(content: str, filename: str) -> list[dict]:
    data = json.loads(content)
    if isinstance(data, dict):
        data = data.get("logs", data.get("entries", [data]))
    entries = []
    for row in data:
        entry = _base_entry(filename)
        entry["timestamp"] = row.get("timestamp") or row.get("time") or row.get("date")
        entry["ip"] = row.get("ip") or row.get("src_ip") or row.get("source_ip")
        entry["username"] = row.get("username") or row.get("user")
        entry["event"] = row.get("event") or row.get("event_type") or row.get("action")
        entry["severity"] = row.get("severity", "info") or "info"
        entries.append(entry)
    return entries


def parse_apache_log(content: str, filename: str) -> list[dict]:
    entries = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        match = APACHE_COMBINED_RE.search(line)
        entry = _base_entry(filename)
        if match:
            status = match.group("status")
            path = match.group("path")
            entry["timestamp"] = match.group("time")
            entry["ip"] = match.group("ip")
            entry["username"] = match.group("user") if match.group("user") != "-" else None
            entry["event"] = f'{match.group("method")} {path} -> {status}'
            entry["severity"] = _severity_from_status(status, path)
        else:
            entry["event"] = line
            entry["severity"] = "unknown"
        entries.append(entry)
    return entries


def _severity_from_status(status: str, path: str) -> str:
    lowered_path = path.lower()
    if any(tok in lowered_path for tok in ("select ", "union ", "' or ", "--", "<script")):
        return "high"
    if status.startswith("4"):
        return "medium"
    if status.startswith("5"):
        return "high"
    return "low"


def parse_linux_log(content: str, filename: str) -> list[dict]:
    entries = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        entry = _base_entry(filename)
        header = LINUX_AUTH_RE.match(line)
        if header:
            entry["timestamp"] = header.group("time")
            msg = header.group("msg")
            entry["event"] = msg
            user_ip = LINUX_AUTH_USER_IP_RE.search(msg)
            if user_ip:
                entry["username"] = user_ip.group("user")
                entry["ip"] = user_ip.group("ip")
            if "Failed" in msg or "Invalid user" in msg:
                entry["severity"] = "medium"
            elif "Accepted" in msg:
                entry["severity"] = "low"
        else:
            entry["event"] = line
            entry["severity"] = "unknown"
        entries.append(entry)
    return entries


def parse_txt(content: str, filename: str) -> list[dict]:
    entries = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        entry = _base_entry(filename)
        entry["event"] = line
        ip_match = re.search(r'\d{1,3}(?:\.\d{1,3}){3}', line)
        if ip_match:
            entry["ip"] = ip_match.group(0)
        entries.append(entry)
    return entries


def detect_and_parse(filename: str, content_bytes: bytes) -> list[dict]:
    content = content_bytes.decode("utf-8", errors="replace")
    lower_name = filename.lower()

    if lower_name.endswith(".csv"):
        return parse_csv(content, filename)
    if lower_name.endswith(".json"):
        return parse_json(content, filename)
    if "apache" in lower_name or "access" in lower_name:
        return parse_apache_log(content, filename)
    if "auth" in lower_name or "linux" in lower_name or "syslog" in lower_name:
        return parse_linux_log(content, filename)

    stripped = content.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return parse_json(content, filename)
    if APACHE_COMBINED_RE.search(content.splitlines()[0]) if content.splitlines() else False:
        return parse_apache_log(content, filename)
    if LINUX_AUTH_RE.match(content.splitlines()[0]) if content.splitlines() else False:
        return parse_linux_log(content, filename)

    return parse_txt(content, filename)
