"""Generate large, attack-rich security logs in uploadable formats.

<<<<<<< HEAD
Produces realistic logs the SentinelMAS parser understands (Apache access,
=======
Produces realistic logs the SecureOrch parser understands (Apache access,
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70
Linux auth, CSV, JSON) with an attack mix tuned to trigger every Log Analysis
detection rule: brute force, failed login, SQL injection, XSS, privilege
escalation, port scan, and suspicious (4xx/5xx) traffic.

Usage:
    python datasets/generate_datasets.py                      # default 10k + 50k set
    python datasets/generate_datasets.py --count 100000 --format csv --out datasets/huge.csv

Notes:
  * Attacker IPs come from the reserved TEST-NET ranges (RFC 5737), so they are
    safe to publish and won't hit real hosts.
  * The unique-attacker-IP pool is kept small (~20) on purpose: with live
    AbuseIPDB/VirusTotal keys the Threat Intel agent makes one call per unique
    IP, and those free tiers are rate-limited (VirusTotal: 4 req/min). Fewer
    unique IPs keeps enrichment fast. (Detection itself is keyless and instant.)
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import random
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

ATTACKER_IPS = [f"203.0.113.{i}" for i in range(1, 21)]       # TEST-NET-3
BENIGN_IPS = [f"198.51.100.{i}" for i in range(1, 60)]        # TEST-NET-2
USERS = ["root", "admin", "jdoe", "svc-deploy", "guest", "backup", "oracle"]
# Kept to 3 so ordinary users don't trip the port-scan rule (>=4 distinct paths).
BENIGN_PATHS = ["/", "/home", "/dashboard"]
SCAN_PATHS = ["/admin", "/wp-admin", "/.env", "/phpmyadmin", "/config.php", "/.git/config",
              "/api/v1/users", "/backup.zip", "/server-status", "/actuator"]
SQLI_PATHS = ["/products?id=1' OR '1'='1", "/items?id=1 UNION SELECT username,password FROM users",
              "/search?q=1;DROP TABLE users--", "/login?user=admin'--"]
XSS_PATHS = ["/search?q=<script>alert(1)</script>", "/comment?text=<img src=x onerror=alert(1)>",
             "/page?name=<script>document.cookie</script>"]

# Each attacker IP is restricted to a fixed subset of attack kinds ("profile"),
# rather than every IP being able to commit all 6 kinds. Risk score is driven
# by max finding severity + attack-type diversity (capped at 4) + asset
# criticality + IP reputation -- if every IP can trigger every kind, every
# incident converges on the same maxed-out score (severity=high, diversity=4,
# capped at risk 10.0), which is exactly what produced a flat "all Critical"
# bar chart. Restricting each IP's profile produces a genuine spread across
# Medium/High/Critical when run through the real risk-assessment formula.
#
# Exact scores aren't precisely predictable from a profile alone: some
# detection rules share signals across kinds (e.g. port_scan and
# suspicious_traffic both key off HTTP status codes; port_scan's
# distinct-path counter picks up any kind whose synthetic paths vary, like
# sqli/xss). That's a real property of the detection engine, not a dataset
# bug -- diverse attack payloads legitimately can look like scanning. The
# tiers below are ordered narrow -> broad and roughly Medium -> Critical, but
# some cross-triggering across nearby tiers is expected and fine.
_A = ATTACKER_IPS
IP_PROFILES: dict[str, list[str]] = {
    **{ip: ["port_scan"] for ip in _A[0:2]},                          # Medium/High
    **{ip: ["priv_esc"] for ip in _A[2:4]},                           # Medium
    **{ip: ["server_error"] for ip in _A[4:6]},                       # Medium
    **{ip: ["brute_force"] for ip in _A[6:8]},                        # High
    **{ip: ["sqli"] for ip in _A[8:10]},                              # High/Critical
    **{ip: ["port_scan", "priv_esc"] for ip in _A[10:12]},            # High
    **{ip: ["brute_force", "sqli"] for ip in _A[12:14]},              # Critical
    **{ip: ["xss", "port_scan", "priv_esc"] for ip in _A[14:16]},     # Critical
    **{ip: ["brute_force", "port_scan", "sqli", "xss", "priv_esc", "server_error"]
       for ip in _A[16:20]},                                          # Critical (10.0, capped)
}


def _pick_attack(rng: random.Random) -> tuple[str, str]:
    """Pick an attacker IP uniformly, then a kind from that IP's profile."""
    ip = rng.choice(ATTACKER_IPS)
    return rng.choice(IP_PROFILES[ip]), ip


def _records(count: int, seed: int):
    rng = random.Random(seed)
    base = datetime(2026, 7, 1, tzinfo=timezone.utc)
    for i in range(count):
        ts = base + timedelta(seconds=i)
        is_benign = rng.random() < 0.45
        if is_benign:
            yield {"kind": "benign", "ts": ts, "ip": rng.choice(BENIGN_IPS), "user": None,
                   "method": "GET", "path": rng.choice(BENIGN_PATHS), "status": 200}
            continue

        kind, ip = _pick_attack(rng)
        if kind == "brute_force":
            yield {"kind": kind, "ts": ts, "ip": ip, "user": rng.choice(USERS),
                   "method": "POST", "path": "/login", "status": 401}
        elif kind == "port_scan":
            yield {"kind": kind, "ts": ts, "ip": ip, "user": None,
                   "method": "GET", "path": rng.choice(SCAN_PATHS), "status": 404}
        elif kind == "sqli":
            yield {"kind": kind, "ts": ts, "ip": ip, "user": None,
                   "method": "GET", "path": rng.choice(SQLI_PATHS), "status": 200}
        elif kind == "xss":
            yield {"kind": kind, "ts": ts, "ip": ip, "user": None,
                   "method": "GET", "path": rng.choice(XSS_PATHS), "status": 200}
        elif kind == "priv_esc":
            yield {"kind": kind, "ts": ts, "ip": ip, "user": "root",
                   "method": None, "path": None, "status": None}
        else:  # server_error
            yield {"kind": kind, "ts": ts, "ip": ip, "user": None,
                   "method": "POST", "path": "/api/v1/checkout", "status": 500}


def _severity(kind: str) -> str:
    return {"sqli": "high", "xss": "high", "server_error": "high",
            "brute_force": "medium", "port_scan": "medium", "priv_esc": "medium"}.get(kind, "low")


def _event_text(r: dict) -> str:
    if r["kind"] == "brute_force":
        return f"Failed password for {r['user']} from {r['ip']}"
    if r["kind"] == "priv_esc":
        return "sudo su - root ; usermod -aG sudo attacker"
    return f'{r["method"]} {r["path"]} -> {r["status"]}'


def to_csv(records) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "ip", "username", "event", "severity"])
    for r in records:
        w.writerow([r["ts"].isoformat(), r["ip"], r["user"] or "", _event_text(r), _severity(r["kind"])])
    return buf.getvalue()


def to_json(records) -> str:
    rows = [{"timestamp": r["ts"].isoformat(), "ip": r["ip"], "username": r["user"],
             "event": _event_text(r), "severity": _severity(r["kind"])} for r in records]
    return json.dumps({"logs": rows}, indent=0)


def to_apache(records) -> str:
    lines = []
    for r in records:
        # Apache carries web traffic; auth/priv-esc events become a login probe.
        method = r["method"] or "POST"
        # Real web servers URL-encode the request path; encoding also keeps it a
        # single whitespace-free token so the combined-log-format parser can
        # still extract the client IP from attack payloads.
        path = quote(r["path"] or "/login", safe="/?=&")
        status = r["status"] if r["status"] is not None else 401
        user = r["user"] or "-"
        t = r["ts"].strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{r["ip"]} - {user} [{t}] "{method} {path} HTTP/1.1" {status} {r["ts"].second * 7 + 128}')
    return "\n".join(lines) + "\n"


def to_linux(records) -> str:
    lines = []
    for r in records:
        t = r["ts"].strftime("%b %e %H:%M:%S")
        if r["kind"] == "brute_force":
            msg = f"Failed password for invalid user {r['user']} from {r['ip']} port {r['ts'].second + 1024} ssh2"
        else:
            # An auth log only meaningfully carries login events; other attack
            # kinds (web/priv-esc) surface as benign accepted logins here. Those
            # attacks are exercised in the CSV/JSON datasets instead. This keeps
            # brute-force clusters (grouped by source IP) as the clean signal.
            benign_ip = BENIGN_IPS[(r["ts"].second) % len(BENIGN_IPS)]
            msg = f"Accepted password for jdoe from {benign_ip} port {r['ts'].second + 2048} ssh2"
        lines.append(f"{t} srv01 sshd[{1000 + (r['ts'].second % 900)}]: {msg}")
    return "\n".join(lines) + "\n"


SERIALIZERS = {"csv": to_csv, "json": to_json, "apache": to_apache, "linux": to_linux}


def generate(count: int, fmt: str, out: str, seed: int = 1337) -> None:
    content = SERIALIZERS[fmt](list(_records(count, seed)))
    with open(out, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    print(f"wrote {out}  ({count:,} logs, {fmt})")


DEFAULT_SET = [
    (10_000, "csv", "datasets/large_logs_10k.csv"),
    (10_000, "apache", "datasets/large_apache_access_10k.log"),
    (10_000, "linux", "datasets/large_linux_auth_10k.log"),
    (50_000, "csv", "datasets/large_logs_50k.csv"),
]


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--count", type=int, help="number of log lines")
    p.add_argument("--format", choices=SERIALIZERS, help="output format")
    p.add_argument("--out", help="output file path")
    p.add_argument("--seed", type=int, default=1337)
    args = p.parse_args()

    if args.count and args.format and args.out:
        generate(args.count, args.format, args.out, args.seed)
    else:
        for count, fmt, out in DEFAULT_SET:
            generate(count, fmt, out, args.seed)


if __name__ == "__main__":
    main()
