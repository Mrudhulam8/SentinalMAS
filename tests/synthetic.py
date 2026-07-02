"""Synthetic log generation for tests and performance benchmarking.

Produces parsed-schema entries (as emitted by agents.log_parser) so tests can
drive the pipeline directly without going through file parsing. The mix is
tuned to exercise every Log Analysis detection rule at realistic proportions.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

# A pool of "attacker" IPs that will trip detection rules, plus benign IPs.
_ATTACKER_IPS = [f"203.0.113.{i}" for i in range(1, 21)]
_BENIGN_IPS = [f"198.18.{a}.{b}" for a in range(4) for b in range(1, 40)]
_USERS = ["root", "admin", "jdoe", "svc-deploy", "guest", "backup"]
_SCAN_PATHS = ["/admin", "/login", "/wp-admin", "/.env", "/api/v1/users", "/phpmyadmin", "/config"]


def _entry(event: str, ip: str | None, username: str | None, severity: str, ts: datetime) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": ts.isoformat(),
        "ip": ip,
        "username": username,
        "event": event,
        "severity": severity,
        "source": "synthetic",
    }


def generate_entries(count: int, seed: int = 1337) -> list[dict]:
    """Return `count` parsed log entries with an attack-rich but realistic mix.

    Roughly: 55% benign traffic, 20% failed logins (brute-force clusters),
    10% web scans, 8% SQLi/XSS, 5% privilege escalation, 2% server errors.
    """
    rng = random.Random(seed)
    base = datetime(2026, 7, 1, tzinfo=timezone.utc)
    entries: list[dict] = []

    for i in range(count):
        ts = base + timedelta(seconds=i)
        roll = rng.random()

        if roll < 0.55:
            ip = rng.choice(_BENIGN_IPS)
            path = rng.choice(["/", "/home", "/dashboard", "/api/v1/ping", "/static/app.js"])
            entries.append(_entry(f"GET {path} -> 200", ip, None, "low", ts))
        elif roll < 0.75:
            ip = rng.choice(_ATTACKER_IPS)
            user = rng.choice(_USERS)
            entries.append(_entry(f"Failed password for {user} from {ip} port 22 ssh2",
                                  ip, user, "medium", ts))
        elif roll < 0.85:
            ip = rng.choice(_ATTACKER_IPS)
            path = rng.choice(_SCAN_PATHS)
            entries.append(_entry(f"GET {path} -> 404", ip, None, "medium", ts))
        elif roll < 0.93:
            ip = rng.choice(_ATTACKER_IPS)
            if rng.random() < 0.5:
                event = "GET /products?id=1' OR '1'='1 -> 200"
            else:
                event = "GET /search?q=<script>alert(1)</script> -> 200"
            entries.append(_entry(event, ip, None, "high", ts))
        elif roll < 0.98:
            ip = rng.choice(_ATTACKER_IPS)
            entries.append(_entry("sudo su - root ; usermod -aG sudo attacker",
                                  ip, "root", "medium", ts))
        else:
            ip = rng.choice(_ATTACKER_IPS)
            entries.append(_entry(f"POST /api/v1/checkout -> 500", ip, None, "high", ts))

    return entries
