"""Scenario-based log generator for attack simulation.

Generates synthetic log entries in the common schema (same format the parser
produces) so they can be fed directly into the orchestrator pipeline. Each
scenario produces a realistic mix of attack traffic + benign noise.
"""
import random
import uuid
from datetime import datetime, timedelta, timezone

ATTACKER_IPS = [f"203.0.113.{i}" for i in range(10, 30)]
BENIGN_IPS = [f"198.51.100.{i}" for i in range(1, 40)]
USERS = ["admin", "jdoe", "root", "svc-deploy", "guest", "backup", "oracle"]
BENIGN_PATHS = ["/", "/home", "/dashboard", "/profile", "/settings"]
SCAN_PATHS = [
    "/admin", "/wp-admin", "/.env", "/phpmyadmin", "/config.php",
    "/.git/config", "/api/v1/users", "/backup.zip", "/server-status",
    "/actuator", "/debug", "/console", "/swagger.json", "/metrics",
]
SQLI_PAYLOADS = [
    "/products?id=1' OR '1'='1",
    "/items?id=1 UNION SELECT username,password FROM users",
    "/search?q=1;DROP TABLE users--",
    "/login?user=admin'--",
    "/api/users?sort=name;SELECT * FROM credentials--",
]
XSS_PAYLOADS = [
    "/search?q=<script>alert(1)</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/page?name=<script>document.cookie</script>",
    "/profile?bio=<svg onload=alert('xss')>",
]
PRIV_ESC_COMMANDS = [
    "sudo su - root ; usermod -aG sudo attacker",
    "chmod +s /bin/bash",
    "sudo bash -c 'echo attacker ALL=(ALL) NOPASSWD:ALL >> /etc/sudoers'",
    "usermod -aG wheel attacker",
]

# Geolocation data for impossible travel simulation
GEO_LOCATIONS = [
    {"city": "New York", "country": "US", "lat": 40.71, "lon": -74.01},
    {"city": "Moscow", "country": "RU", "lat": 55.76, "lon": 37.62},
    {"city": "Tokyo", "country": "JP", "lat": 35.68, "lon": 139.69},
    {"city": "Sydney", "country": "AU", "lat": -33.87, "lon": 151.21},
    {"city": "London", "country": "GB", "lat": 51.51, "lon": -0.13},
    {"city": "São Paulo", "country": "BR", "lat": -23.55, "lon": -46.63},
]


def _entry(ts, ip, username, event, severity, source="simulation", geo_location=None):
    e = {
        "id": str(uuid.uuid4()),
        "timestamp": ts.isoformat(),
        "ip": ip,
        "username": username,
        "event": event,
        "severity": severity,
        "source": source,
    }
    if geo_location:
        e["geo_location"] = geo_location
    return e


def _benign_entry(rng, ts):
    ip = rng.choice(BENIGN_IPS)
    path = rng.choice(BENIGN_PATHS)
    return _entry(ts, ip, None, f"GET {path} -> 200", "low")


def generate_brute_force(count=100, seed=None):
    """Generate brute force attack logs: many failed logins from a few IPs."""
    rng = random.Random(seed)
    base = datetime.now(timezone.utc) - timedelta(minutes=count)
    attacker_ips = rng.sample(ATTACKER_IPS, min(3, len(ATTACKER_IPS)))
    target_user = rng.choice(["admin", "root", "jdoe"])
    entries = []

    for i in range(count):
        ts = base + timedelta(seconds=i * 2)
        if rng.random() < 0.6:
            ip = rng.choice(attacker_ips)
            entries.append(_entry(
                ts, ip, target_user,
                f"Failed password for {target_user} from {ip}",
                "medium", "simulation-ssh",
            ))
        else:
            entries.append(_benign_entry(rng, ts))

    return entries


def generate_sql_injection(count=100, seed=None):
    """Generate SQL injection attack logs: requests with SQL payloads."""
    rng = random.Random(seed)
    base = datetime.now(timezone.utc) - timedelta(minutes=count)
    attacker_ips = rng.sample(ATTACKER_IPS, min(2, len(ATTACKER_IPS)))
    entries = []

    for i in range(count):
        ts = base + timedelta(seconds=i * 2)
        if rng.random() < 0.5:
            ip = rng.choice(attacker_ips)
            payload = rng.choice(SQLI_PAYLOADS)
            entries.append(_entry(ts, ip, None, f"GET {payload} -> 200", "high"))
        else:
            entries.append(_benign_entry(rng, ts))

    return entries


def generate_xss(count=100, seed=None):
    """Generate XSS attack logs: requests with script injection payloads."""
    rng = random.Random(seed)
    base = datetime.now(timezone.utc) - timedelta(minutes=count)
    attacker_ips = rng.sample(ATTACKER_IPS, min(2, len(ATTACKER_IPS)))
    entries = []

    for i in range(count):
        ts = base + timedelta(seconds=i * 2)
        if rng.random() < 0.5:
            ip = rng.choice(attacker_ips)
            payload = rng.choice(XSS_PAYLOADS)
            entries.append(_entry(ts, ip, None, f"GET {payload} -> 200", "high"))
        else:
            entries.append(_benign_entry(rng, ts))

    return entries


def generate_port_scan(count=100, seed=None):
    """Generate port scan logs: one IP probing many endpoints."""
    rng = random.Random(seed)
    base = datetime.now(timezone.utc) - timedelta(minutes=count)
    scanner_ip = rng.choice(ATTACKER_IPS)
    entries = []

    for i in range(count):
        ts = base + timedelta(seconds=i)
        if rng.random() < 0.6:
            path = rng.choice(SCAN_PATHS)
            status = rng.choice([403, 404, 404, 404])
            entries.append(_entry(ts, scanner_ip, None, f"GET {path} -> {status}", "medium"))
        else:
            entries.append(_benign_entry(rng, ts))

    return entries


def generate_privilege_escalation(count=100, seed=None):
    """Generate privilege escalation logs: sudo/chmod/usermod commands."""
    rng = random.Random(seed)
    base = datetime.now(timezone.utc) - timedelta(minutes=count)
    attacker_ip = rng.choice(ATTACKER_IPS)
    entries = []

    for i in range(count):
        ts = base + timedelta(seconds=i * 3)
        if rng.random() < 0.45:
            cmd = rng.choice(PRIV_ESC_COMMANDS)
            entries.append(_entry(ts, attacker_ip, "root", cmd, "medium"))
        else:
            entries.append(_benign_entry(rng, ts))

    return entries


def generate_impossible_travel(count=100, seed=None):
    """Generate impossible travel logs: same user authenticates from distant cities within minutes."""
    rng = random.Random(seed)
    base = datetime.now(timezone.utc) - timedelta(minutes=count)
    target_user = "jdoe"
    # Pick two distant locations
    loc_a, loc_b = rng.sample(GEO_LOCATIONS, 2)
    ip_a = "203.0.113.10"
    ip_b = "203.0.113.50"
    entries = []

    # First: normal login from location A
    entries.append(_entry(
        base, ip_a, target_user,
        f"Accepted password for {target_user} from {ip_a}",
        "low", "simulation-ssh",
        geo_location=loc_a,
    ))

    # Generate some benign filler
    for i in range(1, count - 2):
        ts = base + timedelta(seconds=i * 2)
        if i == count // 2:
            # Midway: suspicious login from location B (only 2 min after login from A)
            login_ts = base + timedelta(minutes=2)
            entries.append(_entry(
                login_ts, ip_b, target_user,
                f"Accepted password for {target_user} from {ip_b}",
                "low", "simulation-ssh",
                geo_location=loc_b,
            ))
        else:
            entries.append(_benign_entry(rng, ts))

    # Add another login from B at the end to reinforce
    entries.append(_entry(
        base + timedelta(minutes=5), ip_b, target_user,
        f"Accepted password for {target_user} from {ip_b}",
        "low", "simulation-ssh",
        geo_location=loc_b,
    ))

    return entries


SCENARIOS = {
    "brute_force": generate_brute_force,
    "sql_injection": generate_sql_injection,
    "xss": generate_xss,
    "port_scan": generate_port_scan,
    "privilege_escalation": generate_privilege_escalation,
    "impossible_travel": generate_impossible_travel,
}


def generate_scenario(scenario: str, count: int = 100, seed: int | None = None) -> list[dict]:
    """Generate log entries for a named attack scenario."""
    generator = SCENARIOS.get(scenario)
    if generator is None:
        raise ValueError(f"Unknown scenario: {scenario!r}. Available: {list(SCENARIOS)}")
    return generator(count=count, seed=seed)
