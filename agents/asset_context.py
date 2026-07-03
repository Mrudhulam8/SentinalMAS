"""Asset Context Agent: maintains asset registry (owner, department, criticality, sensitivity).

Reads from the `assets` table when a database is configured. Falls back to a
small local seed registry so the pipeline is demoable offline / before a
database is wired up.
"""

# criticality: 1 (low) - 5 (critical)
_LOCAL_SEED_ASSETS = {
    "192.168.1.10": {
        "asset_id": "web-01", "hostname": "web-01.internal", "owner": "platform-team",
        "department": "Engineering", "criticality": 4, "data_sensitivity": "internal",
    },
    "198.51.100.23": {
        "asset_id": "admin-portal", "hostname": "admin.internal", "owner": "security-team",
        "department": "IT", "criticality": 5, "data_sensitivity": "confidential",
    },
    "10.0.0.5": {
        "asset_id": "orders-svc", "hostname": "orders-svc.internal", "owner": "payments-team",
        "department": "Engineering", "criticality": 5, "data_sensitivity": "restricted",
    },
}


# Per-IP lookup cache: many findings share the same IP, so resolve each once.
_asset_cache: dict[str, dict | None] = {}


def get_asset_by_ip(ip: str) -> dict | None:
    """Single-IP lookup (used outside the batch pipeline path, e.g. ad-hoc queries)."""
    if ip not in _asset_cache:
        from backend.db import get_asset_by_ip as db_get_asset
        _asset_cache[ip] = db_get_asset(ip) or _LOCAL_SEED_ASSETS.get(ip)
    return _asset_cache[ip]


def _populate_cache(ips: list[str]) -> None:
    new_ips = [ip for ip in ips if ip not in _asset_cache]
    if not new_ips:
        return

    from backend.db import get_assets_by_ips
    found = get_assets_by_ips(new_ips)  # one round trip for every uncached IP
    for ip in new_ips:
        _asset_cache[ip] = found.get(ip) or _LOCAL_SEED_ASSETS.get(ip)


def enrich_finding(finding: dict) -> dict:
    ip = finding.get("ip")
    asset = _asset_cache.get(ip) if ip else None
    return {**finding, "asset_context": asset}


def enrich_findings(findings: list[dict]) -> list[dict]:
    unique_ips = list(dict.fromkeys(f["ip"] for f in findings if f.get("ip")))
    _populate_cache(unique_ips)
    return [enrich_finding(f) for f in findings]
