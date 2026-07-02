"""Asset Context Agent: maintains asset registry (owner, department, criticality, sensitivity).

Reads from Firestore `assets` collection when available. Falls back to a small
local seed registry so the pipeline is demoable offline / before Firebase is wired up.
"""
import logging

logger = logging.getLogger(__name__)

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


def _lookup_asset(ip: str) -> dict | None:
    try:
        from backend.firebase_client import get_firestore
        db = get_firestore()
        query = db.collection("assets").where("ip", "==", ip).limit(1).stream()
        for doc in query:
            return doc.to_dict()
    except Exception:
        logger.debug("Firestore unavailable; using local asset seed for %s", ip)

    return _LOCAL_SEED_ASSETS.get(ip)


def get_asset_by_ip(ip: str) -> dict | None:
    if ip not in _asset_cache:
        _asset_cache[ip] = _lookup_asset(ip)
    return _asset_cache[ip]


def enrich_finding(finding: dict) -> dict:
    ip = finding.get("ip")
    asset = get_asset_by_ip(ip) if ip else None
    return {**finding, "asset_context": asset}


def enrich_findings(findings: list[dict]) -> list[dict]:
    return [enrich_finding(f) for f in findings]
