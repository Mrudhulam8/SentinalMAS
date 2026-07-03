"""Threat Intelligence Agent: IP/domain reputation + MITRE ATT&CK mapping."""
import logging
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# Static local mapping: attack_type (from Log Analysis Agent) -> MITRE ATT&CK technique
MITRE_MAPPING = {
    "brute_force": {"technique_id": "T1110", "technique": "Brute Force"},
    "failed_login": {"technique_id": "T1110", "technique": "Brute Force"},
    "sql_injection": {"technique_id": "T1190", "technique": "Exploit Public-Facing Application"},
    "xss": {"technique_id": "T1190", "technique": "Exploit Public-Facing Application"},
    "port_scan": {"technique_id": "T1046", "technique": "Network Service Discovery"},
    "suspicious_traffic": {"technique_id": "T1071", "technique": "Application Layer Protocol"},
    "privilege_escalation": {"technique_id": "T1068", "technique": "Exploitation for Privilege Escalation"},
}


def map_to_mitre(attack_type: str) -> dict | None:
    return MITRE_MAPPING.get(attack_type)


def check_ip_abuseipdb(ip: str) -> dict | None:
    if not settings.abuseipdb_api_key:
        return None
    try:
        resp = httpx.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "is_tor": data.get("isTor"),
            "isp": data.get("isp"),
        }
    except Exception:
        logger.warning("AbuseIPDB lookup failed for %s", ip, exc_info=True)
        return None


def check_ip_virustotal(ip: str) -> dict | None:
    if not settings.virustotal_api_key:
        return None
    try:
        resp = httpx.get(
            VIRUSTOTAL_IP_URL.format(ip=ip),
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=10,
        )
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception:
        logger.warning("VirusTotal lookup failed for %s", ip, exc_info=True)
        return None


# Per-IP reputation cache. Many findings share an IP, and the reputation APIs
# have tight free-tier rate limits (VirusTotal: 4 req/min), so each IP is looked
# up at most once per process.
_reputation_cache: dict[str, dict] = {}
_NO_REPUTATION = {"abuseipdb": None, "virustotal": None}

# A large upload can contain far more unique attacker IPs than the free-tier
# reputation APIs can service on demand. Bound each pipeline run to a fixed
# number of *new* lookups and a wall-clock budget, so enrichment can never
# stall the request for minutes — IPs beyond the budget simply go without
# live reputation data (mitre mapping still applies) rather than blocking.
MAX_NEW_LOOKUPS_PER_RUN = 25
TIME_BUDGET_SECONDS = 8.0

# Shared, reused across lookups — creating/tearing down an executor per IP has
# real OS thread-lifecycle overhead (noticeably so on Windows).
_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="threat-intel")


def _fetch_reputation(ip: str) -> dict:
    """Look up AbuseIPDB + VirusTotal for one IP concurrently (not sequentially)."""
    abuse_future = _executor.submit(check_ip_abuseipdb, ip)
    vt_future = _executor.submit(check_ip_virustotal, ip)
    return {"abuseipdb": abuse_future.result(), "virustotal": vt_future.result()}


def _populate_cache(ips: list[str]) -> None:
    start = time.monotonic()
    lookups = 0
    for ip in ips:
        if ip in _reputation_cache:
            continue
        if lookups >= MAX_NEW_LOOKUPS_PER_RUN or (time.monotonic() - start) > TIME_BUDGET_SECONDS:
            logger.info(
                "Threat intel budget reached after %d new lookup(s); remaining "
                "findings proceed without live reputation data", lookups,
            )
            break
        _reputation_cache[ip] = _fetch_reputation(ip)
        lookups += 1


def enrich_finding(finding: dict) -> dict:
    """Attach IP reputation + MITRE mapping to a single Log Analysis finding."""
    ip = finding.get("ip")
    reputation = _reputation_cache.get(ip, _NO_REPUTATION) if ip else _NO_REPUTATION
    enrichment = {
        "mitre": map_to_mitre(finding.get("attack_type")),
        "abuseipdb": reputation["abuseipdb"],
        "virustotal": reputation["virustotal"],
    }
    return {**finding, "threat_intel": enrichment}


def enrich_findings(findings: list[dict]) -> list[dict]:
    unique_ips = list(dict.fromkeys(f["ip"] for f in findings if f.get("ip")))
    _populate_cache(unique_ips)
    return [enrich_finding(f) for f in findings]
