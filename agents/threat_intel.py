"""Threat Intelligence Agent: IP/domain reputation + MITRE ATT&CK mapping."""
import logging

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


def _reputation(ip: str) -> dict:
    if ip not in _reputation_cache:
        _reputation_cache[ip] = {
            "abuseipdb": check_ip_abuseipdb(ip),
            "virustotal": check_ip_virustotal(ip),
        }
    return _reputation_cache[ip]


def enrich_finding(finding: dict) -> dict:
    """Attach IP reputation + MITRE mapping to a single Log Analysis finding."""
    ip = finding.get("ip")
    reputation = _reputation(ip) if ip else {"abuseipdb": None, "virustotal": None}
    enrichment = {
        "mitre": map_to_mitre(finding.get("attack_type")),
        "abuseipdb": reputation["abuseipdb"],
        "virustotal": reputation["virustotal"],
    }
    return {**finding, "threat_intel": enrichment}


def enrich_findings(findings: list[dict]) -> list[dict]:
    return [enrich_finding(f) for f in findings]
