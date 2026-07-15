"""Correlation Agent: merges log/threat-intel/vuln/asset evidence into incidents."""
import uuid
from collections import defaultdict


def _group_key(finding: dict) -> str:
    return finding.get("ip") or finding.get("username") or f"unknown-{finding['id']}"


def correlate(findings: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for finding in findings:
        groups[_group_key(finding)].append(finding)

    incidents = []
    for key, group in groups.items():
        attack_types = sorted({f["attack_type"] for f in group})
        entry_ids = sorted({eid for f in group for eid in f.get("entry_ids", [])})
        mitre_techniques = [
            f["threat_intel"]["mitre"] for f in group
            if f.get("threat_intel", {}).get("mitre")
        ]
        asset = next((f.get("asset_context") for f in group if f.get("asset_context")), None)
        severities = [f.get("severity") for f in group]
        max_severity = max(severities, key=lambda s: {"low": 1, "medium": 2, "high": 3}.get(s, 0), default="low")

        incidents.append({
            "incident_id": str(uuid.uuid4()),
            "ip": group[0].get("ip"),
            "username": group[0].get("username"),
            "attack_types": attack_types,
            "finding_ids": [f["id"] for f in group],
            "entry_ids": entry_ids,
            "mitre_techniques": mitre_techniques,
            "asset_context": asset,
            "max_severity": max_severity,
            "finding_count": len(group),
            "findings": group,
            "status": "open",
        })

    return incidents
