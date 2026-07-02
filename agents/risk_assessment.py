"""Risk Assessment Agent: computes risk score, threat level, and priority for incidents."""

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}


def _reputation_score(incident: dict) -> float:
    best = 0.0
    for finding in incident.get("findings", []):
        ti = finding.get("threat_intel") or {}
        abuse = ti.get("abuseipdb") or {}
        vt = ti.get("virustotal") or {}
        if abuse.get("abuse_confidence_score") is not None:
            best = max(best, abuse["abuse_confidence_score"] / 100 * 3)
        if vt.get("malicious") is not None:
            best = max(best, min(vt["malicious"], 10) / 10 * 3)
    return best


def compute_risk(incident: dict) -> dict:
    severity_component = SEVERITY_WEIGHT.get(incident.get("max_severity"), 1) * 2.0
    diversity_component = min(len(incident.get("attack_types", [])), 4) * 1.0
    asset = incident.get("asset_context") or {}
    criticality_component = (asset.get("criticality", 1) or 1) * 0.6
    reputation_component = _reputation_score(incident)

    raw_score = severity_component + diversity_component + criticality_component + reputation_component
    risk_score = round(min(raw_score, 10.0), 2)

    if risk_score >= 8:
        threat_level, priority = "Critical", "P1"
    elif risk_score >= 6:
        threat_level, priority = "High", "P2"
    elif risk_score >= 3.5:
        threat_level, priority = "Medium", "P3"
    else:
        threat_level, priority = "Low", "P4"

    return {
        **incident,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "priority": priority,
    }


def assess_risks(incidents: list[dict]) -> list[dict]:
    return [compute_risk(i) for i in incidents]
