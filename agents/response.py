"""Response Recommendation Agent: suggests mitigation actions for an incident."""

ATTACK_ACTIONS = {
    "brute_force": ["Block IP", "Enable MFA", "Notify administrator"],
    "failed_login": ["Monitor account", "Enable MFA"],
    "sql_injection": ["Patch vulnerable systems", "Block IP", "Notify administrator"],
    "xss": ["Patch vulnerable systems", "Notify administrator"],
    "port_scan": ["Block IP", "Notify administrator"],
    "suspicious_traffic": ["Block IP", "Notify administrator"],
    "privilege_escalation": ["Disable account", "Notify administrator", "Patch vulnerable systems"],
    "impossible_travel": ["Disable account", "Enable MFA", "Notify administrator"],
}

THREAT_LEVEL_EXTRA_ACTIONS = {
    "Critical": ["Notify administrator", "Isolate affected asset"],
    "High": ["Notify administrator"],
}


def recommend(incident: dict) -> dict:
    actions: set[str] = set()
    for attack_type in incident.get("attack_types", []):
        actions.update(ATTACK_ACTIONS.get(attack_type, []))

    actions.update(THREAT_LEVEL_EXTRA_ACTIONS.get(incident.get("threat_level"), []))

    # Preserve a stable, sensible ordering
    ordering = [
        "Isolate affected asset", "Block IP", "Disable account", "Enable MFA",
        "Patch vulnerable systems", "Monitor account", "Notify administrator",
    ]
    ordered_actions = [a for a in ordering if a in actions]

    return {**incident, "recommended_actions": ordered_actions}


def recommend_responses(incidents: list[dict]) -> list[dict]:
    return [recommend(i) for i in incidents]
