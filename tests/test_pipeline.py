"""Integration: full orchestrator pipeline end-to-end (offline / no credentials)."""
from agents.orchestrator import run_pipeline, stream_pipeline
from tests.synthetic import generate_entries

INCIDENT_KEYS = {
    "incident_id", "attack_types", "mitre_techniques", "risk_score",
    "threat_level", "priority", "recommended_actions",
}


def test_pipeline_produces_scored_incidents():
    result = run_pipeline(generate_entries(500))
    assert result["findings"], "expected findings from attack-rich sample"
    assert result["incidents"], "expected correlated incidents"

    for incident in result["incidents"]:
        assert INCIDENT_KEYS <= set(incident)
        assert 0 <= incident["risk_score"] <= 10
        assert incident["threat_level"] in {"Critical", "High", "Medium", "Low"}
        assert incident["priority"] in {"P1", "P2", "P3", "P4"}


def test_threat_level_matches_risk_score_bands():
    for incident in run_pipeline(generate_entries(500))["incidents"]:
        score, level = incident["risk_score"], incident["threat_level"]
        if score >= 8:
            assert level == "Critical"
        elif score >= 6:
            assert level == "High"
        elif score >= 3.5:
            assert level == "Medium"
        else:
            assert level == "Low"


def test_incidents_have_recommended_actions():
    for incident in run_pipeline(generate_entries(500))["incidents"]:
        if incident["attack_types"]:
            assert incident["recommended_actions"], incident["attack_types"]


def test_stream_pipeline_emits_all_nodes_then_done():
    events = list(stream_pipeline(generate_entries(200)))
    nodes = [e["node"] for e in events]
    assert nodes[-1] == "done"
    for expected in ("log_analysis", "threat_intel", "asset_context",
                     "correlation", "risk_assessment", "response"):
        assert expected in nodes
    assert events[-1]["result"]["incidents"], "done event should carry final incidents"


def test_empty_input_yields_no_incidents():
    result = run_pipeline([])
    assert result["findings"] == []
    assert result["incidents"] == []
