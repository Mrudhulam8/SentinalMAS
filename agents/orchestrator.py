"""Orchestrator Agent: LangGraph pipeline wiring all SentinelMAS agents together.

Flow:
  entries -> Log Analysis -> Threat Intelligence -> Asset Context
          -> Correlation -> Risk Assessment -> Response Recommendation
"""
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from agents.asset_context import enrich_findings as asset_enrich
from agents.correlation import correlate
from agents.log_analysis import analyze
from agents.response import recommend_responses
from agents.risk_assessment import assess_risks
from agents.threat_intel import enrich_findings as threat_intel_enrich
from backend.blocklist import blocklist_manager
from backend.alerting import alert_manager


class PipelineState(TypedDict, total=False):
    entries: list[dict]
    findings: list[dict]
    incidents: list[dict]


def log_analysis_node(state: PipelineState) -> PipelineState:
    return {"findings": analyze(state["entries"])}


def threat_intel_node(state: PipelineState) -> PipelineState:
    return {"findings": threat_intel_enrich(state["findings"])}


def asset_context_node(state: PipelineState) -> PipelineState:
    return {"findings": asset_enrich(state["findings"])}


def correlation_node(state: PipelineState) -> PipelineState:
    return {"incidents": correlate(state["findings"])}


def risk_assessment_node(state: PipelineState) -> PipelineState:
    return {"incidents": assess_risks(state["incidents"])}


def response_node(state: PipelineState) -> PipelineState:
    return {"incidents": recommend_responses(state["incidents"])}


def auto_block_alert_node(state: PipelineState) -> PipelineState:
    """Auto-block attacker IPs and create alerts for High/Critical incidents."""
    incidents = state["incidents"]
    updated = []
    for incident in incidents:
        threat_level = incident.get("threat_level", "")
        ip = incident.get("ip")
        blocked = False
        if ip and threat_level in ("High", "Critical"):
            attack_str = ", ".join(incident.get("attack_types", []))
            blocklist_manager.block(
                ip=ip,
                reason=attack_str,
                threat_level=threat_level,
                incident_id=incident.get("incident_id", ""),
            )
            blocked = True
        alert_manager.create_alert(incident, blocked=blocked)
        updated.append({**incident, "blocked": blocked})
    return {"incidents": updated}


def build_graph():
    graph = StateGraph(PipelineState)
    graph.add_node("log_analysis", log_analysis_node)
    graph.add_node("threat_intel", threat_intel_node)
    graph.add_node("asset_context", asset_context_node)
    graph.add_node("correlation", correlation_node)
    graph.add_node("risk_assessment", risk_assessment_node)
    graph.add_node("response", response_node)
    graph.add_node("auto_block_alert", auto_block_alert_node)

    graph.add_edge(START, "log_analysis")
    graph.add_edge("log_analysis", "threat_intel")
    graph.add_edge("threat_intel", "asset_context")
    graph.add_edge("asset_context", "correlation")
    graph.add_edge("correlation", "risk_assessment")
    graph.add_edge("risk_assessment", "response")
    graph.add_edge("response", "auto_block_alert")
    graph.add_edge("auto_block_alert", END)

    return graph.compile()


_compiled_graph = None


def get_graph():
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph()
    return _compiled_graph


def run_pipeline(entries: list[dict]) -> dict:
    graph = get_graph()
    result = graph.invoke({"entries": entries})
    return {
        "findings": result.get("findings", []),
        "incidents": result.get("incidents", []),
    }


NODE_ORDER = [
    "log_analysis", "threat_intel", "asset_context",
    "correlation", "risk_assessment", "response", "auto_block_alert",
]


def stream_pipeline(entries: list[dict]):
    """Yields one progress event per completed agent node, then a final 'done' event."""
    graph = get_graph()
    accumulated_state = {"entries": entries}

    for update in graph.stream({"entries": entries}, stream_mode="updates"):
        for node_name, partial in update.items():
            accumulated_state.update(partial)
            yield {
                "node": node_name,
                "status": "completed",
                "findings_count": len(accumulated_state.get("findings", [])),
                "incidents_count": len(accumulated_state.get("incidents", [])),
            }

    yield {
        "node": "done",
        "status": "completed",
        "result": {
            "findings": accumulated_state.get("findings", []),
            "incidents": accumulated_state.get("incidents", []),
        },
    }
