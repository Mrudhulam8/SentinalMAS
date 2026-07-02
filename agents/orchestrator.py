"""Orchestrator Agent: LangGraph pipeline wiring all SecureOrch agents together.

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


def build_graph():
    graph = StateGraph(PipelineState)
    graph.add_node("log_analysis", log_analysis_node)
    graph.add_node("threat_intel", threat_intel_node)
    graph.add_node("asset_context", asset_context_node)
    graph.add_node("correlation", correlation_node)
    graph.add_node("risk_assessment", risk_assessment_node)
    graph.add_node("response", response_node)

    graph.add_edge(START, "log_analysis")
    graph.add_edge("log_analysis", "threat_intel")
    graph.add_edge("threat_intel", "asset_context")
    graph.add_edge("asset_context", "correlation")
    graph.add_edge("correlation", "risk_assessment")
    graph.add_edge("risk_assessment", "response")
    graph.add_edge("response", END)

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
