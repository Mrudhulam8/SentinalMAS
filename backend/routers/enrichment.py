from fastapi import APIRouter
from pydantic import BaseModel

from agents.asset_context import enrich_findings as enrich_asset
from agents.threat_intel import enrich_findings as enrich_threat_intel

router = APIRouter(prefix="/api/enrichment", tags=["enrichment"])


class Finding(BaseModel):
    id: str
    attack_type: str
    entry_ids: list[str] = []
    ip: str | None = None
    username: str | None = None
    severity: str | None = None
    confidence: float | None = None
    evidence: str | None = None
    explanation: str | None = None


class EnrichRequest(BaseModel):
    findings: list[Finding]


@router.post("/run")
def run_enrichment(request: EnrichRequest):
    findings = [f.model_dump() for f in request.findings]
    findings = enrich_threat_intel(findings)
    findings = enrich_asset(findings)
    return {"findings": findings}
