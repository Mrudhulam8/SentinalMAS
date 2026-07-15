from fastapi import APIRouter
from pydantic import BaseModel

from agents.log_analysis import analyze
from backend.db import save_findings

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


class LogEntry(BaseModel):
    id: str
    timestamp: str | None = None
    ip: str | None = None
    username: str | None = None
    event: str | None = None
    severity: str | None = None
    source: str | None = None


class AnalyzeRequest(BaseModel):
    entries: list[LogEntry]


@router.post("/run")
def run_analysis(request: AnalyzeRequest):
    entries = [e.model_dump() for e in request.entries]
    findings = analyze(entries)
    stored = save_findings(findings)
    return {"finding_count": len(findings), "stored": stored, "findings": findings}
