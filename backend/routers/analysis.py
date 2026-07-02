import logging

from fastapi import APIRouter
from pydantic import BaseModel

from agents.log_analysis import analyze
from backend.firebase_client import get_firestore

logger = logging.getLogger(__name__)
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

    stored = True
    try:
        db = get_firestore()
        batch = db.batch()
        collection = db.collection("findings")
        for finding in findings:
            batch.set(collection.document(finding["id"]), finding)
        batch.commit()
    except Exception:
        stored = False
        logger.warning("Firestore not configured; findings were not persisted", exc_info=True)

    return {"finding_count": len(findings), "stored": stored, "findings": findings}
