import json
import logging

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from agents.orchestrator import run_pipeline, stream_pipeline
from backend.firebase_client import get_firestore

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/pipeline", tags=["pipeline"])


class LogEntry(BaseModel):
    id: str
    timestamp: str | None = None
    ip: str | None = None
    username: str | None = None
    event: str | None = None
    severity: str | None = None
    source: str | None = None


class PipelineRequest(BaseModel):
    entries: list[LogEntry]


@router.post("/run")
def run(request: PipelineRequest):
    entries = [e.model_dump() for e in request.entries]
    result = run_pipeline(entries)

    try:
        db = get_firestore()
        batch = db.batch()
        collection = db.collection("incidents")
        for incident in result["incidents"]:
            batch.set(collection.document(incident["incident_id"]), incident)
        batch.commit()
    except Exception:
        logger.warning("Firestore not configured; incidents were not persisted", exc_info=True)

    return result


@router.post("/stream")
def stream(request: PipelineRequest):
    entries = [e.model_dump() for e in request.entries]

    def event_source():
        final_incidents = []
        for event in stream_pipeline(entries):
            if event.get("node") == "done":
                final_incidents = event["result"]["incidents"]
            yield f"data: {json.dumps(event)}\n\n"

        try:
            db = get_firestore()
            batch = db.batch()
            collection = db.collection("incidents")
            for incident in final_incidents:
                batch.set(collection.document(incident["incident_id"]), incident)
            batch.commit()
        except Exception:
            logger.warning("Firestore not configured; incidents were not persisted", exc_info=True)

    return StreamingResponse(event_source(), media_type="text/event-stream")
