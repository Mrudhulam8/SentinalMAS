"""Simulation router: generates attack scenario logs and streams them through the pipeline."""
import json

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from agents.orchestrator import stream_pipeline
from agents.scenario_generator import generate_scenario
from backend.db import save_incidents

router = APIRouter(prefix="/api/simulate", tags=["simulate"])


class SimulateRequest(BaseModel):
    scenario: str
    count: int = 100


@router.post("/stream")
def simulate_stream(request: SimulateRequest):
    count = max(20, min(request.count, 500))
    entries = generate_scenario(request.scenario, count=count)

    def event_source():
        final_incidents = []
        for event in stream_pipeline(entries):
            if event.get("node") == "done":
                final_incidents = event["result"]["incidents"]
            yield f"data: {json.dumps(event)}\n\n"

        save_incidents(final_incidents)

    return StreamingResponse(event_source(), media_type="text/event-stream")
