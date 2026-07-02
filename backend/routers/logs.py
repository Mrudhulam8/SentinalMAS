from fastapi import APIRouter, HTTPException, UploadFile

from agents.log_parser import detect_and_parse
from backend.db import list_logs as db_list_logs
from backend.db import save_logs

router = APIRouter(prefix="/api/logs", tags=["logs"])

ALLOWED_EXTENSIONS = {".csv", ".json", ".txt", ".log"}


@router.post("/upload")
async def upload_logs(file: UploadFile):
    filename = file.filename or "upload.txt"
    if not any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise HTTPException(400, f"Unsupported file type. Allowed: {sorted(ALLOWED_EXTENSIONS)}")

    content_bytes = await file.read()
    if not content_bytes:
        raise HTTPException(400, "Uploaded file is empty")

    entries = detect_and_parse(filename, content_bytes)
    if not entries:
        raise HTTPException(422, "No log entries could be parsed from this file")

    stored = save_logs(entries)
    return {"filename": filename, "parsed_count": len(entries), "stored": stored, "entries": entries}


@router.get("")
def list_logs(limit: int = 100):
    return {"logs": db_list_logs(limit)}
