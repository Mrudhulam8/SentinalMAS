import logging

from fastapi import APIRouter, HTTPException, UploadFile

from agents.log_parser import detect_and_parse
from backend.firebase_client import get_firestore

logger = logging.getLogger(__name__)
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

    stored = True
    try:
        db = get_firestore()
        batch = db.batch()
        collection = db.collection("logs")
        for entry in entries:
            batch.set(collection.document(entry["id"]), entry)
        batch.commit()
    except Exception:
        stored = False
        logger.warning("Firestore not configured; parsed logs were not persisted", exc_info=True)

    return {"filename": filename, "parsed_count": len(entries), "stored": stored, "entries": entries}


@router.get("")
def list_logs(limit: int = 100):
    try:
        db = get_firestore()
        docs = db.collection("logs").limit(limit).stream()
        return {"logs": [doc.to_dict() for doc in docs]}
    except Exception:
        logger.warning("Firestore not configured; returning empty log list", exc_info=True)
        return {"logs": []}
