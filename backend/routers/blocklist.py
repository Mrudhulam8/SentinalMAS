"""Blocklist router: view, block, and unblock IPs."""
from fastapi import APIRouter
from pydantic import BaseModel

from backend.blocklist import blocklist_manager

router = APIRouter(prefix="/api/blocklist", tags=["blocklist"])


class BlockRequest(BaseModel):
    ip: str
    reason: str = "Manual block"
    threat_level: str = "High"
    incident_id: str = ""


@router.get("")
def list_blocked():
    return {"blocked": blocklist_manager.list_all(), "count": len(blocklist_manager.list_all())}


@router.post("/block")
def block_ip(request: BlockRequest):
    entry = blocklist_manager.block(
        ip=request.ip,
        reason=request.reason,
        threat_level=request.threat_level,
        incident_id=request.incident_id,
    )
    return {"status": "blocked", "entry": entry.to_dict()}


@router.delete("/{ip}")
def unblock_ip(ip: str):
    success = blocklist_manager.unblock(ip)
    if success:
        return {"status": "unblocked", "ip": ip}
    return {"status": "not_found", "ip": ip}
