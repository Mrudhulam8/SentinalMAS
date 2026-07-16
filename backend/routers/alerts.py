"""Alerts router: view and manage security alerts."""
from fastapi import APIRouter
from pydantic import BaseModel

from backend.alerting import alert_manager

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
def list_alerts():
    return {
        "alerts": alert_manager.list_all(),
        "unread_count": alert_manager.unread_count(),
    }


@router.post("/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    success = alert_manager.acknowledge(alert_id)
    return {"status": "acknowledged" if success else "not_found"}


@router.post("/acknowledge-all")
def acknowledge_all():
    count = alert_manager.acknowledge_all()
    return {"status": "acknowledged", "count": count}
