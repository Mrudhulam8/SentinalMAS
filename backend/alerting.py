"""Alert manager: generates in-app alerts and optional email notifications.

Creates alert records when High/Critical incidents are detected, and optionally
sends email for Critical incidents when SMTP is configured.
"""
import logging
import smtplib
import uuid
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger(__name__)


class Alert:
    __slots__ = ("id", "timestamp", "severity", "message", "incident_id",
                 "ip", "attack_types", "acknowledged")

    def __init__(self, severity: str, message: str, incident_id: str,
                 ip: str | None, attack_types: list[str]):
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc)
        self.severity = severity
        self.message = message
        self.incident_id = incident_id
        self.ip = ip
        self.attack_types = attack_types
        self.acknowledged = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "message": self.message,
            "incident_id": self.incident_id,
            "ip": self.ip,
            "attack_types": self.attack_types,
            "acknowledged": self.acknowledged,
        }


class AlertManager:
    def __init__(self):
        self._alerts: list[Alert] = []

    def create_alert(self, incident: dict, blocked: bool = False) -> Alert | None:
        """Create an alert for a High/Critical incident. Returns None if below threshold."""
        threat_level = incident.get("threat_level", "")
        if threat_level not in ("High", "Critical"):
            return None

        ip = incident.get("ip") or "unknown"
        attack_types = incident.get("attack_types", [])
        attack_str = ", ".join(attack_types) if attack_types else "unknown attack"
        blocked_str = " — IP blocked" if blocked else ""

        message = f"{threat_level.upper()}: {attack_str} from {ip}{blocked_str}"

        alert = Alert(
            severity=threat_level,
            message=message,
            incident_id=incident.get("incident_id", ""),
            ip=ip,
            attack_types=attack_types,
        )
        self._alerts.append(alert)
        logger.info("Alert created: %s", message)

        # Send email for Critical incidents
        if threat_level == "Critical":
            self._send_email(alert, incident)

        return alert

    def acknowledge(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged."""
        for alert in self._alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                return True
        return False

    def acknowledge_all(self) -> int:
        """Mark all alerts as acknowledged. Returns count."""
        count = 0
        for alert in self._alerts:
            if not alert.acknowledged:
                alert.acknowledged = True
                count += 1
        return count

    def list_all(self) -> list[dict]:
        return [a.to_dict() for a in reversed(self._alerts)]

    def unread_count(self) -> int:
        return sum(1 for a in self._alerts if not a.acknowledged)

    def _send_email(self, alert: Alert, incident: dict) -> None:
        """Send email notification for a Critical alert — best-effort, never blocks."""
        try:
            from backend.config import settings
            if not settings.smtp_host or not settings.alert_email:
                return

            risk_score = incident.get("risk_score", "N/A")
            actions = ", ".join(incident.get("recommended_actions", []))
            body = (
                f"SentinelMAS has detected a CRITICAL security incident.\n\n"
                f"Alert: {alert.message}\n"
                f"Risk Score: {risk_score}\n"
                f"Attack Types: {', '.join(alert.attack_types)}\n"
                f"Attacker IP: {alert.ip}\n"
                f"Recommended Actions: {actions}\n"
                f"Timestamp: {alert.timestamp.isoformat()}\n"
                f"Incident ID: {alert.incident_id}\n"
            )

            msg = MIMEText(body)
            msg["Subject"] = f"[SentinelMAS] CRITICAL: {', '.join(alert.attack_types)} from {alert.ip}"
            msg["From"] = settings.smtp_user or "sentinelmas@noreply.local"
            msg["To"] = settings.alert_email

            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
                if settings.smtp_user and settings.smtp_password:
                    server.starttls()
                    server.login(settings.smtp_user, settings.smtp_password)
                server.send_message(msg)
            logger.info("Email alert sent to %s for incident %s", settings.alert_email, alert.incident_id)
        except Exception:
            logger.warning("Email alert failed (SMTP not configured or unreachable)", exc_info=True)


# Singleton instance
alert_manager = AlertManager()
