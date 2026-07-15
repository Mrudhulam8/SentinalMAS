"""Blocklist manager: tracks IPs blocked by the auto-response system.

Maintains an in-memory blocklist that can optionally be persisted to the
database when DATABASE_URL is configured. The blocklist is intended for
consumption by external infrastructure tools (WAF, iptables, cloud security
groups) via the REST API — SentinelMAS itself does not modify network rules.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class BlockEntry:
    __slots__ = ("ip", "reason", "threat_level", "incident_id", "blocked_at")

    def __init__(self, ip: str, reason: str, threat_level: str,
                 incident_id: str, blocked_at: datetime | None = None):
        self.ip = ip
        self.reason = reason
        self.threat_level = threat_level
        self.incident_id = incident_id
        self.blocked_at = blocked_at or datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "threat_level": self.threat_level,
            "incident_id": self.incident_id,
            "blocked_at": self.blocked_at.isoformat(),
        }


class BlocklistManager:
    def __init__(self):
        self._blocked: dict[str, BlockEntry] = {}

    def block(self, ip: str, reason: str, threat_level: str,
              incident_id: str) -> BlockEntry:
        """Add an IP to the blocklist. No-op if already blocked."""
        if ip in self._blocked:
            return self._blocked[ip]
        entry = BlockEntry(ip, reason, threat_level, incident_id)
        self._blocked[ip] = entry
        logger.info("Blocked IP %s — reason: %s (incident %s)", ip, reason, incident_id)
        self._persist(entry)
        return entry

    def unblock(self, ip: str) -> bool:
        """Remove an IP from the blocklist. Returns True if it was blocked."""
        if ip in self._blocked:
            del self._blocked[ip]
            logger.info("Unblocked IP %s", ip)
            self._unpersist(ip)
            return True
        return False

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def list_all(self) -> list[dict]:
        return [entry.to_dict() for entry in self._blocked.values()]

    def get_blocked_ips(self) -> set[str]:
        """Return the set of currently blocked IP addresses."""
        return set(self._blocked.keys())

    def _persist(self, entry: BlockEntry) -> None:
        """Persist to DB if available — best-effort, never blocks."""
        try:
            from backend.db import get_engine
            engine = get_engine()
            if engine is None:
                return
            from sqlalchemy import text
            with engine.begin() as conn:
                conn.execute(text(
                    "INSERT INTO blocklist (ip, reason, threat_level, incident_id, blocked_at) "
                    "VALUES (:ip, :reason, :tl, :iid, :ba) "
                    "ON CONFLICT (ip) DO NOTHING"
                ), {"ip": entry.ip, "reason": entry.reason, "tl": entry.threat_level,
                    "iid": entry.incident_id, "ba": entry.blocked_at})
        except Exception:
            logger.debug("Blocklist DB persist skipped", exc_info=True)

    def _unpersist(self, ip: str) -> None:
        """Remove from DB if available — best-effort."""
        try:
            from backend.db import get_engine
            engine = get_engine()
            if engine is None:
                return
            from sqlalchemy import text
            with engine.begin() as conn:
                conn.execute(text("DELETE FROM blocklist WHERE ip = :ip"), {"ip": ip})
        except Exception:
            logger.debug("Blocklist DB unpersist skipped", exc_info=True)

    def load_from_db(self) -> None:
        """Load persisted blocklist on startup — best-effort."""
        try:
            from backend.db import get_engine
            engine = get_engine()
            if engine is None:
                return
            from sqlalchemy import text
            with engine.connect() as conn:
                rows = conn.execute(text(
                    "SELECT ip, reason, threat_level, incident_id, blocked_at FROM blocklist"
                )).fetchall()
                for row in rows:
                    self._blocked[row[0]] = BlockEntry(
                        ip=row[0], reason=row[1], threat_level=row[2],
                        incident_id=row[3], blocked_at=row[4],
                    )
            if self._blocked:
                logger.info("Loaded %d blocked IP(s) from database", len(self._blocked))
        except Exception:
            logger.debug("Blocklist DB load skipped", exc_info=True)


# Singleton instance
blocklist_manager = BlocklistManager()
