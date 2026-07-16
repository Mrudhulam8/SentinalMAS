"""Persistence layer backed by Postgres (Supabase, or any Postgres).

Persistence is optional. When ``DATABASE_URL`` is not configured, every write is
a no-op and reads return empty, so the pipeline runs fully stateless — the same
graceful-degradation contract the rest of the system follows.

Documents are stored in ``jsonb`` columns keyed by their natural id, so the flat
log entries and the nested incident objects both round-trip without a rigid
schema. Tables are created lazily on first successful connection.
"""
import logging

import psycopg
from psycopg.types.json import Jsonb

from backend.config import settings

logger = logging.getLogger(__name__)

_initialized = False
_unavailable = False

_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS assets (
    ip TEXT PRIMARY KEY,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


class PersistenceUnavailable(RuntimeError):
    """Raised when no database is configured or a connection cannot be made."""


def _connect():
    """Open a connection, creating the schema once. Caches the unavailable state
    so a missing/unreachable database never re-runs a slow connect per call."""
    global _initialized, _unavailable

    if _unavailable:
        raise PersistenceUnavailable("Database unavailable (cached)")
    if not settings.database_url:
        _unavailable = True
        raise PersistenceUnavailable("DATABASE_URL not configured")

    try:
        conn = psycopg.connect(settings.database_url, connect_timeout=10)
    except Exception as exc:
        _unavailable = True
        raise PersistenceUnavailable(str(exc)) from exc

    if not _initialized:
        with conn.cursor() as cur:
            cur.execute(_SCHEMA)
        conn.commit()
        _initialized = True
    return conn


def _copy_insert(conn, table: str, key_column: str, rows: list[tuple[str, dict]]) -> None:
    """Bulk-load via the COPY protocol: one streamed transfer instead of one
    round trip per row (or even one per pipelined batch). This is the fast
    path — thousands of rows in roughly the time of a single query."""
    with conn.cursor() as cur, cur.copy(f"COPY {table} ({key_column}, data) FROM STDIN") as copy:
        for key, data in rows:
            copy.write_row((key, Jsonb(data)))


def _upsert_rows(conn, table: str, key_column: str, rows: list[tuple[str, dict]]) -> None:
    """Slower row-by-row upsert. Used only as a fallback (see _upsert)."""
    sql = (
        f"INSERT INTO {table} ({key_column}, data) VALUES (%s, %s) "
        f"ON CONFLICT ({key_column}) DO UPDATE SET data = EXCLUDED.data"
    )
    with conn.pipeline(), conn.cursor() as cur:
        cur.executemany(sql, [(key, Jsonb(data)) for key, data in rows])


def _upsert(table: str, key_column: str, rows: list[tuple[str, dict]]) -> bool:
    if not rows:
        return False
    try:
        with _connect() as conn:
            try:
                _copy_insert(conn, table, key_column, rows)
            except Exception:
                # COPY has no ON CONFLICT, so it fails outright on a key
                # collision. Every id here is a freshly generated UUID, so
                # that should never happen in practice — but if it (or
                # anything else about the fast path) ever does fail, fall
                # back to the slower upsert rather than losing the write.
                conn.rollback()
                _upsert_rows(conn, table, key_column, rows)
        return True
    except Exception:
        logger.warning("Persistence unavailable; %s not saved", table, exc_info=True)
        return False


def save_logs(entries: list[dict]) -> bool:
    return _upsert("logs", "id", [(e["id"], e) for e in entries])


def save_findings(findings: list[dict]) -> bool:
    return _upsert("findings", "id", [(f["id"], f) for f in findings])


def save_incidents(incidents: list[dict]) -> bool:
    return _upsert("incidents", "incident_id", [(i["incident_id"], i) for i in incidents])


def list_logs(limit: int = 100) -> list[dict]:
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT data FROM logs ORDER BY created_at DESC LIMIT %s", (limit,))
            return [row[0] for row in cur.fetchall()]
    except Exception:
        logger.warning("Persistence unavailable; returning empty log list", exc_info=True)
        return []


def get_asset_by_ip(ip: str) -> dict | None:
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT data FROM assets WHERE ip = %s LIMIT 1", (ip,))
            row = cur.fetchone()
            return row[0] if row else None
    except Exception:
        logger.debug("Persistence unavailable; asset lookup fell back to seed for %s", ip)
        return None


def get_assets_by_ips(ips: list[str]) -> dict[str, dict]:
    """Batch asset lookup — one round trip for many IPs, not one connection per IP.

    A pipeline run can involve dozens of unique attacker IPs; connect() opens a
    fresh connection each call (no pooling), so looking those up one at a time
    means one TCP+TLS+auth handshake per IP — against a remote pooler that's
    ~1-1.5s each, easily tens of seconds for a single run. A single ANY(...)
    query avoids that entirely.
    """
    if not ips:
        return {}
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT ip, data FROM assets WHERE ip = ANY(%s)", (ips,))
            return {ip: data for ip, data in cur.fetchall()}
    except Exception:
        logger.debug("Persistence unavailable; asset batch lookup fell back to seed", exc_info=True)
        return {}
