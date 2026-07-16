"""Persistence integration tests.

These exercise the real Postgres path and are skipped unless TEST_DATABASE_URL
is set (e.g. a Supabase/local Postgres connection string). Everything else in
the suite runs stateless, so CI stays green without a database.

    TEST_DATABASE_URL=postgresql://... pytest tests/test_persistence.py
"""
import os
import uuid

import pytest

TEST_DB = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_DB, reason="TEST_DATABASE_URL not set")


@pytest.fixture()
def db(monkeypatch):
    from backend.config import settings
    import backend.db as db_module

    monkeypatch.setattr(settings, "database_url", TEST_DB)
    db_module._unavailable = False
    db_module._initialized = False
    return db_module


def test_save_and_list_logs_roundtrip(db):
    log_id = f"test-{uuid.uuid4()}"
    entry = {"id": log_id, "ip": "203.0.113.7", "event": "Failed password", "severity": "medium"}

    assert db.save_logs([entry]) is True
    fetched = {e["id"]: e for e in db.list_logs(limit=500)}
    assert log_id in fetched
    assert fetched[log_id]["ip"] == "203.0.113.7"


def test_save_logs_upserts_on_duplicate_id(db):
    log_id = f"test-{uuid.uuid4()}"
    assert db.save_logs([{"id": log_id, "event": "v1"}]) is True
    assert db.save_logs([{"id": log_id, "event": "v2"}]) is True  # no PK violation
    fetched = {e["id"]: e for e in db.list_logs(limit=500)}
    assert fetched[log_id]["event"] == "v2"


def test_save_incidents_roundtrip(db):
    incident_id = f"inc-{uuid.uuid4()}"
    assert db.save_incidents([{"incident_id": incident_id, "risk_score": 9.1, "findings": []}]) is True


def test_asset_lookup_returns_none_for_unknown_ip(db):
    assert db.get_asset_by_ip(f"unknown-{uuid.uuid4()}") is None
