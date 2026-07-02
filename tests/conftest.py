"""Shared pytest configuration.

Runs the whole suite with the database/LLM disabled so tests are deterministic
and offline. The pipeline is designed to degrade gracefully to local seed data
when no credentials are present, which is exactly the path we exercise here.
"""
import logging

import pytest

# External integration keys that must NOT be exercised during unit tests, so the
# suite stays hermetic even when a developer has a populated .env. (The DB is
# handled separately: test_persistence.py opts in via TEST_DATABASE_URL.)
_DISABLED_SETTINGS = [
    "gemini_api_key",
    "abuseipdb_api_key",
    "virustotal_api_key",
    "nvd_api_key",
    "database_url",
]


@pytest.fixture(autouse=True)
def _offline_env(monkeypatch):
    """Force the offline/degraded path regardless of the local .env."""
    from backend.config import settings

    for name in _DISABLED_SETTINGS:
        monkeypatch.setattr(settings, name, "")
    yield


@pytest.fixture(autouse=True)
def _silence_logging():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def pytest_configure(config):
    config.addinivalue_line("markers", "perf: performance/throughput benchmarks")
