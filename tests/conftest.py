"""Shared pytest configuration.

Runs the whole suite with Firestore/LLM disabled so tests are deterministic
and offline. The pipeline is designed to degrade gracefully to local seed data
when no credentials are present, which is exactly the path we exercise here.
"""
import logging

import pytest


@pytest.fixture(autouse=True)
def _silence_logging():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def pytest_configure(config):
    config.addinivalue_line("markers", "perf: performance/throughput benchmarks")
