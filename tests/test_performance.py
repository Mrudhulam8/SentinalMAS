"""Performance validation: PRD requires processing 10k logs in under 60s.

Runs the full pipeline (log analysis -> threat intel -> asset context ->
correlation -> risk assessment -> response) on 10,000 synthetic entries and
asserts the end-to-end wall time stays within budget.
"""
import time

import pytest

from agents.orchestrator import run_pipeline
from tests.synthetic import generate_entries

TARGET_SECONDS = 60.0
LOG_COUNT = 10_000


@pytest.mark.perf
def test_10k_logs_under_60s():
    entries = generate_entries(LOG_COUNT)

    start = time.perf_counter()
    result = run_pipeline(entries)
    elapsed = time.perf_counter() - start

    assert result["incidents"], "pipeline should surface incidents from attack-rich data"
    assert elapsed < TARGET_SECONDS, (
        f"processed {LOG_COUNT} logs in {elapsed:.2f}s, exceeding {TARGET_SECONDS}s budget"
    )
    print(f"\n{LOG_COUNT} logs processed in {elapsed:.3f}s "
          f"({LOG_COUNT / elapsed:,.0f} logs/s), "
          f"{len(result['findings'])} findings, {len(result['incidents'])} incidents")


@pytest.mark.perf
def test_scales_roughly_linearly():
    # Warm up imports / graph compile so the measurement reflects steady state.
    run_pipeline(generate_entries(200))

    def timed(n):
        entries = generate_entries(n)
        t0 = time.perf_counter()
        run_pipeline(entries)
        return time.perf_counter() - t0

    t_small = timed(2_000)
    t_large = timed(10_000)
    # 5x the input should stay well under 15x the time (no quadratic blowup).
    assert t_large < max(t_small * 15, 5.0)
