# Testing & Performance (Phase 6)

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest                 # full suite (unit + integration + performance)
pytest -m perf -s      # performance benchmarks only, with timing output
```

The whole suite runs **offline** — no API keys, no database. The pipeline is
designed to degrade gracefully to local seed data when credentials are absent,
which is the exact path the tests exercise.

## Test suite

| File | Scope | Covers |
|---|---|---|
| `tests/test_log_parser.py` | Log Parsing Agent | CSV/JSON/Apache/Linux/TXT detection, column aliasing, schema normalization, unique IDs |
| `tests/test_log_analysis.py` | Log Analysis Agent | brute-force threshold, failed-login, SQLi, URL-encoded XSS, privilege escalation, port scan, benign-traffic no-ops |
| `tests/test_pipeline.py` | Orchestrator (integration) | end-to-end scoring, risk-band ↔ threat-level consistency, recommended actions, SSE streaming events, empty input |
| `tests/test_report.py` | Report Generation Agent | valid JSON structure, HTML table/summary, PDF header, empty-incident handling |
| `tests/test_performance.py` | Performance | **10k logs < 60s**, roughly-linear scaling (no quadratic blowup) |
| `tests/test_persistence.py` | Postgres (opt-in) | save/list/upsert round-trips; skipped unless `TEST_DATABASE_URL` is set |
| `tests/synthetic.py` | Fixtures | deterministic, seeded, attack-rich synthetic log generator |

Current status: **25 tests passing**.

## Performance benchmark

Full pipeline (log analysis → threat intel → asset context → correlation →
risk assessment → response) on seeded synthetic data, best-of-3 steady state
(after import/graph-compile warmup):

| Logs | Time (s) | Throughput (logs/s) | Findings | Incidents |
|-----:|---------:|--------------------:|---------:|----------:|
| 1,000 | 0.014 | 71,000 | 317 | 57 |
| 5,000 | 0.080 | 62,000 | 943 | 175 |
| 10,000 | 0.163 | 61,000 | 1,618 | 176 |
| 25,000 | 0.468 | 53,000 | 3,615 | 176 |

**PRD target: 10,000 logs in < 60s → met with a ~350× margin (0.16s).**

Numbers from a Windows 11 dev laptop; treat as order-of-magnitude, not a
guaranteed SLA. Re-run locally with `pytest -m perf -s`.

## Performance fix uncovered during Phase 6

The first 10k-log benchmark did not complete (hung for minutes). Profiling
isolated it to the Asset Context stage:

- The persistence client cached the *connection* but not a *failed* connection,
  so every call re-ran the blocking credential/connection probe (~13s each when
  unconfigured). With 1,618 findings this was effectively unbounded.
- `asset_context` looked up the datastore once **per finding** rather than per
  **unique IP** (~1,600 lookups for ~20 distinct IPs).

Fixes (the pattern carried over when persistence moved from Firestore to
Postgres in `backend/db.py`):
- The persistence layer fast-fails when no database is configured and caches the
  unavailable state, so the slow probe happens at most once.
- `agents/asset_context.py` memoizes lookups per IP.

Result: 10k-log run went from *not completing* to **0.16s**.

## Success metrics

| Metric | Target | Result |
|---|---|---|
| Process 10k logs | < 60s | 0.16s ✅ |
| Throughput | — | ~60k logs/s |
| Scaling | sub-quadratic | linear to 25k ✅ |
| Detection coverage | all rule types | brute-force, failed-login, SQLi, XSS, privilege-escalation, port-scan, suspicious-traffic ✅ |
| Report formats | JSON/HTML/PDF | all validated ✅ |
| Offline / no-key operation | works | full pipeline + reports ✅ |
| Automated tests | present & green | 25 passing ✅ |
