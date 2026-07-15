# SentinelMAS
=======

**Multi-agent AI orchestration framework for intelligent security operations and automated incident response.**

Upload a security log and SentinelMAS parses it, detects attacks, enriches findings
with threat intelligence and asset context, correlates them into incidents, scores
risk, recommends mitigations, and produces a downloadable report — coordinated by a
LangGraph agent pipeline with a live React dashboard.

> **Runs fully offline.** Every stage degrades gracefully when API keys / a
> database are absent, so the entire pipeline — including reports — works with
> zero credentials for local demos and CI. Keys simply add live enrichment.

---

## Features

- **7 specialized agents** orchestrated with LangGraph (see below)
- **Multi-format log ingestion** — CSV, JSON, Apache access, Linux auth, plain text
- **Rule-based attack detection** — brute force, failed logins, SQL injection, XSS,
  privilege escalation, port scans, suspicious traffic (deterministic, no LLM needed)
- **Optional LLM enrichment** — natural-language finding explanations via Groq (Llama)
- **Threat intel** — IP reputation (AbuseIPDB, VirusTotal) + MITRE ATT&CK mapping
- **Vulnerability lookup** — CVE/CVSS via NVD with patch recommendations
- **Risk scoring** — severity + attack diversity + asset criticality + IP reputation → threat level & priority
- **Reports** — JSON, HTML, and PDF incident reports
- **Live dashboard** — per-agent execution status streamed over SSE, risk chart, incident table, one-click downloads
- **Validated performance** — 10,000 logs processed in ~0.16s (target: < 60s)

## Architecture

```
                         React Dashboard (Vite)
                                  │  upload log → stream progress → download report
                                  ▼
                          FastAPI Backend
                                  │
                                  ▼
                    Orchestrator Agent (LangGraph)
                                  │
   Log Analysis → Threat Intelligence → Asset Context
                                  │
                          Correlation
                                  │
                        Risk Assessment
                                  │
                     Response Recommendation
                                  │
                                  ▼
                     scored incidents ──► Report Agent (on-demand: JSON/HTML/PDF)

   Supporting capability: Vulnerability Agent (NVD CVE/CVSS lookup)
```

The **Report Agent** runs on demand when a report is requested (not as a pipeline
node), and the **Vulnerability Agent** is a standalone enrichment capability. See
[docs/architecture.md](docs/architecture.md) for details.

### Agents

| Agent | Responsibility |
|---|---|
| Orchestrator | Coordinates the workflow via LangGraph; streams per-node progress |
| Log Parsing | Normalizes CSV/JSON/Apache/Linux/TXT logs into a common schema |
| Log Analysis | Detects attack patterns (rules + optional Groq/Llama explanations) |
| Threat Intelligence | IP/domain reputation (AbuseIPDB, VirusTotal) + MITRE ATT&CK mapping |
| Asset Context | Business criticality from the `assets` registry table (local seed fallback) |
| Correlation | Merges related findings into incidents |
| Risk Assessment | Computes risk score, threat level, and priority |
| Response | Recommends mitigation actions |
| Report | Generates PDF/HTML/JSON incident reports |
| Vulnerability | CVE lookup via NVD, CVSS scoring, patch recommendations |

## Tech stack

- **Frontend:** React 19 + Vite, Recharts
- **Backend:** FastAPI, Uvicorn
- **Agent orchestration:** LangGraph
- **LLM:** Groq / Llama (optional)
- **Threat intel:** AbuseIPDB, VirusTotal (optional)
- **Vulnerability data:** NVD / CVE (works keyless at low rate limit)
- **Database:** Postgres / Supabase (optional; stateless + local seed fallback)
- **Reports:** ReportLab (PDF)
- **Tests:** pytest

## Project structure

```
<<<<<<< HEAD
sentinelmas/
=======
secureorch/
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70
├── agents/            # 10 agent modules (orchestrator + 9 specialists)
├── backend/
│   ├── main.py        # FastAPI app + router registration
│   ├── config.py      # Settings (env-driven)
│   ├── db.py          # Postgres persistence (optional; stateless if unset)
│   └── routers/       # logs, analysis, enrichment, pipeline, reports
├── frontend/          # React + Vite dashboard
├── datasets/          # Sample logs (Apache, Linux auth, CSV)
├── tests/             # pytest suite + synthetic log generator
├── docs/              # architecture + testing/performance
└── prompts/           # LLM prompt templates
```

## Setup

### Backend

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (source .venv/bin/activate on macOS/Linux)
pip install -r requirements.txt
cp .env.example .env              # optional — fill in API keys to enable live enrichment
uvicorn backend.main:app --reload
```

Backend runs at `http://localhost:8000` (`GET /api/health` to check).

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Dashboard runs at `http://localhost:5173`.

## Usage

1. Start the backend and frontend (above).
2. Open the dashboard and upload a log file — try the samples in `datasets/`
   (`sample_apache_access.log`, `sample_linux_auth.log`, `sample_logs.csv`).
3. Watch each agent complete in real time, then review incidents in the table and
   the risk chart.
4. Download the incident report as **PDF**, **HTML**, or **JSON**.

## API reference

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/logs/upload` | Parse an uploaded log file → normalized entries |
| `GET` | `/api/logs` | List stored logs (Postgres; empty if unconfigured) |
| `POST` | `/api/analysis/run` | Run Log Analysis on entries |
| `POST` | `/api/enrichment/run` | Threat-intel + asset-context enrichment on findings |
| `POST` | `/api/pipeline/run` | Run the full pipeline synchronously |
| `POST` | `/api/pipeline/stream` | Run the pipeline, streaming per-agent progress (SSE) |
| `POST` | `/api/reports/{json,html,pdf}` | Generate an incident report |
| `GET` | `/api/vulnerability/lookup?keyword=` | CVE/CVSS lookup for a software keyword (NVD) |

## Configuration

All keys are **optional** (see `.env.example`):

| Variable | Enables |
|---|---|
| `GROQ_API_KEY` | LLM explanations on findings |
| `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY` | Live IP reputation |
| `NVD_API_KEY` | Higher NVD CVE rate limit (lookups work without it) |
| `DATABASE_URL` | Postgres persistence (e.g. Supabase); blank = stateless |
| `CORS_ORIGINS` | Allowed frontend origins |

## Deployment

For a live prototype — backend on **Railway**, frontend on **Vercel**, with
**Supabase (Postgres)** persistence and all four API integrations wired in —
follow the step-by-step [docs/deployment.md](docs/deployment.md). Config is
already in the repo: [`railway.json`](railway.json) / [`Procfile`](Procfile)
(backend) and [`frontend/vercel.json`](frontend/vercel.json). All secrets live
in the host dashboards; nothing sensitive is committed.

## Testing & performance

```bash
pip install -r requirements-dev.txt
pytest                 # 25 tests, fully offline
pytest -m perf -s      # performance benchmark with timing
```

The pipeline processes **10,000 logs in ~0.16s** (~60k logs/s), against a target of
< 60s. Full methodology, benchmark table, and success metrics are in
[docs/testing-and-performance.md](docs/testing-and-performance.md).
