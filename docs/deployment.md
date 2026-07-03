# Deployment Guide

Stand up a live SecureOrch prototype:

- **Backend** (FastAPI) → **Railway**
- **Frontend** (React/Vite) → **Vercel**
- **Persistence** → **Supabase** (Postgres)
- **Live enrichment** → Groq (Llama), AbuseIPDB, VirusTotal, NVD

> **Order matters** — the services reference each other's URLs:
> 1. Get keys → 2. Create Supabase DB → 3. Deploy backend (Railway) →
> 4. Deploy frontend (Vercel) with the backend URL → 5. Point the backend's
> `CORS_ORIGINS` at the frontend URL.

No secrets are ever committed — everything lives in the host dashboards. The
tables are created automatically on first connection; there's no SQL to run.

---

## 1. Get the API keys

| Service | Where | Notes |
|---|---|---|
| Groq | https://console.groq.com/keys | Free tier, fast Llama models |
| AbuseIPDB | https://www.abuseipdb.com/account/api | Free tier |
| VirusTotal | https://www.virustotal.com/gui/my-apikey | Free tier |
| NVD | https://nvd.nist.gov/developers/request-an-api-key | Optional; raises rate limit |

## 2. Create the database (Supabase)

1. https://supabase.com → **New project** (note the database password you set).
2. Click **Connect** (top bar) → **Session pooler** → copy the URI. It looks
   like `postgresql://postgres.PROJECT:PASSWORD@aws-0-REGION.pooler.supabase.com:5432/postgres`.
   Substitute your real password. This is your `DATABASE_URL`.

   > ⚠️ Use the **Session pooler** string, not the "Direct connection" one.
   > Supabase's direct connection is IPv6-only, and Railway is IPv4 — the direct
   > string will fail to connect. The pooler is IPv4-compatible.
3. That's it — SecureOrch creates the `logs`, `findings`, `incidents`, and
   `assets` tables automatically on first write.

> Prefer a different Postgres (Neon, Railway's own Postgres, RDS)? Any of them
> works — just supply its connection string as `DATABASE_URL`.

## 3. Deploy the backend to Railway

1. https://railway.app → **New Project → Deploy from GitHub repo** → pick this repo.
   Railway reads [`railway.json`](../railway.json) / [`Procfile`](../Procfile)
   and builds from `requirements.txt`.
2. **Variables** → add:

   | Variable | Value |
   |---|---|
   | `DATABASE_URL` | from step 2 |
   | `GROQ_API_KEY` | from step 1 |
   | `ABUSEIPDB_API_KEY` | from step 1 |
   | `VIRUSTOTAL_API_KEY` | from step 1 |
   | `NVD_API_KEY` | from step 1 (optional) |
   | `CORS_ORIGINS` | placeholder for now; set in step 5 |

3. **Settings → Networking → Generate Domain** to get a public URL, e.g.
   `https://secureorch-api.up.railway.app`.
4. Verify: open `https://<your-backend>/api/health` → `{"status":"ok"}`.

## 4. Deploy the frontend to Vercel

1. https://vercel.com → **Add New → Project** → import the repo.
2. **Set Root Directory to `frontend`** (important — it's a monorepo). Framework
   auto-detects **Vite** (see [`frontend/vercel.json`](../frontend/vercel.json)).
3. Add an environment variable:

   | Variable | Value |
   |---|---|
   | `VITE_API_BASE` | your Railway backend URL from step 3 |

4. Deploy. Note the URL, e.g. `https://secureorch.vercel.app`.

## 5. Connect them (CORS)

1. Back in Railway → **Variables** → set:
   ```
   CORS_ORIGINS = https://secureorch.vercel.app
   ```
   (comma-separate multiple; add `http://localhost:5173` if you also develop
   locally against the deployed backend). Railway redeploys automatically.

## 6. Verify end-to-end

1. Open the Vercel URL.
2. Upload a sample log from `datasets/` (or your own).
3. Watch the agents stream to completion; review incidents + risk chart; download
   a PDF/HTML/JSON report.
4. Confirm persistence: in Supabase → **Table Editor**, the `logs` and
   `incidents` tables now contain rows.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Browser CORS error | `CORS_ORIGINS` on Railway doesn't exactly match the Vercel origin (scheme + host, no trailing slash) |
| Frontend calls `localhost:8000` | `VITE_API_BASE` not set at build time — set it and redeploy the frontend |
| Incidents compute but Supabase stays empty | `DATABASE_URL` missing/wrong — check Railway deploy logs for `PersistenceUnavailable`; confirm the password in the URI |
| No LLM explanations / empty IP reputation | Corresponding key missing — pipeline still runs, those fields stay empty |
| Backend build fails on a dependency | Confirm Python 3.12 (pinned via [`.python-version`](../.python-version)) |

Everything degrades gracefully: any missing key disables just that enrichment,
and a missing/broken `DATABASE_URL` falls back to stateless operation instead of
crashing.

## Local development against real services

Copy `.env.example` → `.env`, fill in `DATABASE_URL` + keys, then:

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload      # http://localhost:8000

cd frontend && npm install && npm run dev   # http://localhost:5173
```

Run the persistence tests against a real database with:

```bash
TEST_DATABASE_URL="postgresql://..." pytest tests/test_persistence.py
```
