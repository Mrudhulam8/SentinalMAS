# Deployment Guide

This walks through standing up a live SecureOrch prototype:

- **Backend** (FastAPI) → **Render**
- **Frontend** (React/Vite) → **Vercel**
- **Persistence** → **Firebase Firestore**
- **Live enrichment** → Gemini, AbuseIPDB, VirusTotal, NVD

> **Order matters** because the two services reference each other's URLs:
> 1. Get keys + Firebase → 2. Deploy backend (Render) → 3. Deploy frontend
> (Vercel) with the backend URL → 4. Point the backend's `CORS_ORIGINS` at the
> frontend URL and redeploy.

Nothing here requires committing a secret — all keys live in the host dashboards.

---

## 1. Get the API keys

| Service | Where | Notes |
|---|---|---|
| Gemini | https://aistudio.google.com/app/apikey | Free tier |
| AbuseIPDB | https://www.abuseipdb.com/account/api | Free tier |
| VirusTotal | https://www.virustotal.com/gui/my-apikey | Free tier |
| NVD | https://nvd.nist.gov/developers/request-an-api-key | Optional; raises rate limit |

Keep them somewhere safe for step 3.

## 2. Set up Firebase Firestore

1. https://console.firebase.google.com → **Add project**.
2. **Build → Firestore Database → Create database** (production or test mode).
3. **Project settings → Service accounts → Generate new private key** → downloads
   a JSON file.
4. Note your **Project ID** (Project settings → General).

You will paste the *entire contents* of that JSON file into the
`FIREBASE_SERVICE_ACCOUNT_JSON` env var in step 3 — do **not** commit the file.
(The code prefers this env var over any file path, which is why it's safe for a
public repo.)

## 3. Deploy the backend to Render

1. https://dashboard.render.com → **New → Blueprint** → connect the GitHub repo.
   Render reads [`render.yaml`](../render.yaml) and provisions `secureorch-api`.
2. When prompted, fill in the secret env vars (all marked `sync: false`):

   | Env var | Value |
   |---|---|
   | `GEMINI_API_KEY` | from step 1 |
   | `ABUSEIPDB_API_KEY` | from step 1 |
   | `VIRUSTOTAL_API_KEY` | from step 1 |
   | `NVD_API_KEY` | from step 1 (optional) |
   | `FIREBASE_SERVICE_ACCOUNT_JSON` | paste the whole service-account JSON |
   | `FIREBASE_PROJECT_ID` | from step 2 |
   | `CORS_ORIGINS` | leave as `*` or a placeholder for now; set in step 5 |

3. Deploy. When it's live, note the URL, e.g. `https://secureorch-api.onrender.com`.
4. Verify: open `https://<your-backend>/api/health` → `{"status":"ok"}`.

> Render's free tier sleeps after inactivity; the first request after idle takes
> ~30s to wake. Fine for a prototype.

## 4. Deploy the frontend to Vercel

1. https://vercel.com → **Add New → Project** → import the repo.
2. **Set the Root Directory to `frontend`** (important — it's a monorepo).
   Framework preset auto-detects **Vite** (config is in
   [`frontend/vercel.json`](../frontend/vercel.json)).
3. Add an environment variable:

   | Env var | Value |
   |---|---|
   | `VITE_API_BASE` | your Render backend URL from step 3 |

4. Deploy. Note the URL, e.g. `https://secureorch.vercel.app`.

## 5. Connect them (CORS)

1. Back in Render → `secureorch-api` → **Environment** → set:

   ```
   CORS_ORIGINS = https://secureorch.vercel.app
   ```
   (comma-separate multiple origins; include `http://localhost:5173` if you also
   develop locally against the deployed backend).
2. Save → Render redeploys automatically.

## 6. Verify end-to-end

1. Open the Vercel URL.
2. Upload a sample log from `datasets/` (or your own).
3. Watch the agents stream to completion, review incidents + risk chart, and
   download a PDF/HTML/JSON report.
4. Confirm persistence: in the Firebase console, the `logs` and `incidents`
   collections should now contain documents.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Browser console CORS error | `CORS_ORIGINS` on Render doesn't match the exact Vercel origin (scheme + host, no trailing slash) |
| Frontend calls `localhost:8000` | `VITE_API_BASE` not set at build time — set it and redeploy the frontend |
| Incidents compute but nothing in Firestore | `FIREBASE_SERVICE_ACCOUNT_JSON` / `FIREBASE_PROJECT_ID` missing or malformed; check Render logs for `FirestoreUnavailable` |
| No LLM explanations / empty IP reputation | Corresponding key missing — the pipeline still runs, those fields just stay empty |
| First request hangs ~30s | Render free-tier cold start; subsequent requests are fast |

Everything degrades gracefully: any missing key just disables that one
enrichment, and a missing Firebase config falls back to stateless operation.
