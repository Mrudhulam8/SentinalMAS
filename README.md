# SecureOrch

Multi-agent AI orchestration framework for intelligent security operations and automated incident response.

## Stack
- Frontend: React (Vite)
- Backend: FastAPI
- Agent orchestration: LangGraph
- LLM: Gemini
- Threat intel: AbuseIPDB, VirusTotal
- Vulnerability data: NVD (CVE)
- Database: Firebase Firestore

## Setup

### Backend
```
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r ../requirements.txt
cp ../.env.example ../.env   # fill in API keys
uvicorn backend.main:app --reload
```

### Frontend
```
cd frontend
npm install
npm run dev
```

See `docs/` for architecture and agent responsibilities.
