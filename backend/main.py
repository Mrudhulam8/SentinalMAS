from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.routers import analysis, enrichment, logs

app = FastAPI(title="SecureOrch API", version="1.0.0")
app.include_router(logs.router)
app.include_router(analysis.router)
app.include_router(enrichment.router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok"}
