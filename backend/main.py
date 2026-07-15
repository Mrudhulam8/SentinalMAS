from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.routers import analysis, enrichment, logs, pipeline, reports, vulnerability
<<<<<<< HEAD
from backend.routers import simulate as simulate_router
from backend.routers import blocklist as blocklist_router
from backend.routers import alerts as alerts_router

app = FastAPI(title="SentinelMAS API", version="1.0.0")
=======

app = FastAPI(title="SecureOrch API", version="1.0.0")
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70
app.include_router(logs.router)
app.include_router(analysis.router)
app.include_router(enrichment.router)
app.include_router(pipeline.router)
app.include_router(reports.router)
app.include_router(vulnerability.router)
<<<<<<< HEAD
app.include_router(simulate_router.router)
app.include_router(blocklist_router.router)
app.include_router(alerts_router.router)
=======
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70

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
