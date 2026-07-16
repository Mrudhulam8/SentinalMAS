from fastapi import APIRouter
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from agents.report import to_html, to_json, to_pdf

router = APIRouter(prefix="/api/reports", tags=["reports"])


class ReportRequest(BaseModel):
    incidents: list[dict]


@router.post("/json")
def report_json(request: ReportRequest):
    return Response(content=to_json(request.incidents), media_type="application/json")


@router.post("/html", response_class=HTMLResponse)
def report_html(request: ReportRequest):
    return HTMLResponse(content=to_html(request.incidents))


@router.post("/pdf")
def report_pdf(request: ReportRequest):
    pdf_bytes = to_pdf(request.incidents)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=sentinelmas_report.pdf"},
    )
