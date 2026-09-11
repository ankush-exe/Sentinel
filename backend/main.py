from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl

from sentinel_appsec.scan import scan_target

app = FastAPI(title="Sentinel Security Scanner")
REPORTS: dict[str, dict] = {}


class ScanRequest(BaseModel):
    target_url: HttpUrl


@app.post("/scan")
async def start_scan(request: ScanRequest) -> dict:
    scan_id = str(uuid4())
    try:
        report = await scan_target(str(request.target_url))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Scan failed: {exc}") from exc
    REPORTS[scan_id] = report
    return {"scan_id": scan_id, "report": report}


@app.get("/scan/{scan_id}/report")
def get_report(scan_id: str) -> dict:
    report = REPORTS.get(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return report


@app.get("/")
def frontend() -> FileResponse:
    return FileResponse("frontend/index.html")
