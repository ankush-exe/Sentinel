from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Sentinel Demo Reports API", version="1.0.0")

USERS = {
    "token-user-a": {"username": "user_a", "role": "user"},
    "token-user-b": {"username": "user_b", "role": "user"},
    "token-admin": {"username": "admin", "role": "admin"},
}

REPORTS = {
    1: {"id": 1, "owner": "user_a", "title": "Quarterly revenue", "body": "Confidential revenue data"},
    2: {"id": 2, "owner": "user_b", "title": "Launch plan", "body": "Internal launch notes"},
}


class ReportUpdate(BaseModel):
    title: str | None = None
    body: str | None = None


def current_user(x_demo_token: Annotated[str | None, Header()] = None) -> dict:
    user = USERS.get(x_demo_token or "")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid demo token")
    return user


@app.get("/api/reports/{report_id}", tags=["reports"])
def read_report(report_id: int, user: Annotated[dict, Depends(current_user)]) -> dict:
    """Intentionally vulnerable: it never checks the report owner."""
    report = REPORTS.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {**report, "viewer": user["username"]}


@app.get("/api/reports/{report_id}/notes", tags=["reports"])
def read_report_notes(report_id: int, user: Annotated[dict, Depends(current_user)]) -> dict:
    """Intentionally vulnerable nested resource."""
    if report_id not in REPORTS:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"report_id": report_id, "notes": "Owner-only review notes", "viewer": user["username"]}


@app.get("/api/reports/{report_id}/owner", tags=["reports"])
def read_owner_view(report_id: int, user: Annotated[dict, Depends(current_user)]) -> dict:
    report = REPORTS.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if user["role"] != "admin" and report["owner"] != user["username"]:
        raise HTTPException(status_code=403, detail="You do not own this report")
    return {"id": report_id, "owner": report["owner"], "title": report["title"]}


@app.get("/api/reports/{report_id}/admin-summary", tags=["reports"])
def admin_summary(report_id: int, user: Annotated[dict, Depends(current_user)]) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    if report_id not in REPORTS:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"id": report_id, "owner": REPORTS[report_id]["owner"], "risk": "low"}
