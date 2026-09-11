from datetime import datetime, timezone
from typing import Any


def build_report(target_url: str, findings: list[dict[str, Any]], scanned_count: int) -> dict[str, Any]:
    return {
        "target_url": target_url.rstrip("/"),
        "scanned_endpoints": scanned_count,
        "vulnerability_count": len(findings),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
