from typing import Any


REMEDIATION = {
    "BOLA/IDOR": {
        "risk": "HIGH",
        "title": "Broken Object-Level Authorization (BOLA/IDOR)",
        "suggestion": (
            "Add an ownership check before returning the resource: verify the "
            "authenticated user's ID matches the resource's owner_id (or a "
            "permitted role) before serving this route."
        ),
    },
}


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    metadata = REMEDIATION.get(finding["type"], {})
    finding["risk"] = metadata.get("risk", "MEDIUM")
    finding["title"] = metadata.get("title", finding["type"])
    finding["suggestion"] = metadata.get("suggestion", "Review access control logic.")
    evidence = finding["evidence"]["responses"]
    finding["evidence_summary"] = (
        f"{finding['violating_user']} received {evidence[finding['violating_user']]['status_code']} "
        "OK for a resource owned by user_a; expected 403 or 404."
    )
    finding["regression_test_path"] = (
        f"tests/regression/test_{finding['operation_id']}_bola.py"
    )
    return finding