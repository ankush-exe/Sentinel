from typing import Any

import httpx

from security_engine.authorization.diff import exercise_endpoint
from security_engine.discovery.openapi import discover_endpoints
from security_engine.reporter.report import build_report
from security_engine.regression.generate import generate_regression_test
from security_engine.validator.classify import classify_observation


async def scan_target(target_url: str) -> dict[str, Any]:
    base_url = target_url.rstrip("/")
    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        spec_response = await client.get("/openapi.json")
        spec_response.raise_for_status()
        endpoints = discover_endpoints(spec_response.json())
        findings = []
        for endpoint in endpoints:
            observation = await exercise_endpoint(client, endpoint)
            finding = classify_observation(observation)
            if finding:
                finding["regression_test"] = generate_regression_test(finding, base_url)
                findings.append(finding)
    return build_report(base_url, findings, len(endpoints))
