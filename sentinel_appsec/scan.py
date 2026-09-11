from typing import Any

import httpx

from sentinel_appsec.authorization.diff import exercise_endpoint
from sentinel_appsec.discovery.openapi import discover_endpoints
from sentinel_appsec.reporter.report import build_report
from sentinel_appsec.regression.generate import generate_regression_test
from sentinel_appsec.validator.classify import classify_observation


async def scan_target(target_url: str, timeout: float = 10.0) -> dict[str, Any]:
    base_url = target_url.rstrip("/")
    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
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
