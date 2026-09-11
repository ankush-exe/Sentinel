from fastapi.openapi.utils import get_openapi
import pytest

from demo_app.main import app
from sentinel_appsec.discovery.openapi import discover_endpoints
from sentinel_appsec.validator.classify import classify_observation
from sentinel_appsec import Scanner


def test_scanner_rejects_non_positive_timeout():
    with pytest.raises(ValueError, match="timeout"):
        Scanner(timeout=0)


def test_discovery_only_returns_authenticated_path_parameter_routes():
    spec = get_openapi(title=app.title, version=app.version, routes=app.routes)
    endpoints = discover_endpoints(spec)
    paths = {endpoint.path for endpoint in endpoints}
    assert "/api/reports/{report_id}" in paths
    assert "/api/reports/{report_id}/owner" in paths
    assert all("{" in endpoint.path for endpoint in endpoints)


def test_validator_flags_non_owner_200():
    from sentinel_appsec.authorization.diff import AuthorizationObservation
    from sentinel_appsec.discovery.openapi import DiscoveredEndpoint

    observation = AuthorizationObservation(
        endpoint=DiscoveredEndpoint("GET", "/api/reports/{report_id}", "read_report_api_reports__report_id__get"),
        responses={"user_a": {"status_code": 200, "body": {}}, "user_b": {"status_code": 200, "body": {}}, "admin": {"status_code": 200, "body": {}}},
    )
    assert classify_observation(observation)["type"] == "BOLA/IDOR"
