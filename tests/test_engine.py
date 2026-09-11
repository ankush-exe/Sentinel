from fastapi.openapi.utils import get_openapi

from demo_app.main import app
from security_engine.discovery.openapi import discover_endpoints
from security_engine.validator.classify import classify_observation


def test_discovery_only_returns_authenticated_path_parameter_routes():
    spec = get_openapi(title=app.title, version=app.version, routes=app.routes)
    endpoints = discover_endpoints(spec)
    paths = {endpoint.path for endpoint in endpoints}
    assert "/api/reports/{report_id}" in paths
    assert "/api/reports/{report_id}/owner" in paths
    assert all("{" in endpoint.path for endpoint in endpoints)


def test_validator_flags_non_owner_200():
    from security_engine.authorization.diff import AuthorizationObservation
    from security_engine.discovery.openapi import DiscoveredEndpoint

    observation = AuthorizationObservation(
        endpoint=DiscoveredEndpoint("GET", "/api/reports/{report_id}", "read_report_api_reports__report_id__get"),
        responses={"user_a": {"status_code": 200, "body": {}}, "user_b": {"status_code": 200, "body": {}}, "admin": {"status_code": 200, "body": {}}},
    )
    assert classify_observation(observation)["type"] == "BOLA/IDOR"
