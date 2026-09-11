from fastapi.testclient import TestClient

from demo_app.main import app

client = TestClient(app)


def test_user_b_can_read_user_a_report_because_demo_is_vulnerable():
    response = client.get("/api/reports/1", headers={"X-Demo-Token": "token-user-b"})
    assert response.status_code == 200


def test_owner_route_denies_non_owner():
    response = client.get("/api/reports/1/owner", headers={"X-Demo-Token": "token-user-b"})
    assert response.status_code == 403


def test_admin_route_requires_admin_role():
    response = client.get("/api/reports/1/admin-summary", headers={"X-Demo-Token": "token-user-b"})
    assert response.status_code == 403
