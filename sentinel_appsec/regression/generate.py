from typing import Any


def generate_regression_test(finding: dict[str, Any], base_url: str) -> str:
    path = finding["endpoint"]
    return f'''import httpx\n\n\ndef test_fix_for_{finding["operation_id"]}():\n    response = httpx.get(\n        "{base_url.rstrip('/')}{path.replace('{report_id}', '1').replace('{id}', '1')}",\n        headers={{"X-Demo-Token": "token-user-b"}},\n    )\n    assert response.status_code in (403, 404)\n'''
