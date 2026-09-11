from dataclasses import asdict, dataclass
from typing import Any

import httpx

from security_engine.discovery.openapi import DiscoveredEndpoint

TOKENS = {"user_a": "token-user-a", "user_b": "token-user-b", "admin": "token-admin"}


@dataclass
class AuthorizationObservation:
    endpoint: DiscoveredEndpoint
    responses: dict[str, dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return {"endpoint": asdict(self.endpoint), "responses": self.responses}


async def exercise_endpoint(
    client: httpx.AsyncClient,
    endpoint: DiscoveredEndpoint,
    resource_id: int = 1,
) -> AuthorizationObservation:
    path = endpoint.path.replace("{id}", str(resource_id)).replace("{report_id}", str(resource_id))
    responses = {}
    for username, token in TOKENS.items():
        response = await client.request(endpoint.method, path, headers={"X-Demo-Token": token})
        try:
            body = response.json()
        except ValueError:
            body = response.text
        responses[username] = {"status_code": response.status_code, "body": body}
    return AuthorizationObservation(endpoint=endpoint, responses=responses)
