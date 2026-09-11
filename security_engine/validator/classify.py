from typing import Any

from security_engine.authorization.diff import AuthorizationObservation


def classify_observation(observation: AuthorizationObservation) -> dict[str, Any] | None:
    owner_response = observation.responses["user_a"]
    non_owner_response = observation.responses["user_b"]
    if owner_response["status_code"] == 200 and non_owner_response["status_code"] == 200:
        return {
            "type": "BOLA/IDOR",
            "severity": "high",
            "endpoint": observation.endpoint.path,
            "method": observation.endpoint.method,
            "operation_id": observation.endpoint.operation_id,
            "owner": "user_a",
            "violating_user": "user_b",
            "evidence": observation.as_dict(),
        }
    return None
