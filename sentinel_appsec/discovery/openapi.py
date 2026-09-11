from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DiscoveredEndpoint:
    method: str
    path: str
    operation_id: str


def discover_endpoints(spec: dict[str, Any]) -> list[DiscoveredEndpoint]:
    discovered = []
    for path, path_item in spec.get("paths", {}).items():
        if "{" not in path:
            continue
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            parameters = path_item.get("parameters", []) + operation.get("parameters", [])
            has_auth_header = any(
                parameter.get("in") == "header" and parameter.get("name", "").lower() == "x-demo-token"
                for parameter in parameters
            )
            if has_auth_header:
                discovered.append(
                    DiscoveredEndpoint(
                        method=method.upper(),
                        path=path,
                        operation_id=operation.get("operationId", f"{method}_{path}"),
                    )
                )
    return discovered
