from __future__ import annotations

import json
import os
import time
from typing import Any

import requests
from fastmcp import FastMCP

MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8080"))

MG_API_BASE_URL = os.getenv("MG_API_BASE_URL", "https://kresource-dev.menarini.net")
MG_TOKEN_URL = os.getenv(
    "MG_TOKEN_URL",
    "https://keycloak-dev.menarini.net/auth/realms/menarini/protocol/openid-connect/token",
)
MG_CLIENT_ID = os.getenv("MG_CLIENT_ID", "mg-app_resourceAdministration")
MG_CLIENT_SECRET = os.getenv("MG_CLIENT_SECRET", "")
MG_USERNAME = os.getenv("MG_USERNAME", "kscanner_service_account")
MG_PASSWORD = os.getenv("MG_PASSWORD", "kscanner2025!")
MG_VERIFY_SSL = os.getenv("MG_VERIFY_SSL", "false").lower() in {"1", "true", "yes"}
MG_TIMEOUT_SECONDS = float(os.getenv("MG_TIMEOUT_SECONDS", "30"))

# Optional fallback catalog. Useful because the provided swagger includes app details
# by id but not an explicit "list all applications" endpoint.
MG_APPLICATION_IDS = [
    int(x.strip())
    for x in os.getenv("MG_APPLICATION_IDS", "").split(",")
    if x.strip()
]
MG_APPLICATION_CODES = [
    x.strip() for x in os.getenv("MG_APPLICATION_CODES", "").split(",") if x.strip()
]

mcp = FastMCP("resource-admin")


class OAuthTokenProvider:
    def __init__(self) -> None:
        self._access_token: str | None = None
        self._expires_at: float = 0

    def get_access_token(self) -> str:
        now = time.time()
        if self._access_token and now < self._expires_at - 60:
            return self._access_token

        if not MG_CLIENT_SECRET:
            raise RuntimeError("Missing MG_CLIENT_SECRET")
        if not MG_PASSWORD:
            raise RuntimeError("Missing MG_PASSWORD")

        auth_data = {
            "client_id": MG_CLIENT_ID,
            "client_secret": MG_CLIENT_SECRET,
            "username": MG_USERNAME,
            "password": MG_PASSWORD,
            "grant_type": "password",
        }
        response = requests.post(
            MG_TOKEN_URL,
            data=auth_data,
            timeout=MG_TIMEOUT_SECONDS,
            verify=MG_VERIFY_SSL,
        )
        response.raise_for_status()
        payload = response.json()

        access_token = payload.get("access_token")
        if not access_token:
            raise RuntimeError("Token response does not include access_token")

        expires_in = int(payload.get("expires_in", 300))
        self._access_token = access_token
        self._expires_at = now + expires_in
        return access_token


class ResourceAdminApi:
    def __init__(self, token_provider: OAuthTokenProvider) -> None:
        self._token_provider = token_provider

    def _headers(self) -> dict[str, str]:
        token = self._token_provider.get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def _get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        url = f"{MG_API_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
        response = requests.get(
            url,
            headers=self._headers(),
            params=params,
            timeout=MG_TIMEOUT_SECONDS,
            verify=MG_VERIFY_SSL,
        )
        if response.status_code not in expected:
            response.raise_for_status()

        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type or "+json" in content_type:
            return response.json()
        return {"raw": response.text, "content_type": content_type}

    def list_applications(self) -> list[dict[str, Any]]:
        candidates = [
            "api/application",
            "api/application/all",
            "api/application/list",
        ]

        for endpoint in candidates:
            try:
                data = self._get(endpoint)
            except requests.HTTPError as err:
                if err.response is not None and err.response.status_code in (401, 403, 404, 405):
                    continue
                raise
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)]

        details = []
        for app_id in MG_APPLICATION_IDS:
            details.append(self.get_application_details(app_id))
        return details

    def get_application_details(self, application_id: int) -> dict[str, Any]:
        data = self._get(f"api/application/{application_id}/application-details")
        if not isinstance(data, dict):
            raise RuntimeError("Unexpected application details payload")
        return data

    def list_application_users(
        self,
        application_code: str,
        *,
        include_disabled: bool = True,
    ) -> list[dict[str, Any]]:
        data = self._get(f"api/application/{application_code}/identity/all")
        if not isinstance(data, list):
            raise RuntimeError("Unexpected identity list payload")
        users = [x for x in data if isinstance(x, dict)]
        if include_disabled:
            return users
        return [u for u in users if u.get("enabled", True)]


_token_provider = OAuthTokenProvider()
_api = ResourceAdminApi(_token_provider)


def _unique_app_codes(apps: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for app in apps:
        code = app.get("code")
        if isinstance(code, str) and code and code not in seen:
            seen.add(code)
            output.append(code)
    for code in MG_APPLICATION_CODES:
        if code not in seen:
            seen.add(code)
            output.append(code)
    return output


@mcp.tool()
def ra_read_catalog(include_details: bool = True) -> str:
    """Read scope: list applications and optionally load details per application id.

    Scope design:
    - Required scope: resource-admin.read.catalog
    - Server behavior is GET-only.
    """
    applications = _api.list_applications()

    if include_details:
        with_ids = [a for a in applications if isinstance(a.get("id"), int)]
        detailed = [_api.get_application_details(a["id"]) for a in with_ids]
        return json.dumps(
            {
                "scope": "resource-admin.read.catalog",
                "applications": applications,
                "application_details": detailed,
                "note": "If list endpoint is unavailable, set MG_APPLICATION_IDS for full details coverage.",
            },
            ensure_ascii=True,
        )

    return json.dumps(
        {
            "scope": "resource-admin.read.catalog",
            "applications": applications,
        },
        ensure_ascii=True,
    )


@mcp.tool()
def ra_read_application_users(application_code: str, include_disabled: bool = True) -> str:
    """Read scope: list users for one application.

    Scope design:
    - Required scope: resource-admin.read.users
    - Server behavior is GET-only.
    """
    users = _api.list_application_users(application_code, include_disabled=include_disabled)
    return json.dumps(
        {
            "scope": "resource-admin.read.users",
            "application_code": application_code,
            "count": len(users),
            "users": users,
        },
        ensure_ascii=True,
    )


@mcp.tool()
def ra_read_full_inventory(include_disabled_users: bool = True) -> str:
    """Read scope: aggregate applications, details, and users in one call.

    Scope design:
    - Required scopes: resource-admin.read.catalog + resource-admin.read.users
    - Server behavior is GET-only.

    This tool intentionally combines multiple API reads so the AI client can work
    from a single coherent payload.
    """
    applications = _api.list_applications()

    details: list[dict[str, Any]] = []
    for app in applications:
        app_id = app.get("id")
        if isinstance(app_id, int):
            details.append(_api.get_application_details(app_id))

    users_by_application: dict[str, Any] = {}
    for app_code in _unique_app_codes(details or applications):
        try:
            users = _api.list_application_users(
                app_code,
                include_disabled=include_disabled_users,
            )
            users_by_application[app_code] = {
                "count": len(users),
                "users": users,
            }
        except requests.HTTPError as err:
            users_by_application[app_code] = {
                "error": str(err),
            }

    return json.dumps(
        {
            "scopes": [
                "resource-admin.read.catalog",
                "resource-admin.read.users",
            ],
            "applications": applications,
            "application_details": details,
            "users_by_application": users_by_application,
            "notes": [
                "GET-only implementation mapped to the provided swagger.",
                "Configure MG_APPLICATION_IDS and MG_APPLICATION_CODES when your API does not expose a list-all-applications endpoint.",
            ],
        },
        ensure_ascii=True,
    )


if __name__ == "__main__":
    mcp.run(
        transport="sse",
        host=MCP_HOST,
        port=MCP_PORT,
    )
