"""OPA Guard: domain-level PEP in front of a Micro-MCP server.

Flow: Bearer token -> Keycloak introspection -> JSON-RPC inspection -> OPA decision -> proxy.
"""
import logging
import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

DOMAIN = os.getenv("DOMAIN", "unknown")
UPSTREAM_URL = os.environ["UPSTREAM_URL"]
INTROSPECT_URL = os.getenv(
    "KEYCLOAK_INTROSPECT_URL",
    "http://keycloak:8080/realms/mcp-demo/protocol/openid-connect/token/introspect",
)
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "mcp-gateway")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "mcp-secret-123")
OPA_URL = os.getenv("OPA_URL", "http://opa:8181/v1/data/mcp/authz")

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(f"guard-{DOMAIN}")

app = FastAPI(title=f"OPA Guard ({DOMAIN})")
client = httpx.AsyncClient(timeout=30)

FORWARD_HEADERS = ("accept", "content-type", "mcp-session-id", "mcp-protocol-version")


def rpc_error(status: int, message: str, rpc_id=None) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32001, "message": message}},
        status_code=status,
    )


@app.get("/health")
def health():
    return {"status": "ok", "domain": DOMAIN}


@app.post("/mcp")
async def mcp_proxy(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        log.warning("401 missing bearer token")
        return rpc_error(401, "Missing bearer token")
    token = auth.split(" ", 1)[1]

    try:
        intro = (
            await client.post(INTROSPECT_URL, data={"token": token}, auth=(CLIENT_ID, CLIENT_SECRET))
        ).json()
    except Exception as exc:
        log.error("introspection failed: %s", exc)
        return rpc_error(502, "Identity provider unavailable")
    if not intro.get("active"):
        log.warning("401 token inactive (introspection)")
        return rpc_error(401, "Token inactive")

    body = await request.body()
    try:
        rpc = await request.json()
    except Exception:
        return rpc_error(400, "Invalid JSON-RPC payload")
    if not isinstance(rpc, dict):
        return rpc_error(400, "JSON-RPC batches are not supported")
    params = rpc.get("params") or {}

    opa_input = {
        "domain": DOMAIN,
        "token": {
            "active": True,
            "username": intro.get("preferred_username"),
            "roles": intro.get("realm_access", {}).get("roles", []),
        },
        "rpc": {
            "method": rpc.get("method"),
            "tool": params.get("name"),
            "arguments": params.get("arguments") or {},
        },
    }
    try:
        opa = (await client.post(OPA_URL, json={"input": opa_input})).json().get("result", {})
    except Exception as exc:
        log.error("OPA failed: %s", exc)
        return rpc_error(502, "Policy engine unavailable")

    allowed = opa.get("allow") is True
    log.info("OPA decision user=%s roles=%s method=%s tool=%s args=%s -> %s%s",
             opa_input["token"]["username"], opa_input["token"]["roles"], opa_input["rpc"]["method"],
             opa_input["rpc"]["tool"], opa_input["rpc"]["arguments"], "ALLOW" if allowed else "DENY",
             "" if allowed else f" ({opa.get('reason')})")
    if not allowed:
        return rpc_error(403, f"Policy denied: {opa.get('reason', 'not allowed')}", rpc.get("id"))

    headers = {k: v for k, v in request.headers.items() if k in FORWARD_HEADERS}
    headers["authorization"] = auth
    log.info("forwarding to %s", UPSTREAM_URL)
    upstream = await client.post(UPSTREAM_URL, content=body, headers=headers)
    out = {k: v for k, v in upstream.headers.items() if k.lower() in ("content-type", "mcp-session-id")}
    return Response(upstream.content, status_code=upstream.status_code, headers=out)
