import os
from functools import partial
import logging

import requests
from flask import Flask, Response, jsonify, request, stream_with_context

KEYCLOAK_INTROSPECT_URL = os.getenv(
    "KEYCLOAK_INTROSPECT_URL",
    "http://localhost:8081/realms/mcp/protocol/openid-connect/token/introspect",
)
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "mcp")
KEYCLOAK_CLIENT_SECRET = os.getenv(
    "KEYCLOAK_CLIENT_SECRET", "uOxcgeKNfuWs7QK4D8qTqsQ8JzsLJe22"
)
KEYCLOAK_INTROSPECT_HOST_HEADER = os.getenv("KEYCLOAK_INTROSPECT_HOST_HEADER")
OPA_URL = os.getenv("OPA_URL", "http://opa:8181/v1/data/mcp/allow")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://mcp-server:8080/mcp")

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("opa-guard")

app = Flask(__name__)


def introspect_token(token: str) -> dict:
    headers = {}
    if KEYCLOAK_INTROSPECT_HOST_HEADER:
        headers["Host"] = KEYCLOAK_INTROSPECT_HOST_HEADER
    resp = requests.post(
        KEYCLOAK_INTROSPECT_URL,
        data={"token": token},
        auth=(KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET),
        timeout=50,
        headers=headers or None,
    )
    resp.raise_for_status()
    logger.info(
        "Keycloak introspection request payload=%s headers=%s",
        resp.request.body,
        resp.request.headers,
    )
    body = resp.json()
    logger.info(
        "Keycloak introspection response status=%s body=%s",
        resp.status_code,
        body,
    )
    return resp.json()


def evaluate_policy(token_info: dict) -> bool:
    logger.info("Evaluating OPA policy for token_info=%s", token_info)
    payload = {
        "input": {
            "token": token_info,
            "request": {
                "http": {
                    "method": request.method,
                    "path": request.path,
                    "headers": dict(request.headers),
                }
            },
        }
    }
    headers = {}
    if KEYCLOAK_INTROSPECT_HOST_HEADER:
        headers["Host"] = KEYCLOAK_INTROSPECT_HOST_HEADER
    resp = requests.post(OPA_URL, json=payload, timeout=5, headers=headers or None,)
    resp.raise_for_status()
    result = bool(resp.json().get("result"))
    logger.info("OPA request payload=%s response=%s", payload, resp.json())
    logger.info("OPA decision=%s payload=%s", result, payload)
    return result


def forward_to_mcp() -> Response:
    downstream_headers = {
        "Content-Type": request.headers.get("Content-Type", "application/json"),
        "Accept": request.headers.get("Accept", "application/json"),
    }
    logger.info("Forwarding request to MCP: headers=%s", downstream_headers)
    resp = requests.post(
        MCP_SERVER_URL,
        headers=downstream_headers,
        data=request.get_data(),
        timeout=30,
        stream=True,
    )

    output_headers = {
        "Content-Type": resp.headers.get("Content-Type", "text/event-stream"),
    }

    def stream():
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                yield chunk

    return Response(
        stream_with_context(stream()),
        status=resp.status_code,
        headers=output_headers,
    )


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/mcp", methods=["POST"])
def proxy_tool():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        logger.warning("Missing Authorization header")
        return jsonify(error="Missing bearer token"), 401
    token = auth.split(" ", 1)[1]
    logger.info("Received Authorization header token=%s", token[:20] + "..." if len(token) > 20 else token)
    token_info = introspect_token(token)
    logger.info("Token introspection result: %s", token_info)
    if not token_info.get("active"):
        logger.warning("Token inactive, introspection=%s", token_info)
        return jsonify(error="Token inactive"), 401

    if not evaluate_policy(token_info):
        logger.warning("Policy rejected, token=%s", token_info.get("sub"))
        return jsonify(error="Policy rejected the call"), 403

    return forward_to_mcp()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090)
