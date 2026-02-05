"""Simple MCP consumer that authenticates with Keycloak and calls the local MCP server."""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import sys

import requests


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("mcp-client")

KEYCLOAK_URL = os.getenv("KEYCLOAK_TOKEN_URL", "http://localhost:8081/realms/mcp/protocol/openid-connect/token")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "mcp")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "uOxcgeKNfuWs7QK4D8qTqsQ8JzsLJe22")
PASSWORD_USER = os.getenv("KEYCLOAK_PASSWORD_USER", "testuser01")
PASSWORD_PASSWORD = os.getenv("KEYCLOAK_PASSWORD_PASSWORD", PASSWORD_USER)
MCP_ENDPOINT = os.getenv("MCP_ENDPOINT", "http://localhost:8000/mcp")


def decode_jwt(token: str) -> dict:
    """Decode the payload of a JWT without checking signatures."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload_segment = parts[1]
    padding = "=" * (-len(payload_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload_segment + padding)
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return {}


def summarize_claims(claims: dict) -> str:
    if not claims:
        return "empty claims"
    return ", ".join(f"{k}={claims[k]}" for k in sorted(claims.keys()) if k in {"sub", "exp", "client_id", "realm_access"} or k.endswith("_scope"))


def fetch_token(grant_type: str) -> str:
    """Obtain an access token from Keycloak using the requested grant."""
    payload = {"grant_type": grant_type}
    auth = (CLIENT_ID, CLIENT_SECRET)

    if grant_type == "password":
        payload.update({"username": PASSWORD_USER, "password": PASSWORD_PASSWORD})

    logger.info("Requesting token grant=%s user=%s", grant_type, PASSWORD_USER if grant_type == "password" else "N/A")
    resp = requests.post(
        KEYCLOAK_URL,
        data=payload,
        auth=auth,
        timeout=10,
    )
    resp.raise_for_status()
    token_data = resp.json()
    token = token_data["access_token"]
    claims = decode_jwt(token)
    logger.info(
        "Captured token exp=%s claims=%s",
        claims.get("exp"),
        summarize_claims(claims),
    )
    print("JWT:", token)
    return token


def call_tool(tool: str, args: dict[str, str], grant_type: str) -> dict:
    """Send a tools/call JSON-RPC request to the MCP gateway."""
    token = fetch_token(grant_type)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json,text/event-stream",
    }
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": args,
        },
    }
    resp = requests.post(MCP_ENDPOINT, json=payload, headers=headers, timeout=20)
    resp.raise_for_status()
    if resp.headers.get("Content-Type", "").startswith("text/event-stream"):
        return parse_event_stream(resp)
    return resp.json()


def parse_event_stream(resp: requests.Response) -> dict:
    """Extract the first JSON payload from a text/event-stream response."""
    for raw_line in resp.iter_lines(decode_unicode=True):
        if not raw_line:
            continue
        raw_line = raw_line.strip()
        if raw_line.startswith("data:"):
            raw_payload = raw_line[len("data:") :].strip()
            if raw_payload:
                return json.loads(raw_payload)
    raise ValueError("No data lines found in event stream response")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Call MCP tool via Kong with Keycloak auth.")
    parser.add_argument("--city", "-c", default="Firenze", help="City name to fetch weather for.")
    parser.add_argument("--tool", "-t", default="get_current_weather", help="Tool name to invoke.")
    parser.add_argument(
        "--grant-type",
        "-g",
        choices=("client_credentials", "password"),
        default="client_credentials",
        help="Keycloak grant that should be used (password uses testuser01/testuser01).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = call_tool(args.tool, {"city": args.city}, args.grant_type)
    except (requests.RequestException, ValueError) as exc:
        print("Request failed:", exc, file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
