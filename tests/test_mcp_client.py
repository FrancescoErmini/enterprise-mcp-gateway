"""AI Agent simulator: authenticates as a user and calls MCP tools through Kong.

Usage: python tests/test_mcp_client.py          # mario.sales -> get_customers
       python tests/test_mcp_client.py --all    # plus authorization scenarios
"""
import argparse
import json
import sys
import time

import requests

KEYCLOAK = "http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token"
KONG = "http://localhost:8000"
# Deterministic routing (same map as kong/kong.yml): tool namespace -> Kong path. No scatter-gather.
NAMESPACE_ROUTES = {"crm": "/mcp/crm", "orders": "/mcp/orders"}
HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def wait_for_stack(timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get("http://localhost:8080/realms/mcp-demo", timeout=3).ok:
                return
        except requests.RequestException:
            pass
        print("Waiting for Keycloak...")
        time.sleep(3)
    sys.exit("Keycloak not reachable")


def get_token(username, password="test"):
    r = requests.post(KEYCLOAK, data={
        "grant_type": "password", "client_id": "frontend-web",
        "username": username, "password": password,
    })
    r.raise_for_status()
    return r.json()["access_token"]


def parse(resp):
    """Handle plain JSON or SSE-framed JSON-RPC responses."""
    if "text/event-stream" in resp.headers.get("content-type", ""):
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:])
    return resp.json() if resp.text else None


def rpc(path, token, method, params=None, rpc_id=1):
    headers = dict(HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if rpc_id is not None:
        body["id"] = rpc_id
    r = requests.post(f"{KONG}{path}", headers=headers, json=body)
    return r.status_code, parse(r) if r.status_code != 202 else None


def route_for(tool):
    """O(1): `crm_get_customers` -> /mcp/crm."""
    return NAMESPACE_ROUTES[tool.split("_", 1)[0]]


def call_tool(token, tool, arguments=None):
    path = route_for(tool)
    rpc(path, token, "initialize", {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "agent-simulator", "version": "1.0"},
    })
    rpc(path, token, "notifications/initialized", rpc_id=None)
    return rpc(path, token, "tools/call", {"name": tool, "arguments": arguments or {}}, rpc_id=2)


def list_tools(token, namespace):
    _, body = rpc(NAMESPACE_ROUTES[namespace], token, "tools/list")
    return sorted(t["name"] for t in body["result"]["tools"])


def check_list(label, token, namespace, expected):
    names = list_tools(token, namespace)
    ok = names == sorted(expected)
    print(f"[{'PASS' if ok else 'FAIL'}] {label}: tools/list {namespace} -> {names} (expected {sorted(expected)})")
    return ok


def scenario(label, expected_status, token, tool, arguments=None, body_has=None):
    status, body = call_tool(token, tool, arguments)
    ok = status == expected_status and (body_has is None or any(s in json.dumps(body) for s in body_has))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}: HTTP {status} (expected {expected_status})")
    print(json.dumps(body, indent=2)[:600])
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="run authorization scenarios too")
    args = ap.parse_args()

    wait_for_stack()
    mario, luigi, anna = get_token("mario.sales"), get_token("luigi.finance"), get_token("anna.admin")

    results = [scenario("mario.sales -> crm_get_customers", 200, mario, "crm_get_customers")]
    if args.all:
        results += [
            scenario("mario.sales -> orders_get_orders", 403, mario, "orders_get_orders"),
            scenario("mario.sales -> crm_delete_customer (needs crm-admin)", 403, mario, "crm_delete_customer", {"customer_id": 3}),
            scenario("anna.admin -> crm_delete_customer", 200, anna, "crm_delete_customer", {"customer_id": 3},
                     body_has=("deleted", "not found")),  # 2nd run: already deleted
            scenario("luigi.finance -> orders_get_orders", 200, luigi, "orders_get_orders"),
            scenario("luigi.finance -> crm_get_customers", 403, luigi, "crm_get_customers"),
            scenario("no token -> crm_get_customers", 401, None, "crm_get_customers"),
            check_list("mario.sales", mario, "crm", ["crm_get_customers"]),
            check_list("mario.sales", mario, "orders", []),
            check_list("anna.admin", anna, "crm", ["crm_get_customers", "crm_delete_customer"]),
            check_list("luigi.finance", luigi, "orders", ["orders_get_orders"]),
        ]
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
