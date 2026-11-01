import logging
import os

import httpx
from mcp.server.fastmcp import Context, FastMCP

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
# The SDK logs a harmless ClosedResourceError traceback when each stateless request ends
logging.getLogger("mcp.server.streamable_http").setLevel(logging.CRITICAL)
log = logging.getLogger("crm-mcp")

CRM_API_URL = os.getenv("CRM_API_URL", "http://crm-api:8000")

mcp = FastMCP("crm-mcp", host="0.0.0.0", port=8000, stateless_http=True, json_response=True)


def _call(ctx: Context, method: str, path: str) -> str:
    """Translate the tool call into a REST call, propagating the caller's JWT."""
    auth = ctx.request_context.request.headers.get("authorization", "")
    log.info("tool -> REST %s %s%s (JWT forwarded: %s)", method, CRM_API_URL, path, bool(auth))
    resp = httpx.request(method, f"{CRM_API_URL}{path}", headers={"Authorization": auth}, timeout=10)
    log.info("REST <- %s", resp.status_code)
    if resp.status_code >= 400:
        return f"CRM API error {resp.status_code}: {resp.text}"
    return resp.text


@mcp.tool()
def get_customers(ctx: Context) -> str:
    """List all CRM customers."""
    return _call(ctx, "GET", "/api/customers")


@mcp.tool()
def delete_customer(customer_id: int, ctx: Context) -> str:
    """Delete a CRM customer by id."""
    return _call(ctx, "DELETE", f"/api/customers/{customer_id}")


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
