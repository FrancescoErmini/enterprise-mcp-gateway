import logging
import os

import httpx
from mcp.server.fastmcp import Context, FastMCP

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
# The SDK logs a harmless ClosedResourceError traceback when each stateless request ends
logging.getLogger("mcp.server.streamable_http").setLevel(logging.CRITICAL)
log = logging.getLogger("orders-mcp")

ORDERS_API_URL = os.getenv("ORDERS_API_URL", "http://orders-api:8000")

mcp = FastMCP("orders-mcp", host="0.0.0.0", port=8000, stateless_http=True, json_response=True)


@mcp.tool()
def get_orders(ctx: Context) -> str:
    """List all orders."""
    auth = ctx.request_context.request.headers.get("authorization", "")
    log.info("tool get_orders -> REST GET %s/api/orders (JWT forwarded: %s)", ORDERS_API_URL, bool(auth))
    resp = httpx.get(f"{ORDERS_API_URL}/api/orders", headers={"Authorization": auth}, timeout=10)
    log.info("REST <- %s", resp.status_code)
    if resp.status_code >= 400:
        return f"Orders API error {resp.status_code}: {resp.text}"
    return resp.text


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
