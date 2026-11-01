import os

import httpx
from mcp.server.fastmcp import Context, FastMCP

ORDERS_API_URL = os.getenv("ORDERS_API_URL", "http://orders-api:8000")

mcp = FastMCP("orders-mcp", host="0.0.0.0", port=8000, stateless_http=True, json_response=True)


@mcp.tool()
def get_orders(ctx: Context) -> str:
    """List all orders."""
    auth = ctx.request_context.request.headers.get("authorization", "")
    resp = httpx.get(f"{ORDERS_API_URL}/api/orders", headers={"Authorization": auth}, timeout=10)
    if resp.status_code >= 400:
        return f"Orders API error {resp.status_code}: {resp.text}"
    return resp.text


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
