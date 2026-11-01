"""Chat backend: OpenAI tool-calling loop whose tools are the MCP servers behind Kong.

The user's Keycloak JWT is forwarded on every MCP call, so Kong -> OPA guard -> micro-MCP -> API
all act on behalf of the logged-in user.
"""
import json
import logging
import os

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("chat")

KONG_URL = os.getenv("KONG_URL", "http://kong:8000")
MCP_PATHS = os.getenv("MCP_PATHS", "/mcp/crm,/mcp/orders").split(",")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
MAX_STEPS = 5

SYSTEM_PROMPT = (
    "You are an enterprise assistant. Use the available tools to answer questions about CRM "
    "customers and orders. Always ask the user for explicit confirmation before deleting anything. "
    "If a tool reports that access is denied, tell the user they lack permission."
)

app = FastAPI(title="MCP Chat")
client = httpx.AsyncClient(timeout=60)


class ChatRequest(BaseModel):
    messages: list[dict]


async def mcp_rpc(path: str, token: str, method: str, params: dict | None = None):
    resp = await client.post(
        f"{KONG_URL}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
    )
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, {"error": {"message": resp.text}}


async def discover_tools(token: str):
    """tools/list on every MCP endpoint -> (OpenAI tool specs, tool name -> endpoint path)."""
    specs, routes = [], {}
    for path in MCP_PATHS:
        status, body = await mcp_rpc(path, token, "tools/list")
        if status != 200:
            continue
        for tool in body.get("result", {}).get("tools", []):
            routes[tool["name"]] = path
            specs.append({"type": "function", "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool.get("inputSchema", {"type": "object", "properties": {}}),
            }})
    return specs, routes


async def run_tool(path: str, token: str, name: str, args: dict) -> str:
    status, body = await mcp_rpc(path, token, "tools/call", {"name": name, "arguments": args})
    if status != 200:
        return f"ACCESS DENIED or error (HTTP {status}): {body.get('error', {}).get('message', body)}"
    result = body.get("result", {})
    return "".join(c.get("text", "") for c in result.get("content", [])) or json.dumps(result)


@app.get("/health")
def health():
    return {"status": "ok", "openai_configured": bool(OPENAI_API_KEY)}


@app.post("/api/chat")
async def chat(req: ChatRequest, request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = auth.split(" ", 1)[1]
    if not OPENAI_API_KEY:
        raise HTTPException(500, "OPENAI_API_KEY not configured (.env)")

    tools, routes = await discover_tools(token)
    log.info("user message=%r | tools discovered via Kong: %s", req.messages[-1].get("content"), list(routes))
    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + req.messages
    trace = []

    for _ in range(MAX_STEPS):
        payload = {"model": OPENAI_MODEL, "messages": messages}
        if tools:
            payload["tools"] = tools
        r = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json=payload,
        )
        if r.status_code != 200:
            raise HTTPException(502, f"OpenAI error {r.status_code}: {r.text[:300]}")
        msg = r.json()["choices"][0]["message"]
        log.info("OpenAI (%s) -> %s", OPENAI_MODEL, "tool_calls" if msg.get("tool_calls") else "final answer")
        messages.append(msg)
        if not msg.get("tool_calls"):
            return {"reply": msg.get("content") or "", "tool_calls": trace}

        for call in msg["tool_calls"]:
            name = call["function"]["name"]
            args = json.loads(call["function"]["arguments"] or "{}")
            path = routes.get(name)
            log.info("MCP call %s tool=%s args=%s", path, name, args)
            result = await run_tool(path, token, name, args) if path else f"Unknown tool {name}"
            log.info("MCP result %s: %s", name, result[:120])
            trace.append({"tool": name, "arguments": args, "result": result})
            messages.append({"role": "tool", "tool_call_id": call["id"], "content": result})

    return {"reply": "Stopped: too many tool-call steps.", "tool_calls": trace}


@app.get("/")
def index():
    return FileResponse("index.html")
