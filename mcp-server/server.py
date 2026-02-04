import os

import requests
from fastmcp import FastMCP

MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8080"))
WEATHER_API_BASE_URL = os.getenv("WEATHER_API_BASE_URL", "http://weather-api:5000/weather")
DEFAULT_WEATHER_API_KEY = os.getenv("WEATHERAPI_API_KEY", "mcp-test-key-2026")

mcp = FastMCP("weather", stateless_http=True)


@mcp.tool()
def ping() -> str:
    """Return pong"""
    return "pong"


@mcp.tool()
def add(x: int, y: int) -> int:
    """Add two numbers"""
    return x + y


@mcp.tool()
def get_current_weather(city: str = "Firenze") -> str:
    """Fetch current weather by calling the local Flask weather API."""
    params = {"city": city}
    headers = {"X-API-Key": DEFAULT_WEATHER_API_KEY}
    response = requests.get(WEATHER_API_BASE_URL, params=params, headers=headers)
    response.raise_for_status()
    data = response.json()

    location = data.get("location", city)
    temperature = data.get("temperature", data.get("temp", "unknown temperature"))
    unit = data.get("unit", "")
    condition = data.get("description", data.get("condition", "unknown condition"))

    unit_display = f" {unit}" if unit else ""
    return f"Weather in {location}: {temperature}{unit_display}, {condition}"


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host=MCP_HOST,
        port=MCP_PORT,
    )
