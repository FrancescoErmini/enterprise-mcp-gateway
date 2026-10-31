# MCP demo

1. `docker compose up -d`
2. `DECK_WEATHERAPI_LOCAL_KEY=mcp-test-key-2026 deck gateway sync kong/weather-api-deck.yaml`
3. Configure Keycloak realm `mcp`, client `mcp`, user `testuser01` / password `testuser01` (or reuse your own secrets)
4. `cd mcp-client && python client.py --grant-type password`
