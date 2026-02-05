# MCP Client

Lightweight consumer script that authenticates against Keycloak and sends a JSON-RPC request to the MCP server exposed via Kong.

## Requirements

- Python 3.11+
- The dependencies in `requirements.txt` (`requests`)
- Keycloak running with the `mcp` realm/client and the credentials you already configured.

## Usage

1. Install dependencies: `pip install -r requirements.txt`
2. Export overrides if you changed defaults:
   ```bash
   export KEYCLOAK_TOKEN_URL=http://localhost:8081/realms/mcp/protocol/openid-connect/token
   export KEYCLOAK_CLIENT_ID=mcp
   export KEYCLOAK_CLIENT_SECRET=uOxcgeKNfuWs7QK4D8qTqsQ8JzsLJe22
   export MCP_ENDPOINT=http://localhost:8000/mcp
   export KEYCLOAK_PASSWORD_USER=testuser01
   export KEYCLOAK_PASSWORD_PASSWORD=testuser01
   ```
3. Run `python client.py --city Firenze`.

To use the password grant (testuser01/testuser01), add `--grant-type password`.

The script will fetch a token, call the `get_current_weather` tool (or whichever tool you pass via `--tool`), and print the JSON-RPC response.
