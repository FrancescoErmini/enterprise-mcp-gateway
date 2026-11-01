import os

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

ISSUER = os.getenv("JWT_ISSUER", "http://localhost:8080/realms/mcp-demo")
JWKS_URL = os.getenv(
    "JWKS_URL", "http://keycloak:8080/realms/mcp-demo/protocol/openid-connect/certs"
)

_bearer = HTTPBearer(auto_error=False)
_jwks = jwt.PyJWKClient(JWKS_URL, cache_keys=True)


def require_role(role: str):
    """FastAPI dependency: validates the Keycloak JWT and checks for a realm role."""

    def dependency(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> dict:
        if creds is None:
            raise HTTPException(401, "Missing bearer token")
        try:
            key = _jwks.get_signing_key_from_jwt(creds.credentials).key
            claims = jwt.decode(
                creds.credentials,
                key,
                algorithms=["RS256"],
                issuer=ISSUER,
                options={"verify_aud": False},
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(401, f"Invalid token: {exc}")
        if role not in claims.get("realm_access", {}).get("roles", []):
            raise HTTPException(403, f"Role '{role}' required")
        return claims

    return dependency
