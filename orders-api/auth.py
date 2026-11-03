import logging
import os

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

ISSUER = os.getenv("JWT_ISSUER", "http://localhost:8080/realms/mcp-demo")
JWKS_URL = os.getenv(
    "JWKS_URL", "http://keycloak:8080/realms/mcp-demo/protocol/openid-connect/certs"
)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("orders-api")

_bearer = HTTPBearer(auto_error=False)
_jwks = jwt.PyJWKClient(JWKS_URL, cache_keys=True)


def require_role(role: str):
    """FastAPI dependency: validates the Keycloak JWT and checks for a realm role."""

    def dependency(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> dict:
        if creds is None:
            log.warning("DENY 401 no bearer token")
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
            log.warning("DENY 401 invalid token: %s", exc)
            raise HTTPException(401, f"Invalid token: {exc}")
        if role not in claims.get("realm_access", {}).get("roles", []):
            log.warning("DENY 403 user=%s lacks role %s", claims.get("preferred_username"), role)
            raise HTTPException(403, f"Role '{role}' required")
        log.info("ALLOW user=%s role=%s", claims.get("preferred_username"), role)
        return claims

    return dependency
