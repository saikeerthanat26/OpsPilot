"""Local bearer principal resolver. Production should replace this with OIDC."""
import json
import os
import secrets
from dataclasses import dataclass

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.platform.enterprise import AgentIdentity

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    subject: str
    identity: AgentIdentity


def authenticated_principal(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})
    try:
        configured = json.loads(os.getenv("OPSPILOT_API_IDENTITIES", "{}"))
        if not isinstance(configured, dict):
            raise ValueError()
        for token, claims in configured.items():
            if not token or not secrets.compare_digest(token.encode(), credentials.credentials.encode()):
                continue
            subject, tenant = claims["subject"], claims["tenant_id"]
            roles, scopes = claims["roles"], claims["environment_scopes"]
            if (not isinstance(subject, str) or not subject.strip()
                    or not isinstance(tenant, str) or not tenant.strip()
                    or not isinstance(roles, list) or not all(isinstance(r, str) for r in roles)
                    or not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes)):
                raise ValueError()
            return Principal(subject, AgentIdentity(subject, tenant, tuple(roles), tuple(scopes)))
    except (ValueError, KeyError, TypeError, AttributeError):
        raise HTTPException(503, "identity configuration invalid") from None
    raise HTTPException(401, "invalid credentials", headers={"WWW-Authenticate": "Bearer"})
