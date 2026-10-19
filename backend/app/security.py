from dataclasses import dataclass
from functools import lru_cache
from typing import Any
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from app.config import settings

bearer = HTTPBearer(auto_error=False)

@dataclass(frozen=True)
class Principal:
    subject: str
    organization_id: str
    roles: frozenset[str]
    claims: dict[str, Any]

@lru_cache
def jwks_client():
    return PyJWKClient(settings.oidc_jwks_url, cache_keys=True)

def current_principal(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
    if credentials is None:
        raise HTTPException(401, "Sign-in required", headers={"WWW-Authenticate":"Bearer"})
    try:
        signing_key = jwks_client().get_signing_key_from_jwt(credentials.credentials)
        claims = jwt.decode(credentials.credentials, signing_key.key,
            algorithms=["RS256"], issuer=settings.oidc_issuer,
            audience=settings.oidc_audience, options={"require":["exp","iat","iss"]})
    except Exception as exc:
        raise HTTPException(401, "Invalid or expired identity token") from exc
    if settings.require_mfa:
        amr = claims.get("amr", [])
        if isinstance(amr,str): amr=[amr]
        acr = str(claims.get("acr", "")).lower()
        if not any(str(x).lower() in {"mfa", "otp", "hwk", "webauthn"} for x in amr) and not any(x in acr for x in ("mfa", "loa2", "loa3")):
            raise HTTPException(403, "Your identity provider must assert MFA for this session")
    roles = set(claims.get("roles", []))
    roles.update(claims.get("realm_access", {}).get("roles", []))
    if {"program_manager","security_analyst","authorization_approver","scanner_operator","validation_approver","evidence_custodian","remediation_owner","auditor"}.issubset(roles): roles.add("admin")
    org = claims.get("organization_id") or claims.get("org_id")
    if not org and settings.environment == "development":
        org = settings.oidc_dev_tenant
    if not org:
        raise HTTPException(403, "Identity token is missing the organization claim")
    subject = claims.get("sub") or claims.get("preferred_username") or claims.get("azp")
    if not subject:
        raise HTTPException(401, "Identity token is missing a subject")
    return Principal(str(subject), str(org), frozenset(roles), claims)

def require_roles(*required: str):
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.roles.intersection(required) and "admin" not in principal.roles:
            raise HTTPException(403, "Insufficient role")
        return principal
    return dependency
