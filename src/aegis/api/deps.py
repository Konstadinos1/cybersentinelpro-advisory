"""FastAPI dependencies: service lookup and caller authentication."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from aegis.agency_guard import IdentityError, UserIdentity
from aegis.runtime import Services

ADMIN_ROLE = "security-admin"

_bearer = HTTPBearer(auto_error=False)


def get_services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services


ServicesDep = Annotated[Services, Depends(get_services)]
CredentialsDep = Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]


def bearer_token(credentials: CredentialsDep) -> str:
    if credentials is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


TokenDep = Annotated[str, Depends(bearer_token)]


def current_identity(services: ServicesDep, token: TokenDep) -> UserIdentity:
    try:
        return services.verifier.verify(token)
    except IdentityError as error:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, str(error), headers={"WWW-Authenticate": "Bearer"}
        ) from error


IdentityDep = Annotated[UserIdentity, Depends(current_identity)]


def require_admin(identity: IdentityDep) -> UserIdentity:
    if ADMIN_ROLE not in identity.roles:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"role {ADMIN_ROLE!r} required")
    return identity


AdminDep = Annotated[UserIdentity, Depends(require_admin)]
