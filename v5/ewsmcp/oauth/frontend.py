"""HTTP face of multi-user mode: OAuth routes in, a per-user Context out.

Public: RFC 8414 / RFC 9728 metadata, /register, /authorize, /token,
/revoke (all from the MCP SDK) and /login. Everything else passes through
bearer authentication; the verified token's sealed credentials select the
caller's own Context, which the MCP handlers and the REST shim pick up from
the ASGI scope.
"""

import json
from typing import Any

from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.routes import (
    build_resource_metadata_url,
    create_auth_routes,
    create_protected_resource_routes,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.routing import Route

from ..config import Settings
from ..server import CTX_SCOPE_KEY
from ..tenancy import UserContexts
from ..tools.base import Context
from .login import FixedWindowLimiter, LoginForm
from .provider import SCOPE, EwsOAuthProvider
from .store import OAuthStore

PRM_PATH = "/.well-known/oauth-protected-resource"


class OAuthFrontend:
    def __init__(self, settings: Settings, base: Context):
        self.store = OAuthStore(settings.data_dir)
        self.store.purge_expired()
        self.provider = EwsOAuthProvider(settings, self.store)
        self.tenants = UserContexts(base, on_revoke=self.provider.revoke_subject)
        issuer = AnyHttpUrl(self.provider.issuer)
        resource = AnyHttpUrl(self.provider.resource)
        self.resource_metadata_url = build_resource_metadata_url(resource)

        routes = create_auth_routes(
            self.provider, issuer,
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]),
            revocation_options=RevocationOptions(enabled=True),
        )
        prm = create_protected_resource_routes(
            resource, [issuer], scopes_supported=[SCOPE],
            resource_name="Exchange mailbox (EWS)")
        routes += prm
        # Clients that probe the bare well-known path get the same document.
        routes.append(Route(PRM_PATH, endpoint=prm[0].endpoint, methods=["GET", "OPTIONS"]))
        routes.append(Route("/login", LoginForm(self.provider).handle, methods=["GET", "POST"]))
        self._paths = {r.path for r in routes}
        self._routes_app = Starlette(routes=routes)
        self._register_limiter = FixedWindowLimiter(20, 3600)
        self._backend = BearerAuthBackend(ProviderTokenVerifier(self.provider),
                                          resource_server_url=resource)

    def owns(self, path: str) -> bool:
        return path in self._paths

    async def handle(self, scope, receive, send) -> None:
        if scope["path"] == "/register" and scope["method"] == "POST":
            ip = (scope.get("client") or ("-",))[0]
            if not self._register_limiter.allow(ip):
                body = json.dumps({"error": "slow_down",
                                   "error_description": "too many registrations"}).encode()
                await send({"type": "http.response.start", "status": 429, "headers": [
                    (b"content-type", b"application/json"), (b"retry-after", b"3600"),
                    (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
        await self._routes_app(scope, receive, send)

    def protect(self, inner: Any) -> Any:
        """Wrap ``inner`` so it only ever runs as a verified user, with that
        user's Context in the scope. Failures answer 401 + resource_metadata."""
        tenants = self.tenants

        async def bind_user(scope, receive, send):
            token = scope["user"].access_token
            scope[CTX_SCOPE_KEY] = tenants.get(token.subject, token.username, token.secret)
            await inner(scope, receive, send)

        return AuthenticationMiddleware(
            RequireAuthMiddleware(bind_user, [], self.resource_metadata_url),
            backend=self._backend)
