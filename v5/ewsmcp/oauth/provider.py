"""OAuthAuthorizationServerProvider for the MCP SDK's auth routes.

The SDK owns the protocol surface (metadata, /register, /authorize
validation, /token with PKCE, /revoke); this class owns storage, the
redirect-URI policy and the hand-off to the ``/login`` form.
"""

import ipaddress
import logging
import secrets
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import Field

from ..config import Settings
from .sealing import new_token, seal, token_id, unseal
from .store import Grant, OAuthStore

logger = logging.getLogger(__name__)

SCOPE = "ews"
CODE_TTL_SECONDS = 300
LOGIN_TTL_SECONDS = 600
MAX_PENDING_LOGINS = 1000


# Grant models extended with the decrypted Exchange credentials. ``secret``
# lives only in memory for the request that unsealed it: never repr'd,
# never serialized.
class EwsAuthorizationCode(AuthorizationCode):
    username: str = ""
    secret: str = Field(default="", repr=False, exclude=True)
    family: str = ""


class EwsRefreshToken(RefreshToken):
    username: str = ""
    secret: str = Field(default="", repr=False, exclude=True)
    family: str = ""


class EwsAccessToken(AccessToken):
    username: str = ""
    secret: str = Field(default="", repr=False, exclude=True)
    family: str = ""


def is_loopback_redirect(uri: str) -> bool:
    parsed = urlparse(uri)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    if parsed.hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


class PendingLogin:
    def __init__(self, client: OAuthClientInformationFull, params: AuthorizationParams):
        self.client = client
        self.params = params
        self.expires_at = time.time() + LOGIN_TTL_SECONDS


class EwsOAuthProvider:
    def __init__(self, settings: Settings, store: OAuthStore):
        self.settings = settings
        self.store = store
        self.issuer = settings.mcp_public_url
        self.resource = f"{settings.mcp_public_url}/mcp"
        self._allowed_redirects = {
            u.strip() for u in settings.mcp_oauth_allowed_redirect_uris.split(",") if u.strip()
        }
        self._pending: Dict[str, PendingLogin] = {}
        self._pending_lock = threading.Lock()

    # ---------------------------------------------------------------- clients

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        info = self.store.get_client(client_id)
        return OAuthClientInformationFull.model_validate(info) if info else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            uri = str(uri)
            if not (is_loopback_redirect(uri) or uri in self._allowed_redirects):
                raise RegistrationError(
                    "invalid_redirect_uri",
                    f"redirect_uri {uri} is not allowed on this server "
                    "(loopback, or an exact MCP_OAUTH_ALLOWED_REDIRECT_URIS entry)")
        if not self.store.put_client(client_info.client_id,
                                     client_info.model_dump(mode="json")):
            raise RegistrationError("invalid_client_metadata",
                                    "client registry is full; try again later")
        logger.info("oauth client registered: %s (%s)", client_info.client_id,
                    client_info.client_name or "-")

    # -------------------------------------------------------------- authorize

    async def authorize(self, client: OAuthClientInformationFull,
                        params: AuthorizationParams) -> str:
        txn = secrets.token_urlsafe(24)
        now = time.time()
        with self._pending_lock:
            for k in [k for k, p in self._pending.items() if p.expires_at < now]:
                del self._pending[k]
            if len(self._pending) >= MAX_PENDING_LOGINS:
                self._pending.pop(next(iter(self._pending)))
            self._pending[txn] = PendingLogin(client, params)
        return f"{self.issuer}/login?txn={txn}"

    def pending(self, txn: str) -> Optional[PendingLogin]:
        with self._pending_lock:
            p = self._pending.get(txn or "")
            if p is not None and p.expires_at < time.time():
                del self._pending[txn]
                p = None
        return p

    def complete_login(self, txn: str, subject: str, username: str, password: str) -> str:
        """Mint the authorization code for a verified login; returns the
        client redirect URL. The pending request is single-use."""
        with self._pending_lock:
            p = self._pending.pop(txn, None)
        if p is None or p.expires_at < time.time():
            raise KeyError("login request expired")
        code = new_token("ewsac")
        self.store.put_grant(Grant(
            id=token_id(code), kind="code", family=secrets.token_hex(16),
            client_id=p.client.client_id, subject=subject, username=username,
            scopes=p.params.scopes or [SCOPE], resource=self.resource,
            expires_at=time.time() + CODE_TTL_SECONDS, sealed=seal(code, password),
            extra={
                "code_challenge": p.params.code_challenge,
                "redirect_uri": str(p.params.redirect_uri),
                "redirect_uri_provided_explicitly": p.params.redirect_uri_provided_explicitly,
            }))
        logger.info("oauth code issued for %s (client %s)", subject, p.client.client_id)
        return construct_redirect_uri(str(p.params.redirect_uri), code=code,
                                      state=p.params.state)

    # ------------------------------------------------------------------ codes

    def _load(self, token: str, kind: str, client_id: Optional[str]) -> Optional[Tuple[Grant, str]]:
        g = self.store.get_grant(token_id(token), kind)
        if g is None or (client_id is not None and g.client_id != client_id):
            return None
        secret = unseal(token, g.sealed)
        if secret is None:
            return None
        return g, secret

    async def load_authorization_code(self, client: OAuthClientInformationFull,
                                      authorization_code: str
                                      ) -> Optional[EwsAuthorizationCode]:
        hit = self._load(authorization_code, "code", client.client_id)
        if hit is None:
            return None
        g, secret = hit
        return EwsAuthorizationCode(
            code=authorization_code, scopes=g.scopes, expires_at=g.expires_at,
            client_id=g.client_id, code_challenge=g.extra["code_challenge"],
            redirect_uri=g.extra["redirect_uri"],
            redirect_uri_provided_explicitly=g.extra["redirect_uri_provided_explicitly"],
            resource=g.resource, subject=g.subject, username=g.username, secret=secret,
            family=g.family)

    async def exchange_authorization_code(self, client: OAuthClientInformationFull,
                                          authorization_code: EwsAuthorizationCode
                                          ) -> OAuthToken:
        self.store.delete_grant(token_id(authorization_code.code))  # single-use
        return self._issue(client.client_id, authorization_code.subject or "",
                           authorization_code.username, authorization_code.secret,
                           authorization_code.scopes, authorization_code.family)

    # ----------------------------------------------------------------- tokens

    def _issue(self, client_id: str, subject: str, username: str, secret: str,
               scopes: List[str], family: str) -> OAuthToken:
        now = time.time()
        access, refresh = new_token("ewsat"), new_token("ewsrt")
        ttl = self.settings.mcp_oauth_access_ttl_seconds
        for token, kind, expires in (
                (access, "access", now + ttl),
                (refresh, "refresh", now + self.settings.mcp_oauth_refresh_ttl_seconds)):
            self.store.put_grant(Grant(
                id=token_id(token), kind=kind, family=family, client_id=client_id,
                subject=subject, username=username, scopes=scopes, resource=self.resource,
                expires_at=expires, sealed=seal(token, secret), extra={}))
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ttl,
                          refresh_token=refresh, scope=" ".join(scopes))

    async def load_refresh_token(self, client: OAuthClientInformationFull,
                                 refresh_token: str) -> Optional[EwsRefreshToken]:
        hit = self._load(refresh_token, "refresh", client.client_id)
        if hit is None:
            return None
        g, secret = hit
        return EwsRefreshToken(
            token=refresh_token, client_id=g.client_id, scopes=g.scopes,
            expires_at=int(g.expires_at), resource=g.resource, subject=g.subject,
            username=g.username, secret=secret, family=g.family)

    async def exchange_refresh_token(self, client: OAuthClientInformationFull,
                                     refresh_token: EwsRefreshToken,
                                     scopes: List[str]) -> OAuthToken:
        # Rotation: the old refresh token AND its access tokens die now, so
        # a replayed refresh token is simply unknown.
        self.store.delete_family(refresh_token.family)
        return self._issue(client.client_id, refresh_token.subject or "",
                           refresh_token.username, refresh_token.secret,
                           scopes or refresh_token.scopes, secrets.token_hex(16))

    async def load_access_token(self, token: str) -> Optional[EwsAccessToken]:
        hit = self._load(token, "access", None)
        if hit is None:
            return None
        g, secret = hit
        return EwsAccessToken(
            token=token, client_id=g.client_id, scopes=g.scopes,
            expires_at=int(g.expires_at), resource=g.resource, subject=g.subject,
            username=g.username, secret=secret, family=g.family)

    async def revoke_token(self, token) -> None:
        family = getattr(token, "family", "")
        if family:
            self.store.delete_family(family)
        else:
            self.store.delete_grant(token_id(token.token))

    def revoke_subject(self, subject: str) -> None:
        n = self.store.delete_subject(subject)
        logger.warning("revoked %d oauth grant(s) for %s: Exchange rejected the "
                       "stored credentials", n, subject)
