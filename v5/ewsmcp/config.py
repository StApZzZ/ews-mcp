"""Environment-driven configuration (12-factor; every knob defaults safe)."""

from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlparse

from exchangelib import EWSTimeZone
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Path fragments that identify cloud-synced folders. The data dir holds
# mail-at-rest (alias DB, audit chain, cache mirror) — it must never ride
# a sync client onto other machines or a vendor cloud.
_SYNCED_MARKERS = ("onedrive", "dropbox", "google drive", "googledrive", "icloud")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # --- Exchange upstream -------------------------------------------------
    ews_server_url: str
    # Single-mailbox modes only; in OAuth mode every user signs in with their
    # own Exchange credentials and these stay unset.
    ews_email: Optional[str] = None
    ews_username: Optional[str] = None
    ews_password: Optional[str] = None
    # NEVER pin auth_type against this Exchange: the front door only works
    # via exchangelib auto-negotiation (verified live 2026-06-12; pinning
    # BASIC/NTLM both fail). Escape hatch for a *different* server only.
    ews_auth_type_force: Optional[Literal["basic", "ntlm", "digest"]] = None
    ews_insecure_skip_verify: bool = False
    ews_tz: str = ""  # IANA name; empty → the host's local zone (UTC if unknown)
    request_timeout: int = 30

    # --- Reliability --------------------------------------------------------
    ews_warmup_max_backoff_seconds: int = 300
    ews_heartbeat_seconds: int = 600
    ews_retry_max_wait_seconds: int = 300
    ews_max_concurrency: int = 4
    circuit_failure_threshold: int = 5
    circuit_open_seconds: int = 60

    # --- Safety -------------------------------------------------------------
    ews_capability_tier: Literal["read", "draft", "full"] = "draft"
    send_enabled: bool = False  # kill-switch: v5 defaults SAFE (off)
    send_confirm_secret: Optional[str] = None
    confirm_ttl_seconds: int = 600  # ONE default everywhere (== confirm.DEFAULT_TTL_SECONDS)
    ews_recipient_allowlist: str = ""
    ews_recipient_denylist: str = ""
    ews_max_sends_per_hour: int = 10

    # --- Serving ------------------------------------------------------------
    mcp_transport: Literal["stdio", "http"] = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8000
    mcp_api_key: Optional[str] = None
    # Refuse an unauthenticated HTTP listener on a non-loopback address
    # unless this is set deliberately (e.g. a sidecar proxy does auth).
    mcp_allow_unauthenticated: bool = False
    # Client addresses whose X-Forwarded-* headers uvicorn trusts (the
    # reverse proxy). Login rate limits key on the resulting client IP.
    mcp_forwarded_allow_ips: str = "127.0.0.1"
    log_level: str = "INFO"

    # --- Multi-user OAuth 2.1 (HTTP only; DESIGN.md §Multi-user) ------------
    # The server becomes its own authorization server: clients register
    # dynamically, users sign in on /login with their Exchange credentials,
    # and every request runs against the caller's own mailbox.
    mcp_oauth_enabled: bool = False
    mcp_public_url: Optional[str] = None  # issuer, e.g. https://mcp.example.com
    # Exact-match allowlist for non-loopback redirect URIs (comma-separated),
    # e.g. https://claude.ai/api/mcp/auth_callback. Loopback is always allowed.
    mcp_oauth_allowed_redirect_uris: str = ""
    mcp_oauth_access_ttl_seconds: int = 3600
    mcp_oauth_refresh_ttl_seconds: int = 30 * 86400
    ews_user_idle_seconds: int = 1800  # drop an idle user's EWS session
    ews_max_users: int = 200  # live per-user EWS sessions (LRU beyond)

    # --- Storage (NEVER a synced folder) -------------------------------------
    data_dir: str = ""  # empty → ~/.ewsmcp; always resolved to an absolute path
    data_dir_allow_synced: bool = False  # explicit opt-out of the synced-path guard

    # --- Cache mirror (cache-first reads; false = pure EWS, fully functional)
    ews_cache_enabled: bool = True
    ews_cache_folders: str = "inbox,sent"
    ews_cache_sync_seconds: int = 45
    ews_cache_hierarchy_seconds: int = 600
    ews_cache_window_days: int = 365
    ews_cache_purge_on_boot: bool = False  # admin path: wipe + resync from scratch

    # --- Optional semantic tier (adapter; core stays dependency-free) --------
    ews_semantic_index: Literal["none", "pgvector"] = "none"
    ews_semantic_pg_dsn: Optional[str] = None  # from env only, never committed
    ews_semantic_ollama_url: str = "http://localhost:11434"
    ews_semantic_model: str = "bge-m3"  # 1024-d, Arabic-capable

    # --- Response economy ----------------------------------------------------
    default_page_size: int = Field(default=20, le=50)
    body_max_chars: int = 4000

    @model_validator(mode="after")
    def _resolve_data_dir(self) -> "Settings":
        raw = self.data_dir or str(Path.home() / ".ewsmcp")
        resolved = Path(raw).expanduser().resolve()
        if not self.data_dir_allow_synced:
            lowered = str(resolved).lower()
            marker = next((m for m in _SYNCED_MARKERS if m in lowered), None)
            if marker is not None:
                raise ValueError(
                    f"DATA_DIR {resolved} appears to be inside a cloud-synced "
                    f"folder ({marker!r}). It stores mail-at-rest (aliases, "
                    "audit chain, cache) and must stay local — point DATA_DIR "
                    "at a local path, or set DATA_DIR_ALLOW_SYNCED=true to "
                    "accept the risk deliberately."
                )
        self.data_dir = str(resolved)
        return self

    @model_validator(mode="after")
    def _resolve_tz(self) -> "Settings":
        if not self.ews_tz:
            self.ews_tz = _local_tz_name()
        return self

    @model_validator(mode="after")
    def _check_serving(self) -> "Settings":
        if self.mcp_oauth_enabled:
            if self.mcp_transport != "http":
                raise ValueError("MCP_OAUTH_ENABLED requires MCP_TRANSPORT=http")
            url = (self.mcp_public_url or "").rstrip("/")
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc or parsed.path or parsed.query:
                raise ValueError(
                    "MCP_OAUTH_ENABLED requires MCP_PUBLIC_URL as a bare origin, "
                    "e.g. https://mcp.example.com (it is the OAuth issuer)")
            if parsed.scheme != "https" and parsed.hostname not in LOOPBACK_HOSTS:
                raise ValueError("MCP_PUBLIC_URL must be https:// (http only for loopback)")
            self.mcp_public_url = url
        elif not self.ews_email:
            raise ValueError("EWS_EMAIL is required unless MCP_OAUTH_ENABLED=true")
        if (self.mcp_transport == "http" and not self.mcp_oauth_enabled
                and not self.mcp_api_key and not self.mcp_allow_unauthenticated
                and self.mcp_host not in LOOPBACK_HOSTS):
            raise ValueError(
                f"Refusing to serve {self.mcp_host}:{self.mcp_port} without auth: the "
                "listener exposes a mailbox. Set MCP_API_KEY or MCP_OAUTH_ENABLED=true "
                "(or MCP_ALLOW_UNAUTHENTICATED=true if a proxy in front does auth).")
        return self


LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def _local_tz_name() -> str:
    try:
        return EWSTimeZone.localzone().key
    except Exception:
        return "UTC"


def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
