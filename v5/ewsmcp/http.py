"""HTTP serving: Streamable HTTP /mcp + REST shim + health (DESIGN.md §Transports)."""

import hmac
import json
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import jsonschema
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings

from . import __version__
from .config import LOOPBACK_HOSTS
from .errors import HTTP_BY_CODE
from .server import CTX_SCOPE_KEY, build_context, build_mcp_server, start_connection_manager
from .tools.base import dispatch

logger = logging.getLogger(__name__)

PUBLIC_PATHS = {"/health", "/livez", "/readyz", "/version"}
MAX_BODY_BYTES = 1_048_576  # 1 MiB — tool arguments, not attachments


def _validator_for(spec) -> Any:
    """Compiled validator for the tool's PUBLIC schema (which includes
    confirm_token for two-phase tools), cached on the spec itself so it can
    never go stale against a different spec of the same name."""
    v = getattr(spec, "_rest_validator", None)
    if v is None:
        v = jsonschema.Draft202012Validator(spec.public_schema()["inputSchema"])
        spec._rest_validator = v
    return v


def _authorized(headers, api_key: str) -> bool:
    expected = api_key.encode()
    for name, value in headers or []:
        lname = name.lower() if isinstance(name, bytes) else str(name).encode().lower()
        raw = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
        if lname == b"authorization" and raw.lower().startswith("bearer "):
            if hmac.compare_digest(raw[7:].strip().encode(), expected):
                return True
        elif lname == b"x-api-key":
            if hmac.compare_digest(raw.strip().encode(), expected):
                return True
    return False


async def _send_json(send, status: int, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False, default=str).encode()
    await send({"type": "http.response.start", "status": status, "headers": [
        [b"content-type", b"application/json"],
        [b"content-length", str(len(body)).encode()],
    ]})
    await send({"type": "http.response.body", "body": body})


def _metrics_text(ctx, oauth=None) -> str:
    """Prometheus exposition (text format 0.0.4). Behind the API key like
    every non-health endpoint — scrape with a bearer token."""
    import time as _t
    lines = [
        "# TYPE ewsmcp_uptime_seconds gauge",
        f"ewsmcp_uptime_seconds {int(_t.time() - ctx.started_at)}",
    ]
    if oauth is not None:
        lines += ["# TYPE ewsmcp_user_sessions gauge",
                  f"ewsmcp_user_sessions {len(oauth.tenants)}"]
    state = ctx.manager.state if ctx.manager else "unmanaged"
    lines += ["# TYPE ewsmcp_connection_warm gauge",
              f"ewsmcp_connection_warm {1 if state in ('warm', 'unmanaged') else 0}"]
    lines.append("# TYPE ewsmcp_tool_calls_total counter")
    lines.append("# TYPE ewsmcp_errors_total counter")
    for key, value in sorted(ctx.counters.items()):
        if key.startswith("tool."):
            lines.append(f'ewsmcp_tool_calls_total{{tool="{key[5:]}"}} {value}')
        elif key.startswith("err."):
            lines.append(f'ewsmcp_errors_total{{code="{key[4:]}"}} {value}')
    if ctx.cache is not None:
        try:
            stats = ctx.cache.stats()
            lines.append("# TYPE ewsmcp_cache_rows gauge")
            for table, n in stats.get("rows", {}).items():
                lines.append(f'ewsmcp_cache_rows{{table="{table}"}} {n}')
            lines.append("# TYPE ewsmcp_cache_db_mb gauge")
            lines.append(f"ewsmcp_cache_db_mb {stats.get('db_mb', 0)}")
        except Exception:
            pass
    if ctx.sync is not None:
        status = ctx.sync.status()
        lines.append("# TYPE ewsmcp_sync_cycles_total counter")
        lines.append(f"ewsmcp_sync_cycles_total {status.get('cycles', 0)}")
        age = status.get("last_cycle_age_s")
        if age is not None:
            lines.append("# TYPE ewsmcp_sync_last_cycle_age_seconds gauge")
            lines.append(f"ewsmcp_sync_last_cycle_age_seconds {age}")
        lines.append("# TYPE ewsmcp_sync_degraded gauge")
        lines.append(f"ewsmcp_sync_degraded {1 if status.get('last_error') else 0}")
    if ctx.semantic is not None:
        lines.append("# TYPE ewsmcp_semantic_enabled gauge")
        lines.append("ewsmcp_semantic_enabled 1")
    return "\n".join(lines) + "\n"


def _openapi(ctx) -> Dict[str, Any]:
    paths = {}
    for name, spec in ctx.registry.items():
        schema = spec.public_schema()
        paths[f"/api/tools/{name}"] = {"post": {
            "operationId": name,
            "summary": schema["description"][:120],
            "requestBody": {"content": {"application/json": {"schema": schema["inputSchema"]}}},
            "responses": {"200": {"description": "tool result"}},
        }}
    return {"openapi": "3.0.3",
            "info": {"title": "ews-mcp v5", "version": __version__},
            "paths": paths}


async def _read_json_body(receive, send) -> Optional[Any]:
    """Drain the request body (bounded) and parse JSON.

    Returns the parsed value, or None after having already sent an error
    response. A client disconnect mid-body returns None without sending
    (the old loop hung forever waiting for more http.request messages).
    """
    chunks = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None
        if message["type"] == "http.request":
            body = message.get("body", b"")
            size += len(body)
            if size > MAX_BODY_BYTES:
                await _send_json(send, 413, {"ok": False, "error": {
                    "code": "validation",
                    "message": f"request body exceeds {MAX_BODY_BYTES} bytes"}})
                return None
            chunks.append(body)
            if not message.get("more_body"):
                break
    try:
        return json.loads(b"".join(chunks) or b"{}")
    except Exception as e:
        await _send_json(send, 400, {"ok": False, "error": {
            "code": "validation", "message": f"invalid JSON body: {e}"}})
        return None


_NOT_FOUND = {"ok": False, "error": {"code": "validation", "message": "not found"}}
_UNAUTHORIZED = {"ok": False, "error": {
    "code": "auth_failed", "message": "missing or invalid bearer token"}}


def build_app(ctx, settings, streamable: Optional[Any] = None, oauth: Optional[Any] = None):
    """ASGI app closure — separated from serve_http so tests can drive it.

    ``oauth`` (an ``OAuthFrontend``) switches on multi-user mode: OAuth
    routes are served publicly and every other route runs as the verified
    caller, with their own Context in the scope.
    """
    api_key = settings.mcp_api_key or ""

    async def core(scope, receive, send):
        target = scope.get(CTX_SCOPE_KEY, ctx)
        path, method = scope["path"], scope["method"]
        if path == "/mcp":
            if streamable is None:
                return await _send_json(send, 503, {"ok": False, "error": {
                    "code": "upstream_unavailable",
                    "message": "MCP transport not mounted"}})
            return await streamable.handle_request(scope, receive, send)
        if path == "/openapi.json" and method == "GET":
            return await _send_json(send, 200, _openapi(ctx))
        if path == "/api/tools" and method == "GET":
            return await _send_json(send, 200, {"tools": [
                {"name": s.name, "class": s.side_effect_class,
                 "description": s.description[:140]}
                for s in ctx.registry.values()
            ]})
        if path.startswith("/api/tools/") and method == "POST":
            name = path.removeprefix("/api/tools/")
            spec = ctx.registry.get(name)
            if spec is None:
                return await _send_json(send, 404, {"ok": False, "error": {
                    "code": "validation", "message": f"Unknown tool: {name}"}})
            arguments = await _read_json_body(receive, send)
            if arguments is None:
                return
            if not isinstance(arguments, dict):
                return await _send_json(send, 400, {"ok": False, "error": {
                    "code": "validation",
                    "message": "request body must be a JSON object of tool arguments"}})
            error = jsonschema.exceptions.best_match(
                _validator_for(spec).iter_errors(arguments))
            if error is not None:
                return await _send_json(send, 400, {"ok": False, "error": {
                    "code": "validation", "message": error.message,
                    "hint": f"See the {name} schema in /openapi.json."}})
            result = await dispatch(target, spec, arguments, transport="rest")
            status = 200
            if isinstance(result, dict) and result.get("ok") is False:
                status = HTTP_BY_CODE.get(result.get("error", {}).get("code", ""), 500)
            return await _send_json(send, status, result)

        return await _send_json(send, 404, _NOT_FOUND)

    protected = oauth.protect(core) if oauth is not None else None

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await start_connection_manager(ctx)
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        path, method = scope["path"], scope["method"]

        if path == "/livez" and method == "GET":
            return await _send_json(send, 200, {"status": "ok"})
        if path == "/health" and method == "GET":
            return await _send_json(send, 200, {"status": "ok", "tools": len(ctx.registry)})
        if path == "/version" and method == "GET":
            return await _send_json(send, 200, {"version": __version__})
        if path == "/readyz" and method == "GET":
            conn = ctx.manager.status() if ctx.manager else {"state": "unmanaged"}
            warm = conn.get("state") in ("warm", "unmanaged")
            payload = {"status": "ok" if warm else "unavailable",
                       "connection": conn, "tools": len(ctx.registry)}
            if oauth is not None:
                payload["users"] = len(oauth.tenants)
            return await _send_json(send, 200 if warm else 503, payload)

        if path == "/metrics" and method == "GET":
            # Operator surface: the API key guards it; in multi-user mode it
            # exists only when a key is configured (user tokens never see it).
            if oauth is not None and not api_key:
                return await _send_json(send, 404, _NOT_FOUND)
            if api_key and not _authorized(scope.get("headers"), api_key):
                return await _send_json(send, 401, _UNAUTHORIZED)
            body = _metrics_text(ctx, oauth).encode()
            await send({"type": "http.response.start", "status": 200, "headers": [
                [b"content-type", b"text/plain; version=0.0.4; charset=utf-8"],
                [b"content-length", str(len(body)).encode()],
            ]})
            return await send({"type": "http.response.body", "body": body})

        if oauth is not None:
            if oauth.owns(path):
                return await oauth.handle(scope, receive, send)
            return await protected(scope, receive, send)
        if api_key and not _authorized(scope.get("headers"), api_key):
            return await _send_json(send, 401, _UNAUTHORIZED)
        return await core(scope, receive, send)

    return app


_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
]


def with_security_headers(app):
    """Baseline response headers on every route (DAST baseline findings)."""
    async def wrapped(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {bytes(k).lower() for k, _ in headers}
                headers += [(k, v) for k, v in _SECURITY_HEADERS if k not in present]
                message = {**message, "headers": headers}
            await send(message)

        await app(scope, receive, send_with_headers)
    return wrapped


def _transport_security(settings):
    """DNS-rebinding guard for loopback listeners: a web page in the user's
    browser must not be able to drive a local mailbox server."""
    if settings.mcp_host not in LOOPBACK_HOSTS:
        return None
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    if settings.mcp_public_url:  # behind a local reverse proxy
        public = urlparse(settings.mcp_public_url)
        hosts.append(public.netloc)
        origins.append(f"{public.scheme}://{public.netloc}")
    return TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                     allowed_hosts=hosts, allowed_origins=origins)


async def serve_http(settings) -> None:
    import uvicorn

    ctx = build_context(settings)
    oauth = None
    if settings.mcp_oauth_enabled:
        from .oauth.frontend import OAuthFrontend
        oauth = OAuthFrontend(settings, ctx)
    mcp_server = build_mcp_server(ctx)
    streamable = StreamableHTTPSessionManager(
        app=mcp_server, json_response=False, stateless=True,
        security_settings=_transport_security(settings))
    app = with_security_headers(build_app(ctx, settings, streamable, oauth))
    config = uvicorn.Config(app, host=settings.mcp_host, port=settings.mcp_port,
                            log_level=settings.log_level.lower(), http="h11",
                            proxy_headers=True,
                            forwarded_allow_ips=settings.mcp_forwarded_allow_ips,
                            server_header=False)
    try:
        async with streamable.run():
            await uvicorn.Server(config).serve()
    finally:
        if oauth is not None:
            oauth.tenants.close_all()
