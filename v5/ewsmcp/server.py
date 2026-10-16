"""MCP wiring: low-level Server, annotations, structured output, lifecycle."""

import json
import logging
from typing import Any, Dict, Optional

from mcp.server import Server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
    ToolAnnotations,
)

from . import __version__
from .audit import AuditLog
from .config import Settings
from .gateway.client import EWSGateway
from .gateway.connection import ConnectionManager
from .ids import NullAliaser, get_aliaser
from .tools import build_registry
from .tools.base import Context, dispatch

logger = logging.getLogger(__name__)

# ASGI scope key under which the HTTP layer hands the caller's own Context
# (multi-user mode) to the MCP handlers.
CTX_SCOPE_KEY = "ewsmcp.ctx"

ANNOTATIONS = {
    "read": ToolAnnotations(read_only_hint=True, destructive_hint=False,
                            idempotent_hint=True, open_world_hint=False),
    "write": ToolAnnotations(read_only_hint=False, destructive_hint=False,
                             idempotent_hint=False, open_world_hint=False),
    "destructive": ToolAnnotations(read_only_hint=False, destructive_hint=True,
                                   idempotent_hint=False, open_world_hint=False),
    "send": ToolAnnotations(read_only_hint=False, destructive_hint=True,
                            idempotent_hint=False, open_world_hint=True),
}


class _NullAudit:
    def record(self, *args, **kwargs) -> None:
        return None


def build_context(settings: Settings) -> Context:
    if settings.mcp_oauth_enabled:
        return _build_service_context(settings)
    gateway = EWSGateway(settings)
    # Aliaser/audit are quality-of-life layers — their storage failing
    # (bad volume, permissions) degrades them to pass-through, never
    # prevents boot: the never-exit contract covers local disks too.
    try:
        aliaser = get_aliaser(f"{settings.data_dir}/memory")
    except Exception as exc:
        logger.error("aliaser init failed (%s) — running with raw EWS ids", exc)
        aliaser = NullAliaser()
    audit = _build_audit(settings)
    cache = None
    if settings.ews_cache_enabled:
        try:
            from .cache import CacheStore
            cache = CacheStore(f"{settings.data_dir}/cache/mirror.db")
            if settings.ews_cache_purge_on_boot:
                cache.purge()
        except Exception as exc:
            logger.error("cache init failed (%s) — running pure-EWS reads", exc)
            cache = None
    semantic = None
    try:
        from .semantic import build_semantic_index
        semantic = build_semantic_index(settings)
    except Exception as exc:
        logger.error("semantic index init failed (%s) — keyword-only", exc)
    ctx = Context(
        settings=settings,
        gateway=gateway,
        manager=None,
        aliaser=aliaser,
        audit=audit,
        cache=cache,
        semantic=semantic,
    )
    build_registry(ctx)
    return ctx


def _build_audit(settings: Settings):
    try:
        return AuditLog(settings.data_dir)
    except Exception as exc:
        logger.error("audit init failed (%s) — audit disabled", exc)
        return _NullAudit()


def _build_service_context(settings: Settings) -> Context:
    """Multi-user mode: the process-level Context owns no mailbox — it holds
    the registry, audit and counters that per-user contexts share."""
    ctx = Context(settings=settings, gateway=None, manager=None,
                  aliaser=NullAliaser(), audit=_build_audit(settings))
    build_registry(ctx)
    return ctx


async def start_connection_manager(ctx: Context) -> None:
    if ctx.gateway is None:  # multi-user: sessions open per user, on demand
        return
    manager = ConnectionManager(
        ctx.gateway,
        max_backoff=float(ctx.settings.ews_warmup_max_backoff_seconds),
        heartbeat_seconds=int(ctx.settings.ews_heartbeat_seconds),
    )
    ctx.manager = manager

    async def on_warm() -> None:
        # The sync engine is owned by the warm state: it starts only once
        # Exchange has answered (and keeps running through later outages —
        # its own cycles degrade gracefully).
        if ctx.cache is not None and ctx.sync is None:
            try:
                from .cache import SyncEngine
                ctx.sync = SyncEngine(ctx.settings, ctx.gateway, ctx.cache,
                                      semantic=ctx.semantic)
                await ctx.sync.start()
            except Exception as exc:
                logger.error("sync engine start failed (%s) — cache stays "
                             "stale; reads fall back to live EWS", exc)

    await manager.start(on_warm=on_warm)
    logger.info("Exchange warmup running in background (see /readyz)")


def tool_result(result: Any) -> CallToolResult:
    """Envelope dict → CallToolResult: JSON text for every client plus the
    same object as structured content; ``ok: false`` marks an error result."""
    text = json.dumps(result, ensure_ascii=False, default=str, indent=2)
    structured = json.loads(text) if isinstance(result, dict) else None
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=structured,
        is_error=isinstance(result, dict) and result.get("ok") is False,
    )


def build_mcp_server(ctx: Context) -> Server:
    multi_user = bool(ctx.settings.mcp_oauth_enabled)

    def caller_ctx(rctx) -> Optional[Context]:
        request = getattr(rctx, "request", None)
        scope = getattr(request, "scope", None) or {}
        user_ctx = scope.get(CTX_SCOPE_KEY)
        if user_ctx is not None:
            return user_ctx
        return None if multi_user else ctx

    async def list_tools(rctx, params: Optional[PaginatedRequestParams]) -> ListToolsResult:
        tools = []
        for spec in ctx.registry.values():
            schema = spec.public_schema()
            tools.append(Tool(
                name=schema["name"],
                description=schema["description"],
                input_schema=schema["inputSchema"],
                annotations=ANNOTATIONS.get(spec.side_effect_class, ANNOTATIONS["write"]),
            ))
        return ListToolsResult(tools=tools)

    async def call_tool(rctx, params: CallToolRequestParams) -> CallToolResult:
        target = caller_ctx(rctx)
        if target is None:
            return tool_result({"ok": False, "error": {
                "code": "auth_failed", "message": "no signed-in user for this request"}})
        name = params.name
        arguments: Dict[str, Any] = dict(params.arguments or {})
        spec = target.registry.get(name)
        if spec is None:
            return tool_result({"ok": False, "error": {
                "code": "validation",
                "message": f"Unknown tool: {name}",
                "hint": f"Available: {', '.join(sorted(target.registry))}",
            }})
        return tool_result(await dispatch(target, spec, arguments, transport="mcp"))

    return Server("ews-mcp-v5", version=__version__,
                  on_list_tools=list_tools, on_call_tool=call_tool)


async def run_stdio(settings: Settings) -> None:
    from mcp.server.stdio import stdio_server

    ctx = build_context(settings)
    server = build_mcp_server(ctx)
    await start_connection_manager(ctx)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())
