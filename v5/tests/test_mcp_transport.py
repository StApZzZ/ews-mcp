"""MCP over Streamable HTTP in single-mailbox mode (SDK 2.x wiring).

Drives the real StreamableHTTPSessionManager + build_app with an API key:
initialize → tools/list (annotations present) → tools/call (envelope as
JSON text + structured content, ``ok: false`` flagged as an error).
"""

import json

import httpx
import pytest
from conftest import make_settings
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from ewsmcp.audit import AuditLog
from ewsmcp.http import build_app
from ewsmcp.ids import get_aliaser
from ewsmcp.server import build_mcp_server
from ewsmcp.tools.base import Context, ToolSpec

KEY = "k-123"
HEADERS = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json",
           "Accept": "application/json, text/event-stream",
           "MCP-Protocol-Version": "2025-06-18"}


async def _echo(ctx, q=""):
    if q == "fail":
        return {"ok": False, "error": {"code": "validation", "message": "nope"}}
    return {"ok": True, "echo": q, "mailbox": ctx.settings.ews_email}


def _ctx(tmp_path):
    ctx = Context(settings=make_settings(mcp_api_key=KEY), gateway=None, manager=None,
                  aliaser=get_aliaser(str(tmp_path / "alias")),
                  audit=AuditLog(str(tmp_path / "audit")))
    ctx.registry = {"echo": ToolSpec(
        name="echo", description="echo", side_effect_class="read",
        input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
        handler=_echo, requires_ews=False)}
    return ctx


def _result(response):
    for line in response.text.splitlines():
        if line.startswith("data:"):
            msg = json.loads(line[5:])
            if "result" in msg or "error" in msg:
                return msg
    return response.json()


async def _rpc(client, rid, method, params):
    r = await client.post("/mcp", headers=HEADERS, json={
        "jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    assert r.status_code == 200, r.text
    return _result(r)


@pytest.mark.asyncio
async def test_list_and_call_over_streamable_http(tmp_path):
    ctx = _ctx(tmp_path)
    streamable = StreamableHTTPSessionManager(app=build_mcp_server(ctx), stateless=True)
    app = build_app(ctx, ctx.settings, streamable)
    async with streamable.run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1:8000") as client:
            assert (await client.post("/mcp", json={})).status_code == 401  # key required
            init = await _rpc(client, 1, "initialize", {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"}})
            assert init["result"]["serverInfo"]["name"] == "ews-mcp-v5"

            tools = (await _rpc(client, 2, "tools/list", {}))["result"]["tools"]
            assert [t["name"] for t in tools] == ["echo"]
            assert tools[0]["annotations"]["readOnlyHint"] is True

            ok = (await _rpc(client, 3, "tools/call",
                             {"name": "echo", "arguments": {"q": "hi"}}))["result"]
            assert ok["structuredContent"] == {"ok": True, "echo": "hi",
                                               "mailbox": "exec@corp.example"}
            assert json.loads(ok["content"][0]["text"])["echo"] == "hi"
            assert not ok.get("isError")

            bad = (await _rpc(client, 4, "tools/call",
                              {"name": "echo", "arguments": {"q": "fail"}}))["result"]
            assert bad["isError"] is True

            unknown = (await _rpc(client, 5, "tools/call",
                                  {"name": "nope", "arguments": {}}))["result"]
            assert unknown["isError"] is True and "Unknown tool" in unknown["content"][0]["text"]
