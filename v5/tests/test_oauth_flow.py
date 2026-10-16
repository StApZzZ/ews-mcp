"""Multi-user OAuth mode end to end, through the real ASGI app.

Exchange is replaced by a fake ``verify_login`` (the only upstream call the
OAuth layer makes); tools are fakes that report which mailbox's Context
they ran in. Covers discovery, DCR + redirect policy, the login form,
PKCE code exchange, per-user isolation over REST and MCP, refresh
rotation, revocation, the auth-failure sign-out and login rate limiting.
"""

import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import pytest_asyncio
from conftest import make_settings
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from ewsmcp.http import build_app, with_security_headers
from ewsmcp.oauth import login as login_mod
from ewsmcp.oauth.frontend import OAuthFrontend
from ewsmcp.oauth.upstream import LoginRejected
from ewsmcp.server import build_context, build_mcp_server
from ewsmcp.tools.base import ToolSpec

PUBLIC = "http://127.0.0.1:8000"
REDIRECT = "http://127.0.0.1:33418/callback"
USERS = {"alice@corp.example": "alice-pw", "bob@corp.example": "bob-pw"}


async def _whoami(ctx):
    return {"ok": True, "user": ctx.user, "mailbox": ctx.settings.ews_email,
            "username": ctx.settings.ews_username}


async def _upstream_401(ctx):
    raise RuntimeError("401 Unauthorized: invalid credentials")


def _spec(name, handler):
    return ToolSpec(name=name, description=f"{name} test tool", side_effect_class="read",
                    input_schema={"type": "object", "properties": {}}, handler=handler,
                    requires_ews=False)


@pytest.fixture
def fake_exchange(monkeypatch):
    calls = []

    def verify(settings, username, password):
        calls.append(username)
        if USERS.get(username) != password:
            raise LoginRejected("auth_failed")
        return username

    monkeypatch.setattr(login_mod, "verify_login", verify)
    return calls


@pytest_asyncio.fixture
async def server():
    settings = make_settings(ews_email=None, ews_username=None, ews_password=None,
                             mcp_transport="http", mcp_oauth_enabled=True,
                             mcp_public_url=PUBLIC)
    ctx = build_context(settings)
    ctx.registry = {"whoami": _spec("whoami", _whoami),
                    "upstream_401": _spec("upstream_401", _upstream_401)}
    oauth = OAuthFrontend(settings, ctx)
    streamable = StreamableHTTPSessionManager(app=build_mcp_server(ctx), stateless=True)
    app = with_security_headers(build_app(ctx, settings, streamable, oauth))
    # streamable.run() is entered inside the tests that speak MCP: its anyio
    # task group must open and close in the same task (fixture teardown runs
    # in another one).
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url=PUBLIC) as client:
        client.oauth = oauth
        client.streamable = streamable
        yield client
    oauth.tenants.close_all()


async def _register(client, redirect=REDIRECT, auth_method="none"):
    return await client.post("/register", json={
        "redirect_uris": [redirect], "token_endpoint_auth_method": auth_method,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"], "client_name": "Test Client"})


async def _start_login(client, client_id):
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    r = await client.get("/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "st-1"})
    assert r.status_code == 302, r.text
    login_url = urlparse(r.headers["location"])
    assert login_url.path == "/login"
    return parse_qs(login_url.query)["txn"][0], verifier


async def _sign_in(client, username, auth_method="none"):
    reg = (await _register(client, auth_method=auth_method)).json()
    creds = {"client_id": reg["client_id"]}
    if reg.get("client_secret"):
        creds["client_secret"] = reg["client_secret"]
    txn, verifier = await _start_login(client, reg["client_id"])
    r = await client.post("/login", data={"txn": txn, "username": username,
                                          "password": USERS[username], "consent": "yes"})
    assert r.status_code == 303, r.text
    back = urlparse(r.headers["location"])
    q = parse_qs(back.query)
    assert f"{back.scheme}://{back.netloc}{back.path}" == REDIRECT and q["state"] == ["st-1"]
    r = await client.post("/token", data={
        "grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": REDIRECT,
        "code_verifier": verifier, **creds})
    assert r.status_code == 200, r.text
    return creds, r.json(), q["code"][0], verifier


def _bearer(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def _mcp_call(client, tokens, tool):
    headers = {**_bearer(tokens), "Accept": "application/json, text/event-stream",
               "Content-Type": "application/json", "MCP-Protocol-Version": "2025-06-18"}
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "t", "version": "1"}}}
    r = await client.post("/mcp", json=init, headers=headers)
    assert r.status_code == 200, r.text
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}}
    r = await client.post("/mcp", json=call, headers=headers)
    assert r.status_code == 200, r.text
    return _rpc_result(r)


def _rpc_result(response):
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()["result"]
    for line in response.text.splitlines():
        if line.startswith("data:"):
            msg = json.loads(line[5:])
            if "result" in msg:
                return msg["result"]
    raise AssertionError(f"no JSON-RPC result in {response.text!r}")


# ---------------------------------------------------------------- discovery

@pytest.mark.asyncio
async def test_discovery_documents(server):
    meta = (await server.get("/.well-known/oauth-authorization-server")).json()
    assert meta["issuer"].rstrip("/") == PUBLIC
    assert meta["registration_endpoint"] == f"{PUBLIC}/register"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    for path in ("/.well-known/oauth-protected-resource/mcp",
                 "/.well-known/oauth-protected-resource"):
        prm = (await server.get(path)).json()
        assert prm["resource"] == f"{PUBLIC}/mcp"
        assert [a.rstrip("/") for a in prm["authorization_servers"]] == [PUBLIC]


@pytest.mark.asyncio
async def test_protected_routes_challenge_with_resource_metadata(server):
    for method, path in (("POST", "/mcp"), ("POST", "/api/tools/whoami"),
                         ("GET", "/openapi.json")):
        r = await server.request(method, path)
        assert r.status_code == 401
        assert "resource_metadata=" in r.headers["www-authenticate"]
    r = await server.post("/mcp", headers={"Authorization": "Bearer ewsat_forged"})
    assert r.status_code == 401
    # public probes stay public; the operator surface is off without a key
    assert (await server.get("/livez")).status_code == 200
    assert (await server.get("/metrics")).status_code == 404
    assert (await server.get("/livez")).headers["x-content-type-options"] == "nosniff"


# ------------------------------------------------------------- registration

@pytest.mark.asyncio
async def test_registration_redirect_policy(server):
    assert (await _register(server)).status_code == 201
    assert (await _register(server, "http://localhost:5000/cb")).status_code == 201
    r = await _register(server, "https://attacker.example/cb")
    assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri"


# -------------------------------------------------------------------- login

@pytest.mark.asyncio
async def test_login_form_hardening_and_failures(server, fake_exchange):
    reg = (await _register(server)).json()
    txn, _ = await _start_login(server, reg["client_id"])
    page = await server.get("/login", params={"txn": txn})
    assert page.status_code == 200 and "Test Client" in page.text
    assert "http://127.0.0.1:33418" in page.text  # where the user is sent back
    assert page.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["cache-control"] == "no-store"

    no_consent = await server.post("/login", data={
        "txn": txn, "username": "alice@corp.example", "password": "alice-pw"})
    assert no_consent.status_code == 200 and "Confirm the access" in no_consent.text
    assert fake_exchange == []  # Exchange not even asked without consent

    wrong = await server.post("/login", data={
        "txn": txn, "username": "alice@corp.example", "password": "nope", "consent": "yes"})
    assert wrong.status_code == 401 and "wrong login or password" in wrong.text

    assert (await server.get("/login", params={"txn": "forged"})).status_code == 400


@pytest.mark.asyncio
async def test_login_attempts_are_rate_limited_per_user(server, fake_exchange):
    reg = (await _register(server)).json()
    txn, _ = await _start_login(server, reg["client_id"])
    statuses = []
    for _ in range(7):
        r = await server.post("/login", data={
            "txn": txn, "username": "bob@corp.example", "password": "x", "consent": "yes"})
        statuses.append(r.status_code)
    assert statuses[:5] == [401] * 5 and statuses[5:] == [429, 429]
    assert len(fake_exchange) == 5  # the limiter, not AD, absorbed the rest


# ------------------------------------------------------------ token + usage

@pytest.mark.asyncio
async def test_code_flow_issues_tokens_and_code_is_single_use(server, fake_exchange):
    creds, tokens, code, verifier = await _sign_in(server, "alice@corp.example")
    assert tokens["token_type"].lower() == "bearer"
    assert tokens["access_token"].startswith("ewsat_")
    assert tokens["refresh_token"].startswith("ewsrt_")
    replay = await server.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "code_verifier": verifier, **creds})
    assert replay.status_code == 400


@pytest.mark.asyncio
async def test_users_are_isolated_over_rest_and_mcp(server, fake_exchange):
    _, alice = (await _sign_in(server, "alice@corp.example"))[:2]
    _, bob = (await _sign_in(server, "bob@corp.example"))[:2]

    async with server.streamable.run():
        for tokens, who in ((alice, "alice@corp.example"), (bob, "bob@corp.example")):
            r = await server.post("/api/tools/whoami", json={}, headers=_bearer(tokens))
            assert r.status_code == 200, r.text
            assert r.json() == {"ok": True, "user": who, "mailbox": who, "username": who}
            result = await _mcp_call(server, tokens, "whoami")
            assert result["structuredContent"]["mailbox"] == who
            assert result.get("isError") in (False, None)
    assert len(server.oauth.tenants) == 2

    # the at-rest store holds neither tokens nor passwords
    rows = server.oauth.store._db.execute("SELECT * FROM grants").fetchall()
    dump = json.dumps(rows)
    for secret in (alice["access_token"], alice["refresh_token"], "alice-pw", "bob-pw"):
        assert secret not in dump


@pytest.mark.asyncio
async def test_refresh_rotates_and_kills_the_old_pair(server, fake_exchange):
    creds, tokens = (await _sign_in(server, "alice@corp.example"))[:2]
    r = await server.post("/token", data={"grant_type": "refresh_token", **creds,
                                          "refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200, r.text
    fresh = r.json()
    assert (await server.post("/api/tools/whoami", json={},
                              headers=_bearer(fresh))).status_code == 200
    assert (await server.post("/api/tools/whoami", json={},
                              headers=_bearer(tokens))).status_code == 401
    replay = await server.post("/token", data={"grant_type": "refresh_token", **creds,
                                               "refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 400


@pytest.mark.asyncio
async def test_revocation_endpoint(server, fake_exchange):
    # The SDK's /revoke authenticates the client, so it serves confidential
    # clients (client_secret_post) — public clients simply let tokens expire.
    creds, tokens = (await _sign_in(server, "alice@corp.example",
                                    auth_method="client_secret_post"))[:2]
    assert "client_secret" in creds
    r = await server.post("/revoke", data={"token": tokens["access_token"], **creds})
    assert r.status_code == 200, r.text
    assert (await server.post("/api/tools/whoami", json={},
                              headers=_bearer(tokens))).status_code == 401


@pytest.mark.asyncio
async def test_upstream_auth_failure_signs_the_user_out(server, fake_exchange):
    _, alice = (await _sign_in(server, "alice@corp.example"))[:2]
    _, bob = (await _sign_in(server, "bob@corp.example"))[:2]
    r = await server.post("/api/tools/upstream_401", json={}, headers=_bearer(alice))
    assert r.status_code == 401 and r.json()["error"]["code"] == "auth_failed"
    # alice must sign in again; bob is untouched
    assert (await server.post("/api/tools/whoami", json={},
                              headers=_bearer(alice))).status_code == 401
    assert (await server.post("/api/tools/whoami", json={},
                              headers=_bearer(bob))).status_code == 200
