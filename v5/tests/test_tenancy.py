"""Per-user Context registry: isolation, credential rotation, eviction."""

from conftest import make_settings

from ewsmcp.server import build_context
from ewsmcp.tenancy import UserContexts, user_dir


def _tenants(**overrides):
    settings = make_settings(ews_email=None, mcp_transport="http", mcp_oauth_enabled=True,
                             mcp_public_url="http://127.0.0.1:8000", **overrides)
    revoked = []
    return UserContexts(build_context(settings), on_revoke=revoked.append), revoked


def _closed(ctx):
    return ctx.gateway._pool._shutdown


def test_each_user_gets_an_isolated_context():
    t, _ = _tenants()
    a = t.get("a@corp.example", "a", "pw-a")
    b = t.get("b@corp.example", "b", "pw-b")
    assert a is not b and a.gateway is not b.gateway and a.aliaser is not b.aliaser
    assert (a.settings.ews_email, a.settings.ews_password) == ("a@corp.example", "pw-a")
    assert a.settings.ews_cache_enabled is False and a.cache is None
    assert a.settings.data_dir == str(user_dir(t.settings, "a@corp.example"))
    assert a.audit is t.base.audit and a.registry is t.base.registry
    assert t.get("a@corp.example", "a", "pw-a") is a  # cached


def test_password_change_replaces_the_session():
    t, _ = _tenants()
    old = t.get("a@corp.example", "a", "old-pw")
    new = t.get("a@corp.example", "a", "new-pw")
    assert new is not old and _closed(old) and len(t) == 1


def test_auth_failure_drops_the_user_and_revokes():
    t, revoked = _tenants()
    a = t.get("a@corp.example", "a", "pw")
    b = t.get("b@corp.example", "b", "pw")
    a.on_auth_failed()
    assert revoked == ["a@corp.example"] and _closed(a) and not _closed(b) and len(t) == 1


def test_lru_cap_and_idle_eviction(monkeypatch):
    t, _ = _tenants(ews_max_users=2)
    a = t.get("a@corp.example", "a", "pw")
    t.get("b@corp.example", "b", "pw")
    t.get("c@corp.example", "c", "pw")
    assert _closed(a) and len(t) == 2

    import ewsmcp.tenancy as tenancy
    t2, _ = _tenants(ews_user_idle_seconds=60)
    idle = t2.get("a@corp.example", "a", "pw")
    now = tenancy.time.time()
    monkeypatch.setattr(tenancy.time, "time", lambda: now + 120)
    t2.get("b@corp.example", "b", "pw")
    assert _closed(idle) and len(t2) == 1
