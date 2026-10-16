"""Gateway probe/reset behavior — the false-warm fix (Phase B critical #4).

``inbox.total_count`` is a cached property after its first read, so probing
it reported warm forever (the /readyz lie). The probe must round-trip every
call, and reset() must evict exchangelib's protocol cache so a wedged
session actually renegotiates auth.
"""

from unittest.mock import MagicMock

from conftest import make_settings
from exchangelib import Credentials

from ewsmcp.gateway import client as client_mod
from ewsmcp.gateway.client import EWSGateway


def _gateway_with_mock_account():
    gw = EWSGateway(make_settings())
    account = MagicMock(name="account")
    gw._account = account
    return gw, account


def test_probe_round_trips_on_every_call():
    gw, account = _gateway_with_mock_account()
    assert gw.test_connection() is True
    assert gw.test_connection() is True
    assert account.root.refresh.call_count == 2  # not a cached-property read


def test_probe_failure_is_reported_not_cached():
    gw, account = _gateway_with_mock_account()
    account.root.refresh.side_effect = ConnectionError("front door down")
    assert gw.test_connection() is False
    assert "front door down" in gw.last_connection_error
    account.root.refresh.side_effect = None
    assert gw.test_connection() is True  # recovery observed immediately
    assert gw.last_connection_error is None


def test_reset_evicts_own_protocol_and_folder_cache(monkeypatch):
    gw, account = _gateway_with_mock_account()
    other = Credentials("someone-else", "pw2")
    cache = {
        (gw.settings.ews_server_url, Credentials("svc", "pw")): (object(), None),
        (gw.settings.ews_server_url, other): (object(), None),
    }
    monkeypatch.setattr(client_mod.CachingProtocol, "_protocol_cache", cache)
    gw._folder_cache = {"path": object()}
    gw._folder_cache_ts = 123.0
    gw.reset()
    assert gw._account is None
    account.protocol.close.assert_called_once()
    # Our wedged Protocol is gone (it would come back otherwise) — but only
    # ours: another user's session in the shared cache survives.
    assert list(cache) == [(gw.settings.ews_server_url, other)]
    assert gw._folder_cache == {}
    assert gw._folder_cache_ts == 0.0


def test_reset_survives_close_failure_and_missing_cache_entry(monkeypatch):
    monkeypatch.setattr(client_mod.CachingProtocol, "_protocol_cache", {})
    gw, account = _gateway_with_mock_account()
    account.protocol.close.side_effect = OSError("socket gone")
    gw.reset()  # must not raise
    assert gw._account is None
