"""Settings guards: absolute data_dir + the synced-folder refusal.

The data dir holds mail-at-rest (aliases, audit chain, cache mirror) —
booting with it inside OneDrive/Dropbox/… replicates a mailbox to every
synced device, so the default posture is refusal with an explicit escape
hatch.
"""

import pytest

from conftest import make_settings


def test_data_dir_is_always_absolute(tmp_path):
    s = make_settings(data_dir=str(tmp_path / "d"))
    import os
    assert os.path.isabs(s.data_dir)


def test_default_data_dir_is_home_scoped_absolute(monkeypatch, tmp_path):
    monkeypatch.delenv("DATA_DIR", raising=False)
    s = make_settings()
    assert s.data_dir.endswith(".ewsmcp")


@pytest.mark.parametrize("marker", ["OneDrive", "Dropbox", "Google Drive"])
def test_synced_paths_are_refused(tmp_path, marker):
    with pytest.raises(Exception, match="synced"):
        make_settings(data_dir=str(tmp_path / marker / "data"))


def test_synced_path_escape_hatch(tmp_path):
    s = make_settings(data_dir=str(tmp_path / "OneDrive" / "data"),
                      data_dir_allow_synced=True)
    assert "OneDrive" in s.data_dir


def test_unauthenticated_public_listener_is_refused():
    with pytest.raises(Exception, match="without auth"):
        make_settings(mcp_transport="http", mcp_host="0.0.0.0")
    # explicit opt-outs: a key, OAuth, the escape hatch, or loopback only
    make_settings(mcp_transport="http", mcp_host="0.0.0.0", mcp_api_key="k")
    make_settings(mcp_transport="http", mcp_host="0.0.0.0", mcp_allow_unauthenticated=True)
    make_settings(mcp_transport="http", mcp_host="127.0.0.1")


def test_oauth_mode_needs_no_mailbox_but_a_public_origin():
    s = make_settings(ews_email=None, ews_username=None, ews_password=None,
                      mcp_transport="http", mcp_host="0.0.0.0", mcp_oauth_enabled=True,
                      mcp_public_url="https://mcp.example.com/")
    assert s.mcp_public_url == "https://mcp.example.com"
    for bad in (None, "https://mcp.example.com/sub", "http://mcp.example.com"):
        with pytest.raises(Exception, match="MCP_PUBLIC_URL"):
            make_settings(ews_email=None, mcp_transport="http", mcp_oauth_enabled=True,
                          mcp_public_url=bad)
    make_settings(ews_email=None, mcp_transport="http", mcp_oauth_enabled=True,
                  mcp_public_url="http://127.0.0.1:8000")
    with pytest.raises(Exception, match="MCP_TRANSPORT=http"):
        make_settings(ews_email=None, mcp_oauth_enabled=True,
                      mcp_public_url="https://mcp.example.com")


def test_single_mailbox_mode_still_requires_ews_email():
    with pytest.raises(Exception, match="EWS_EMAIL"):
        make_settings(ews_email=None)


def test_empty_timezone_resolves_to_a_real_zone():
    from zoneinfo import ZoneInfo
    s = make_settings(ews_tz="")
    assert s.ews_tz
    ZoneInfo(s.ews_tz)  # a valid IANA key, not a hard-coded city


def test_confirm_ttl_default_matches_confirm_module():
    from ewsmcp import confirm
    assert make_settings().confirm_ttl_seconds == confirm.DEFAULT_TTL_SECONDS == 600
