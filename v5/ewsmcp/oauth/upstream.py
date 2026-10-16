"""Sign-in check against Exchange itself — the only identity source.

A login is accepted when EWS answers a real request with the user's own
credentials. The logon name may be a UPN, an SMTP address or DOMAIN\\user;
the mailbox address is resolved through ResolveNames so UPN ≠ SMTP setups
work.
"""

import logging

from exchangelib import DELEGATE, Account, EWSTimeZone
from exchangelib.protocol import Protocol

from ..config import Settings
from ..errors import map_exception
from ..gateway.client import build_configuration, evict_protocol

logger = logging.getLogger(__name__)


class LoginRejected(Exception):
    """Exchange refused the sign-in. ``reason`` is ``auth_failed`` for bad
    credentials, otherwise the error code (mailbox/permission problems)."""

    @property
    def reason(self) -> str:
        return str(self.args[0]) if self.args else "auth_failed"


class UpstreamUnavailable(Exception):
    """Exchange could not be reached — the user should retry later."""


def verify_login(settings: Settings, username: str, password: str) -> str:
    """Blocking; returns the mailbox's primary SMTP address."""
    config = build_configuration(settings, username, password)  # FailFast
    try:
        smtp = _resolve_smtp(Protocol(config=config), username)
        account = Account(primary_smtp_address=smtp, config=config, autodiscover=False,
                          access_type=DELEGATE, default_timezone=EWSTimeZone(settings.ews_tz))
        account.root.refresh()
        return smtp
    except LoginRejected:
        raise
    except Exception as exc:
        err = map_exception(exc)
        # The operator needs the real cause; the user only sees a category.
        logger.warning("login for %r failed: %s (%s)", username, err.code, err.message[:300])
        if err.code in ("upstream_unavailable", "throttled"):
            raise UpstreamUnavailable(err.message) from exc
        raise LoginRejected(err.code) from exc
    finally:
        # The cached Protocol carries this probe's FailFast retry policy;
        # the user's gateway must build its own (and a rejected password
        # must not linger in the process-wide cache).
        evict_protocol(config)


def _resolve_smtp(protocol: Protocol, username: str) -> str:
    try:
        found = [m for m in protocol.resolve_names([username])
                 if not isinstance(m, Exception) and getattr(m, "email_address", None)]
    except Exception as exc:
        if map_exception(exc).code == "auth_failed":
            raise
        found = []
    addresses = {m.email_address.lower(): m.email_address for m in found}
    if username.lower() in addresses:
        return addresses[username.lower()]
    if len(addresses) == 1:
        return next(iter(addresses.values()))
    if "@" in username:
        return username
    raise LoginRejected("unresolved")
