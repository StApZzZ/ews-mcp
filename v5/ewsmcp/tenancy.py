"""Per-user tool contexts for multi-user (OAuth) mode.

Each signed-in mailbox gets its own Context: its own EWS session and worker
pool, alias store, circuit breaker and confirm-token binding — the tool
layer is unchanged, it simply sees a single-mailbox server. Shared: the
registry, the audit chain (entries carry ``user``) and the counters.
The local cache mirror and the semantic tier stay off: a shared host must
not accumulate other people's mail at rest.
"""

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Callable, List, Tuple

from .config import Settings
from .gateway.client import EWSGateway
from .ids import NullAliaser, get_aliaser
from .tools.base import Context

logger = logging.getLogger(__name__)


def user_dir(settings: Settings, subject: str) -> Path:
    digest = hashlib.sha256(subject.lower().encode("utf-8")).hexdigest()[:16]
    return Path(settings.data_dir) / "users" / digest


class UserContexts:
    def __init__(self, base: Context, on_revoke: Callable[[str], None]):
        self.base = base
        self.settings: Settings = base.settings
        self._on_revoke = on_revoke
        self._lock = threading.Lock()
        # key -> (subject, ctx, last_used); key covers the credentials, so a
        # changed password yields a fresh session instead of a stale one.
        self._entries: "OrderedDict[str, Tuple[str, Context, float]]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, subject: str, username: str, secret: str) -> Context:
        key = hashlib.sha256(f"{subject}\0{username}\0{secret}".encode("utf-8")).hexdigest()
        now = time.time()
        stale: List[Context] = []
        with self._lock:
            hit = self._entries.get(key)
            if hit is not None:
                self._entries[key] = (subject, hit[1], now)
                self._entries.move_to_end(key)
                ctx = hit[1]
            else:
                stale += self._pop(lambda k, s, last: s == subject)
                ctx = self._build(subject, username, secret)
                self._entries[key] = (subject, ctx, now)
            idle = self.settings.ews_user_idle_seconds
            stale += self._pop(lambda k, s, last: k != key and now - last > idle)
            while len(self._entries) > max(1, self.settings.ews_max_users):
                stale.append(self._entries.popitem(last=False)[1][1])
        for old in stale:
            _close(old)
        return ctx

    def drop_subject(self, subject: str) -> None:
        with self._lock:
            stale = self._pop(lambda k, s, last: s == subject)
        for old in stale:
            _close(old)

    def close_all(self) -> None:
        with self._lock:
            stale = self._pop(lambda k, s, last: True)
        for old in stale:
            _close(old)

    # ------------------------------------------------------------- internals

    def _pop(self, pred) -> List[Context]:
        keys = [k for k, (s, _, last) in self._entries.items() if pred(k, s, last)]
        return [self._entries.pop(k)[1] for k in keys]

    def _build(self, subject: str, username: str, secret: str) -> Context:
        home = user_dir(self.settings, subject)
        user_settings = self.settings.model_copy(update=dict(
            ews_email=subject, ews_username=username, ews_password=secret,
            ews_cache_enabled=False, ews_semantic_index="none", data_dir=str(home),
        ))
        try:
            aliaser = get_aliaser(str(home / "memory"))
        except Exception as exc:
            logger.error("aliaser init failed for a user (%s) — raw EWS ids", exc)
            aliaser = NullAliaser()
        ctx = Context(
            settings=user_settings, gateway=EWSGateway(user_settings), manager=None,
            aliaser=aliaser, audit=self.base.audit, registry=self.base.registry,
            counters=self.base.counters, started_at=self.base.started_at, user=subject,
        )
        ctx.on_auth_failed = lambda: self._auth_failed(subject)
        logger.info("user session opened (%d live)", len(self._entries) + 1)
        return ctx

    def _auth_failed(self, subject: str) -> None:
        self.drop_subject(subject)
        self._on_revoke(subject)


def _close(ctx: Context) -> None:
    try:
        ctx.gateway.close()
    except Exception as exc:
        logger.debug("user session close failed: %s", exc)
