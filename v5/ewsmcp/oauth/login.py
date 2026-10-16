"""``/login``: the consent + Exchange sign-in form behind ``/authorize``.

Hardening: the pending-request id (``txn``) is random, single-use and
expires (it doubles as the CSRF token); failures are generic (no user
enumeration); attempts are rate-limited per client IP and per logon name
so the form can never be used to lock AD accounts out; the page refuses
framing and caching.
"""

import asyncio
import html
import threading
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .provider import EwsOAuthProvider
from .upstream import LoginRejected, UpstreamUnavailable, verify_login

PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                               "frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


class FixedWindowLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self._hits: Dict[str, Tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            if len(self._hits) > 50_000:
                self._hits = {k: v for k, v in self._hits.items() if now - v[0] < self.window}
            start, count = self._hits.get(key, (now, 0))
            if now - start >= self.window:
                start, count = now, 0
            if count >= self.limit:
                return False
            self._hits[key] = (start, count + 1)
            return True


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "-"


class LoginForm:
    def __init__(self, provider: EwsOAuthProvider):
        self.provider = provider
        self.settings = provider.settings
        self.per_ip = FixedWindowLimiter(20, 900)
        # Well under typical AD lockout thresholds (5-10 per 15-30 min).
        self.per_user = FixedWindowLimiter(5, 900)

    async def handle(self, request: Request) -> Response:
        if request.method == "GET":
            txn = request.query_params.get("txn", "")
            if self.provider.pending(txn) is None:
                return self._expired()
            return self._form(txn)
        form = await request.form()
        txn = str(form.get("txn", ""))
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))
        if self.provider.pending(txn) is None:
            return self._expired()
        if not username or not password:
            return self._form(txn, username, "Enter your login and password.")
        if form.get("consent") != "yes":
            return self._form(txn, username, "Confirm the access request to continue.")
        if not self.per_ip.allow(client_ip(request)) or \
                not self.per_user.allow(username.lower()):
            return self._form(txn, username, "Too many attempts. Wait 15 minutes "
                                             "and try again.", status=429)
        try:
            subject = await asyncio.to_thread(verify_login, self.settings, username, password)
        except LoginRejected as exc:
            if exc.reason == "auth_failed":
                return self._form(txn, username, "Sign-in failed: wrong login or password.",
                                  status=401)
            return self._form(txn, username, f"Exchange refused the sign-in ({exc.reason}). "
                                             "Contact your administrator.", status=403)
        except UpstreamUnavailable:
            return self._form(txn, username, "Exchange is unreachable right now. "
                                             "Try again in a minute.", status=503)
        try:
            target = self.provider.complete_login(txn, subject, username, password)
        except KeyError:
            return self._expired()
        return RedirectResponse(target, status_code=303, headers={"Cache-Control": "no-store"})

    # ------------------------------------------------------------------ pages

    def _expired(self) -> Response:
        return self._page(
            "<h1>Sign-in link expired</h1><p>Start the connection again from your "
            "MCP client.</p>", status=400)

    def _form(self, txn: str, username: str = "", error: Optional[str] = None,
              status: int = 200) -> Response:
        p = self.provider.pending(txn)
        client = (p.client.client_name if p else None) or "An MCP client"
        redirect = urlparse(str(p.params.redirect_uri)) if p else None
        target = f"{redirect.scheme}://{redirect.netloc}" if redirect else "-"
        e = html.escape
        err = f'<p class="err">{e(error)}</p>' if error else ""
        body = f"""
<h1>Connect to Exchange</h1>
<p><b>{e(client)}</b> asks for access to your mailbox, calendar and contacts
on this server. After sign-in you will be returned to <code>{e(target)}</code>.</p>
{err}
<form method="post" action="/login" autocomplete="on">
  <input type="hidden" name="txn" value="{e(txn)}">
  <label>Login (email or DOMAIN\\user)
    <input name="username" value="{e(username)}" autocomplete="username" required autofocus></label>
  <label>Password
    <input name="password" type="password" autocomplete="current-password" required></label>
  <label class="row"><input type="checkbox" name="consent" value="yes">
    I allow {e(client)} to act on my Exchange mailbox</label>
  <button type="submit">Sign in</button>
</form>
<p class="note">Your password is checked against Exchange and stored only in
encrypted form, unlockable solely with the token issued to your client.</p>"""
        return self._page(body, status)

    def _page(self, body: str, status: int = 200) -> Response:
        doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Exchange sign-in</title><style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;color:#1b1b1b}}
label{{display:block;margin:.8rem 0}} input:not([type=checkbox]){{display:block;width:100%;padding:.5rem;
box-sizing:border-box;margin-top:.25rem}} .row{{display:flex;gap:.5rem;align-items:flex-start}}
button{{padding:.6rem 1.2rem;margin-top:.5rem}} .err{{color:#b00020}} .note{{color:#666;font-size:13px}}
code{{word-break:break-all}}
@media (prefers-color-scheme:dark){{body{{background:#121212;color:#e6e6e6}} .note{{color:#999}}}}
</style></head><body>{body}</body></html>"""
        return HTMLResponse(doc, status_code=status, headers=PAGE_HEADERS)
