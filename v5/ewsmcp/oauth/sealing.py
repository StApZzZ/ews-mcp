"""Token-bound sealing of upstream credentials.

Every grant (authorization code, access token, refresh token) carries the
user's Exchange password encrypted with AES-256-GCM under
``HKDF-SHA256(token)``. The server never stores the token — only
``sha256(token)`` as the row key — so the at-rest store opens nothing
without the bearer the client holds. The row key is bound in as AAD, so a
ciphertext cannot be transplanted onto another row.
"""

import base64
import hashlib
import os
import secrets
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"ewsmcp-oauth-seal-v1"


def new_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def token_id(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _key(token: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=_INFO).derive(token.encode("utf-8"))


def seal(token: str, plaintext: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_key(token)).encrypt(nonce, plaintext.encode("utf-8"),
                                     token_id(token).encode("ascii"))
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def unseal(token: str, sealed: str) -> Optional[str]:
    try:
        raw = base64.urlsafe_b64decode(sealed.encode("ascii"))
        pt = AESGCM(_key(token)).decrypt(raw[:12], raw[12:],
                                         token_id(token).encode("ascii"))
        return pt.decode("utf-8")
    except (InvalidTag, ValueError):
        return None
