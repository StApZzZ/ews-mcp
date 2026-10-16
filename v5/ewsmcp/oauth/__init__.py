"""Multi-user mode: the server as its own OAuth 2.1 authorization server.

Clients register dynamically (RFC 7591), send the user through ``/login``
(PKCE S256, consent shown) and get opaque bearer tokens. Each token maps to
the user's own Exchange credentials, sealed under a key derived from the
token itself — the server keeps only ciphertext and token hashes, so its
database alone opens no mailbox (DESIGN.md §Multi-user).
"""
