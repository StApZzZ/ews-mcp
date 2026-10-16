"""Token-bound sealing: the store alone opens nothing."""

from ewsmcp.oauth.sealing import new_token, seal, token_id, unseal


def test_roundtrip_with_the_token():
    token = new_token("ewsat")
    assert unseal(token, seal(token, "pässwörd")) == "pässwörd"


def test_other_token_cannot_unseal():
    sealed = seal(new_token("ewsat"), "secret")
    assert unseal(new_token("ewsat"), sealed) is None


def test_tampered_ciphertext_is_rejected():
    token = new_token("ewsrt")
    sealed = seal(token, "secret")
    flipped = sealed[:-4] + ("AAAA" if sealed[-4:] != "AAAA" else "BBBB")
    assert unseal(token, flipped) is None
    assert unseal(token, "not-base64!") is None


def test_row_key_is_a_hash_not_the_token():
    token = new_token("ewsat")
    assert token not in token_id(token) and len(token_id(token)) == 64
    assert token.startswith("ewsat_")
