"""Session and encryption key derivation."""

import hashlib
import hmac


SESSION_SEED = bytes.fromhex(
    "e81e8b5927621eaa861518eac0bf668c6dbf8393bcaa80525b1edc23a012b750"
)
ENCRYPTION_SEED = bytes.fromhex(
    "71c9ed5aa70e4dff4c36a65a3e468a4a5da148c830474adef60d6cbe6fe45573"
)


def _validate(value, length):
    if type(value) is not bytes or len(value) != length:
        raise ValueError("INVALID_INPUT")


def derive_session(material, client_challenge, server_challenge):
    """Derive a 40-byte session from exact bytes of lengths 64, 32, 32."""
    _validate(material, 64)
    _validate(client_challenge, 32)
    _validate(server_challenge, 32)
    key = hashlib.sha512(material).digest()
    digest = hmac.new(
        key, server_challenge + client_challenge + SESSION_SEED, hashlib.sha512
    ).digest()
    return hashlib.sha512(
        hashlib.sha512(digest[:32]).digest()
        + bytes(64)
        + hashlib.sha512(digest[32:]).digest()
    ).digest()[:40]


def derive_encryption(session, client_challenge, server_challenge):
    """Derive a 32-byte encryption key from exact bytes of lengths 40, 32, 32."""
    _validate(session, 40)
    _validate(client_challenge, 32)
    _validate(server_challenge, 32)
    return hmac.new(
        session,
        client_challenge + server_challenge + ENCRYPTION_SEED,
        hashlib.sha512,
    ).digest()[:32]
