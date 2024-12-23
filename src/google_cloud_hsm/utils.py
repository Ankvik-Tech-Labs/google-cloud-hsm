"""Cryptographic utilities."""

import ecdsa
from eth_keys import KeyAPI
from eth_typing import Hash32

# secp256k1 curve order
SECP256K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


def normalize_signature(der_sig: bytes) -> tuple[bytes, bytes]:
    """Normalize a DER signature according to EIP-2."""
    # Decode DER signature
    r, s = ecdsa.util.sigdecode_der(der_sig, ecdsa.SECP256k1.order)

    # Normalize s value
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s

    # Convert to bytes
    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")

    return r_bytes, s_bytes


def recover_public_key(msg_hash: Hash32, r: bytes, s: bytes, expected_key: bytes) -> int:
    """Find recovery value by trying possibilities."""
    keys = KeyAPI()
    expected = keys.PublicKey(expected_key)

    for v in (0, 1):
        sig = keys.Signature(vrs=(v, int.from_bytes(r, "big"), int.from_bytes(s, "big")))
        try:
            recovered = sig.recover_public_key_from_msg_hash(msg_hash)
            if recovered == expected:
                return v
        except Exception:
            continue

    raise ValueError("Could not recover public key")
