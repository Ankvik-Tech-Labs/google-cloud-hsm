from eth_account._utils.signing import to_standard_v
from eth_account._utils.transactions import encode_transaction, serializable_unsigned_transaction_from_dict
from eth_keys import KeyAPI
from google.cloud.kms_v1 import (
    CryptoKey,
    CryptoKeyVersion,
    KeyManagementServiceClient,
    ProtectionLevel,
)


def derive_ethereum_address(public_key_bytes: bytes) -> str:
    """Derive Ethereum address from public key."""
    keys = KeyAPI()
    public_key = keys.PublicKey(public_key_bytes)
    return keys.PublicKey.to_address(public_key)


def serialize_transaction(transaction_dict: dict, chain_id: int) -> bytes:
    """Serialize an Ethereum transaction for signing."""
    unsigned_transaction = serializable_unsigned_transaction_from_dict(transaction_dict)
    return encode_transaction(unsigned_transaction, chain_id)


def to_eth_v(v: int, chain_id: int) -> int:
    """Convert signature v value to Ethereum format."""
    return to_standard_v(v) + (chain_id * 2 + 35)


def setup_eth_signing_key(project_id: str, location_id: str, key_ring_id: str, key_id: str) -> CryptoKey:
    """
    Creates a key ring and asymmetric signing key for Ethereum transactions.

    Note: This only needs to be run once to set up your HSM key.
    """
    client = KeyManagementServiceClient()

    # First create key ring if it doesn't exist
    key_ring_parent = f"projects/{project_id}/locations/{location_id}"
    try:
        key_ring = client.create_key_ring(
            request={"parent": key_ring_parent, "key_ring_id": key_ring_id, "key_ring": {}}
        )
        print(f"Created new key ring: {key_ring.name}")  # noqa: T201
    except Exception as e:
        print(f"Key ring already exists or error: {e}")  # noqa: T201

    # Now create the signing key
    key_ring_name = f"{key_ring_parent}/keyRings/{key_ring_id}"

    # Configure for secp256k1 signing
    key = {
        "purpose": CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        "version_template": {
            "algorithm": CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256,
            "protection_level": ProtectionLevel.HSM,
        },
    }

    try:
        created_key = client.create_crypto_key(
            request={"parent": key_ring_name, "crypto_key_id": key_id, "crypto_key": key}
        )
        print(f"Created new signing key: {created_key.name}")  # noqa: T201
        return created_key
    except Exception as e:
        print(f"Error creating key: {e}")  # noqa: T201
        raise
