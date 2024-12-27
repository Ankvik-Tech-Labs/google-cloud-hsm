# from typing import Any

import ecdsa  # type: ignore

# from ape.api.transactions import TransactionAPI
# from ape.types import MessageSignature
from cryptography.hazmat.primitives import serialization

# from eth_account.messages import encode_defunct
# from web3 import Web3

SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


def extract_public_key_bytes(pem_str: str) -> bytes:
    """
    Extract raw public key bytes from PEM format.

    Args:
        pem_str: PEM-encoded public key string

    Returns:
        bytes: Raw public key bytes (64 bytes of X,Y coordinates)

    Raises:
        ValueError: If the PEM string is invalid
    """
    if not pem_str.startswith("-----BEGIN PUBLIC KEY-----"):
        pem_str = f"-----BEGIN PUBLIC KEY-----\n{pem_str}\n-----END PUBLIC KEY-----"

    try:
        pem_bytes = pem_str.encode()
        public_key = serialization.load_pem_public_key(pem_bytes)

        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
        )
        return raw_bytes[-64:]
    except Exception as err:
        msg = "Invalid PEM format"
        raise ValueError(msg) from err


def convert_der_to_rsv(signature: bytes, v_adjustment_factor: int = 0) -> dict:
    """
    Convert DER signature to RSV format.

    Args:
        signature: The DER-encoded signature bytes
        v_adjustment_factor: The v value adjustment factor for the signature

    Returns:
        SignatureComponents: A dictionary containing the r, s, and v components

    Raises:
        ValueError: If the signature is invalid or cannot be decoded
    """
    r, s = ecdsa.util.sigdecode_der(signature, ecdsa.SECP256k1.order)
    v = v_adjustment_factor
    if s > SECP256_K1_N / 2:
        s = SECP256_K1_N - s
    r = r.to_bytes(32, byteorder="big")
    s = s.to_bytes(32, byteorder="big")
    return {"v": v, "r": r, "s": s}


# def verify_signed_message(
#     w3: Web3, message: str, signature: MessageSignature, signer_address: str
# ) -> tuple[bool, dict[str, Any]]:
#     """
#     Verify a signed Ethereum message.
#
#     Args:
#         w3: Web3 instance
#         message: Original message that was signed
#         signature: MessageSignature object containing v, r, s
#         signer_address: Expected signer's address
#
#     Returns:
#         Tuple[bool, dict]: (is_valid, details)
#
#     Example:
#         >>> w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
#         >>> signed_message = account.sign_message("Hello")
#         >>> is_valid, details = verify_signed_message(
#         ...     w3, "Hello", signed_message, account.address
#         ... )
#     """
#     try:
#         message_hash = encode_defunct(text=message)
#         recovered_address = w3.eth.account.recover_message(message_hash, vrs=(signature.v, signature.r, signature.s))
#
#         is_valid = recovered_address.lower() == signer_address.lower()
#
#         return is_valid, {
#             "original_address": signer_address,
#             "recovered_address": recovered_address,
#             "is_valid": is_valid,
#             "signature": {
#                 "r": signature.r.hex(),
#                 "s": signature.s.hex(),
#                 "v": signature.v,
#                 "full_signature": signature.encode_vrs().hex(),
#             },
#         }
#     except Exception as e:
#         return False, {"error": str(e)}
#
#
# def verify_signed_transaction(w3: Web3, signed_tx: TransactionAPI, signer_address: str) -> tuple[bool, dict[str, Any]]:  # noqa: E501
#     """
#     Verify a signed Ethereum transaction.
#
#     Args:
#         w3: Web3 instance
#         signed_tx: Signed transaction
#         signer_address: Expected signer's address
#
#     Returns:
#         Tuple[bool, dict]: (is_valid, details)
#
#     Example:
#         >>> w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
#         >>> signed_tx = account.sign_transaction(StaticFeeTransaction(**tx))
#         >>> is_valid, details = verify_signed_transaction(
#         ...     w3, signed_tx, account.address
#         ... )
#     """
#     try:
#         raw_tx = signed_tx.serialize_transaction()
#         recovered_address = w3.eth.account.recover_transaction(raw_tx)
#
#         is_valid = recovered_address.lower() == signer_address.lower()
#
#         return is_valid, {
#             "original_address": signer_address,
#             "recovered_address": recovered_address,
#             "is_valid": is_valid,
#             "transaction_hash": w3.keccak(raw_tx).hex(),
#         }
#     except Exception as e:
#         return False, {"error": str(e)}
