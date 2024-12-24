from functools import cached_property

import rlp
from eth_account import Account
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_account.messages import _hash_eip191_message, encode_defunct
from eth_typing import ChecksumAddress
from eth_utils import keccak, to_checksum_address
from google.cloud import kms
from pydantic import BaseModel, Field, PrivateAttr

from google_cloud_hsm.config import BaseConfig
from google_cloud_hsm.types.ethereum_types import Signature, Transaction
from google_cloud_hsm.utils import convert_der_to_rsv, extract_public_key_bytes


class GCPKmsAccount(BaseModel):
    """Account implementation using Google Cloud KMS."""

    # Public fields
    key_path: str = Field(default="")

    # Private attributes
    _client: kms.KeyManagementServiceClient = PrivateAttr()
    _cached_public_key: bytes | None = PrivateAttr(default=None)
    _settings: BaseConfig = PrivateAttr()

    def __init__(self, **data):
        super().__init__(**data)
        self._client = kms.KeyManagementServiceClient()
        self._settings = BaseConfig()
        self.key_path = self._get_key_version_path()

    def _get_key_version_path(self) -> str:
        """Get the full path to the key version in Cloud KMS."""
        return self._client.crypto_key_version_path(
            self._settings.project_id,
            self._settings.location_id,
            self._settings.key_ring_id,
            self._settings.key_id,
            "1",  # Using version 1
        )

    @property
    def public_key(self) -> bytes:
        """Get public key bytes from KMS."""
        if self._cached_public_key is None:
            response = self._client.get_public_key({"name": self.key_path})
            if not response.pem:
                raise ValueError("No PEM data in response")

            self._cached_public_key = extract_public_key_bytes(response.pem)
        return self._cached_public_key

    @cached_property
    def address(self) -> ChecksumAddress:
        """Get Ethereum address derived from public key."""
        return to_checksum_address(keccak(self.public_key)[-20:].hex().lower())

    def _sign_raw_hash(self, msghash: bytes) -> bytes | None:
        """Sign a message hash using KMS."""
        try:
            response = self._client.asymmetric_sign(request={"name": self.key_path, "digest": {"sha256": msghash}})
            return response.signature
        except Exception as e:
            raise Exception(f"Signing error: {e}")

    def sign_message(self, message: str | bytes) -> Signature:
        """
        Sign a message with the GCP KMS key.

        Args:
            message: Message to sign (str or bytes)

        Returns:
            Signature: The v, r, s components of the signature

        Example:
            >>> account = GCPKmsAccount()
            >>> signature = account.sign_message("Hello Ethereum!")
        """
        # Convert message to SignableMessage format
        if isinstance(message, str):
            if message.startswith("0x"):
                hash_message = encode_defunct(hexstr=message)
            else:
                hash_message = encode_defunct(text=message)
        elif isinstance(message, bytes):
            hash_message = encode_defunct(primitive=message)
        else:
            raise TypeError(f"Unsupported message type: {type(message)}")

        # Sign message hash
        msghash = _hash_eip191_message(hash_message)
        if len(msghash) != 32:
            raise ValueError("Invalid message hash length")

        der_signature = self._sign_raw_hash(msghash)
        if not der_signature:
            raise Exception("Failed to sign message")

        # Convert to RSV format with v = 27
        sig_dict = convert_der_to_rsv(der_signature, 27)
        signature = Signature(v=sig_dict["v"], r=sig_dict["r"], s=sig_dict["s"])

        # # Verify recovery and try alternative v value if needed
        # recovered = self._w3.eth.account.recover_message(hash_message, vrs=(signature.v, signature.r, signature.s))
        #
        # if recovered.lower() != self.address.lower():
        #     signature.v += 1

        return signature

    def sign_transaction(self, transaction: Transaction) -> bytes | None:
        """
        Sign an EIP-155 transaction.

        Args:
            transaction: Transaction to sign

        Returns:
            Optional[bytes]: Serialized signed transaction or None if signing fails
        """
        # Create unsigned transaction dictionary
        unsigned_tx = {
            "nonce": transaction.nonce,
            "gasPrice": transaction.gas_price,
            "gas": transaction.gas_limit,
            "to": transaction.to,
            "value": transaction.value,
            "data": transaction.data,
            "chainId": transaction.chain_id,
        }

        # Convert to UnsignedTransaction and get hash
        unsigned_tx_obj = serializable_unsigned_transaction_from_dict(unsigned_tx)
        msg_hash = unsigned_tx_obj.hash()

        # Sign the transaction hash
        der_signature = self._sign_raw_hash(msg_hash)
        if not der_signature:
            return None

        # Calculate v value based on chain ID
        v_base = (2 * transaction.chain_id + 35) if transaction.chain_id else 27
        sig_dict = convert_der_to_rsv(der_signature, v_base)

        # Create RLP serializable fields
        rlp_data = [
            transaction.nonce,
            transaction.gas_price,
            transaction.gas_limit,
            bytes.fromhex(transaction.to[2:]),  # Convert address to bytes
            transaction.value,
            bytes.fromhex(transaction.data[2:] if transaction.data.startswith("0x") else transaction.data),
            sig_dict["v"],
            int.from_bytes(sig_dict["r"], "big"),
            int.from_bytes(sig_dict["s"], "big"),
        ]

        # RLP encode the transaction
        encoded_tx = rlp.encode(rlp_data)

        # Verify the signature
        recovered = Account.recover_transaction(encoded_tx)
        if recovered.lower() != self.address.lower():
            # Try with v + 1
            rlp_data[6] = sig_dict["v"] + 1  # Update v value
            encoded_tx = rlp.encode(rlp_data)

            # Verify again
            recovered = Account.recover_transaction(encoded_tx)
            if recovered.lower() != self.address.lower():
                raise ValueError("Failed to create valid signature")

        return encoded_tx
