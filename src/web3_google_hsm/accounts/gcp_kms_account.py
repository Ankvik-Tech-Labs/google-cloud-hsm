from functools import cached_property
from typing import Any, cast

import rlp  # type: ignore
from eth_account import Account
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict  # noqa: PLC2701
from eth_account.messages import _hash_eip191_message, encode_defunct  # noqa: PLC2701
from eth_typing import ChecksumAddress
from eth_utils import keccak, to_checksum_address
from google.cloud import kms
from pydantic import BaseModel, Field, PrivateAttr
from rich.traceback import install

from web3_google_hsm.config import BaseConfig
from web3_google_hsm.exceptions import SignatureError
from web3_google_hsm.types.ethereum_types import MSG_HASH_LENGTH, Signature, Transaction
from web3_google_hsm.utils import convert_der_to_rsv, extract_public_key_bytes

# initialise the rich traceback for better tracebacks
install()


class GCPKmsAccount(BaseModel):
    """Account implementation using Google Cloud KMS."""

    # Public fields
    key_path: str = Field(default="")

    # Private attributes
    _client: kms.KeyManagementServiceClient = PrivateAttr()
    _cached_public_key: bytes | None = PrivateAttr(default=None)
    _settings: BaseConfig = PrivateAttr()

    def __init__(self, config: BaseConfig | None = None, **data: Any):
        super().__init__(**data)
        self._client = kms.KeyManagementServiceClient()
        self._settings = config or BaseConfig.from_env()
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
                msg = "No PEM data in response"
                raise ValueError(msg)

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
            msg = f"Signing error: {e}"
            raise Exception(msg) from e

    def sign_message(self, message: str | bytes) -> Signature:
        """
        Sign a message with the GCP KMS key.

        Args:
            message: Message to sign (str or bytes)

        Returns:
            Signature: The v, r, s components of the signature

        Raises:
            TypeError: If message is not str or bytes
            ValueError: If message hash length is invalid
            SignatureError: If signature verification fails
            Exception: If signing fails

        Example:
            ```{ .python .copy }
                account = GCPKmsAccount()
                print(f"GCP KMS Account address: {account.address}")
                message = "Hello Ethereum!"
                # Sign the message
                signed_message = account.sign_message(message)
            ```
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
            msg = f"Unsupported message type: {type(message)}"
            raise TypeError(msg)

        # Sign message hash
        msghash = _hash_eip191_message(hash_message)
        if len(msghash) != MSG_HASH_LENGTH:
            msg = "Invalid message hash length"
            raise ValueError(msg)

        der_signature = self._sign_raw_hash(msghash)
        if not der_signature:
            msg = "Failed to sign message"
            raise Exception(msg)

        # Try both v values (27 and 28) to find the correct one
        for v_value in (27, 28):
            sig_dict = convert_der_to_rsv(der_signature, v_value)
            signature = Signature(v=sig_dict["v"], r=sig_dict["r"], s=sig_dict["s"])

            # Verify the signature
            recovered = Account.recover_message(hash_message, vrs=(signature.v, signature.r, signature.s))

            if recovered.lower() == self.address.lower():
                return signature

        msg = "Failed to create valid signature"
        raise SignatureError(msg)

    def sign_transaction(self, transaction: Transaction) -> bytes | None:
        """
        Sign an EIP-155 transaction.

        Args:
            transaction: Transaction to sign

        Returns:
            bytes | None: Serialized signed transaction or None if signing fails
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
        unsigned_tx_obj = serializable_unsigned_transaction_from_dict(unsigned_tx)  # type: ignore
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

        # RLP encode the transaction and ensure it returns bytes
        encoded_tx = cast(bytes, rlp.encode(rlp_data))

        # Verify the signature
        recovered = Account.recover_transaction(encoded_tx)
        if recovered.lower() != self.address.lower():
            # Try with v + 1
            rlp_data[6] = sig_dict["v"] + 1  # Update v value
            encoded_tx = cast(bytes, rlp.encode(rlp_data))

            # Verify again
            recovered = Account.recover_transaction(encoded_tx)
            if recovered.lower() != self.address.lower():
                msg = "Failed to create valid signature"
                raise SignatureError(msg)

        return encoded_tx
