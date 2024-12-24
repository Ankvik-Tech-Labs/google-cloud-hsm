"""Ethereum type definitions."""

from eth_account import Account
from eth_account._utils.legacy_transactions import (
    encode_transaction,  # noqa: PLC2701
    serializable_unsigned_transaction_from_dict,  # noqa: PLC2701
)
from eth_utils import is_address, to_checksum_address, to_int
from pydantic import BaseModel, ConfigDict, Field, field_validator

from google_cloud_hsm.exceptions import SignatureError

SIGNATURE_LENGTH: int = 65
MSG_HASH_LENGTH: int = 32


class Signature(BaseModel):
    """Represents an Ethereum signature with v, r, s components."""

    v: int = Field(..., description="Recovery identifier")
    r: bytes = Field(..., description="R component of signature")
    s: bytes = Field(..., description="S component of signature")

    @field_validator("r", "s")
    @classmethod
    def validate_length(cls, v: bytes) -> bytes:
        if len(v) != MSG_HASH_LENGTH:
            msg = f"Length must be 32 bytes, got {len(v)} bytes"
            raise ValueError(msg)
        return v

    @field_validator("v")
    @classmethod
    def validate_v(cls, v: int) -> int:
        if v < 0:
            msg = "v must be non-negative"
            raise ValueError(msg)
        return v

    def to_hex(self) -> str:
        """Convert signature to hex string."""
        return "0x" + (self.r + self.s + bytes([self.v])).hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> "Signature":
        """Create signature from hex string."""
        if hex_str.startswith("0x"):
            hex_str = hex_str[2:]
        sig_bytes = bytes.fromhex(hex_str)
        if len(sig_bytes) != SIGNATURE_LENGTH:
            msg = f"Invalid signature length: {len(sig_bytes)}"
            raise ValueError(msg)
        return cls(v=sig_bytes[64], r=sig_bytes[0:32], s=sig_bytes[32:64])


class Transaction(BaseModel):
    """Represents an Ethereum transaction."""

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)

    chain_id: int = Field(..., description="Chain ID", validation_alias="chainId")
    nonce: int = Field(..., ge=0, description="Transaction nonce")
    gas_price: int = Field(..., gt=0, description="Gas price in Wei", validation_alias="gasPrice")
    gas_limit: int = Field(..., gt=0, description="Gas limit", validation_alias="gas")
    to: str = Field(..., description="Recipient address")
    value: int = Field(..., ge=0, description="Transaction value in Wei")
    data: str = Field("0x", description="Transaction data")
    from_: str = Field(..., description="Sender address", validation_alias="from")
    signature: Signature | None = Field(None, description="Transaction signature")

    @field_validator("to", "from_")
    @classmethod
    def validate_address(cls, v: str) -> str:
        if not is_address(v):
            msg = "Invalid Ethereum address"
            raise ValueError(msg)
        return to_checksum_address(v)

    @field_validator("data")
    @classmethod
    def validate_hex(cls, v: str) -> str:
        if not v.startswith("0x"):
            v = "0x" + v
        try:
            bytes.fromhex(v[2:])
        except ValueError as error:
            msg = "Invalid hex string"
            raise ValueError(msg) from error
        return v

    def to_dict(self) -> dict:
        """Convert transaction to dictionary format for web3.py."""
        tx_dict = {
            "chainId": self.chain_id,
            "nonce": self.nonce,
            "gasPrice": self.gas_price,
            "gas": self.gas_limit,
            "to": self.to,
            "value": self.value,
            "data": self.data,
            "from": self.from_,
        }
        return tx_dict

    def to_transaction_dict(self) -> dict:
        """Convert to dictionary format suitable for signing."""
        tx_dict = {
            "chainId": self.chain_id,
            "nonce": self.nonce,
            "gasPrice": self.gas_price,
            "gas": self.gas_limit,
            "to": self.to,
            "value": self.value,
            "data": self.data,
        }
        # Add signature if present
        if self.signature:
            tx_dict.update(
                {
                    "v": self.signature.v,
                    "r": int.from_bytes(self.signature.r, "big"),
                    "s": int.from_bytes(self.signature.s, "big"),
                }
            )
        return tx_dict

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        """
        Create transaction from dictionary.

        Args:
            data: Transaction data dictionary.

        Returns:
            Transaction: A new transaction instance

        Raises:
            ValueError: If required fields are missing or invalid
        """
        tx_data = data.copy()

        # Handle signature if present
        signature = None
        if all(k in tx_data for k in ["v", "r", "s"]):
            r_value = tx_data.pop("r")
            s_value = tx_data.pop("s")

            # Convert hex strings to bytes if necessary
            if isinstance(r_value, str):
                r_value = bytes.fromhex(r_value[2:] if r_value.startswith("0x") else r_value)
            if isinstance(s_value, str):
                s_value = bytes.fromhex(s_value[2:] if s_value.startswith("0x") else s_value)

            signature = Signature(v=tx_data.pop("v"), r=r_value, s=s_value)
            tx_data["signature"] = signature

        return cls(**tx_data)

    def serialize_transaction(self) -> bytes:
        """
        Serialize a transaction to bytes.

        Returns:
            bytes: The serialized transaction

        Raises:
            SignatureError: If transaction is not signed or signature verification fails
        """
        if not self.signature:
            msg = "The transaction is not signed."
            raise SignatureError(msg)

        # Create transaction dict without 'from' and with proper signature format
        txn_data = self.to_dict()

        if "from" in txn_data:
            txn_data.pop("from")

        # Create unsigned transaction dict
        unsigned_txn = serializable_unsigned_transaction_from_dict(txn_data)
        signature = (self.signature.v, to_int(self.signature.r), to_int(self.signature.s))

        signed_txn = encode_transaction(unsigned_txn, signature)

        # Verify signature
        recovered = Account.recover_transaction(signed_txn)
        if self.from_ and recovered.lower() != self.from_.lower():
            msg = f"Recovered signer doesn't match sender! Expected: {self.from_}, got: {recovered}"
            raise SignatureError(msg)

        return signed_txn
