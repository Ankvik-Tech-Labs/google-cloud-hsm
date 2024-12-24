from eth_account import Account
from eth_account._utils.legacy_transactions import (
    encode_transaction,  # noqa: PLC2701
    serializable_unsigned_transaction_from_dict,  # noqa: PLC2701
)
from eth_utils import is_address, to_checksum_address, to_int
from pydantic import BaseModel, Field, field_validator

from google_cloud_hsm.accounts.gcp_kms_account import MSG_HASH_LENGTH
from google_cloud_hsm.exceptions import SignatureError

SIGNATURE_LENGTH: int = 65


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

    chain_id: int = Field(..., description="Chain ID")
    nonce: int = Field(..., ge=0, description="Transaction nonce")
    gas_price: int = Field(..., gt=0, description="Gas price in Wei")
    gas_limit: int = Field(..., gt=0, description="Gas limit")
    to: str = Field(..., description="Recipient address")
    value: int = Field(..., ge=0, description="Transaction value in Wei")
    data: str = Field("0x", description="Transaction data")
    from_: str = Field(..., alias="from", description="Sender address")
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
        if self.signature:
            tx_dict.update(
                {"v": self.signature.v, "r": "0x" + self.signature.r.hex(), "s": "0x" + self.signature.s.hex()}
            )
        return tx_dict

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        """
        Create transaction from dictionary.

        Args:
            data: Transaction data dictionary. Must contain either 'from' or 'from_' field.

        Returns:
            Transaction: A new transaction instance

        Raises:
            ValueError: If required fields are missing or invalid
        """
        tx_data = data.copy()

        # Handle alternative field names and convert to our format
        if "from" in tx_data:
            tx_data["from_"] = tx_data.pop("from")
        if "gas" in tx_data:
            tx_data["gas_limit"] = tx_data.pop("gas")
        if "gasPrice" in tx_data:
            tx_data["gas_price"] = tx_data.pop("gasPrice")

        # Handle signature if present
        signature = None
        if all(k in tx_data for k in ["v", "r", "s"]):
            signature = Signature(
                v=tx_data.pop("v"),
                r=bytes.fromhex(tx_data.pop("r")[2:] if tx_data["r"].startswith("0x") else tx_data["r"]),
                s=bytes.fromhex(tx_data.pop("s")[2:] if tx_data["s"].startswith("0x") else tx_data["s"]),
            )
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

        txn_data: dict = self.to_dict()

        if txn_data.get("sender"):
            del txn_data["sender"]
        unsigned_txn = serializable_unsigned_transaction_from_dict(txn_data)
        signature = (
            self.signature.v,
            to_int(self.signature.r),
            to_int(self.signature.s),
        )

        signed_txn = encode_transaction(unsigned_txn, signature)

        if self.from_ and Account.recover_transaction(signed_txn) != self.from_:
            msg = "Recovered signer doesn't match sender!"
            raise SignatureError(msg)

        return signed_txn

    class Config:
        arbitrary_types_allowed = True  # Needed for bytes fields
