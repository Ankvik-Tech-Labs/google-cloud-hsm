
from eth_utils import is_address, to_checksum_address
from pydantic import BaseModel, Field, field_validator


class Signature(BaseModel):
    """Represents an Ethereum signature with v, r, s components."""

    v: int = Field(..., description="Recovery identifier")
    r: bytes = Field(..., description="R component of signature")
    s: bytes = Field(..., description="S component of signature")

    @field_validator("r", "s")
    @classmethod
    def validate_length(cls, v: bytes) -> bytes:
        if len(v) != 32:
            raise ValueError(f"Length must be 32 bytes, got {len(v)} bytes")
        return v

    @field_validator("v")
    @classmethod
    def validate_v(cls, v: int) -> int:
        if v < 0:
            raise ValueError("v must be non-negative")
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
        if len(sig_bytes) != 65:
            raise ValueError(f"Invalid signature length: {len(sig_bytes)}")
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
    signature: Signature | None = Field(None, description="Transaction signature")

    @field_validator("to")
    @classmethod
    def validate_address(cls, v: str) -> str:
        if not is_address(v):
            raise ValueError("Invalid Ethereum address")
        return to_checksum_address(v)

    @field_validator("data")
    @classmethod
    def validate_hex(cls, v: str) -> str:
        if not v.startswith("0x"):
            v = "0x" + v
        try:
            bytes.fromhex(v[2:])
        except ValueError:
            raise ValueError("Invalid hex string")
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
        }
        if self.signature:
            tx_dict.update(
                {"v": self.signature.v, "r": "0x" + self.signature.r.hex(), "s": "0x" + self.signature.s.hex()}
            )
        return tx_dict

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        """Create transaction from dictionary."""
        signature = None
        if all(k in data for k in ["v", "r", "s"]):
            signature = Signature(
                v=data["v"],
                r=bytes.fromhex(data["r"][2:] if data["r"].startswith("0x") else data["r"]),
                s=bytes.fromhex(data["s"][2:] if data["s"].startswith("0x") else data["s"]),
            )

        return cls(
            chain_id=data["chainId"],
            nonce=data["nonce"],
            gas_price=data["gasPrice"],
            gas_limit=data["gas"],
            to=data["to"],
            value=data["value"],
            data=data.get("data", "0x"),
            signature=signature,
        )

    class Config:
        arbitrary_types_allowed = True  # Needed for bytes fields
