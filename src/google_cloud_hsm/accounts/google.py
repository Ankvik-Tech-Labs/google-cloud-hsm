from eth_typing import Address, HexStr
from eth_utils import to_bytes, to_checksum_address

from google_cloud_hsm.base import BaseAccount
from google_cloud_hsm.config import GoogleHSMConfig
from google_cloud_hsm.exceptions import ConfigurationError
from google_cloud_hsm.providers.google import GoogleCloudHSM
from google_cloud_hsm.utils import derive_ethereum_address, serialize_transaction, to_eth_v


class GoogleAccount(BaseAccount):
    """Google Cloud HSM-backed Ethereum account."""

    def __init__(self, config: GoogleHSMConfig):
        self.config = config
        self.hsm = GoogleCloudHSM(config)
        self._address = None

    @classmethod
    def load_from_hsm(
        cls, project_id: str, region: str, key_ring_id: str, key_id: str, service_account_path: str | None = None
    ) -> "GoogleAccount":
        """Create account from Google Cloud HSM configuration."""
        config = GoogleHSMConfig(
            provider="google",
            project_id=project_id,
            region=region,
            key_ring_id=key_ring_id,
            key_id=key_id,
            service_account_path=service_account_path,
        )
        return cls(config)

    @property
    def address(self) -> Address:
        """Get Ethereum address derived from HSM public key."""
        if self._address is None:
            public_key = self.hsm.get_public_key()
            self._address = to_checksum_address(derive_ethereum_address(public_key))
        return self._address

    def sign_transaction(self, transaction) -> HexStr:
        """Sign an Ethereum transaction using Google Cloud HSM."""
        if "chainId" not in transaction:
            msg = "chainId must be specified in transaction"
            raise ConfigurationError(msg)

        chain_id = transaction["chainId"]
        serialized_tx = serialize_transaction(transaction, chain_id)

        # Sign the transaction using HSM
        signature = self.hsm.sign(serialized_tx)

        # Extract r, s, v from signature
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:64], "big")
        v = to_eth_v(signature[64], chain_id)

        # Create signed transaction
        signed = {**transaction, "v": v, "r": r, "s": s}

        return signed

    def sign_message(self, message: bytes | str) -> HexStr:
        """Sign a message using Google Cloud HSM."""
        if isinstance(message, str):
            message = to_bytes(text=message)

        # Ethereum signed message prefix
        prefix = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message

        # Sign the prefixed message
        signature = self.hsm.sign(prefix)

        return "0x" + signature.hex()
