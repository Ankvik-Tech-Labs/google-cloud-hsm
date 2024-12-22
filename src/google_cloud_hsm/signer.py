from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address
from google.cloud import kms

# from web3.types import TxParams
from google_cloud_hsm.config import GoogleHSMConfig
from google_cloud_hsm.exceptions import KeyNotFoundError, SigningError


class GoogleHSMSigner:
    """Google Cloud HSM signer for Ethereum transactions."""

    def __init__(
        self, project_id: str, key_ring_id: str, key_id: str, location_id: str = "us-east1", chain_id: int = 1
    ):
        """Initialize signer with HSM configuration."""
        self.config = GoogleHSMConfig(
            project_id=project_id, location_id=location_id, key_ring_id=key_ring_id, key_id=key_id, chain_id=chain_id
        )
        self.client = kms.KeyManagementServiceClient()
        self._public_key = None
        self._address = None

    @property
    def address(self) -> str:
        """Get Ethereum address."""
        if self._address is None:
            if self._public_key is None:
                self._load_public_key()
            # Convert public key to address
            hash_bytes = keccak(self._public_key[-64:])
            self._address = to_checksum_address(hash_bytes[-20:])
        return self._address

    def _load_public_key(self) -> None:
        """Load public key from HSM."""
        try:
            response = self.client.get_public_key(request={"name": self.config.version_path})
            self._public_key = response.pem
        except Exception as e:
            msg = f"Failed to get public key: {e!s}"
            raise KeyNotFoundError(msg)

    def sign_message(self, message: str) -> dict:
        """Sign a message following EIP-191."""
        try:
            # Create message hash
            msg = encode_defunct(text=message)
            msg_hash = keccak(text=message)

            # Sign with HSM
            response = self.client.asymmetric_sign(
                request={
                    "name": self.config.version_path,
                    "digest": {"sha256": msg_hash},
                }
            )

            # Normalize signature components
            signature = response.signature
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:64], "big")

            # Try recovery values
            for v in (27, 28):
                if Account.recover_message(msg, vrs=(v, r, s)) == self.address:
                    return {"r": hex(r), "s": hex(s), "v": v}

            msg = "Could not recover signature"
            raise SigningError(msg)

        except Exception as e:
            msg = f"Failed to sign message: {e!s}"
            raise SigningError(msg)  # noqa: B904

    # def sign_transaction(self, transaction) -> dict:
    #     """Sign a transaction following EIP-155."""
    #     try:
    #         # Ensure chainId
    #         chain_id = transaction.get("chainId", self.config.chain_id)
    #         transaction["chainId"] = chain_id
    #
    #         # Create hash
    #         unsigned_tx = Account()._prepare_transaction(transaction_dict=transaction, chain_id=chain_id)
    #         msg_hash = unsigned_tx.hash()
    #
    #         # Sign with HSM
    #         response = self.client.asymmetric_sign(
    #             request={
    #                 "name": self.config.version_path,
    #                 "digest": {"sha256": msg_hash},
    #             }
    #         )
    #
    #         # Create signature components
    #         signature = response.signature
    #         r = int.from_bytes(signature[:32], "big")
    #         s = int.from_bytes(signature[32:64], "big")
    #
    #         # Try recovery values
    #         for v_raw in (0, 1):
    #             v = (chain_id * 2 + 35) + v_raw
    #             tx_params = {**transaction, "v": v, "r": r, "s": s}
    #             if Account.recover_transaction(tx_params) == self.address:
    #                 return {"r": hex(r), "s": hex(s), "v": v}
    #
    #         msg = "Could not recover signature"
    #         raise SigningError(msg)
    #
    #     except Exception as e:
    #         msg = f"Failed to sign transaction: {e!s}"
    #         raise SigningError(msg)  # noqa: B904
