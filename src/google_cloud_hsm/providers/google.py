from eth_utils import keccak
from google.cloud import kms
from google.cloud.kms_v1 import KeyManagementServiceClient

from google_cloud_hsm.config import GoogleHSMConfig
from google_cloud_hsm.exceptions import SigningError
from google_cloud_hsm.providers.base import HSMProvider


class GoogleCloudHSM(HSMProvider):
    """Google Cloud HSM implementation."""

    def __init__(self, config: GoogleHSMConfig):
        super().__init__(config)
        self.config = config
        self.client = self._create_client()
        self.key_name = self._get_key_name()

    def _create_client(self) -> KeyManagementServiceClient:
        """Create Google Cloud KMS client."""
        if self.config.service_account_path:
            return kms.KeyManagementServiceClient.from_service_account_json(self.config.service_account_path)
        return kms.KeyManagementServiceClient()

    def _get_key_name(self) -> str:
        """Get the full key name."""
        return (
            f"projects/{self.config.project_id}/locations/{self.config.region}/"
            f"keyRings/{self.config.key_ring_id}/cryptoKeys/{self.config.key_id}"
        )

    def sign(self, message: bytes) -> bytes:
        """Sign a message using Google Cloud HSM."""
        try:
            digest = self._create_digest(message)
            response = self.client.asymmetric_sign(
                request={
                    "name": f"{self.key_name}/cryptoKeyVersions/1",
                    "digest": {"sha256": digest},
                }
            )
            return response.signature
        except Exception as e:
            msg = f"Failed to sign message: {e!s}"
            raise SigningError(msg)

    def get_public_key(self) -> bytes:
        """Get the public key from Google Cloud HSM."""
        try:
            response = self.client.get_public_key(request={"name": f"{self.key_name}/cryptoKeyVersions/1"})
            return response.pem.encode()
        except Exception as e:
            msg = f"Failed to get public key: {e!s}"
            raise SigningError(msg)

    @staticmethod
    def _create_digest(message: bytes) -> bytes:
        return keccak(message)
