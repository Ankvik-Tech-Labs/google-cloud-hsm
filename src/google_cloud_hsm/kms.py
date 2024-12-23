"""KMS provider implementation."""

import base64
from dataclasses import dataclass

from google.cloud.kms_v1 import KeyManagementServiceClient


@dataclass
class KmsKeyRef:
    """Reference to a KMS key."""

    project_id: str
    location: str
    key_ring: str

    def to_key_path(self) -> str:
        """Get the full key path."""
        return f"projects/{self.project_id}/locations/{self.location}/keyRings/{self.key_ring}"

    def to_key_version_ref(self, key_id: str, key_version: int = 1) -> str:
        """Get the full path to a specific key version."""
        return f"{self.to_key_path()}/cryptoKeys/{key_id}/cryptoKeyVersions/{key_version}"


class KmsProvider:
    """Google Cloud KMS provider."""

    def __init__(self, key_ref: KmsKeyRef):
        self.key_ref = key_ref
        self.client = KeyManagementServiceClient()

    async def get_public_key(self, key_id: str, key_version: int = 1) -> bytes:
        """Get the public key in DER format."""
        key_path = self.key_ref.to_key_version_ref(key_id, key_version)

        # Add request headers for routing
        request = {"name": key_path, "x-goog-request-params": f"name={key_path}"}

        response = self.client.get_public_key(request=request)
        return base64.b64decode(response.pem)

    def sign_digest(self, key_id: str, digest: bytes, key_version: int = 1) -> bytes:
        """Sign a digest with the HSM key."""
        key_path = self.key_ref.to_key_version_ref(key_id, key_version)

        # Add request headers for routing
        request = {"name": key_path, "digest": {"sha256": digest}, "x-goog-request-params": f"name={key_path}"}

        response = self.client.asymmetric_sign(request=request)
        return response.signature
