from pydantic import BaseModel, Field


class GoogleHSMConfig(BaseModel):
    """Configuration for Google Cloud HSM."""

    project_id: str = Field(..., description="Google Cloud project ID")
    location_id: str = Field(default="us-east1", description="Cloud KMS location")
    key_ring_id: str = Field(..., description="ID of the key ring")
    key_id: str = Field(..., description="ID of the key")
    key_version: int = Field(default=1, description="Version of the key")
    chain_id: int = Field(default=1, description="Ethereum chain ID")

    @property
    def key_path(self) -> str:
        """Full path to the key."""
        return (
            f"projects/{self.project_id}/locations/{self.location_id}/"
            f"keyRings/{self.key_ring_id}/cryptoKeys/{self.key_id}"
        )

    @property
    def version_path(self) -> str:
        """Full path to specific key version."""
        return f"{self.key_path}/cryptoKeyVersions/{self.key_version}"
