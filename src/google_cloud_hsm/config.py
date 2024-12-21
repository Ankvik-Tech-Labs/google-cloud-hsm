from pydantic import BaseModel, Field


class HSMConfig(BaseModel):
    """Base configuration for HSM providers."""

    provider: str = Field(..., description="HSM provider name (e.g., 'google', 'aws')")
    region: str = Field(..., description="Cloud provider region")


class GoogleHSMConfig(HSMConfig):
    """Configuration specific to Google Cloud HSM."""

    project_id: str = Field(..., description="Google Cloud project ID")
    key_ring_id: str = Field(..., description="ID of the key ring")
    key_id: str = Field(..., description="ID of the key")
    service_account_path: str | None = Field(None, description="Path to service account JSON")


# cloud_hsm_eth/exceptions.py
class CloudHSMError(Exception):
    """Base exception for Cloud HSM operations."""

    pass


class SigningError(CloudHSMError):
    """Error during transaction or message signing."""

    pass


class ConfigurationError(CloudHSMError):
    """Error in HSM configuration."""

    pass
