"""Configuration settings for the application."""

import os

from pydantic import BaseModel, Field, field_validator

# Configuration Constants
ENV_PROJECT_ID = "GOOGLE_CLOUD_PROJECT"
ENV_LOCATION_ID = "GOOGLE_CLOUD_REGION"
ENV_KEY_RING_ID = "KEY_RING"
ENV_KEY_ID = "KEY_NAME"
ENV_WEB3_PROVIDER_URI = "WEB3_PROVIDER_URI"
DEFAULT_WEB3_PROVIDER_URI = "http://localhost:8545"


class BaseConfig(BaseModel):
    """Application settings for Google Cloud KMS."""

    # Google Cloud settings
    project_id: str = Field(..., min_length=1)
    location_id: str = Field(..., min_length=1)
    key_ring_id: str = Field(..., min_length=1)
    key_id: str = Field(..., min_length=1)

    # Web3 settings
    web3_provider_uri: str = Field(default=DEFAULT_WEB3_PROVIDER_URI, min_length=1)

    @field_validator("project_id", "location_id", "key_ring_id", "key_id", "web3_provider_uri")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        """Validate that fields are not empty or whitespace."""
        if not v or not v.strip():
            msg = "Field cannot be empty or whitespace"
            raise ValueError(msg)
        return v.strip()

    class Config:
        validate_assignment = True

    @classmethod
    def from_env(cls) -> "BaseConfig":
        """
        Create configuration from environment variables.

        Returns:
            BaseConfig: Configuration instance with values from environment variables.

        Raises:
            ValidationError: If any required fields are missing or invalid
        """
        return cls(
            project_id=os.getenv(ENV_PROJECT_ID, ""),
            location_id=os.getenv(ENV_LOCATION_ID, ""),
            key_ring_id=os.getenv(ENV_KEY_RING_ID, ""),
            key_id=os.getenv(ENV_KEY_ID, ""),
            web3_provider_uri=os.getenv(ENV_WEB3_PROVIDER_URI, DEFAULT_WEB3_PROVIDER_URI),
        )
