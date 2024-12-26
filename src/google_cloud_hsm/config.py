"""Configuration settings for the application."""

import os
from typing import Any

from pydantic import BaseModel


def _validate_value(value: str) -> bool:
    """Check if a value is valid (non-empty and not just whitespace)."""
    return bool(value and value.strip())


class BaseConfig(BaseModel):
    """Application settings loaded from environment variables."""

    # Google Cloud settings
    project_id: str = ""
    location_id: str = ""
    key_ring_id: str = ""
    key_id: str = ""

    # Web3 settings
    web3_provider_uri: str = "http://localhost:8545"

    def __init__(self, **kwargs: Any):
        # First initialize with any provided kwargs
        super().__init__(**kwargs)

        # Then, override with environment variables if they exist
        if os.getenv("GOOGLE_CLOUD_PROJECT"):
            self.project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "")
        if os.getenv("GOOGLE_CLOUD_REGION"):
            self.location_id = os.getenv("GOOGLE_CLOUD_REGION", "")
        if os.getenv("KEY_RING"):
            self.key_ring_id = os.getenv("KEY_RING", "")
        if os.getenv("KEY_NAME"):
            self.key_id = os.getenv("KEY_NAME", "")
        if os.getenv("WEB3_PROVIDER_URI"):
            self.web3_provider_uri = os.getenv("WEB3_PROVIDER_URI", "http://localhost:8545")

        self._validate_settings()

    def _validate_settings(self) -> None:
        """Validate that all required settings are present."""
        missing_vars = []
        required_vars = {
            "project_id": self.project_id,
            "location_id": self.location_id,
            "key_ring_id": self.key_ring_id,
            "key_id": self.key_id,
        }

        for var_name, var_value in required_vars.items():
            if not _validate_value(var_value):
                missing_vars.append(var_name)

        if missing_vars:
            msg = f"Missing required environment variables: {', '.join(missing_vars)}"
            raise ValueError(msg)

    def update(self, **kwargs: Any) -> None:
        """Update config values."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self._validate_settings()
