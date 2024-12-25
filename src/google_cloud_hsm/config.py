import os
from typing import Any

import dotenv
from pydantic_settings import BaseSettings

dotenv.load_dotenv()


class BaseConfig(BaseSettings):
    """Application settings loaded from environment variables."""

    # Google Cloud settings
    project_id: str = os.getenv("GOOGLE_CLOUD_PROJECT", "")
    location_id: str = os.getenv("GOOGLE_CLOUD_REGION", "")
    key_ring_id: str = os.getenv("KEY_RING", "")
    key_id: str = os.getenv("KEY_NAME", "")

    # Web3 settings
    web3_provider_uri: str = os.getenv("WEB3_PROVIDER_URI", "http://localhost:8545")

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
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
            if not var_value:
                missing_vars.append(var_name)

        if missing_vars:
            msg = f"Missing required environment variables: {', '.join(missing_vars)}"
            raise ValueError(msg)
