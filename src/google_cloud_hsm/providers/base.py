from abc import abstractmethod

from pydantic import BaseModel

from google_cloud_hsm.config import HSMConfig


class HSMProvider(BaseModel):
    """Base class for HSM providers."""

    @abstractmethod
    def __init__(self, config: HSMConfig):
        pass

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Sign a message using the HSM."""
        pass

    @abstractmethod
    def get_public_key(self) -> bytes:
        """Get the public key from HSM."""
        pass
