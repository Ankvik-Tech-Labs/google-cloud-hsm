class HSMError(Exception):
    """Base exception for HSM operations."""

    pass


class SigningError(HSMError):
    """Error during signature operations."""

    pass


class KeyNotFoundError(HSMError):
    """Key not found in HSM."""

    pass
