class CloudHSMError(Exception):
    """Base exception for Cloud HSM operations."""

    pass


class SigningError(CloudHSMError):
    """Error during transaction or message signing."""

    pass


class ConfigurationError(CloudHSMError):
    """Error in HSM configuration."""

    pass
