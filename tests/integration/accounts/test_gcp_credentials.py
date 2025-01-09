import os

from pydantic import ValidationError
import pytest
from web3_google_hsm.accounts.gcp_kms_account import GCPKmsAccount
from web3_google_hsm.config import BaseConfig
import json

# Define required environment variables
REQUIRED_ENV_VARS = {
    "GOOGLE_CLOUD_PROJECT": os.getenv("GOOGLE_CLOUD_PROJECT"),
    "GOOGLE_CLOUD_REGION": os.getenv("GOOGLE_CLOUD_REGION"),
    "KEY_RING": os.getenv("KEY_RING"),
    "KEY_NAME": os.getenv("KEY_NAME"),
    "GCP_ADC_CREDENTIALS_STRING": os.getenv("GCP_ADC_CREDENTIALS_STRING"),
}

# Skip all tests if any required env var is missing
missing_vars = [k for k, v in REQUIRED_ENV_VARS.items() if not v]
pytestmark = pytest.mark.skipif(
    bool(missing_vars),
    reason=f"Missing required environment variables: {', '.join(missing_vars)}"
)

def test_account_initialization_with_both():
    """Test initializing account with both config and credentials."""
    # Load credentials from GCP_ADC_CREDENTIALS_STRING env var
    credentials = json.loads(os.environ["GCP_ADC_CREDENTIALS_STRING"])

    # Create config from environment
    config = BaseConfig.from_env()

    # Initialize account with both
    account = GCPKmsAccount(config=config, credentials=credentials)

    # Verify initialization
    assert account._client is not None
    assert account._settings is not None
    assert account.key_path is not None
    assert account.address.startswith("0x")

    # Test basic functionality
    message = "Test message"
    signature = account.sign_message(message)
    assert signature.v in (27, 28)
    assert len(signature.r) == 32
    assert len(signature.s) == 32

def test_account_initialization_with_neither():
    """Test initializing account with neither config nor credentials (using env vars)."""
    # Initialize account without explicit config or credentials
    account = GCPKmsAccount()

    # Verify initialization
    assert account._client is not None
    assert account._settings is not None  # Should be created from env
    assert account.key_path is not None
    assert account.address.startswith("0x")

    # Test basic functionality
    message = "Test message"
    signature = account.sign_message(message)
    assert signature.v in (27, 28)
    assert len(signature.r) == 32
    assert len(signature.s) == 32

def test_fail_account_initialization_with_only_config(monkeypatch):
    """Test that initializing with only config raises error."""
    env_vars_to_clear = [
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_REGION",
        "KEY_RING",
        "KEY_NAME",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GCP_ADC_CREDENTIALS_STRING"
    ]

    for env_var in env_vars_to_clear:
        monkeypatch.delenv(env_var, raising=False)

    with pytest.raises(ValidationError):
        config = BaseConfig.from_env()
        GCPKmsAccount(config=config)

def test_fail_account_initialization_with_only_credentials(monkeypatch):
    """Test that initializing with only credentials raises error."""
    env_vars_to_clear = [
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_REGION",
        "KEY_RING",
        "KEY_NAME",
    ]

    for env_var in env_vars_to_clear:
        monkeypatch.delenv(env_var, raising=False)
    credentials = json.loads(os.environ["GCP_ADC_CREDENTIALS_STRING"])

    with pytest.raises(ValidationError):
        GCPKmsAccount(credentials=credentials)

def test_key_path_matches_config(monkeypatch):
    """Test that the key path matches the config values."""
    # Load both config and credentials
    credentials = json.loads(os.environ["GCP_ADC_CREDENTIALS_STRING"])

    config = BaseConfig.from_env()
    account = GCPKmsAccount(config=config, credentials=credentials)

    # Verify key path contains all the expected components
    assert config.project_id in account.key_path
    assert config.location_id in account.key_path
    assert config.key_ring_id in account.key_path
    assert config.key_id in account.key_path
