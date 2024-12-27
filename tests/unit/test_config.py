"""Unit tests for configuration."""
import pytest
from web3_google_hsm.config import (
    BaseConfig,
    ENV_PROJECT_ID,
    ENV_LOCATION_ID,
    ENV_KEY_RING_ID,
    ENV_KEY_ID,
    ENV_WEB3_PROVIDER_URI,
    DEFAULT_WEB3_PROVIDER_URI,
)
from unittest.mock import patch
from pydantic import ValidationError

# Test Constants
TEST_CONFIG = {
    "project_id": "test-project",
    "location_id": "test-region",
    "key_ring_id": "test-keyring",
    "key_id": "test-key",
}

def test_env_constants():
    """Test that environment variable constants are correct."""
    assert ENV_PROJECT_ID == "GOOGLE_CLOUD_PROJECT"
    assert ENV_LOCATION_ID == "GOOGLE_CLOUD_REGION"
    assert ENV_KEY_RING_ID == "KEY_RING"
    assert ENV_KEY_ID == "KEY_NAME"
    assert ENV_WEB3_PROVIDER_URI == "WEB3_PROVIDER_URI"
    assert DEFAULT_WEB3_PROVIDER_URI == "http://localhost:8545"

def test_config_from_env():
    """Test configuration creation from environment variables."""
    env_vars = {
        ENV_PROJECT_ID: "env-project",
        ENV_LOCATION_ID: "env-region",
        ENV_KEY_RING_ID: "env-keyring",
        ENV_KEY_ID: "env-key",
        ENV_WEB3_PROVIDER_URI: "http://custom:8545"
    }

    with patch.dict("os.environ", env_vars, clear=True):
        config = BaseConfig.from_env()
        assert config.project_id == "env-project"
        assert config.location_id == "env-region"
        assert config.key_ring_id == "env-keyring"
        assert config.key_id == "env-key"
        assert config.web3_provider_uri == "http://custom:8545"

def test_config_from_empty_env():
    """Test configuration creation from empty environment."""
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(ValidationError) as exc_info:
            BaseConfig.from_env()
        errors = exc_info.value.errors()
        fields = {"project_id", "location_id", "key_ring_id", "key_id"}
        error_fields = {error["loc"][0] for error in errors}
        assert fields.issubset(error_fields)

def test_config_from_partial_env():
    """Test configuration creation from partial environment variables."""
    env_vars = {
        ENV_PROJECT_ID: "env-project",
        ENV_LOCATION_ID: "env-region",
    }

    with patch.dict("os.environ", env_vars, clear=True):
        with pytest.raises(ValidationError) as exc_info:
            BaseConfig.from_env()
        errors = exc_info.value.errors()
        assert any(error["loc"][0] == "key_ring_id" for error in errors)
        assert any(error["loc"][0] == "key_id" for error in errors)

def test_config_initialization():
    """Test direct initialization with valid values."""
    config = BaseConfig(**TEST_CONFIG)
    assert config.project_id == TEST_CONFIG["project_id"]
    assert config.location_id == TEST_CONFIG["location_id"]
    assert config.key_ring_id == TEST_CONFIG["key_ring_id"]
    assert config.key_id == TEST_CONFIG["key_id"]
    assert config.web3_provider_uri == DEFAULT_WEB3_PROVIDER_URI

def test_config_validation_empty():
    """Test validation with empty config."""
    with pytest.raises(ValidationError) as exc_info:
        BaseConfig()
    errors = exc_info.value.errors()
    fields = {"project_id", "location_id", "key_ring_id", "key_id"}
    error_fields = {error["loc"][0] for error in errors}
    assert fields.issubset(error_fields)

def test_config_web3_provider_override():
    """Test setting custom web3 provider URI."""
    custom_uri = "http://custom:8545"
    config = BaseConfig(
        **TEST_CONFIG,
        web3_provider_uri=custom_uri
    )
    assert config.web3_provider_uri == custom_uri

@pytest.mark.parametrize("whitespace", ["  ", "\t", "\n", "\r\n"])
def test_config_whitespace_env_vars(whitespace):
    """Test that whitespace environment variables are treated as missing."""
    env_vars = {
        ENV_PROJECT_ID: whitespace,
        ENV_LOCATION_ID: whitespace,
        ENV_KEY_RING_ID: whitespace,
        ENV_KEY_ID: whitespace
    }

    with patch.dict("os.environ", env_vars, clear=True):
        with pytest.raises(ValidationError) as exc_info:
            BaseConfig.from_env()
        errors = exc_info.value.errors()
        fields = {"project_id", "location_id", "key_ring_id", "key_id"}
        error_fields = {error["loc"][0] for error in errors}
        assert fields.issubset(error_fields)

def test_config_empty_string_validation():
    """Test that empty strings are considered invalid."""
    invalid_config = TEST_CONFIG.copy()
    invalid_config["project_id"] = ""

    with pytest.raises(ValidationError) as exc_info:
        BaseConfig(**invalid_config)
    errors = exc_info.value.errors()
    assert any(error["loc"][0] == "project_id" for error in errors)
