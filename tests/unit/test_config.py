"""Unit tests for configuration."""
import pytest
from google_cloud_hsm.config import BaseConfig
from unittest.mock import patch

# Test Constants
TEST_ENV = {
    "project_id": "test-project",
    "location_id": "test-region",
    "key_ring_id": "test-keyring",
    "key_id": "test-key",
}


def test_config_initialization():
    """Test initialization with instance variables."""
    config = BaseConfig(**TEST_ENV)
    assert config.project_id == TEST_ENV["project_id"]
    assert config.location_id == TEST_ENV["location_id"]
    assert config.key_ring_id == TEST_ENV["key_ring_id"]
    assert config.key_id == TEST_ENV["key_id"]

def test_config_default_values():
    """Test default values for non-required fields."""
    config = BaseConfig(**TEST_ENV)
    assert config.web3_provider_uri == "http://localhost:8545"

def test_config_validation_empty():
    """Test validation with empty config."""
    with pytest.raises(ValueError) as exc_info:
        BaseConfig()
    error_msg = str(exc_info.value)
    assert "project_id" in error_msg
    assert "location_id" in error_msg
    assert "key_ring_id" in error_msg
    assert "key_id" in error_msg

def test_config_partial_values():
    """Test validation with partial values."""
    partial_config = {
        "project_id": "test-project",
        "location_id": "test-region",
    }
    with pytest.raises(ValueError) as exc_info:
        BaseConfig(**partial_config)
    error_msg = str(exc_info.value)
    assert "key_ring_id" in error_msg
    assert "key_id" in error_msg

def test_config_update():
    """Test updating config values."""
    config = BaseConfig(**TEST_ENV)

    # Update single value
    config.update(project_id="new-project")
    assert config.project_id == "new-project"

    # Update multiple values
    config.update(
        location_id="new-region",
        key_ring_id="new-keyring"
    )
    assert config.location_id == "new-region"
    assert config.key_ring_id == "new-keyring"

def test_config_update_validation():
    """Test validation after update."""
    config = BaseConfig(**TEST_ENV)

    # Update with empty value should fail validation
    with pytest.raises(ValueError) as exc_info:
        config.update(project_id="")
    assert "project_id" in str(exc_info.value)

def test_config_web3_provider_override():
    """Test overriding web3 provider URI."""
    custom_uri = "http://custom:8545"
    config = BaseConfig(
        **TEST_ENV,
        web3_provider_uri=custom_uri
    )
    assert config.web3_provider_uri == custom_uri

def test_config_empty_string_validation():
    """Test that empty strings are considered invalid."""
    env = TEST_ENV.copy()
    env["project_id"] = ""  # Empty string

    with pytest.raises(ValueError) as exc_info:
        BaseConfig(**env)
    assert "project_id" in str(exc_info.value)

def test_config_whitespace_validation():
    """Test that whitespace strings are considered invalid."""
    env = TEST_ENV.copy()
    env["project_id"] = "   "  # Whitespace

    with pytest.raises(ValueError) as exc_info:
        BaseConfig(**env)
    assert "project_id" in str(exc_info.value)


def test_config_from_env_vars():
    """Test BaseConfig initialization from environment variables."""
    env_vars = {
        "GOOGLE_CLOUD_PROJECT": "env-project",
        "GOOGLE_CLOUD_REGION": "env-region",
        "KEY_RING": "env-keyring",
        "KEY_NAME": "env-key"
    }

    with patch.dict("os.environ", env_vars, clear=True):
        config = BaseConfig()  # No arguments provided

        # Values should be loaded from environment
        assert config.project_id == "env-project"
        assert config.location_id == "env-region"
        assert config.key_ring_id == "env-keyring"
        assert config.key_id == "env-key"


def test_config_env_precedence():
    """Test that environment variables take precedence over provided values."""
    env_vars = {
        "GOOGLE_CLOUD_PROJECT": "env-project",
        "GOOGLE_CLOUD_REGION": "env-region",
        "KEY_RING": "env-keyring",
        "KEY_NAME": "env-key"
    }

    with patch.dict("os.environ", env_vars, clear=True):
        config = BaseConfig(
            project_id="kwarg-project",
            location_id="kwarg-region",
            key_ring_id="kwarg-keyring",
            key_id="kwarg-key"
        )

        # Environment values should override kwargs
        assert config.project_id == "env-project"
        assert config.location_id == "env-region"
        assert config.key_ring_id == "env-keyring"
        assert config.key_id == "env-key"


def test_config_partial_env_vars():
    """Test BaseConfig with a mix of environment and provided values."""
    env_vars = {
        "GOOGLE_CLOUD_PROJECT": "env-project",
        "GOOGLE_CLOUD_REGION": "env-region",
    }

    with patch.dict("os.environ", env_vars, clear=True):
        config = BaseConfig(
            key_ring_id="kwarg-keyring",
            key_id="kwarg-key"
        )

        # Should be mix of env vars and kwargs
        assert config.project_id == "env-project"
        assert config.location_id == "env-region"
        assert config.key_ring_id == "kwarg-keyring"
        assert config.key_id == "kwarg-key"


def test_config_web3_provider_uri_from_env():
    """Test setting web3 provider URI from environment."""
    env_vars = {
        "GOOGLE_CLOUD_PROJECT": "env-project",
        "GOOGLE_CLOUD_REGION": "env-region",
        "KEY_RING": "env-keyring",
        "KEY_NAME": "env-key",
        "WEB3_PROVIDER_URI": "http://env:8545"
    }

    with patch.dict("os.environ", env_vars, clear=True):
        config = BaseConfig()
        assert config.web3_provider_uri == "http://env:8545"
        assert config.location_id == env_vars["GOOGLE_CLOUD_REGION"]
        assert config.key_id == env_vars["KEY_NAME"]


def test_config_empty_env_no_kwargs():
    """Test that empty environment and no kwargs raises error."""
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(ValueError) as exc_info:
            BaseConfig()
        error_msg = str(exc_info.value)
        assert "project_id" in error_msg
        assert "location_id" in error_msg
        assert "key_ring_id" in error_msg
        assert "key_id" in error_msg


@pytest.mark.parametrize("whitespace", ["  ", "\t", "\n", "\r\n"])
def test_config_whitespace_env_vars(whitespace):
    """Test that whitespace environment variables are treated as missing."""
    env_vars = {
        "GOOGLE_CLOUD_PROJECT": whitespace,
        "GOOGLE_CLOUD_REGION": whitespace,
        "KEY_RING": whitespace,
        "KEY_NAME": whitespace
    }

    with patch.dict("os.environ", env_vars, clear=True):
        with pytest.raises(ValueError) as exc_info:
            BaseConfig()
        error_msg = str(exc_info.value)
        assert all(var in error_msg for var in ["project_id", "location_id", "key_ring_id", "key_id"])
