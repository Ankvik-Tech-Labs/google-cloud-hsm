import pytest
from unittest.mock import MagicMock

from google_cloud_hsm.accounts.gcp_kms_account import GCPKmsAccount
# from google_cloud_hsm.exceptions import SignatureError
# from google_cloud_hsm.types.ethereum_types import Transaction

def test_account_initialization(gcp_kms_account: GCPKmsAccount):
    """Test account initialization."""
    assert isinstance(gcp_kms_account, GCPKmsAccount)
    assert gcp_kms_account.key_path is not None

def test_get_public_key(gcp_kms_account: GCPKmsAccount, mock_kms_client: MagicMock):
    """Test getting public key from KMS."""
    public_key = gcp_kms_account.public_key
    assert isinstance(public_key, bytes)
    assert len(public_key) == 64
    mock_kms_client.get_public_key.assert_called_once()

def test_get_address(gcp_kms_account: GCPKmsAccount, test_address: str):
    """Test deriving Ethereum address from public key."""
    address = gcp_kms_account.address
    assert address == test_address
    assert address.startswith("0x")
    assert len(address) == 42

def test_sign_message(gcp_kms_account: GCPKmsAccount, mock_kms_client: MagicMock):
    """Test message signing."""
    message = "Hello, Ethereum!"
    signature = gcp_kms_account.sign_message(message)

    # Verify the signature components
    assert signature.v in (27, 28)
    assert len(signature.r) == 32
    assert len(signature.s) == 32

    # Verify KMS was called correctly
    mock_kms_client.asymmetric_sign.assert_called_once()
    call_args = mock_kms_client.asymmetric_sign.call_args[1]
    assert "name" in call_args["request"]
    assert "digest" in call_args["request"]


def test_invalid_message_type(gcp_kms_account: GCPKmsAccount):
    """Test signing with invalid message type."""
    with pytest.raises(TypeError, match="Unsupported message type"):
        gcp_kms_account.sign_message(123)  # type: ignore

def test_sign_transaction_no_signature(gcp_kms_account: GCPKmsAccount, mock_kms_client: MagicMock):
    """Test transaction signing when KMS fails."""
    mock_kms_client.asymmetric_sign.return_value = None

    with pytest.raises(Exception, match="Signing error"):
        gcp_kms_account.sign_message("test message")
