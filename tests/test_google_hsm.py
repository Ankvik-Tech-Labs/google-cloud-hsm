import pytest
from unittest.mock import Mock, patch
from google_cloud_hsm.accounts.google import GoogleAccount
from google_cloud_hsm.config import GoogleHSMConfig
from google_cloud_hsm.exceptions import ConfigurationError

@pytest.fixture
def mock_hsm():
    with patch('cloud_hsm_eth.providers.google.GoogleCloudHSM') as mock:
        # Mock the required methods
        mock.return_value.get_public_key.return_value = bytes.fromhex('0304...') # Add a valid public key
        mock.return_value.sign.return_value = bytes.fromhex('0123...') # Add a valid signature
        yield mock

def test_account_creation(mock_hsm):
    account = GoogleAccount.load_from_hsm(
        project_id="test-project",
        region="us-east1",
        key_ring_id="test-keyring",
        key_id="test-key"
    )
    assert account.address is not None
    mock_hsm.return_value.get_public_key.assert_called_once()

def test_sign_transaction_without_chain_id(mock_hsm):
    account = GoogleAccount.load_from_hsm(
        project_id="test-project",
        region="us-east1",
        key_ring_id="test-keyring",
        key_id="test-key"
    )
    
    with pytest.raises(ConfigurationError, match="chainId must be specified"):
        account.sign_transaction({
            'nonce': 0,
            'gasPrice': 20000000000,
            'gas': 21000,
            'to': '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
            'value': 1000000000000000000
        })

def test_sign_message(mock_hsm):
    account = GoogleAccount.load_from_hsm(
        project_id="test-project",
        region="us-east1",
        key_ring_id="test-keyring",
        key_id="test-key"
    )
    
    signature = account.sign_message("Hello, Ethereum!")
    assert signature.startswith("0x")
    mock_hsm.return_value.sign.assert_called_once()