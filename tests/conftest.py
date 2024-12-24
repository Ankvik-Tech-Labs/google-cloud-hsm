from typing import Dict, Any
import pytest
from unittest.mock import MagicMock
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from web3 import Web3
from google.cloud import kms

from google_cloud_hsm.types.ethereum_types import Transaction, Signature
from google_cloud_hsm.accounts.gcp_kms_account import GCPKmsAccount

# Test Constants
TEST_ADDRESS = "0x0545640A0EcD6FB6ae94766811F30dCDA4746DFC"
TEST_KEY_PATH = "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1"
TEST_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE0hPxTjwIf407JpkjCdf9kwVPvGdMOZUq
GaVPbV4qdocIUoJlxmWoOQeL/mR28cLrRqgn+Uj8HAoman2lndsp3w==
-----END PUBLIC KEY-----"""

TEST_SIGNATURE_VALUES = {
    "v": 27,
    "r": bytes.fromhex("b3c2fef0472f76bfcbd4f142a2d32e0ca8eaf72e2c5039f27935aaa416f10857"),
    "s": bytes.fromhex("3e2629df516b30b71438d4c8459b1ad279416d3e38bcc3f487038a9468471842")
}

TEST_MESSAGE = "Hello Ethereum!"

# This is a DER-encoded test signature
TEST_DER_SIGNATURE = bytes.fromhex(
    "30450221"  # Sequence tag and length
    "b3c2fef0472f76bfcbd4f142a2d32e0ca8eaf72e2c5039f27935aaa416f10857"  # r
    "02203e2629df516b30b71438d4c8459b1ad279416d3e38bcc3f487038a9468471842"  # s
)

@pytest.fixture
def web3():
    """Initialize Web3 instance."""
    return Web3(Web3.HTTPProvider("http://localhost:8545"))

@pytest.fixture
def test_address() -> ChecksumAddress:
    """Get a test Ethereum address."""
    return to_checksum_address(TEST_ADDRESS)

@pytest.fixture
def test_message() -> str:
    """Get a test message."""
    return TEST_MESSAGE

@pytest.fixture
def test_signature() -> Signature:
    """Create a test signature with real test values."""
    return Signature(**TEST_SIGNATURE_VALUES)

@pytest.fixture
def transaction_dict(web3) -> Dict[str, Any]:
    """Create a test transaction dictionary."""
    return {
        "from": TEST_ADDRESS,
        "chain_id": web3.eth.chain_id,
        "nonce": web3.eth.get_transaction_count(TEST_ADDRESS),
        "value": web3.to_wei(0.000001, "ether"),
        "data": "0x00",
        "to": "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
        "type": 0,
        "gas_limit": 1000000,
        "gas_price": 300000000000,
    }

@pytest.fixture
def test_transaction(transaction_dict: Dict[str, Any]) -> Transaction:
    """Create a test transaction."""
    return Transaction.from_dict(transaction_dict)

@pytest.fixture
def mock_kms_client() -> MagicMock:
    """Create a mock KMS client."""
    mock_client = MagicMock(spec=kms.KeyManagementServiceClient)
    
    # Mock the get_public_key response
    mock_public_key_response = MagicMock()
    mock_public_key_response.pem = TEST_PUBLIC_KEY
    mock_client.get_public_key.return_value = mock_public_key_response
    
    # Mock the asymmetric_sign response with real test values in DER format
    mock_sign_response = MagicMock()
    mock_sign_response.signature = TEST_DER_SIGNATURE
    mock_client.asymmetric_sign.return_value = mock_sign_response
    
    return mock_client

@pytest.fixture
def gcp_kms_account(mock_kms_client: MagicMock) -> GCPKmsAccount:
    """Create a GCP KMS account with mocked client."""
    account = GCPKmsAccount(key_path=TEST_KEY_PATH)
    account._client = mock_kms_client
    return account

@pytest.fixture
def funded_account(web3: Web3) -> Any:
    """Create a funded test account using hardhat's first account."""
    return web3.eth.account.from_key(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )

@pytest.fixture
def fund_test_account(web3: Web3, funded_account: Any, test_address: ChecksumAddress):
    """Fund the test account with some ETH."""
    tx = {
        'from': funded_account.address,
        'to': test_address,
        'value': web3.to_wei(0.1, 'ether'),
        'gas': 21000,
        'gasPrice': web3.eth.gas_price,
        'nonce': web3.eth.get_transaction_count(funded_account.address),
        'chainId': web3.eth.chain_id
    }
    
    signed_tx = web3.eth.account.sign_transaction(tx, funded_account.key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    return web3.eth.wait_for_transaction_receipt(tx_hash)

@pytest.fixture
def address() -> ChecksumAddress:
    """Get a test Ethereum address."""
    return to_checksum_address(TEST_ADDRESS)