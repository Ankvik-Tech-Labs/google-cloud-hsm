import os

import pytest
from unittest.mock import MagicMock

from web3_google_hsm.accounts.gcp_kms_account import GCPKmsAccount
from web3_google_hsm import Transaction
from eth_account.messages import encode_defunct
from hexbytes import HexBytes


# Check required environment variables
REQUIRED_ENV_VARS = {
    "GOOGLE_CLOUD_PROJECT": os.getenv("GOOGLE_CLOUD_PROJECT"),
    "GOOGLE_CLOUD_REGION": os.getenv("GOOGLE_CLOUD_REGION"),
    "KEY_RING": os.getenv("KEY_RING"),
    "KEY_NAME": os.getenv("KEY_NAME"),
    "JSON_RPC_BASE": os.getenv("JSON_RPC_BASE", "http://localhost:8545"),
}

# Skip all tests if any required env var is missing
missing_vars = [k for k, v in REQUIRED_ENV_VARS.items() if not v]
pytestmark = pytest.mark.skipif(
    bool(missing_vars),
    reason=f"Missing required environment variables: {', '.join(missing_vars)}"
)

def test_account_initialization(gcp_account):
    """Test initializing account with real GCP KMS."""
    assert gcp_account.key_path
    assert gcp_account.address.startswith("0x")
    assert len(gcp_account.address) == 42


def test_message_signing_and_verification(gcp_account, web3):
    """Test signing and verifying messages with real GCP KMS."""
    # Sign message
    message = "Hello Ethereum!"
    signature = gcp_account.sign_message(message)

    # Verify components
    assert signature.v in (27, 28)
    assert len(signature.r) == 32
    assert len(signature.s) == 32

    # Verify recovery
    message_hash = encode_defunct(text=message)
    recovered_address = web3.eth.account.recover_message(
        message_hash,
        vrs=(signature.v, signature.r, signature.s)
    )

    assert recovered_address.lower() == gcp_account.address.lower()


def test_transaction_signing(gcp_account, fund_account, web3):
    """Test signing and sending transactions with real GCP KMS."""
    # Create transaction
    tx = Transaction(
        chain_id=web3.eth.chain_id,
        nonce=web3.eth.get_transaction_count(gcp_account.address),
        gas_price=web3.eth.gas_price,
        gas_limit=21000,
        to="0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
        value=web3.to_wei(0.001, "ether"),
        data="0x",
        from_=gcp_account.address
    )

    # Sign transaction
    signed_tx = gcp_account.sign_transaction(tx)
    assert signed_tx is not None

    # Send transaction
    tx_hash = web3.eth.send_raw_transaction(signed_tx)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    # Verify transaction was successful
    assert receipt['status'] == 1
    assert receipt['from'].lower() == gcp_account.address.lower()

    # Verify signature
    recovered = web3.eth.account.recover_transaction(signed_tx)
    assert recovered.lower() == gcp_account.address.lower()


def test_transaction_with_data(gcp_account, fund_account, web3):
    """Test signing transactions with data field."""
    tx = Transaction(
        chain_id=web3.eth.chain_id,
        nonce=web3.eth.get_transaction_count(gcp_account.address),
        gas_price=300000000000,
        gas_limit=1000000,
        to="0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
        value=web3.to_wei(0.000001, "ether"),
        data="0x68656c6c6f",  # "hello" in hex
        from_=gcp_account.address
    )

    signed_tx = gcp_account.sign_transaction(tx)
    assert signed_tx is not None

    # Send and verify
    tx_hash = web3.eth.send_raw_transaction(signed_tx)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt['status'] == 1

    # Verify the transaction data
    tx_details = web3.eth.get_transaction(tx_hash)
    assert tx_details['input'] == HexBytes("0x68656c6c6f")


def test_multiple_transactions(gcp_account, web3):
    """Test sending multiple consecutive transactions."""
    for i in range(3):
        tx = Transaction(
            chain_id=web3.eth.chain_id,
            nonce=web3.eth.get_transaction_count(gcp_account.address),
            gas_price=web3.eth.gas_price,
            gas_limit=21000,
            to="0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
            value=web3.to_wei(0.0001, "ether"),
            data="0x",
            from_=gcp_account.address
        )

        signed_tx = gcp_account.sign_transaction(tx)
        tx_hash = web3.eth.send_raw_transaction(signed_tx)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

        assert receipt['status'] == 1
        assert receipt['from'].lower() == gcp_account.address.lower()


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


def test_invalid_message_type(gcp_kms_account: GCPKmsAccount):
    """Test signing with invalid message type."""
    with pytest.raises(TypeError, match="Unsupported message type"):
        gcp_kms_account.sign_message(123)  # type: ignore

def test_sign_transaction_no_signature(gcp_kms_account: GCPKmsAccount, mock_kms_client: MagicMock):
    """Test transaction signing when KMS fails."""
    mock_kms_client.asymmetric_sign.return_value = None

    with pytest.raises(Exception, match="Signing error"):
        gcp_kms_account.sign_message("test message")
