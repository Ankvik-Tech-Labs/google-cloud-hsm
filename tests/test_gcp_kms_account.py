import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from unittest.mock import MagicMock

from google_cloud_hsm.accounts.gcp_kms_account import GCPKmsAccount
from google_cloud_hsm.exceptions import SignatureError
from google_cloud_hsm.types.ethereum_types import Transaction

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

def test_sign_message_verification(gcp_kms_account: GCPKmsAccount):
    """Test that signed messages can be verified."""
    message = "Hello, Ethereum!"
    signature = gcp_kms_account.sign_message(message)
    
    # Recover the signer's address
    message_hash = encode_defunct(text=message)
    recovered_address = Account.recover_message(
        message_hash,
        vrs=(signature.v, signature.r, signature.s)
    )
    
    assert recovered_address.lower() == gcp_kms_account.address.lower()

def test_sign_hex_message(gcp_kms_account: GCPKmsAccount):
    """Test signing hex messages."""
    hex_message = "0x48656c6c6f2c20457468657265756d21"  # "Hello, Ethereum!" in hex
    signature = gcp_kms_account.sign_message(hex_message)
    
    # Verify signature
    message_hash = encode_defunct(hexstr=hex_message)
    recovered_address = Account.recover_message(
        message_hash,
        vrs=(signature.v, signature.r, signature.s)
    )
    
    assert recovered_address.lower() == gcp_kms_account.address.lower()

def test_sign_transaction(
    gcp_kms_account: GCPKmsAccount,
    test_transaction: Transaction,
    mock_kms_client: MagicMock
):
    """Test transaction signing."""
    signed_tx = gcp_kms_account.sign_transaction(test_transaction)
    
    assert signed_tx is not None
    assert isinstance(signed_tx, bytes)
    
    # Verify KMS was called correctly
    mock_kms_client.asymmetric_sign.assert_called_once()
    
    # Verify the recovered signer matches
    recovered_address = Account.recover_transaction(signed_tx)
    assert recovered_address.lower() == gcp_kms_account.address.lower()

def test_sign_transaction_verification(gcp_kms_account: GCPKmsAccount, test_transaction: Transaction):
    """Test that signed transactions can be verified."""
    signed_tx = gcp_kms_account.sign_transaction(test_transaction)
    assert signed_tx is not None
    
    # Decode and verify the transaction
    recovered_address = Account.recover_transaction(signed_tx)
    assert recovered_address.lower() == gcp_kms_account.address.lower()
    
    # Verify transaction details are preserved
    decoded_tx = Account.decode_transaction(signed_tx)
    assert decoded_tx['nonce'] == test_transaction.nonce
    assert decoded_tx['gasPrice'] == test_transaction.gas_price
    assert decoded_tx['gas'] == test_transaction.gas_limit
    assert decoded_tx['to'].lower() == test_transaction.to.lower()
    assert decoded_tx['value'] == test_transaction.value
    assert decoded_tx['data'] == test_transaction.data

def test_invalid_message_type(gcp_kms_account: GCPKmsAccount):
    """Test signing with invalid message type."""
    with pytest.raises(TypeError, match="Unsupported message type"):
        gcp_kms_account.sign_message(123)  # type: ignore

def test_sign_transaction_no_signature(gcp_kms_account: GCPKmsAccount, mock_kms_client: MagicMock):
    """Test transaction signing when KMS fails."""
    mock_kms_client.asymmetric_sign.return_value = None
    
    with pytest.raises(Exception, match="Signing error"):
        gcp_kms_account.sign_message("test message")

def test_sign_transaction_invalid_recovery(
    gcp_kms_account: GCPKmsAccount,
    test_transaction: Transaction,
    mock_kms_client: MagicMock
):
    """Test transaction signing with invalid signature recovery."""
    # Mock a signature that can't be recovered
    mock_sign_response = MagicMock()
    mock_sign_response.signature = bytes([0] * 64)
    mock_kms_client.asymmetric_sign.return_value = mock_sign_response
    
    with pytest.raises(SignatureError, match="Failed to create valid signature"):
        gcp_kms_account.sign_transaction(test_transaction)