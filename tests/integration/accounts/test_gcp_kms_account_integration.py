from google_cloud_hsm import Transaction
from eth_account.messages import encode_defunct
from hexbytes import HexBytes

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


def test_transaction_signing(gcp_account, web3, fund_account):
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


def test_transaction_with_data(gcp_account, web3, fund_account):
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


def test_multiple_transactions(gcp_account, web3, fund_account):
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
