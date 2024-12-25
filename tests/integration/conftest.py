"""Integration tests for GCP KMS account."""
import os
import pytest
from web3 import Web3

from google_cloud_hsm.accounts.gcp_kms_account import GCPKmsAccount

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


@pytest.fixture(scope="module")
def web3():
    """Initialize Web3 instance."""
    return Web3(Web3.HTTPProvider(REQUIRED_ENV_VARS["JSON_RPC_BASE"]))


@pytest.fixture(scope="module")
def gcp_account():
    """Create real GCP KMS account."""
    return GCPKmsAccount()


@pytest.fixture(scope="module")
def funded_account(web3):
    """Get a funded test account."""
    return web3.eth.account.from_key(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )


@pytest.fixture
def fund_account(web3, funded_account, gcp_account):
    """Fund the GCP account for testing."""
    fund_tx = {
        "from": funded_account.address,
        "to": gcp_account.address,
        "value": web3.to_wei(0.1, "ether"),
        "gas": 21000,
        "gasPrice": web3.eth.gas_price,
        "nonce": web3.eth.get_transaction_count(funded_account.address),
        "chainId": web3.eth.chain_id
    }

    signed_tx = web3.eth.account.sign_transaction(fund_tx, funded_account.key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    return web3.eth.wait_for_transaction_receipt(tx_hash)
