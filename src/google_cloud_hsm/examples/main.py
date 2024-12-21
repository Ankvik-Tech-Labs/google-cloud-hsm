import os

from web3 import Web3

from google_cloud_hsm.accounts.google import GoogleAccount

# USDC contract ABI (minimal for transfer)
USDC_ABI = [
    {
        "constant": False,
        "inputs": [{"name": "to", "type": "address"}, {"name": "value", "type": "uint256"}],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function",
    }
]


def main():
    # Initialize Web3 (using Infura for this example)
    w3 = Web3(Web3.HTTPProvider(os.getenv("WEB3_PROVIDER_URI")))

    # Initialize HSM-backed account
    account = GoogleAccount.load_from_hsm(
        project_id=os.getenv("GOOGLE_CLOUD_PROJECT"),
        region=os.getenv("GOOGLE_CLOUD_REGION", "us-east1"),
        key_ring_id=os.getenv("KEY_RING_ID"),
        key_id=os.getenv("KEY_ID"),
    )

    print(f"HSM Wallet Address: {account.address}")  # noqa: T201
    print(f"ETH Balance: {Web3.from_wei(w3.eth.get_balance(account.address), 'ether')} ETH")  # noqa: T201

    # Set up USDC contract
    usdc_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"  # Mainnet USDC
    usdc = w3.eth.contract(address=usdc_address, abi=USDC_ABI)

    # Example: Transfer 5 USDC
    to_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    amount = 5 * 10**6  # USDC has 6 decimals

    # Prepare transaction
    transaction = usdc.functions.transfer(to_address, amount).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": 100000,
            "gasPrice": w3.eth.gas_price,
            "chainId": 1,  # Mainnet
        }
    )

    # Sign and send transaction
    signed_txn = account.sign_transaction(transaction)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    print(f"Transaction sent: {tx_hash.hex()}")  # noqa: T201

    # Wait for receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Transaction confirmed in block {receipt['blockNumber']}")  # noqa: T201


if __name__ == "__main__":
    # Required environment variables:
    # GOOGLE_CLOUD_PROJECT
    # GOOGLE_CLOUD_REGION
    # GOOGLE_APPLICATION_CREDENTIALS (path to service account JSON)
    # WEB3_PROVIDER_URI (e.g., https://mainnet.infura.io/v3/YOUR-PROJECT-ID)
    main()
