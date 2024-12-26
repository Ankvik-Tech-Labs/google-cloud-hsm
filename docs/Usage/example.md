# Example script

This is the script I have used to build and test this module. It works. Trust me :)


```python
import dotenv
from eth_account.messages import encode_defunct
from web3 import Web3

from google_cloud_hsm.accounts.gcp_kms_account import GCPKmsAccount
from google_cloud_hsm.types.ethereum_types import Signature, Transaction
from rich.console import Console

console = Console()
dotenv.load_dotenv()

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
account = GCPKmsAccount()

console.print(f"GCP KMS Account address: {account.address}")

# 1. Test Message Signing and Verification
message = "Hello Ethereum!"
message_hash = encode_defunct(text=message)

# Sign the message
signed_message = account.sign_message(message)
console.print("\nSigned message details:")
console.print(f"R: {signed_message.r.hex()}")
console.print(f"S: {signed_message.s.hex()}")
console.print(f"V: {signed_message.v}")
console.print(f"Full signature: {signed_message.to_hex()}")

# Verify the signature using web3.py
recovered_address = w3.eth.account.recover_message(
    message_hash, vrs=(signed_message.v, signed_message.r, signed_message.s)
)
console.print("\nSignature verification:")
console.print(f"Original address: {account.address}")
console.print(f"Recovered address: {recovered_address}")
console.print(f"Signature valid: {recovered_address.lower() == account.address.lower()}")

# 2. Test Transaction Signing and Sending
console.print("\nTesting transaction signing...")

# First, fund the account from a test account (using Anvil's default funded account)
funded_account = w3.eth.account.from_key("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")

# Send some ETH to our GCP KMS account
fund_tx = {
    "from": funded_account.address,
    "to": account.address,
    "value": w3.to_wei(0.1, "ether"),
    "gas": 21000,
    "gasPrice": w3.eth.gas_price,
    "nonce": w3.eth.get_transaction_count(funded_account.address),
    "chainId": w3.eth.chain_id,
}

# Send funding transaction
signed_fund_tx = w3.eth.account.sign_transaction(fund_tx, funded_account.key)
fund_tx_hash = w3.eth.send_raw_transaction(signed_fund_tx.raw_transaction)
fund_receipt = w3.eth.wait_for_transaction_receipt(fund_tx_hash)
console.print(f"Funded account with 0.1 ETH. TX hash: {fund_receipt['transactionHash'].hex()}")

# Now create and sign a transaction from our GCP KMS account
tx = {
    "from": funded_account.address,
    "chain_id": w3.eth.chain_id,
    "nonce": w3.eth.get_transaction_count(account.address),
    "value": w3.to_wei(0.000001, "ether"),
    "data": "0x00",
    "to": "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
    "type": 0,
    "gas_limit": 1000000,
    "gas_price": 300000000000,
}

# Sign the transaction
signed_tx = account.sign_transaction(Transaction.from_dict(tx))
console.print(f"{signed_tx=}")

if signed_tx:
    console.print(signed_tx)
    # Send the transaction
    tx_hash = w3.eth.send_raw_transaction(signed_tx)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    console.print("\nTransaction successful!")
    console.print(f"Transaction hash: {receipt['transactionHash'].hex()}")
    console.print(f"From: {receipt['from']}")
    console.print(f"To: {receipt['to']}")
    console.print(f"Gas used: {receipt['gasUsed']}")

    # Verify the transaction signature
    tx_data = w3.eth.get_transaction(tx_hash)
    # Get the raw transaction data
    raw_tx = signed_tx
    recovered_address = w3.eth.account.recover_transaction(raw_tx)
    console.print("\nTransaction signature verification:")
    console.print(f"Original address: {account.address}")
    console.print(f"Recovered address: {recovered_address}")
    console.print(f"Signature valid: {recovered_address.lower() == account.address.lower()}")
else:
    console.print("Failed to sign transaction")
```
