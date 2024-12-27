# Usage Guide

This guide demonstrates how to use the `Google Cloud KMS` Ethereum signer library for message and transaction signing.

## Prerequisites

Before you begin, ensure you have:
1. Set up your environment variables (see [README.md](../index.md))
2. Python `3.10` or higher installed
3. Access to a `Web3` provider (local or remote) (Optional)

## Basic Setup

```python
from web3_google_hsm.accounts.gcp_kms_account import GCPKmsAccount

account = GCPKmsAccount()

# Get the Ethereum address derived from your GCP KMS key
print(f"GCP KMS Account address: {account.address}")
```

## Message Signing

### Simple Message Signing
```python
# Sign a message
message = "Hello Ethereum!"
signed_message = account.sign_message(message)

# Access signature components
print(f"R: {signed_message.r.hex()}")
print(f"S: {signed_message.s.hex()}")
print(f"V: {signed_message.v}")
print(f"Full signature: {signed_message.to_hex()}")
```

### Message Signature Verification
```python
from eth_account.messages import encode_defunct
from web3 import Web3
# Create message hash
message_hash = encode_defunct(text=message)

# Initialize Web3 and GCP KMS account
w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# Verify the signature using web3.py
recovered_address = w3.eth.account.recover_message(
    message_hash,
    vrs=(signed_message.v, signed_message.r, signed_message.s)
)

# Check if signature is valid
is_valid = recovered_address.lower() == account.address.lower()
print(f"Signature valid: {is_valid}")
```

## Transaction Signing

### Creating a Transaction
```python
tx = {
    "from": account.address,
    "chain_id": w3.eth.chain_id,
    "nonce": w3.eth.get_transaction_count(account.address),
    "value": w3.to_wei(0.000001, "ether"),
    "data": "0x00",
    "to": "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
    "type": 0,
    "gas_limit": 1000000,
    "gas_price": 300000000000,
}

# Convert dict to Transaction object and sign
signed_tx = account.sign_transaction(Transaction.from_dict(tx))
```

### Sending a Transaction
```python
if signed_tx:
    # Send the transaction
    tx_hash = w3.eth.send_raw_transaction(signed_tx)

    # Wait for transaction receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"Transaction hash: {receipt['transactionHash'].hex()}")
    print(f"From: {receipt['from']}")
    print(f"To: {receipt['to']}")
    print(f"Gas used: {receipt['gasUsed']}")
```

### Transaction Signature Verification
```python
# Verify the transaction signature
recovered_address = w3.eth.account.recover_transaction(signed_tx)
is_valid = recovered_address.lower() == account.address.lower()
print(f"Signature valid: {is_valid}")
```

## Working with Local Test Networks

### Funding Your Account (for testing with Anvil/Hardhat)
```python
# Use a test account (Anvil's default funded account)
funded_account = w3.eth.account.from_key(
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

# Create funding transaction
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
```

## Using with Different Networks

### Local Network (Anvil/Hardhat)
```python
w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
```

### Mainnet (via Infura)
```python
w3 = Web3(Web3.HTTPProvider(f"https://mainnet.infura.io/v3/{INFURA_KEY}"))
```

### Testnet (sepolia)
```python
w3 = Web3(Web3.HTTPProvider(f"https://sepolia.infura.io/v3/{INFURA_KEY}"))
```

## Error Handling

```python
from web3_google_hsm.types.ethereum_types import Transaction

try:
    signed_message = account.sign_message("Hello")
except Exception as e:
    print(f"Signing error: {e}")

try:
    signed_tx = account.sign_transaction(Transaction.from_dict(tx))
    if not signed_tx:
        print("Failed to sign transaction")
except Exception as e:
    print(f"Transaction error: {e}")
```

## Best Practices

1. Always verify signatures and transactions after signing
2. Handle errors appropriately
3. Wait for transaction receipts before assuming success
4. Use environment variables for sensitive configuration
5. Monitor gas prices and adjust accordingly
6. Test thoroughly on testnets before mainnet deployment

## Notes

- The GCP KMS key must be an `ECDSA` key on the `SECP256K1` curve
- Ensure your service account has the necessary permissions in `Google Cloud`
- Keep your environment variables secure and never commit them to version control
- Always use checksummed addresses when possible
- Monitor your gas usage and transaction costs
