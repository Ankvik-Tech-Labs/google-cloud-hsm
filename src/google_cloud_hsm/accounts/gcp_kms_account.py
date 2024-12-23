from functools import cached_property

import dotenv
from ape_ethereum.transactions import StaticFeeTransaction
from eth_account.messages import _hash_eip191_message, encode_defunct
from eth_typing import ChecksumAddress
from eth_utils import keccak, to_checksum_address
from google.cloud import kms
from pydantic import BaseModel, Field, PrivateAttr
from web3 import Web3

from google_cloud_hsm.config import BaseConfig
from google_cloud_hsm.types.ethereum_types import Signature, Transaction
from google_cloud_hsm.utils import convert_der_to_rsv, extract_public_key_bytes


class GCPKmsAccount(BaseModel):
    """Account implementation using Google Cloud KMS."""

    # Public fields
    key_path: str = Field(default="")

    # Private attributes
    _client: kms.KeyManagementServiceClient = PrivateAttr()
    _cached_public_key: bytes | None = PrivateAttr(default=None)
    _settings: BaseConfig = PrivateAttr()
    _w3: Web3 = PrivateAttr()

    def __init__(self, **data):
        super().__init__(**data)
        self._client = kms.KeyManagementServiceClient()
        self._settings = BaseConfig()
        self._w3 = Web3(Web3.HTTPProvider(self._settings.web3_provider_uri))
        self.key_path = self._get_key_version_path()

    def _get_key_version_path(self) -> str:
        """Get the full path to the key version in Cloud KMS."""
        return self._client.crypto_key_version_path(
            self._settings.project_id,
            self._settings.location_id,
            self._settings.key_ring_id,
            self._settings.key_id,
            "1",  # Using version 1
        )

    @property
    def public_key(self) -> bytes:
        """Get public key bytes from KMS."""
        if self._cached_public_key is None:
            response = self._client.get_public_key({"name": self.key_path})
            if not response.pem:
                raise ValueError("No PEM data in response")

            self._cached_public_key = extract_public_key_bytes(response.pem)
        return self._cached_public_key

    @cached_property
    def address(self) -> ChecksumAddress:
        """Get Ethereum address derived from public key."""
        return to_checksum_address(keccak(self.public_key)[-20:].hex().lower())

    def _sign_raw_hash(self, msghash: bytes) -> bytes | None:
        """Sign a message hash using KMS."""
        try:
            response = self._client.asymmetric_sign(request={"name": self.key_path, "digest": {"sha256": msghash}})
            return response.signature
        except Exception as e:
            raise Exception(f"Signing error: {e}")

    def sign_message(self, message: str | bytes) -> Signature:
        """
        Sign a message with the GCP KMS key.

        Args:
            message: Message to sign (str or bytes)

        Returns:
            Signature: The v, r, s components of the signature

        Example:
            >>> account = GCPKmsAccount()
            >>> signature = account.sign_message("Hello Ethereum!")
        """
        # Convert message to SignableMessage format
        if isinstance(message, str):
            if message.startswith("0x"):
                hash_message = encode_defunct(hexstr=message)
            else:
                hash_message = encode_defunct(text=message)
        elif isinstance(message, bytes):
            hash_message = encode_defunct(primitive=message)
        else:
            raise TypeError(f"Unsupported message type: {type(message)}")

        # Sign message hash
        msghash = _hash_eip191_message(hash_message)
        if len(msghash) != 32:
            raise ValueError("Invalid message hash length")

        der_signature = self._sign_raw_hash(msghash)
        if not der_signature:
            raise Exception("Failed to sign message")

        # Convert to RSV format with v = 27
        sig_dict = convert_der_to_rsv(der_signature, 27)
        signature = Signature(v=sig_dict["v"], r=sig_dict["r"], s=sig_dict["s"])

        # Verify recovery and try alternative v value if needed
        recovered = self._w3.eth.account.recover_message(hash_message, vrs=(signature.v, signature.r, signature.s))

        if recovered.lower() != self.address.lower():
            signature.v += 1

        return signature

    def sign_transaction(self, transaction: Transaction) -> Transaction:
        """
        Sign an Ethereum transaction with the GCP KMS key.

        Args:
            transaction: Transaction to sign

        Returns:
            Transaction: The signed transaction

        Example:
            >>> tx = Transaction(
            ...     chain_id=1,
            ...     nonce=0,
            ...     gas_price=20000000000,
            ...     gas_limit=21000,
            ...     to="0x...",
            ...     value=1000000000000000000
            ... )
            >>> signed_tx = account.sign_transaction(tx)
        """
        # Create the unsigned transaction dictionary
        unsigned_tx = transaction.to_dict()

        # Get the hash of the transaction
        tx_hash = self._w3.eth.account._sign_transaction_dict(unsigned_tx)["hash"]

        # Sign the transaction hash
        der_signature = self._sign_raw_hash(tx_hash)
        if not der_signature:
            raise Exception("Failed to sign transaction")

        # Calculate v value based on chain ID
        v_base = 2 * transaction.chain_id + 35
        sig_dict = convert_der_to_rsv(der_signature, v_base)
        signature = Signature(v=sig_dict["v"], r=sig_dict["r"], s=sig_dict["s"])

        # Verify recovery and try alternative v value if needed
        signed_tx_dict = {**unsigned_tx, "v": signature.v, "r": signature.r, "s": signature.s}
        recovered = self._w3.eth.account.recover_transaction(
            self._w3.eth.account.sign_transaction(signed_tx_dict).rawTransaction
        )

        if recovered.lower() != self.address.lower():
            signature.v += 1

        # Update the transaction with the signature
        transaction.signature = signature
        return transaction


if __name__ == "__main__":
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
        "chain_id": w3.eth.chain_id,
        "nonce": w3.eth.get_transaction_count(account.address),
        "value": w3.to_wei(0.000001, "ether"),
        "data": "0x00",
        "receiver": "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
        "type": 0,
        "gas_limit": 1000000,
        "gas_price": 300000000000,
    }

    # Sign the transaction
    signed_tx = account.sign_transaction(StaticFeeTransaction(**tx))
    console.print(f"{signed_tx=}")

    if signed_tx:
        # Send the transaction
        tx_hash = w3.eth.send_raw_transaction(signed_tx.serialize_transaction())
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        console.print("\nTransaction successful!")
        console.print(f"Transaction hash: {receipt['transactionHash'].hex()}")
        console.print(f"From: {receipt['from']}")
        console.print(f"To: {receipt['to']}")
        console.print(f"Gas used: {receipt['gasUsed']}")

        # Verify the transaction signature
        tx_data = w3.eth.get_transaction(tx_hash)
        # Get the raw transaction data
        raw_tx = signed_tx.serialize_transaction()
        recovered_address = w3.eth.account.recover_transaction(raw_tx)
        console.print("\nTransaction signature verification:")
        console.print(f"Original address: {account.address}")
        console.print(f"Recovered address: {recovered_address}")
        console.print(f"Signature valid: {recovered_address.lower() == account.address.lower()}")
    else:
        console.print("Failed to sign transaction")
