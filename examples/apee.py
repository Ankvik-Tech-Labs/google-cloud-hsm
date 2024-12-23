from functools import cached_property
from typing import Any, Optional

import dotenv
from ape_ethereum.transactions import StaticFeeTransaction
from pydantic import Field, PrivateAttr
import os
from google.cloud import kms
from cryptography.hazmat.primitives import serialization
from ape.api.accounts import AccountAPI, TransactionAPI
from ape.types import AddressType, MessageSignature, SignableMessage, TransactionSignature
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_account.messages import _hash_eip191_message, encode_defunct
from eth_pydantic_types import HexBytes
from eth_typing import Hash32
from eth_utils import keccak, to_checksum_address
import ecdsa
from rich.traceback import install
from web3 import Web3
from rich.console import Console

console = Console()

install()
# Constants
SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


def _convert_der_to_rsv(signature: bytes, v_adjustment_factor: int = 0) -> dict:
    """Convert DER signature to RSV format."""
    r, s = ecdsa.util.sigdecode_der(signature, ecdsa.SECP256k1.order)
    v = v_adjustment_factor
    if s > SECP256_K1_N / 2:
        s = SECP256_K1_N - s
    r = r.to_bytes(32, byteorder="big")
    s = s.to_bytes(32, byteorder="big")
    return dict(v=v, r=r, s=s)


class GCPKmsAccount(AccountAPI):
    """Account implementation using Google Cloud KMS."""

    # Public fields
    key_path: str = Field(default="")

    # Private attributes using Pydantic's PrivateAttr
    _client: kms.KeyManagementServiceClient = PrivateAttr()
    _cached_public_key: Optional[bytes] = PrivateAttr(default=None)
    project_id: str = ""
    location_id: str = ""
    key_ring_id: str = ""
    key_id: str = ""

    def __init__(self, **data):
        super().__init__(**data)
        self._client = kms.KeyManagementServiceClient()

        # Load config from environment
        self.project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
        self.location_id = os.getenv("GOOGLE_CLOUD_REGION")
        self.key_ring_id = os.getenv("KEY_RING")
        self.key_id = os.getenv("KEY_NAME")

        missing_vars = []
        for var in ['project_id', 'location_id', 'key_ring_id', 'key_id']:
            if not getattr(self, var):
                missing_vars.append(var)
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

        self.key_path = self.get_key_version_path()

    def extract_public_key_bytes(self, pem_str: str) -> bytes:
        """Extract raw public key bytes from PEM format"""
        if not pem_str.startswith('-----BEGIN PUBLIC KEY-----'):
            pem_str = f"-----BEGIN PUBLIC KEY-----\n{pem_str}\n-----END PUBLIC KEY-----"

        pem_bytes = pem_str.encode('utf-8')
        public_key = serialization.load_pem_public_key(pem_bytes)

        # Get public key bytes and return only X and Y coordinates (64 bytes)
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        return raw_bytes[-64:]  # Return only the 64 bytes of X,Y coordinates

    def get_key_version_path(self) -> str:
        """Get the full path to the key version in Cloud KMS."""
        return self._client.crypto_key_version_path(
            self.project_id,
            self.location_id,
            self.key_ring_id,
            self.key_id,
            '1'  # Using version 1
        )

    @property
    def public_key(self) -> bytes:
        """Get public key bytes from KMS."""
        if self._cached_public_key is None:
            response = self._client.get_public_key({
                'name': self.key_path
            })
            if not response.pem:
                raise ValueError("No PEM data in response")

            self._cached_public_key = self.extract_public_key_bytes(response.pem)
        return self._cached_public_key

    @cached_property
    def address(self) -> AddressType:
        return to_checksum_address(keccak(self.public_key)[-20:].hex().lower())

    def _sign_raw_hash(self, msghash: HexBytes | Hash32) -> Optional[bytes]:
        """Sign a message hash using KMS."""
        try:
            response = self._client.asymmetric_sign(
                request={
                    'name': self.key_path,
                    'digest': {
                        'sha256': msghash
                    }
                }
            )
            return response.signature
        except Exception as e:
            console.print(f"Signing error: {e}")
            return None

    def sign_raw_msghash(self, msghash: HexBytes | Hash32) -> Optional[MessageSignature]:
        """Sign a raw message hash and return a MessageSignature."""
        if len(msghash) != 32:
            return None
        if not (signature := self._sign_raw_hash(msghash)):
            return None

        msg_sig = MessageSignature(**_convert_der_to_rsv(signature, 27))

        # Try both v values
        if not self.check_signature(msghash, msg_sig):
            msg_sig = MessageSignature(v=msg_sig.v + 1, r=msg_sig.r, s=msg_sig.s)

        return msg_sig

    def sign_message(self, msg: Any, **signer_options) -> Optional[MessageSignature]:
        """Sign a message using the HSM key."""
        if isinstance(msg, SignableMessage):
            message = msg
        elif isinstance(msg, str):
            if msg.startswith("0x"):
                message = encode_defunct(hexstr=msg)
            else:
                message = encode_defunct(text=msg)
        elif isinstance(msg, bytes):
            message = encode_defunct(primitive=msg)
        else:
            raise TypeError(f"Unsupported message type: {type(msg)}")

        return self.sign_raw_msghash(_hash_eip191_message(message))

    def sign_transaction(self, txn: TransactionAPI, **signer_options) -> Optional[TransactionAPI]:
        """Sign an EIP-155 transaction."""
        unsigned_txn = serializable_unsigned_transaction_from_dict(txn.model_dump()).hash()
        if not (msg_sig := self._sign_raw_hash(unsigned_txn)):
            return None
        # Calculate v value based on chain ID
        v_base = (2 * txn.chain_id + 35) if txn.chain_id else 27
        txn.signature = TransactionSignature(
            **_convert_der_to_rsv(msg_sig, v_base)
        )

        # Try alternative v value if signature check fails
        if not self.check_signature(txn):
            txn.signature = TransactionSignature(
                v=txn.signature.v + 1,
                r=txn.signature.r,
                s=txn.signature.s,
            )

        return txn

def main():
    dotenv.load_dotenv()
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    account = GCPKmsAccount()

    console.print(f"GCP KMS Account address: {account.address}")

    # 1. Test Message Signing and Verification
    message = "Hello Ethereum!"
    message_hash = encode_defunct(text=message)

    # Sign the message
    signed_message = account.sign_message(message)
    console.print(f"\nSigned message details:")
    console.print(f"R: {signed_message.r.hex()}")
    console.print(f"S: {signed_message.s.hex()}")
    console.print(f"V: {signed_message.v}")
    console.print(f"Full signature: {signed_message.encode_vrs().hex()}")

    # Verify the signature using web3.py
    recovered_address = w3.eth.account.recover_message(
        message_hash,
        vrs=(signed_message.v, signed_message.r, signed_message.s)
    )
    console.print(f"\nSignature verification:")
    console.print(f"Original address: {account.address}")
    console.print(f"Recovered address: {recovered_address}")
    console.print(f"Signature valid: {recovered_address.lower() == account.address.lower()}")

    # 2. Test Transaction Signing and Sending
    console.print("\nTesting transaction signing...")

    # First, fund the account from a test account (using Anvil's default funded account)
    funded_account = w3.eth.account.from_key("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")

    # Send some ETH to our GCP KMS account
    fund_tx = {
        'from': funded_account.address,
        'to': account.address,
        'value': w3.to_wei(0.1, 'ether'),
        'gas': 21000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(funded_account.address),
        'chainId': w3.eth.chain_id
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
        "value": w3.to_wei(0.000001, 'ether'),
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
        console.print(f"\nTransaction successful!")
        console.print(f"Transaction hash: {receipt['transactionHash'].hex()}")
        console.print(f"From: {receipt['from']}")
        console.print(f"To: {receipt['to']}")
        console.print(f"Gas used: {receipt['gasUsed']}")

        # Verify the transaction signature
        tx_data = w3.eth.get_transaction(tx_hash)
        # Get the raw transaction data
        raw_tx = signed_tx.serialize_transaction()
        recovered_address = w3.eth.account.recover_transaction(raw_tx)
        console.print(f"\nTransaction signature verification:")
        console.print(f"Original address: {account.address}")
        console.print(f"Recovered address: {recovered_address}")
        console.print(f"Signature valid: {recovered_address.lower() == account.address.lower()}")
    else:
        console.print("Failed to sign transaction")


if __name__ == "__main__":
    main()
