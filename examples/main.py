import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import base64
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.datastructures import SignedTransaction
from eth_utils import to_wei, decode_hex, encode_hex
from eth_utils.curried import keccak
from eth_keys import KeyAPI
from google.cloud import kms
from google.cloud.kms import KeyManagementServiceClient
import rlp
from typing import Dict, Any, Optional
import base64
import struct

load_dotenv()


class EthereumTransaction:
    def __init__(
        self,
        nonce: int,
        gas_price: int,
        gas_limit: int,
        to: str,
        value: int,
        data: bytes,
        chain_id: int
    ):
        self.nonce = nonce
        self.gas_price = gas_price
        self.gas_limit = gas_limit
        self.to = decode_hex(to) if to.startswith('0x') else decode_hex('0x' + to)
        self.value = value
        self.data = data
        self.chain_id = chain_id

    def serialize_unsigned(self) -> bytes:
        """Serialize transaction for signing according to EIP-155"""
        fields = [
            self.nonce,
            self.gas_price,
            self.gas_limit,
            self.to,
            self.value,
            self.data,
            self.chain_id,
            0,  # v
            0  # s
        ]
        return rlp.encode(fields)


class CloudHSMEthereumSigner:
    def __init__(self, project_id: str, location_id: str, key_ring_id: str, key_id: str, key_version: str):
        """
        Initialize Cloud HSM signer for Ethereum transactions

        Args:
            project_id: Google Cloud project ID
            location_id: Location of the key ring (e.g., 'global')
            key_ring_id: ID of the key ring
            key_id: ID of the key
            key_version: Version of the key
        """
        self.kms_client = KeyManagementServiceClient()
        self.key_path = (
            f"projects/{project_id}/locations/{location_id}/"
            f"keyRings/{key_ring_id}/cryptoKeys/{key_id}/"
            f"cryptoKeyVersions/{key_version}"
        )
        self.keys = KeyAPI()

    def extract_public_key_bytes(self, pem_str: str) -> bytes:
        """
        Extract the raw public key bytes from PEM format

        Args:
            pem_str: Public key in PEM format

        Returns:
            bytes: Raw public key bytes
        """
        # Add PEM headers if they're not present
        if not pem_str.startswith('-----BEGIN PUBLIC KEY-----'):
            pem_str = f"-----BEGIN PUBLIC KEY-----\n{pem_str}\n-----END PUBLIC KEY-----"

        # Convert PEM string to bytes
        pem_bytes = pem_str.encode('utf-8')

        # Load the public key
        public_key = serialization.load_pem_public_key(pem_bytes)

        # Get the raw bytes in uncompressed format (0x04 + X + Y coordinates)
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        return raw_bytes

    def get_public_key(self) -> bytes:
        """Get public key from Cloud HSM"""
        response = self.kms_client.get_public_key(name=self.key_path)
        pem_str = response.pem  # This is already a string, no need to decode
        # print(pem_str)
        return self.extract_public_key_bytes(pem_str)

    def get_address(self) -> str:
        """Get Ethereum address corresponding to the HSM key"""
        try:
            public_key_bytes = self.get_public_key()
            # Remove the '04' prefix if present (uncompressed point marker)
            if public_key_bytes.startswith(b'\x04'):
                public_key_bytes = public_key_bytes[1:]

            # Calculate keccak256 hash of the public key
            address_bytes = keccak(public_key_bytes)[-20:]  # Take last 20 bytes
            return f"{encode_hex(address_bytes)}"

        except Exception as e:
            raise ValueError(f"Error deriving Ethereum address: {str(e)}")

    def sign_transaction(self, transaction: EthereumTransaction) -> bytes:
        """
        Sign an Ethereum transaction using Cloud HSM

        Args:
            transaction: EthereumTransaction instance to sign

        Returns:
            bytes: RLP encoded signed transaction
        """
        # Serialize transaction
        message = transaction.serialize_unsigned()

        # Calculate message hash according to EIP-155
        message_hash = keccak(message)

        # Sign using Cloud HSM
        sign_request = {
            "digest": {
                "sha256": message_hash
            }
        }

        response = self.kms_client.asymmetric_sign(
            request={
                "name": self.key_path,
                **sign_request
            }
        )

        # Extract R, S values from the signature
        signature = response.signature
        r = int.from_bytes(signature[:32], 'big')
        s = int.from_bytes(signature[32:], 'big')

        # Calculate V value according to EIP-155
        v = 35 + transaction.chain_id * 2

        # Create signed transaction
        signed_fields = [
            transaction.nonce,
            transaction.gas_price,
            transaction.gas_limit,
            transaction.to,
            transaction.value,
            transaction.data,
            v,
            r,
            s
        ]

        return rlp.encode(signed_fields)


def build_transaction(
    nonce: int,
    gas_price_gwei: int,
    gas_limit: int,
    to_address: str,
    value_eth: float,
    data: bytes = b'',
    chain_id: int = 1
) -> EthereumTransaction:
    """Helper function to build an Ethereum transaction"""
    return EthereumTransaction(
        nonce=nonce,
        gas_price=to_wei(gas_price_gwei, 'gwei'),
        gas_limit=gas_limit,
        to=to_address,
        value=to_wei(value_eth, 'ether'),
        data=data,
        chain_id=chain_id
    )


def main():
    # Load environment variables
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    key_ring_id = os.environ.get("KEY_RING")
    key_id = os.environ.get("KEY_NAME")
    location_id = os.environ.get("GOOGLE_CLOUD_REGION")

    # Initialize the signer
    signer = CloudHSMEthereumSigner(
        project_id=project_id,
        location_id=location_id,
        key_ring_id=key_ring_id,
        key_id=key_id,
        key_version="1"
    )

    # Build transaction
    transaction = build_transaction(
        nonce=0,
        gas_price_gwei=50,
        gas_limit=21000,
        to_address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        value_eth=0.1
    )

    # Sign transaction
    signed_tx = signer.sign_transaction(transaction)
    print(f"{signed_tx.hex()=}")

    # Get transaction hash
    tx_hash = keccak(signed_tx)
    print(f"Transaction hash: {encode_hex(tx_hash)}")

    # Get sender address
    sender = signer.get_address()
    print(f"Sender address: {sender}")

"""
signed_tx = 0xf87380850ba43b740082520894742d35cc6634c0532925a3b844bc454e4438f44e88016345785d8a00008025a03045022100f331f868c1f25845aa6f39573d01062d75d00c8885149d57b7fe9aa7ed47d04edb02201f3a4d93dd7240d955e15e8e741d2cc68f6075f5bba217c00e97b017fd7641b8
Transaction hash: 0xebfea470b1694d3c77ca65dbd5f99fd0b930c268fcb140eecc3a8dc8270f9d69
Sender address: 0x0545640a0ecd6fb6ae94766811f30dcda4746dfc
"""

if __name__ == "__main__":
    main()
