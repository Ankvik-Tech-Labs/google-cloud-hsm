from typing import Optional, Dict, Any, Tuple
import os
from abc import ABC, abstractmethod
from rich.console import Console

import dotenv
from google.cloud import kms
from google.cloud.kms_v1 import KeyManagementServiceClient
from eth_account._utils.signing import to_standard_v
from eth_account.messages import encode_defunct
from eth_utils.conversions import to_bytes
from eth_keys import keys
from eth_utils import keccak, to_checksum_address
import rlp
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass
import ecdsa

console = Console()

@dataclass
class UnsignedTransaction:
    """Represents an unsigned Ethereum transaction"""
    nonce: int
    gas_price: int
    gas_limit: int
    to: str
    value: int
    data: bytes
    chain_id: int


class BaseCloudSigner(ABC):
    """Base class for cloud HSM signers"""

    @abstractmethod
    def sign_message(self, message_hash: bytes) -> tuple[bytes, bytes, int]:
        """Sign a message hash and return r, s, v components"""
        pass

    @abstractmethod
    def get_public_key(self) -> bytes:
        """Get the public key bytes"""
        pass

    def get_address(self) -> str:
        """Derive Ethereum address from public key"""
        public_key_bytes = self.get_public_key()
        return keccak(public_key_bytes)[-20:].hex()


# SECP256k1 curve order
SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


def convert_der_to_rs(signature: bytes) -> Tuple[bytes, bytes]:
    """Convert DER signature to R, S components"""
    r, s = ecdsa.util.sigdecode_der(signature, ecdsa.SECP256k1.order)

    # Handle signature malleability - ensure s is in lower half of curve order
    if s > SECP256_K1_N // 2:
        s = SECP256_K1_N - s

    # Convert to 32-byte representation
    r_bytes = r.to_bytes(32, byteorder="big")
    s_bytes = s.to_bytes(32, byteorder="big")

    return r_bytes, s_bytes


class CloudHSMEthereumSigner(BaseCloudSigner):
    """Google Cloud KMS implementation of Ethereum signer"""

    def __init__(
        self,
        project_id: str,
        location_id: str,
        key_ring_id: str,
        key_id: str,
        key_version: str = "1"
    ):
        from google.cloud.kms_v1.types import CryptoKeyVersion

        self.client = KeyManagementServiceClient()
        self.key_path = (
            f"projects/{project_id}/locations/{location_id}/"
            f"keyRings/{key_ring_id}/cryptoKeys/{key_id}/"
            f"cryptoKeyVersions/{key_version}"
        )
        # Cache the public key and address
        self._public_key: Optional[bytes] = None
        self._address: Optional[str] = None

        # Verify key algorithm
        key_version = self.client.get_crypto_key_version(name=self.key_path)
        console.print(f"\nKey Algorithm: {key_version.algorithm}")
        if key_version.algorithm != CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256:
            raise ValueError(
                f"Key must use EC_SIGN_SECP256K1_SHA256 algorithm (31), got {key_version.algorithm}"
            )

    def extract_public_key_bytes(self, pem_str: str) -> bytes:
        """Extract raw public key bytes from PEM format"""
        if not pem_str.startswith('-----BEGIN PUBLIC KEY-----'):
            pem_str = f"-----BEGIN PUBLIC KEY-----\n{pem_str}\n-----END PUBLIC KEY-----"

        pem_bytes = pem_str.encode('utf-8')
        public_key = serialization.load_pem_public_key(pem_bytes)

        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        # Return only X and Y coordinates (64 bytes)
        return raw_bytes[-64:]

    def get_public_key(self) -> bytes:
        """Get or fetch public key bytes"""
        if self._public_key is None:
            public_key = self.client.get_public_key(name=self.key_path)
            self._public_key = self.extract_public_key_bytes(public_key.pem)
        return self._public_key

    def sign_message(self, message_hash: bytes) -> tuple[bytes, bytes, int]:
        """Sign a message hash using Cloud KMS"""
        console.print(f"Signing message hash: {message_hash.hex()}")

        response = self.client.asymmetric_sign(
            request={
                "name": self.key_path,
                "digest": {"sha256": message_hash},
            }
        )

        console.print(f"Raw signature from KMS: {response.signature.hex()}")

        # Convert DER signature to R, S
        r_bytes, s_bytes = convert_der_to_rs(response.signature)

        console.print(f"Decoded R: {r_bytes.hex()}")
        console.print(f"Decoded S: {s_bytes.hex()}")

        import eth_keys

        # Convert public key to eth_keys format
        pub_key_bytes = self.get_public_key()
        public_key = eth_keys.keys.PublicKey(pub_key_bytes)

        # Try both possible v values (0 and 1)
        for v in (0, 1):
            try:
                signature = eth_keys.keys.Signature(
                    vrs=(v,
                         int.from_bytes(r_bytes, 'big'),
                         int.from_bytes(s_bytes, 'big'))
                )

                recovered_key = signature.recover_public_key_from_msg_hash(message_hash)
                console.print(f"Recovered with v={v}: {recovered_key}")
                console.print(f"Expected: {public_key}")

                if recovered_key == public_key:
                    v = v + 27  # Convert to Ethereum format
                    return r_bytes, s_bytes, v

            except Exception as e:
                console.print(f"Failed with v={v}: {e}")

        raise ValueError("Could not determine correct v value")

    def sign_transaction(self, transaction: UnsignedTransaction) -> str:
        """Sign an Ethereum transaction and return the hex string"""
        # Get the message hash
        message = rlp.encode([
            transaction.nonce,
            transaction.gas_price,
            transaction.gas_limit,
            to_bytes(hexstr=transaction.to),
            transaction.value,
            transaction.data,
            transaction.chain_id,
            0,  # v
            0,  # r
            0,  # s
        ])
        msg_hash = keccak(message)

        # Sign the hash
        r, s, v = self.sign_message(msg_hash)

        # Adjust v for EIP-155
        v = to_standard_v(v)
        v = v + 35 + transaction.chain_id * 2

        # Create signed transaction
        signed = rlp.encode([
            transaction.nonce,
            transaction.gas_price,
            transaction.gas_limit,
            to_bytes(hexstr=transaction.to),
            transaction.value,
            transaction.data,
            v,
            int.from_bytes(r, 'big'),
            int.from_bytes(s, 'big'),
        ])

        return '0x' + signed.hex()


class CloudHSMAccount:
    """Web3.py compatible account using Cloud HSM"""

    def __init__(self, signer: CloudHSMEthereumSigner, web3):
        self.signer = signer
        self.web3 = web3
        self.address = to_checksum_address("0x" + signer.get_address())

    def sign_transaction(self, transaction_dict: Dict[str, Any]) -> str:
        """Sign a Web3.py style transaction dict"""
        # Convert transaction dict to UnsignedTransaction
        unsigned = UnsignedTransaction(
            nonce=transaction_dict['nonce'],
            gas_price=transaction_dict['gasPrice'],
            gas_limit=transaction_dict['gas'],
            to=transaction_dict['to'],
            value=transaction_dict['value'],
            data=to_bytes(hexstr=transaction_dict['data']),
            chain_id=transaction_dict.get('chainId', self.web3.eth.chain_id),
        )
        return self.signer.sign_transaction(unsigned)

    @classmethod
    def load_from_hsm(cls, web3, **signer_kwargs):
        """Create account from HSM configuration"""
        signer = CloudHSMEthereumSigner(**signer_kwargs)
        return cls(signer, web3)




def test_signer():
    dotenv.load_dotenv()
    """Test function to verify signer functionality"""
    from web3 import Web3
    web3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

    # Initialize account
    account = CloudHSMAccount.load_from_hsm(
        web3=web3,
        project_id=os.environ["GOOGLE_CLOUD_PROJECT"],
        location_id=os.environ["GOOGLE_CLOUD_REGION"],
        key_ring_id=os.environ["KEY_RING"],
        key_id=os.environ["KEY_NAME"]
    )

    console.print(f"Account address: {account.address}")

    # Get funded account from Anvil
    funded_account = web3.eth.account.from_key(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )

    # Fund the HSM account
    tx = {
        'from': funded_account.address,
        'to': Web3.to_checksum_address(account.address),
        'value': web3.to_wei(0.001, 'ether'),  # Send 0.1 ETH
        'gas': 21000,
        'gasPrice': web3.eth.gas_price,
        'nonce': web3.eth.get_transaction_count(funded_account.address),
        'chainId': web3.eth.chain_id,
        'data': '0x'
    }

    signed_tx = web3.eth.account.sign_transaction(tx, funded_account.key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    console.print(f"Funded account. TX hash: {receipt['transactionHash'].hex()}")
    console.print(f"Balance: {web3.eth.get_balance(account.address)}")

    # Calculate the maximum amount we can send (leaving enough for gas)
    gas_price = web3.eth.gas_price
    gas_limit = 21000  # Standard ETH transfer
    gas_cost = gas_price * gas_limit
    balance = web3.eth.get_balance(account.address)
    send_amount = balance - gas_cost  # Leave enough for gas

    console.print(f"Gas price: {gas_price}")
    console.print(f"Gas cost: {gas_cost}")
    console.print(f"Available to send: {send_amount}")

    # Test a transfer with the calculated amount
    tx = {
        'from': account.address,
        'to': Web3.to_checksum_address("0x4BB009C88B4718b06AbC236faAF1f06bBA3e610d"),
        'value': web3.to_wei(0.0000001, 'ether'),
        'gas': 2100000,
        'gasPrice': 234567897654321,
        'nonce': web3.eth.get_transaction_count(account.address),
        'chainId': web3.eth.chain_id,
        'data': ''
    }

    signed_tx = account.sign_transaction(tx)
    console.print(f"Signed Tx: {signed_tx}")
    console.print(tx)
    tx_hash = web3.eth.send_raw_transaction(signed_tx)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    console.print(f"Transfer successful. TX hash: {receipt['transactionHash'].hex()}")
    console.print(f"Final balance: {web3.eth.get_balance(account.address)}")


if __name__ == "__main__":
    test_signer()
