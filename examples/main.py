from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
import os
from rich.console import Console
from rich.traceback import install

# Install rich traceback handler
install()

import dotenv
from google.cloud import kms
from google.cloud.kms_v1 import KeyManagementServiceClient
from eth_account._utils.signing import to_standard_v
from eth_account.messages import encode_defunct, _hash_eip191_message
from eth_utils.conversions import to_bytes
from eth_keys import keys
from eth_utils import keccak, to_checksum_address
import rlp
from cryptography.hazmat.primitives import serialization
import ecdsa
import binascii

# Initialize console for pretty printing
console = Console()

# Constants
SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


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


class GcpHsmSigner:
    def __init__(
        self,
        key_path: str,
        kms_client: Optional[KeyManagementServiceClient] = None
    ):
        """
        Initialize GCP HSM signer

        Args:
            key_path: Full GCP KMS key version path
            kms_client: Optional KMS client (will create new one if not provided)
        """
        self.key_path = key_path
        self.client = kms_client or KeyManagementServiceClient()
        self._public_key = None
        self._address = None

        # Verify key algorithm
        key_version = self.client.get_crypto_key_version(name=self.key_path)
        console.print(f"\nKey Algorithm: {key_version.algorithm}")
        # if key_version.algorithm != KeyManagementServiceClient.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256:
        #     raise ValueError(
        #         f"Key must use EC_SIGN_SECP256K1_SHA256 algorithm (31), got {key_version.algorithm}"
        #     )

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

    @property
    def public_key(self) -> bytes:
        """Get or fetch public key bytes"""
        if self._public_key is None:
            response = self.client.get_public_key(name=self.key_path)
            if not response.pem:
                raise ValueError("No PEM data in response")
            self._public_key = self.extract_public_key_bytes(response.pem)
        return self._public_key

    @property
    def address(self) -> str:
        """Get Ethereum address derived from public key"""
        if self._address is None:
            self._address = to_checksum_address(
                keccak(self.public_key)[-20:].hex()
            )
        return self._address

    def sign_hash(self, msg_hash: bytes) -> tuple[bytes, bytes, int]:
        """Sign a message hash and return r, s, v components"""
        console.print(f"Signing message hash: {msg_hash.hex()}")

        response = self.client.asymmetric_sign(
            request={
                "name": self.key_path,
                "digest": {"sha256": msg_hash},
            }
        )

        console.print(f"Raw signature from KMS: {response.signature.hex()}")

        # Convert DER signature to R, S
        r_bytes, s_bytes = convert_der_to_rs(response.signature)

        console.print(f"Decoded R: {r_bytes.hex()}")
        console.print(f"Decoded S: {s_bytes.hex()}")

        # Convert public key to eth_keys format
        pub_key_bytes = self.public_key
        public_key = keys.PublicKey(pub_key_bytes)

        # Try both possible v values (0 and 1)
        for v in (0, 1):
            try:
                signature = keys.Signature(
                    vrs=(v,
                         int.from_bytes(r_bytes, 'big'),
                         int.from_bytes(s_bytes, 'big'))
                )

                recovered_key = signature.recover_public_key_from_msg_hash(msg_hash)
                console.print(f"Recovered with v={v}: {recovered_key}")
                console.print(f"Expected: {public_key}")

                if recovered_key == public_key:
                    v = v + 27  # Convert to Ethereum format
                    return r_bytes, s_bytes, v

            except Exception as e:
                console.print(f"Failed with v={v}: {e}")

        raise ValueError("Could not determine correct v value")

    def sign_message(self, message: str | bytes) -> str:
        """Sign an Ethereum message"""
        if isinstance(message, str):
            if message.startswith("0x"):
                message = encode_defunct(hexstr=message)
            else:
                message = encode_defunct(text=message)
        else:
            message = encode_defunct(primitive=message)

        msg_hash = _hash_eip191_message(message)
        r, s, v = self.sign_hash(msg_hash)

        # Convert to hex
        r_hex = binascii.hexlify(r).decode('ascii')
        s_hex = binascii.hexlify(s).decode('ascii')

        return f"0x{r_hex}{s_hex}{format(v, '02x')}"

    def sign_transaction(self, transaction: dict) -> str:
        """Sign an Ethereum transaction"""
        unsigned_tx = UnsignedTransaction(
            nonce=transaction['nonce'],
            gas_price=transaction['gasPrice'],
            gas_limit=transaction['gas'],
            to=transaction['to'],
            value=transaction['value'],
            data=to_bytes(hexstr=transaction['data']),
            chain_id=transaction.get('chainId', 1),
        )

        # Get the message hash
        message = rlp.encode([
            unsigned_tx.nonce,
            unsigned_tx.gas_price,
            unsigned_tx.gas_limit,
            to_bytes(hexstr=unsigned_tx.to),
            unsigned_tx.value,
            unsigned_tx.data,
            unsigned_tx.chain_id,
            0,  # v
            0,  # r
            0,  # s
        ])
        msg_hash = keccak(message)

        # Sign the hash
        r, s, v = self.sign_hash(msg_hash)

        # Adjust v for EIP-155
        v = to_standard_v(v)
        v = v + 35 + unsigned_tx.chain_id * 2

        # Create signed transaction
        signed = rlp.encode([
            unsigned_tx.nonce,
            unsigned_tx.gas_price,
            unsigned_tx.gas_limit,
            to_bytes(hexstr=unsigned_tx.to),
            unsigned_tx.value,
            unsigned_tx.data,
            v,
            int.from_bytes(r, 'big'),
            int.from_bytes(s, 'big'),
        ])

        return '0x' + signed.hex()


class CloudHSMAccount:
    """Web3.py compatible account using Cloud HSM"""

    def __init__(self, signer: GcpHsmSigner, web3):
        self.signer = signer
        self.web3 = web3
        self.address = self.signer.address

    def sign_transaction(self, transaction_dict: Dict[str, Any]) -> str:
        """Sign a Web3.py style transaction dict"""
        return self.signer.sign_transaction(transaction_dict)

    @classmethod
    def load_from_hsm(cls, web3, **signer_kwargs):
        """Create account from HSM configuration"""
        key_path = (
            f"projects/{signer_kwargs['project_id']}/locations/{signer_kwargs['location_id']}/"
            f"keyRings/{signer_kwargs['key_ring_id']}/cryptoKeys/{signer_kwargs['key_id']}/"
            f"cryptoKeyVersions/{signer_kwargs.get('key_version', '1')}"
        )
        signer = GcpHsmSigner(key_path=key_path)
        return cls(signer, web3)


def test_signer():
    """Test function to verify signer functionality"""
    try:
        dotenv.load_dotenv()
        from web3 import Web3

        web3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
        if not web3.is_connected():
            raise ConnectionError("Could not connect to Ethereum node")

        console.print("[bold blue]Creating HSM Account[/bold blue]")
        # Initialize account
        account = CloudHSMAccount.load_from_hsm(
            web3=web3,
            project_id=os.environ["GOOGLE_CLOUD_PROJECT"],
            location_id=os.environ["GOOGLE_CLOUD_REGION"],
            key_ring_id=os.environ["KEY_RING"],
            key_id=os.environ["KEY_NAME"]
        )

        console.print(f"[green]Account address: {account.address}[/green]")

        # Get funded account from Anvil
        funded_account = web3.eth.account.from_key(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        )

        # Fund the HSM account
        console.print("[blue]Funding HSM account...[/blue]")
        tx = {
            'from': funded_account.address,
            'to': Web3.to_checksum_address(account.address),
            'value': web3.to_wei(0.001, 'ether'),
            'gas': 21000,
            'gasPrice': web3.eth.gas_price,
            'nonce': web3.eth.get_transaction_count(funded_account.address),
            'chainId': web3.eth.chain_id,
            'data': '0x'
        }

        signed_tx = web3.eth.account.sign_transaction(tx, funded_account.key)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

        console.print(f"[green]Funded account. TX hash: {receipt['transactionHash'].hex()}[/green]")
        console.print(f"[blue]Balance: {web3.from_wei(web3.eth.get_balance(account.address), 'ether')} ETH[/blue]")

        # Test message signing
        console.print("\n[bold blue]Testing Message Signing[/bold blue]")
        message = "Hello Ethereum!"
        signature = account.signer.sign_message(message)
        console.print(f"Message signature: {signature}")

        # Test transaction signing
        console.print("\n[bold blue]Testing Transaction Signing[/bold blue]")
        tx = {
            'from': account.address,
            'to': Web3.to_checksum_address("0x4BB009C88B4718b06AbC236faAF1f06bBA3e610d"),
            'value': web3.to_wei(0.0000001, 'ether'),
            'gas': 21000,
            'gasPrice': web3.eth.gas_price,
            'nonce': web3.eth.get_transaction_count(account.address),
            'chainId': web3.eth.chain_id,
            'data': '0x'
        }

        signed_tx = account.sign_transaction(tx)
        console.print(f"Signed transaction: {signed_tx}")

        # Send transaction
        tx_hash = web3.eth.send_raw_transaction(signed_tx)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

        console.print(f"[green]Transfer successful. TX hash: {receipt['transactionHash'].hex()}[/green]")
        console.print(
            f"[blue]Final balance: {web3.from_wei(web3.eth.get_balance(account.address), 'ether')} ETH[/blue]")

    except Exception as e:
        console.print_exception()
        raise


if __name__ == "__main__":
    test_signer()
