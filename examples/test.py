import os

from dotenv import load_dotenv
from eth_utils import keccak, to_checksum_address
from google.cloud import kms_v1
from google.cloud.kms_v1 import Digest
from web3 import Web3
from eth_account.messages import encode_defunct
from eth_account import Account
from google.cloud import kms
import base64
import hashlib
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_bytes, to_hex
from coincurve.utils import hex_to_bytes

# Load environment variables from .env file
load_dotenv()

PROJECT_ID = os.environ["GOOGLE_CLOUD_PROJECT"],
LOCATION_ID = os.environ["GOOGLE_CLOUD_REGION"],
KEY_RING_ID = os.environ["KEY_RING"],
KEY_ID = os.environ["KEY_NAME"]


class EthereumHSMSigner:
    def __init__(
        self,
        project_id: str,
        location_id: str,
        key_ring_id: str,
        key_id: str,
        version_id: str
    ):
        self.client = kms.KeyManagementServiceClient()
        self.key_version_name = self.client.crypto_key_version_path(
            project_id, location_id, key_ring_id, key_id, version_id
        )

    def crc32c(self, data: bytes) -> int:
        """Calculate CRC32C checksum"""
        import crcmod
        crc32c_fun = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
        return crc32c_fun(data)

    def prepare_message(self, message: str) -> bytes:
        """Prepare Ethereum message for signing"""
        # Encode message according to EIP-191
        encoded_message = encode_defunct(text=message)
        # Hash the encoded message
        message_hash = keccak(encoded_message.body)
        return message_hash

    def sign_ethereum_message(self, message: str) -> dict:
        """Sign an Ethereum message using GCP HSM"""
        # Prepare the message hash
        message_hash = self.prepare_message(message)

        # Create the sign request
        digest = {"sha256": message_hash}
        digest_crc32c = self.crc32c(message_hash)

        # Sign using GCP KMS
        sign_response = self.client.asymmetric_sign(
            request={
                "name": self.key_version_name,
                "digest": digest,
                "digest_crc32c": digest_crc32c,
            }
        )

        # Verify response integrity
        if not sign_response.verified_digest_crc32c:
            raise Exception("Request corrupted in-transit")
        if not sign_response.name == self.key_version_name:
            raise Exception("Key name mismatch")
        if not sign_response.signature_crc32c == self.crc32c(sign_response.signature):
            raise Exception("Response corrupted in-transit")

        # Convert DER signature to R,S format
        der_sig = sign_response.signature
        r_length = der_sig[3]
        r = int.from_bytes(der_sig[4:4 + r_length], byteorder='big')
        s_length = der_sig[5 + r_length]
        s = int.from_bytes(der_sig[6 + r_length:6 + r_length + s_length], byteorder='big')

        # Format signature components
        r_hex = hex(r)[2:].zfill(64)
        s_hex = hex(s)[2:].zfill(64)

        return {
            'message_hash': to_hex(message_hash),
            'r': r_hex,
            's': s_hex,
            'signature': f"0x{r_hex}{s_hex}"
        }

    def sign_ethereum_transaction(self, transaction_dict: dict) -> dict:
        """Sign an Ethereum transaction using GCP HSM"""
        # Encode transaction according to EIP-155
        # This is a simplified version - you'll need to implement proper RLP encoding
        transaction_bytes = to_bytes(hexstr=transaction_dict['raw'])
        transaction_hash = keccak(transaction_bytes)

        # Rest of the signing process is similar to message signing
        digest = {"sha256": transaction_hash}
        digest_crc32c = self.crc32c(transaction_hash)

        sign_response = self.client.asymmetric_sign(
            request={
                "name": self.key_version_name,
                "digest": digest,
                "digest_crc32c": digest_crc32c,
            }
        )

        # Similar verification and conversion process as message signing
        # You'll need to implement proper signature encoding for transactions

        return {
            'transaction_hash': to_hex(transaction_hash),
            'signature': to_hex(sign_response.signature)
        }


# Example usage:
if __name__ == "__main__":
    signer = EthereumHSMSigner(
        project_id=PROJECT_ID[0],
        location_id=LOCATION_ID[0],
        key_ring_id=KEY_RING_ID[0],
        key_id=KEY_ID,
        version_id="1"
    )

    # Sign a message
    message = "Hello, Ethereum!"
    signature = signer.sign_ethereum_message(message)
    print(f"Message signature: {signature}")

    # Sign a transaction
    transaction = {
        'raw': '0x...',  # Your raw transaction here
        'nonce': 0,
        'gasPrice': 20000000000,
        'gas': 21000,
        'to': '0x...',
        'value': 1000000000000000000,
        'data': ''
    }
    tx_signature = signer.sign_ethereum_transaction(transaction)
    print(f"Transaction signature: {tx_signature}")



# # Example transaction
# tx = {
#     'to': '0xReceiverAddress',
#     'value': web3.to_wei(0.1, 'ether'),
#     'gas': 2000000,
#     'gasPrice': web3.to_wei('50', 'gwei'),
#     'nonce': web3.eth.get_transaction_count(address),
#     'chainId': chain_id
# }
#
# # Sign the transaction
# signed_tx = web3.eth.account.sign_transaction(tx, private_key=signature)
#
# # Send the transaction
# tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
# print(f"Transaction sent: {tx_hash.hex()}")
