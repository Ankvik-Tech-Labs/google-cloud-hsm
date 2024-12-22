from google.cloud import kms
from web3.auto import w3
from eth_keys import keys
from eth_utils import keccak
import base64
import hashlib

class GcpKeyRingRef:
    def __init__(self, project_id, location, key_ring):
        self.project_id = project_id
        self.location = location
        self.key_ring = key_ring

    def to_google_ref(self):
        return f"projects/{self.project_id}/locations/{self.location}/keyRings/{self.key_ring}"

    def to_key_version_ref(self, key_id, key_version):
        return f"{self.to_google_ref()}/cryptoKeys/{key_id}/cryptoKeyVersions/{key_version}"

class GcpKmsProvider:
    def __init__(self, kms_key_ref: GcpKeyRingRef):
        self.client = kms.KeyManagementServiceClient()
        self.kms_key_ref = kms_key_ref

    def get_verifying_key(self, key_id, key_version):
        key_version_ref = self.kms_key_ref.to_key_version_ref(key_id, key_version)
        response = self.client.get_public_key(request={"name": key_version_ref})
        pem_key = response.pem
        # Load the public key from PEM format
        print(pem_key)
        verifying_key = keys.PublicKey.from_compressed_bytes(bytes.fromhex(pem_key))
        return verifying_key

    def sign_digest(self, key_id, key_version, digest):
        key_version_ref = self.kms_key_ref.to_key_version_ref(key_id, key_version)
        digest_bytes = hashlib.sha256(digest).digest()

        response = self.client.asymmetric_sign(
            request={
                "name": key_version_ref,
                "digest": {"sha256": digest_bytes},
            }
        )
        signature = response.signature
        return signature

class GcpKmsSigner:
    def __init__(self, provider: GcpKmsProvider, key_id, key_version, chain_id):
        self.provider = provider
        self.key_id = key_id
        self.key_version = key_version
        self.chain_id = chain_id
        self.verifying_key = provider.get_verifying_key(key_id, key_version)

    def verifying_key_to_address(self):
        uncompressed_key = self.verifying_key.to_bytes()
        address_bytes = keccak(uncompressed_key[1:])[12:]
        return w3.toChecksumAddress(address_bytes.hex())

    def apply_eip155(self, sig_v):
        return (self.chain_id * 2 + 35) + sig_v

    def sign_digest(self, digest):
        signature = self.provider.sign_digest(self.key_id, self.key_version, digest)
        r, s, v = self._recover_signature_parts(signature, digest)
        v = self.apply_eip155(v)
        return {"r": r, "s": s, "v": v}

    def _recover_signature_parts(self, signature, digest):
        # Recover r and s from the DER-encoded signature
        r, s = keys.Signature.from_bytes(signature).rs
        v = 0  # Adjust if needed for recovery ID
        return int(r), int(s), v

    def sign_message(self, message):
        message_hash = keccak(text=message)
        return self.sign_digest(message_hash)

# Example Usage
if __name__ == "__main__":
    import os
    from dotenv import load_dotenv

    load_dotenv()

    # Set up environment variables or hard-code them
    project_id = "hsm-testing-445507" # os.getenv("GOOGLE_PROJECT_ID")
    location = os.getenv("GOOGLE_CLOUD_REGION")
    key_ring = os.getenv("KEY_RING")
    key_name = os.getenv("KEY_NAME")

    key_ref = GcpKeyRingRef(project_id, location, key_ring)
    provider = GcpKmsProvider(key_ref)
    signer = GcpKmsSigner(provider, key_name, 1, 1)

    message = "Hello, Ethereum!"
    signature = signer.sign_message(message)
    address = signer.verifying_key_to_address()

    print(f"Message: {message}")
    print(f"Signature: {signature}")
    print(f"Address: {address}")

"""
Transaction hash: 0xebfea470b1694d3c77ca65dbd5f99fd0b930c268fcb140eecc3a8dc8270f9d69
Sender address: 0x0545640a0ecd6fb6ae94766811f30dcda4746dfc
"""
