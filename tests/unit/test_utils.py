"""Tests for utility functions."""
import pytest
import ecdsa
from web3_google_hsm.utils import extract_public_key_bytes, convert_der_to_rsv

# Real test values
TEST_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE0hPxTjwIf407JpkjCdf9kwVPvGdMOZUq
GaVPbV4qdocIUoJlxmWoOQeL/mR28cLrRqgn+Uj8HAoman2lndsp3w==
-----END PUBLIC KEY-----"""

def create_test_signature():
    """Create a proper DER signature for testing."""
    priv_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    msg = b"test message"
    return priv_key.sign(msg, sigencode=ecdsa.util.sigencode_der)

# Generate a test DER signature
TEST_DER_SIGNATURE = create_test_signature()

def test_extract_public_key_bytes():
    """Test extracting public key bytes from PEM format."""
    # Test with real public key
    public_key_bytes = extract_public_key_bytes(TEST_PUBLIC_KEY)
    assert len(public_key_bytes) == 64

    # Test PEM without header (just the base64 part)
    pem_str_no_header = "\n".join(TEST_PUBLIC_KEY.split("\n")[1:-1])
    public_key_bytes_no_header = extract_public_key_bytes(pem_str_no_header)
    assert len(public_key_bytes_no_header) == 64
    assert public_key_bytes == public_key_bytes_no_header

    # Test invalid PEM
    with pytest.raises(ValueError, match="Invalid PEM format"):
        extract_public_key_bytes("not a valid PEM")

def test_convert_der_to_rsv():
    """Test converting DER signature to RSV format."""
    # Test with real DER signature
    sig_dict = convert_der_to_rsv(TEST_DER_SIGNATURE, 27)

    # Verify structure and lengths
    assert 'v' in sig_dict
    assert 'r' in sig_dict
    assert 's' in sig_dict
    assert sig_dict['v'] == 27
    assert len(sig_dict['r']) == 32
    assert len(sig_dict['s']) == 32

    # Test invalid signature
    with pytest.raises(ecdsa.der.UnexpectedDER):
        convert_der_to_rsv(b"invalid signature", 27)

@pytest.mark.parametrize("v_adjustment", [0, 27, 35, 42])
def test_convert_der_to_rsv_v_values(v_adjustment: int):
    """Test different v adjustment values."""
    sig_dict = convert_der_to_rsv(TEST_DER_SIGNATURE, v_adjustment)

    # V value should match the adjustment
    assert sig_dict['v'] == v_adjustment

    # R and S should be valid 32-byte values
    assert len(sig_dict['r']) == 32
    assert len(sig_dict['s']) == 32

def test_convert_der_to_rsv_normalize_s():
    """Test S-value normalization."""
    # Create a signature where S is greater than N/2
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    msg_hash = b"test message"
    signature = private_key.sign(msg_hash, sigencode=ecdsa.util.sigencode_der)

    # Convert and verify S normalization
    sig_dict = convert_der_to_rsv(signature, 27)
    s_int = int.from_bytes(sig_dict['s'], 'big')
    assert s_int <= ecdsa.SECP256k1.order // 2, "S value was not normalized"

def test_convert_der_to_rsv_consistency():
    """Test that converting the same DER signature multiple times gives consistent results."""
    sig_dict1 = convert_der_to_rsv(TEST_DER_SIGNATURE, 27)
    sig_dict2 = convert_der_to_rsv(TEST_DER_SIGNATURE, 27)

    assert sig_dict1['v'] == sig_dict2['v']
    assert sig_dict1['r'] == sig_dict2['r']
    assert sig_dict1['s'] == sig_dict2['s']
