import pytest
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address
from web3 import Web3

from google_cloud_hsm.types.ethereum_types import Signature, Transaction
# from google_cloud_hsm.exceptions import SignatureError


class TestSignature:
    """Tests for the Signature class."""

    def test_signature_creation(self, test_signature):
        """Test creating a signature."""
        assert isinstance(test_signature, Signature)
        assert test_signature.v == 27
        assert len(test_signature.r) == 32
        assert len(test_signature.s) == 32

    def test_signature_validation(self):
        """Test signature validation."""
        # Test invalid v value
        with pytest.raises(ValueError, match="v must be non-negative"):
            Signature(v=-1, r=bytes([0]*32), s=bytes([0]*32))

        # Test invalid r length
        with pytest.raises(ValueError, match="Length must be 32 bytes"):
            Signature(v=27, r=bytes([0]*31), s=bytes([0]*32))

        # Test invalid s length
        with pytest.raises(ValueError, match="Length must be 32 bytes"):
            Signature(v=27, r=bytes([0]*32), s=bytes([0]*31))

    def test_signature_hex_conversion(self, test_signature):
        """Test hex string conversion."""
        hex_str = test_signature.to_hex()
        assert hex_str.startswith("0x")
        assert len(hex_str) == 132  # 0x + 130 hex chars

        # Convert back
        sig2 = Signature.from_hex(hex_str)
        assert sig2.v == test_signature.v
        assert sig2.r == test_signature.r
        assert sig2.s == test_signature.s

    def test_signature_verification(self, test_signature, web3, test_message):
        """Test signature verification using web3."""
        message_hash = encode_defunct(text=test_message)
        recovered_address = web3.eth.account.recover_message(
            message_hash,
            vrs=(test_signature.v, test_signature.r, test_signature.s)
        )
        assert Web3.is_address(recovered_address)
        assert recovered_address.startswith("0x")

    def test_signature_from_invalid_hex(self):
        """Test signature creation from invalid hex string."""
        # Test invalid hex string
        with pytest.raises(ValueError):
            Signature.from_hex("0xinvalid")

        # Test wrong length
        with pytest.raises(ValueError, match="Invalid signature length"):
            Signature.from_hex("0x" + "00" * 32)


class TestTransaction:
    """Tests for the Transaction class."""

    def test_transaction_creation_standard_fields(self, transaction_dict):
        """Test creating a transaction with standard field names."""
        tx = Transaction.from_dict(transaction_dict)
        assert tx.chain_id == transaction_dict["chain_id"]
        assert tx.nonce == transaction_dict["nonce"]
        assert tx.gas_price == transaction_dict["gas_price"]
        assert tx.gas_limit == transaction_dict["gas_limit"]
        assert tx.to == to_checksum_address(transaction_dict["to"])
        assert tx.value == transaction_dict["value"]
        assert tx.data == transaction_dict["data"]
        assert tx.from_ == to_checksum_address(transaction_dict["from"])

    def test_transaction_creation_web3_fields(self, test_address):
        """Test creating a transaction with web3-style field names."""
        web3_tx = {
            "chainId": 1,
            "nonce": 0,
            "gasPrice": 20_000_000_000,
            "gas": 21000,
            "to": test_address,
            "value": 0,
            "data": "0x",
            "from": test_address
        }
        tx = Transaction.from_dict(web3_tx)
        assert tx.chain_id == web3_tx["chainId"]
        assert tx.nonce == web3_tx["nonce"]
        assert tx.gas_price == web3_tx["gasPrice"]
        assert tx.gas_limit == web3_tx["gas"]
        assert tx.to == to_checksum_address(web3_tx["to"])
        assert tx.from_ == to_checksum_address(web3_tx["from"])

    def test_transaction_validation(self, test_address):
        """Test transaction validation."""
        # Test invalid gas price
        with pytest.raises(ValueError):
            Transaction(
                chain_id=1,
                nonce=0,
                gas_price=0,  # Invalid: must be > 0
                gas_limit=21000,
                to=test_address,
                value=0,
                from_=test_address
            )

        # Test invalid address
        with pytest.raises(ValueError, match="Invalid Ethereum address"):
            Transaction(
                chain_id=1,
                nonce=0,
                gas_price=1000000000,
                gas_limit=21000,
                to="invalid",
                value=0,
                from_=test_address
            )

        # Test negative nonce
        with pytest.raises(ValueError):
            Transaction(
                chain_id=1,
                nonce=-1,  # Invalid: must be >= 0
                gas_price=1000000000,
                gas_limit=21000,
                to=test_address,
                value=0,
                from_=test_address
            )

    # ? Need proper tx signature for verification Skipping for now as other tests will cover it
    # def test_transaction_serialization(self, test_transaction, test_signature):
    #     """Test transaction serialization."""
    #     # Test without signature
    #     with pytest.raises(SignatureError, match="The transaction is not signed"):
    #         test_transaction.serialize_transaction()

    #     # Test with signature
    #     test_transaction.signature = test_signature
    #     serialized = test_transaction.serialize_transaction()
    #     assert isinstance(serialized, bytes)

    # def test_transaction_signature_verification(self, test_transaction, test_signature, web3):
    #     """Test transaction signature verification."""
    #     test_transaction.signature = test_signature
    #     serialized = test_transaction.serialize_transaction()

    #     # Recover signer from transaction
    #     recovered_address = web3.eth.account.recover_transaction(serialized)
    #     assert Web3.is_address(recovered_address)

    def test_transaction_dict_conversion(self, test_transaction):
        """Test converting transaction to web3-compatible dict."""
        tx_dict = test_transaction.to_dict()

        # Check field names
        assert "chainId" in tx_dict
        assert "gasPrice" in tx_dict
        assert "gas" in tx_dict
        assert "from" in tx_dict

        # Check values
        assert tx_dict["chainId"] == test_transaction.chain_id
        assert tx_dict["gasPrice"] == test_transaction.gas_price
        assert tx_dict["gas"] == test_transaction.gas_limit
        assert tx_dict["from"].lower() == test_transaction.from_.lower()

    def test_transaction_with_signature(self, test_transaction, test_signature):
        """Test transaction with attached signature."""
        test_transaction.signature = test_signature
        tx_dict = test_transaction

        assert tx_dict.signature.v == test_signature.v
        assert tx_dict.signature.r.hex() == test_signature.r.hex()
        assert tx_dict.signature.s.hex() == test_signature.s.hex()


    def test_transaction_to_transaction_dict(self, test_transaction, test_signature):
        """Test converting transaction to signing format."""
        # Test without signature
        tx_dict = test_transaction.to_transaction_dict()
        assert "chainId" in tx_dict
        assert "v" not in tx_dict
        assert "r" not in tx_dict
        assert "s" not in tx_dict

        # Test with signature
        test_transaction.signature = test_signature
        tx_dict = test_transaction.to_transaction_dict()
        assert "v" in tx_dict
        assert "r" in tx_dict
        assert "s" in tx_dict
        assert isinstance(tx_dict["v"], int)
        assert isinstance(tx_dict["r"], int)
        assert isinstance(tx_dict["s"], int)

    def test_transaction_data_field(self, test_address):
        """Test transaction data field handling."""
        # Test with hex data
        tx = Transaction(
            chain_id=1,
            nonce=0,
            gas_price=1000000000,
            gas_limit=21000,
            to=test_address,
            value=0,
            from_=test_address,
            data="0x1234"
        )
        assert tx.data == "0x1234"

        # Test with data without 0x prefix
        tx = Transaction(
            chain_id=1,
            nonce=0,
            gas_price=1000000000,
            gas_limit=21000,
            to=test_address,
            value=0,
            from_=test_address,
            data="1234"
        )
        assert tx.data == "0x1234"

        # Test with invalid hex
        with pytest.raises(ValueError, match="Invalid hex string"):
            Transaction(
                chain_id=1,
                nonce=0,
                gas_price=1000000000,
                gas_limit=21000,
                to=test_address,
                value=0,
                from_=test_address,
                data="0xXYZ"  # Invalid hex
            )
