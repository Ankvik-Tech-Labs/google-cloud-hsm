from abc import ABC, abstractmethod

from eth_typing import Address, HexStr


class BaseAccount(ABC):
    """Base class for cloud HSM-backed Ethereum accounts."""

    @property
    @abstractmethod
    def address(self) -> Address:
        """Get the Ethereum address associated with this account."""
        pass

    @abstractmethod
    def sign_transaction(self, transaction) -> HexStr:
        """Sign an Ethereum transaction using the HSM."""
        pass

    @abstractmethod
    def sign_message(self, message: bytes | str) -> HexStr:
        """Sign a message using the HSM."""
        pass

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(address={self.address})"
