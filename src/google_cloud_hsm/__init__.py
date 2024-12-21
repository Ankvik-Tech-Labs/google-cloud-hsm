"""Cloud HSM to sign Web3.py Ethereum transactions"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("google-cloud-hsm")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "unknown"
finally:
    del version, PackageNotFoundError
