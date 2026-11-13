"""certpulse - check TLS certificate expiry for many hosts at once."""

from .core import CertResult, check_host, check_many, parse_target

__all__ = ["CertResult", "check_host", "check_many", "parse_target"]
__version__ = "0.1.0"
