import base64
import hashlib
from typing import Union

def to_base64(data: bytes) -> str:
    """Encode bytes to a base64 string."""
    return base64.b64encode(data).decode('ascii')

def from_base64(data_str: str) -> bytes:
    """Decode a base64 string to bytes."""
    return base64.b64decode(data_str.encode('ascii'))

def to_hex(data: bytes, shorten: bool = False, max_len: int = 16) -> str:
    """Encode bytes to hexadecimal string, optionally shortened."""
    hex_str = data.hex()
    if shorten and len(hex_str) > max_len:
        return f"{hex_str[:max_len]}... ({len(data)} bytes)"
    return hex_str

def sha256_fingerprint(data: bytes, format_type: str = "sha256_base64") -> str:
    """Compute standard SHA256 fingerprint."""
    digest = hashlib.sha256(data).digest()
    if format_type == "sha256_base64":
        return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"
    return hashlib.sha256(data).hexdigest()
