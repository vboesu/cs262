# Functionality shared by client and server

import hashlib

from .protocol_pb2 import LoginRequest, LoginResponse, RegisterResponse


def hash_password(password: str | bytes) -> bytes:
    """
    Deterministically hash the password using SHA-256.
    Returns a 32-byte digest.
    """
    to_encode = password if isinstance(password, bytes) else password.encode("utf-8")
    return hashlib.sha256(to_encode).digest()


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

__all__ = [
    "hash_password",
    "TIMESTAMP_FORMAT",
    "LoginRequest",
    "LoginResponse",
    "RegisterResponse",
]
