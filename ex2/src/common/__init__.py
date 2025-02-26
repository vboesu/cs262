# Functionality shared by client and server

import hashlib

from .protocol_pb2 import (
    Account,
    AccountResponse,
    DeleteMessagesRequest,
    GenericRequest,
    GenericResponse,
    Header,
    ListAccountsRequest,
    LoginRequest,
    LoginResponse,
    Message,
    MessageRequest,
    MessageResponse,
    PaginatedRequest,
    PaginatedResponse,
    RegisterResponse,
    UnreadMessagesRequest,
)


def hash_password(password: str | bytes) -> bytes:
    """
    Deterministically hash the password using SHA-256.
    Returns a 32-byte digest.
    """
    to_encode = password if isinstance(password, bytes) else password.encode("utf-8")
    return hashlib.sha256(to_encode).digest()


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

__all__ = [
    "Account",
    "AccountResponse",
    "DeleteMessagesRequest",
    "GenericRequest",
    "GenericResponse",
    "hash_password",
    "Header",
    "ListAccountsRequest",
    "LoginRequest",
    "LoginRequest",
    "LoginResponse",
    "LoginResponse",
    "Message",
    "MessageRequest",
    "MessageResponse",
    "PaginatedRequest",
    "PaginatedResponse",
    "RegisterResponse",
    "RegisterResponse",
    "TIMESTAMP_FORMAT",
    "UnreadMessagesRequest",
]
