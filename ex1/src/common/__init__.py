# Functionality shared by client and server

import hashlib

from .codec import BVCodec, Codec, JSONCodec
from .request import Header, HeaderV1, Request, RequestCode, checksum


def hash_password(password: str) -> str:
    """
    Deterministically hash the password using SHA-256.
    Returns a 32-byte digest.
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

OP_TO_CODE = {
    "username_exists": 1,
    "register": 2,
    "login": 3,
    "accounts": 4,
    "unread_messages": 5,
    "read_messages": 6,
    "message": 7,
    "delete_messages": 8,
    "delete_account": 9,
}

CODE_TO_OP = {c: o for o, c in OP_TO_CODE.items()}

__all__ = [
    "BVCodec",
    "checksum",
    "Codec",
    "CODE_TO_OP",
    "hash_password",
    "Header",
    "HeaderV1",
    "JSONCodec",
    "OP_TO_CODE",
    "Request",
    "RequestCode",
    "TIMESTAMP_FORMAT",
]
