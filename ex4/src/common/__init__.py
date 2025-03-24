# Functionality shared by client and server

import hashlib

from .codec import BVCodec, Codec, JSONCodec
from .request import Header, HeaderV1, Request, RequestCode, checksum
from .socket import SocketHandler


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
    "internal_heartbeat": 64,
    "internal_log": 65,
    "internal_election": 66,
    "internal_election_ok": 67,
    "internal_leader_announce": 68,
    "internal_acknowledge": 69,
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
    "SocketHandler",
    "TIMESTAMP_FORMAT",
]
