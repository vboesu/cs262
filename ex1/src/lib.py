"""
File with general information/methods shared by client and server.
"""

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
