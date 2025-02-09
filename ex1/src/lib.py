# OPERATIONS = {
#     # operation: (operation_id, (required arguments), (optional arguments))
#     "username_exists": (1, ("username",), tuple()),
#     "register": (2, ("username", "password_digest"), tuple()),
#     "login": (3, ("username", "password_digest"), tuple()),
#     "accounts": (4, tuple(), ("search", "page", "per_page")),
#     "messages": (5, ("unread"), ("page", "per_page")),
#     "message": (6, ("username", "content"), tuple()),
#     "delete_messages": (7, ("messages"), tuple()),
#     "delete_account": (8, tuple(), tuple()),
# }

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
