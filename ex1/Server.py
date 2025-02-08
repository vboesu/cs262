#!/usr/bin/env python3
"""
Server.py – A simple multithreaded TCP server implementing our custom wire protocol
for a chat application. It supports the following operations:
    1. Create Account
    2. Login (returns unread count)
    3. List Accounts (with optional search and pagination)
    4. Send Message (delivers immediately if recipient online; otherwise stores for later)
    5. Read Messages (with a page size parameter)
    6. Delete Message (by a provided message ID)
    7. Delete Account (deletes all associated messages)

Protocol Details:
  - The header is 8 bytes long, with the following fields (all little-endian):
      * Version (1 byte) – currently fixed to 1.
      * Request Code (1 byte) – identifies the operation.
      * Flags/Status (2 bytes) – reserved for future use; set to 0.
      * Packet Checksum (2 bytes) – computed as the sum of payload bytes modulo 65536.
      * Payload Length (2 bytes) – number of bytes in the TLV payload.
  - The payload is encoded as a sequence of TLV fields. Each field consists of:
      * Field ID (1 byte)
      * Field Length (2 bytes)
      * Field Value (raw bytes)
  - Composite objects (such as a full message) are encoded as a nested TLV block.
  - Passwords are hashed deterministically using SHA-256.
"""

import socket
import threading
import struct
import hashlib
import time

# --- Protocol Constants ---
HEADER_FORMAT = "<B B H H H"   # version, request_code, flags, checksum, payload_length
HEADER_SIZE = 8

# Request codes (operations)
REQ_CREATE_ACCOUNT = 1
REQ_LOGIN = 2
REQ_LIST_ACCOUNTS = 3
REQ_SEND_MESSAGE = 4
REQ_READ_MESSAGES = 5
REQ_DELETE_MESSAGE = 6
REQ_DELETE_ACCOUNT = 7

# Field IDs (agreed upon by both client and server)
FIELD_USERNAME         = 1
FIELD_PASSWORD_HASH    = 2
FIELD_MESSAGE_CONTENT  = 3
FIELD_SENDER           = 4
FIELD_RECIPIENT        = 5
FIELD_TIMESTAMP        = 6
FIELD_MESSAGE_ID       = 7  # used for deletion (computed as SHA-256 of the composite message)
FIELD_UNREAD_COUNT     = 8
FIELD_SEARCH_PATTERN   = 9
FIELD_PAGE_NUMBER      = 10
FIELD_PAGE_SIZE        = 11

# --- Global Storage ---
# Accounts structure: maps username -> { "password": hashed_password, "unread": [messages], "read": [messages] }
accounts = {}
# Connected clients: maps username -> connection socket
connected_clients = {}
# A lock to ensure thread safety when accessing shared structures
lock = threading.Lock()

# --- Helper Functions for Protocol ---

def compute_checksum(data: bytes) -> int:
    """Compute checksum as the sum of payload bytes modulo 65536."""
    return sum(data) % 65536

def build_message(request_code: int, fields_bytes: bytes) -> bytes:
    """
    Build a complete message with header and payload.
    Header layout (8 bytes):
      - Version (1 byte)
      - Request Code (1 byte)
      - Flags/Status (2 bytes) [currently 0]
      - Checksum (2 bytes) computed over the payload bytes
      - Payload Length (2 bytes)
    """
    version = 1
    flags = 0
    payload_length = len(fields_bytes)
    checksum = compute_checksum(fields_bytes)
    header = struct.pack(HEADER_FORMAT, version, request_code, flags, checksum, payload_length)
    return header + fields_bytes

def encode_field(field_id: int, field_value: bytes) -> bytes:
    """
    Encode one TLV field: Field ID (1 byte) + Field Length (2 bytes) + Field Value.
    """
    return struct.pack("<B H", field_id, len(field_value)) + field_value

def encode_fields(fields: list) -> bytes:
    """
    Encode a list of TLV fields.
    Each element in 'fields' should be a tuple: (field_id, field_value).
    Returns the concatenated byte string.
    """
    encoded = b""
    for fid, fvalue in fields:
        encoded += encode_field(fid, fvalue)
    return encoded

def hash_password(password: str) -> bytes:
    """
    Deterministically hash a password using SHA-256.
    Returns a 32-byte digest.
    """
    return hashlib.sha256(password.encode("utf-8")).digest()

def parse_message(conn: socket.socket) -> tuple:
    """
    Read a complete message from the socket.
    Returns a tuple (request_code, payload bytes) or None if connection closes.
    """
    header = conn.recv(HEADER_SIZE)
    if len(header) < HEADER_SIZE:
        return None
    version, req_code, flags, checksum, payload_length = struct.unpack(HEADER_FORMAT, header)
    payload = b""
    while len(payload) < payload_length:
        chunk = conn.recv(payload_length - len(payload))
        if not chunk:
            break
        payload += chunk
    if compute_checksum(payload) != checksum:
        print("Checksum error")
        return None
    return req_code, payload

def decode_fields(payload: bytes) -> dict:
    """
    Decode TLV fields from a payload.
    Returns a dictionary mapping field IDs to their corresponding byte values.
    """
    fields = {}
    offset = 0
    while offset + 3 <= len(payload):
        field_id = payload[offset]
        field_length = struct.unpack("<H", payload[offset+1:offset+3])[0]
        offset += 3
        field_value = payload[offset:offset+field_length]
        fields[field_id] = field_value
        offset += field_length
    return fields

# --- Server Operations ---

def handle_client(conn: socket.socket, addr):
    """
    Handle communication with a connected client.
    Maintains the current logged in username for the session.
    """
    print(f"Client connected from {addr}")
    current_user = None
    try:
        while True:
            result = parse_message(conn)
            if not result:
                break
            req_code, payload = result
            fields = decode_fields(payload)
            response_fields = []
            
            # Operation: Create Account
            if req_code == REQ_CREATE_ACCOUNT:
                username = fields.get(FIELD_USERNAME, b"").decode("utf-8")
                password_hash = fields.get(FIELD_PASSWORD_HASH)
                with lock:
                    if username in accounts:
                        response_fields.append((FIELD_MESSAGE_CONTENT, b"Account exists."))
                    else:
                        accounts[username] = {"password": password_hash, "unread": [], "read": []}
                        current_user = username
                        connected_clients[username] = conn
                        response_fields.append((FIELD_MESSAGE_CONTENT, b"Account created."))
                response = build_message(req_code, encode_fields(response_fields))
                conn.sendall(response)
            
            # Operation: Login
            elif req_code == REQ_LOGIN:
                username = fields.get(FIELD_USERNAME, b"").decode("utf-8")
                password_hash = fields.get(FIELD_PASSWORD_HASH)
                with lock:
                    if username not in accounts:
                        response_fields.append((FIELD_MESSAGE_CONTENT, b"Account does not exist."))
                    elif accounts[username]["password"] != password_hash:
                        response_fields.append((FIELD_MESSAGE_CONTENT, b"Incorrect password."))
                    else:
                        current_user = username
                        connected_clients[username] = conn
                        unread_count = len(accounts[username]["unread"])
                        response_fields.append((FIELD_UNREAD_COUNT, struct.pack("<H", unread_count)))
                response = build_message(req_code, encode_fields(response_fields))
                conn.sendall(response)
            
            # Operation: List Accounts (with optional search and pagination)
            elif req_code == REQ_LIST_ACCOUNTS:
                search_pattern = fields.get(FIELD_SEARCH_PATTERN, b"").decode("utf-8")
                page_number = struct.unpack("<H", fields.get(FIELD_PAGE_NUMBER, b"\x00\x01"))[0]
                page_size = struct.unpack("<H", fields.get(FIELD_PAGE_SIZE, b"\x00\x10"))[0]
                with lock:
                    matching = [u for u in accounts if search_pattern in u]
                start = (page_number - 1) * page_size
                end = start + page_size
                list_str = ",".join(matching[start:end])
                response_fields.append((FIELD_MESSAGE_CONTENT, list_str.encode("utf-8")))
                response = build_message(req_code, encode_fields(response_fields))
                conn.sendall(response)
            
            # Operation: Send Message
            elif req_code == REQ_SEND_MESSAGE:
                sender = fields.get(FIELD_SENDER, b"").decode("utf-8")
                recipient = fields.get(FIELD_RECIPIENT, b"").decode("utf-8")
                message_content = fields.get(FIELD_MESSAGE_CONTENT, b"")
                timestamp = struct.pack("<I", int(time.time()))
                # Create composite TLV for the message: includes sender, message content, and timestamp.
                message_fields = [
                    (FIELD_SENDER, sender.encode("utf-8")),
                    (FIELD_MESSAGE_CONTENT, message_content),
                    (FIELD_TIMESTAMP, timestamp)
                ]
                message_object = encode_fields(message_fields)
                # Compute message ID deterministically (used for deletion)
                msg_id = hashlib.sha256(message_object).digest()
                with lock:
                    if recipient in connected_clients:
                        try:
                            send_fields = [(FIELD_MESSAGE_CONTENT, message_object)]
                            send_msg = build_message(REQ_SEND_MESSAGE, encode_fields(send_fields))
                            connected_clients[recipient].sendall(send_msg)
                        except Exception as e:
                            accounts[recipient]["unread"].append(message_object)
                    else:
                        if recipient in accounts:
                            accounts[recipient]["unread"].append(message_object)
                        else:
                            response_fields.append((FIELD_MESSAGE_CONTENT, b"Recipient does not exist."))
                            response = build_message(req_code, encode_fields(response_fields))
                            conn.sendall(response)
                            continue
                response_fields.append((FIELD_MESSAGE_CONTENT, b"Message sent."))
                # Return the message ID for potential deletion.
                response_fields.append((FIELD_MESSAGE_ID, msg_id))
                response = build_message(req_code, encode_fields(response_fields))
                conn.sendall(response)
            
            # Operation: Read Messages (pagination)
            elif req_code == REQ_READ_MESSAGES:
                num_messages = struct.unpack("<H", fields.get(FIELD_PAGE_SIZE, b"\x00\x01"))[0]
                with lock:
                    if current_user is None or current_user not in accounts:
                        response_fields.append((FIELD_MESSAGE_CONTENT, b"Not logged in."))
                    else:
                        unread = accounts[current_user]["unread"]
                        to_send = unread[:num_messages]
                        accounts[current_user]["read"].extend(to_send)
                        accounts[current_user]["unread"] = unread[num_messages:]
                        # Join messages with "||" separator (for simplicity)
                        messages_combined = b"||".join(to_send)
                        response_fields.append((FIELD_MESSAGE_CONTENT, messages_combined))
                response = build_message(req_code, encode_fields(response_fields))
                conn.sendall(response)
            
            # Operation: Delete Message (by message ID)
            elif req_code == REQ_DELETE_MESSAGE:
                msg_id = fields.get(FIELD_MESSAGE_ID, b"")
                with lock:
                    if current_user is None or current_user not in accounts:
                        response_fields.append((FIELD_MESSAGE_CONTENT, b"Not logged in."))
                    else:
                        found = False
                        # Check both unread and read message lists for a matching message ID.
                        for lst in [accounts[current_user]["unread"], accounts[current_user]["read"]]:
                            for i, msg in enumerate(lst):
                                if hashlib.sha256(msg).digest() == msg_id:
                                    del lst[i]
                                    found = True
                                    break
                            if found:
                                break
                        if found:
                            response_fields.append((FIELD_MESSAGE_CONTENT, b"Message deleted."))
                        else:
                            response_fields.append((FIELD_MESSAGE_CONTENT, b"Message not found."))
                response = build_message(req_code, encode_fields(response_fields))
                conn.sendall(response)
            
            # Operation: Delete Account
            elif req_code == REQ_DELETE_ACCOUNT:
                with lock:
                    if current_user is None or current_user not in accounts:
                        response_fields.append((FIELD_MESSAGE_CONTENT, b"Not logged in."))
                    else:
                        del accounts[current_user]
                        if current_user in connected_clients:
                            del connected_clients[current_user]
                        response_fields.append((FIELD_MESSAGE_CONTENT, b"Account deleted."))
                        current_user = None
                response = build_message(req_code, encode_fields(response_fields))
                conn.sendall(response)
            
            else:
                response_fields.append((FIELD_MESSAGE_CONTENT, b"Unknown operation."))
                response = build_message(req_code, encode_fields(response_fields))
                conn.sendall(response)
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        with lock:
            if current_user in connected_clients:
                del connected_clients[current_user]
        print(f"Client {addr} disconnected.")

def start_server(host="127.0.0.1", port=9000):
    """
    Start the server:
      - Create a TCP socket.
      - Bind to the specified host and port.
      - Listen for incoming connections.
      - Spawn a new thread (handle_client) for each accepted connection.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((host, port))
    server_sock.listen(5)
    print(f"Server listening on {host}:{port}")
    try:
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_sock.close()

if __name__ == "__main__":
    start_server()
