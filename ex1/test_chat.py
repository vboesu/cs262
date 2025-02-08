#!/usr/bin/env python3
"""
test_chat.py – Integration tests for our chat server using our custom wire protocol.
Uses Python's unittest framework.
"""

import socket
import threading
import struct
import hashlib
import time
import unittest

# --- Protocol Constants (same as Server.py) ---
HEADER_FORMAT = "<B B H H H"
HEADER_SIZE = 8

REQ_CREATE_ACCOUNT = 1
REQ_LOGIN = 2
REQ_LIST_ACCOUNTS = 3
REQ_SEND_MESSAGE = 4
REQ_READ_MESSAGES = 5
REQ_DELETE_MESSAGE = 6
REQ_DELETE_ACCOUNT = 7

FIELD_USERNAME         = 1
FIELD_PASSWORD_HASH    = 2
FIELD_MESSAGE_CONTENT  = 3
FIELD_SENDER           = 4
FIELD_RECIPIENT        = 5
FIELD_TIMESTAMP        = 6
FIELD_MESSAGE_ID       = 7
FIELD_UNREAD_COUNT     = 8
FIELD_SEARCH_PATTERN   = 9
FIELD_PAGE_NUMBER      = 10
FIELD_PAGE_SIZE        = 11

# --- Helper Functions (same as Server.py) ---
def compute_checksum(data: bytes) -> int:
    return sum(data) % 65536

def build_message(request_code: int, fields_bytes: bytes) -> bytes:
    version = 1
    flags = 0
    payload_length = len(fields_bytes)
    checksum = compute_checksum(fields_bytes)
    header = struct.pack(HEADER_FORMAT, version, request_code, flags, checksum, payload_length)
    return header + fields_bytes

def encode_field(field_id: int, field_value: bytes) -> bytes:
    return struct.pack("<B H", field_id, len(field_value)) + field_value

def encode_fields(fields: list) -> bytes:
    encoded = b""
    for fid, fvalue in fields:
        encoded += encode_field(fid, fvalue)
    return encoded

def hash_password(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()

def parse_message(sock: socket.socket) -> tuple:
    header = sock.recv(HEADER_SIZE)
    if len(header) < HEADER_SIZE:
        return None
    version, req_code, flags, checksum, payload_length = struct.unpack(HEADER_FORMAT, header)
    payload = b""
    while len(payload) < payload_length:
        chunk = sock.recv(payload_length - len(payload))
        if not chunk:
            break
        payload += chunk
    if compute_checksum(payload) != checksum:
        print("Checksum error in response")
        return None
    return req_code, payload

def decode_fields(payload: bytes) -> dict:
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

# --- Test Client Class ---
class TestClient:
    def __init__(self, host="127.0.0.1", port=9000):
        self.sock = socket.create_connection((host, port))
    
    def send_request(self, request_code: int, fields: list) -> tuple:
        message = build_message(request_code, encode_fields(fields))
        self.sock.sendall(message)
        response = parse_message(self.sock)
        if response is None:
            return None, None
        resp_code, payload = response
        return resp_code, decode_fields(payload)
    
    def close(self):
        self.sock.close()

# --- Server Runner for Tests ---
accounts = {}
connected_clients = {}
lock = threading.Lock()

def handle_client(conn: socket.socket, addr):
    # (The same handle_client function from the updated Server.py)
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
            elif req_code == REQ_SEND_MESSAGE:
                sender = fields.get(FIELD_SENDER, b"").decode("utf-8")
                recipient = fields.get(FIELD_RECIPIENT, b"").decode("utf-8")
                message_content = fields.get(FIELD_MESSAGE_CONTENT, b"")
                timestamp = struct.pack("<I", int(time.time()))
                message_fields = [
                    (FIELD_SENDER, sender.encode("utf-8")),
                    (FIELD_MESSAGE_CONTENT, message_content),
                    (FIELD_TIMESTAMP, timestamp)
                ]
                message_object = encode_fields(message_fields)
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
                response_fields.append((FIELD_MESSAGE_ID, msg_id))
                response = build_message(req_code, encode_fields(response_fields))
                conn.sendall(response)
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
                        messages_combined = b"||".join(to_send)
                        response_fields.append((FIELD_MESSAGE_CONTENT, messages_combined))
                response = build_message(req_code, encode_fields(response_fields))
                conn.sendall(response)
            elif req_code == REQ_DELETE_MESSAGE:
                msg_id = fields.get(FIELD_MESSAGE_ID, b"")
                with lock:
                    if current_user is None or current_user not in accounts:
                        response_fields.append((FIELD_MESSAGE_CONTENT, b"Not logged in."))
                    else:
                        found = False
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

# --- Test Cases ---
class TestChatServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the server in a background thread.
        cls.server_thread = threading.Thread(target=start_server, kwargs={"host": "127.0.0.1", "port": 9000})
        cls.server_thread.daemon = True
        cls.server_thread.start()
        # Allow a brief moment for the server to start.
        time.sleep(1)

    def test_create_and_login_account(self):
        client1 = TestClient()
        username = "alice"
        password = "secret123"
        pwd_hash = hash_password(password)
        resp_code, resp_fields = client1.send_request(REQ_CREATE_ACCOUNT, [
            (FIELD_USERNAME, username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, pwd_hash)
        ])
        self.assertIsNotNone(resp_fields)
        msg = resp_fields.get(FIELD_MESSAGE_CONTENT, b"").decode("utf-8")
        self.assertIn("created", msg.lower())
        client1.close()

        client2 = TestClient()
        resp_code, resp_fields = client2.send_request(REQ_LOGIN, [
            (FIELD_USERNAME, username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, pwd_hash)
        ])
        self.assertIsNotNone(resp_fields)
        self.assertIn(FIELD_UNREAD_COUNT, resp_fields)
        unread_count = struct.unpack("<H", resp_fields[FIELD_UNREAD_COUNT])[0]
        self.assertEqual(unread_count, 0)
        client2.close()

    def test_list_accounts(self):
        client1 = TestClient()
        for user in ["bob", "carol"]:
            pwd = "pwd"
            client1.send_request(REQ_CREATE_ACCOUNT, [
                (FIELD_USERNAME, user.encode("utf-8")),
                (FIELD_PASSWORD_HASH, hash_password(pwd))
            ])
            client1.close()
            client1 = TestClient()
        
        client = TestClient()
        resp_code, resp_fields = client.send_request(REQ_LIST_ACCOUNTS, [
            (FIELD_SEARCH_PATTERN, b"o"),
            (FIELD_PAGE_NUMBER, struct.pack("<H", 1)),
            (FIELD_PAGE_SIZE, struct.pack("<H", 10))
        ])
        self.assertIsNotNone(resp_fields)
        accounts_list = resp_fields.get(FIELD_MESSAGE_CONTENT, b"").decode("utf-8")
        self.assertTrue("bob" in accounts_list or "carol" in accounts_list)
        client.close()

    def test_send_and_read_message(self):
        # Create sender "dave" and recipient "erin".
        sender_client = TestClient()
        sender_username = "dave"
        sender_pwd = "davepwd"
        sender_hash = hash_password(sender_pwd)
        sender_client.send_request(REQ_CREATE_ACCOUNT, [
            (FIELD_USERNAME, sender_username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, sender_hash)
        ])
        sender_client.close()

        recipient_client = TestClient()
        recipient_username = "erin"
        recipient_pwd = "erinpwd"
        recipient_hash = hash_password(recipient_pwd)
        recipient_client.send_request(REQ_CREATE_ACCOUNT, [
            (FIELD_USERNAME, recipient_username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, recipient_hash)
        ])
        recipient_client.close()

        sender_client = TestClient()
        resp_code, resp_fields = sender_client.send_request(REQ_LOGIN, [
            (FIELD_USERNAME, sender_username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, sender_hash)
        ])
        self.assertIn(FIELD_UNREAD_COUNT, resp_fields)
        test_message = "Hello, Erin!"
        resp_code, resp_fields = sender_client.send_request(REQ_SEND_MESSAGE, [
            (FIELD_SENDER, sender_username.encode("utf-8")),
            (FIELD_RECIPIENT, recipient_username.encode("utf-8")),
            (FIELD_MESSAGE_CONTENT, test_message.encode("utf-8"))
        ])
        self.assertIsNotNone(resp_fields)
        msg = resp_fields.get(FIELD_MESSAGE_CONTENT, b"").decode("utf-8")
        self.assertIn("sent", msg.lower())
        sender_client.close()

        recipient_client = TestClient()
        resp_code, resp_fields = recipient_client.send_request(REQ_LOGIN, [
            (FIELD_USERNAME, recipient_username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, recipient_hash)
        ])
        unread_count = struct.unpack("<H", resp_fields[FIELD_UNREAD_COUNT])[0]
        self.assertGreaterEqual(unread_count, 1)
        resp_code, resp_fields = recipient_client.send_request(REQ_READ_MESSAGES, [
            (FIELD_PAGE_SIZE, struct.pack("<H", 1))
        ])
        self.assertIsNotNone(resp_fields)
        combined_messages = resp_fields.get(FIELD_MESSAGE_CONTENT, b"")
        messages = combined_messages.split(b"||")
        self.assertTrue(any(test_message.encode("utf-8") in m for m in messages))
        recipient_client.close()

    def test_delete_account(self):
        client = TestClient()
        username = "frank"
        pwd = "frankpwd"
        pwd_hash = hash_password(pwd)
        client.send_request(REQ_CREATE_ACCOUNT, [
            (FIELD_USERNAME, username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, pwd_hash)
        ])
        resp_code, resp_fields = client.send_request(REQ_DELETE_ACCOUNT, [])
        self.assertIsNotNone(resp_fields)
        msg = resp_fields.get(FIELD_MESSAGE_CONTENT, b"").decode("utf-8")
        self.assertIn("deleted", msg.lower())
        client.close()

    def test_delete_message(self):
        # Create account, send a message, then delete it.
        client = TestClient()
        username = "george"
        pwd = "georgepwd"
        pwd_hash = hash_password(pwd)
        client.send_request(REQ_CREATE_ACCOUNT, [
            (FIELD_USERNAME, username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, pwd_hash)
        ])
        client.send_request(REQ_LOGIN, [
            (FIELD_USERNAME, username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, pwd_hash)
        ])
        test_message = "Self message for deletion"
        # Send message to self; server now returns a message ID in FIELD_MESSAGE_ID.
        resp_code, resp_fields = client.send_request(REQ_SEND_MESSAGE, [
            (FIELD_SENDER, username.encode("utf-8")),
            (FIELD_RECIPIENT, username.encode("utf-8")),
            (FIELD_MESSAGE_CONTENT, test_message.encode("utf-8"))
        ])
        self.assertIsNotNone(resp_fields)
        self.assertIn(FIELD_MESSAGE_ID, resp_fields)
        msg_id = resp_fields[FIELD_MESSAGE_ID]
        # Now, delete the message using the returned message ID.
        resp_code, resp_fields = client.send_request(REQ_DELETE_MESSAGE, [
            (FIELD_MESSAGE_ID, msg_id)
        ])
        self.assertIsNotNone(resp_fields)
        msg = resp_fields.get(FIELD_MESSAGE_CONTENT, b"").decode("utf-8")
        self.assertTrue("deleted" in msg.lower() or "not found" in msg.lower())
        client.close()

if __name__ == "__main__":
    unittest.main(verbosity=2)
