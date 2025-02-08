#!/usr/bin/env python3
"""
Client.py – A minimalistic Python UI for our distributed chat application.
This client connects to a centralized server (running on localhost:9000) using our custom wire protocol.
It supports the following operations:
    1. Create an account (username & password)
    2. Login (returns unread message count)
    3. List accounts (with search and pagination)
    4. Send a message (to a specified recipient)
    5. Read unread messages (with pagination)
    6. Delete an account
The UI is built using Tkinter and has two main screens: a login screen and the chat interface.
All messages are sent over TCP using our custom protocol with an 8‐byte header and TLV fields.
"""

import socket
import struct
import hashlib
import time
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext

# --- Protocol Constants ---
HEADER_FORMAT = "<B B H H H"   # version, request_code, flags, checksum, payload_length (little-endian)
HEADER_SIZE = 8

# Request codes (operations)
REQ_CREATE_ACCOUNT = 1
REQ_LOGIN = 2
REQ_LIST_ACCOUNTS = 3
REQ_SEND_MESSAGE = 4
REQ_READ_MESSAGES = 5
REQ_DELETE_MESSAGE = 6
REQ_DELETE_ACCOUNT = 7

# Field IDs (pre-agreed constants)
FIELD_USERNAME         = 1
FIELD_PASSWORD_HASH    = 2
FIELD_MESSAGE_CONTENT  = 3
FIELD_SENDER           = 4
FIELD_RECIPIENT        = 5
FIELD_TIMESTAMP        = 6
FIELD_MESSAGE_ID       = 7  # used to identify messages (e.g. via SHA-256)
FIELD_UNREAD_COUNT     = 8
FIELD_SEARCH_PATTERN   = 9
FIELD_PAGE_NUMBER      = 10
FIELD_PAGE_SIZE        = 11

# --- Helper Functions for the Wire Protocol ---

def compute_checksum(data: bytes) -> int:
    """Compute checksum as the sum of all payload bytes modulo 65536."""
    return sum(data) % 65536

def build_message(request_code: int, fields_bytes: bytes) -> bytes:
    """
    Construct a message by packing the header and appending the payload.
    Header layout (8 bytes):
      - Version (1 byte)  [set to 1]
      - Request code (1 byte)
      - Flags/Status (2 bytes) (reserved for future use; set to 0)
      - Packet checksum (2 bytes) computed on payload bytes
      - Payload length (2 bytes)
    """
    version = 1
    flags = 0
    payload_length = len(fields_bytes)
    checksum = compute_checksum(fields_bytes)
    header = struct.pack(HEADER_FORMAT, version, request_code, flags, checksum, payload_length)
    return header + fields_bytes

def encode_field(field_id: int, field_value: bytes) -> bytes:
    """
    Encode one TLV field.
    Field format: Field ID (1 byte) + Field Length (2 bytes, little-endian) + Field Value.
    """
    return struct.pack("<B H", field_id, len(field_value)) + field_value

def encode_fields(fields: list) -> bytes:
    """
    Encode a list of TLV fields.
    Each element in 'fields' should be a tuple: (field_id, field_value)
    """
    encoded = b""
    for fid, fvalue in fields:
        encoded += encode_field(fid, fvalue)
    return encoded

def hash_password(password: str) -> bytes:
    """
    Deterministically hash the password using SHA-256.
    Returns a 32-byte digest.
    """
    return hashlib.sha256(password.encode("utf-8")).digest()

def parse_message(sock: socket.socket) -> tuple:
    """
    Read a complete message from the socket.
    Returns a tuple (request_code, payload bytes) or None if connection is closed.
    """
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
        print("Checksum error")
        return None
    return req_code, payload

def decode_fields(payload: bytes) -> dict:
    """
    Decode the TLV fields from the payload.
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

# --- Client UI Code (Tkinter) ---

class ChatClientApp:
    def __init__(self, master, sock: socket.socket):
        self.master = master
        self.sock = sock  # the persistent socket connection
        self.current_user = None
        self.unread_count = 0

        master.title("Simple Chat Client")

        # Create Login Frame (first screen)
        self.login_frame = tk.Frame(master)
        self.login_frame.pack(padx=10, pady=10)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, sticky="e")
        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, sticky="e")
        self.username_entry = tk.Entry(self.login_frame)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.username_entry.grid(row=0, column=1)
        self.password_entry.grid(row=1, column=1)

        self.create_button = tk.Button(self.login_frame, text="Create Account", command=self.create_account)
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.create_button.grid(row=2, column=0, pady=5)
        self.login_button.grid(row=2, column=1, pady=5)

        # Create Chat Frame (hidden until login/account creation succeeds)
        self.chat_frame = tk.Frame(master)

        # Info label: shows logged in user and unread count
        self.info_label = tk.Label(self.chat_frame, text="Logged in as: ")
        self.info_label.pack(anchor="w")
        self.unread_label = tk.Label(self.chat_frame, text="Unread messages: 0")
        self.unread_label.pack(anchor="w")

        # Unread messages loading: user specifies number of messages to load
        self.load_frame = tk.Frame(self.chat_frame)
        self.load_frame.pack(pady=5, fill="x")
        tk.Label(self.load_frame, text="Load unread messages (count):").pack(side="left")
        self.load_count_entry = tk.Entry(self.load_frame, width=5)
        self.load_count_entry.pack(side="left")
        self.load_button = tk.Button(self.load_frame, text="Load", command=self.load_messages)
        self.load_button.pack(side="left", padx=5)

        # Chat display: scrollable text widget to show messages
        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, state=tk.DISABLED, width=50, height=15)
        self.chat_display.pack(padx=10, pady=10)

        # Input frame for sending messages
        self.input_frame = tk.Frame(self.chat_frame)
        self.input_frame.pack(padx=10, pady=10, fill="x")
        tk.Label(self.input_frame, text="Recipient:").grid(row=0, column=0, sticky="e")
        tk.Label(self.input_frame, text="Message:").grid(row=1, column=0, sticky="e")
        self.recipient_entry = tk.Entry(self.input_frame)
        self.message_entry = tk.Entry(self.input_frame, width=40)
        self.recipient_entry.grid(row=0, column=1, sticky="w")
        self.message_entry.grid(row=1, column=1, sticky="w")
        self.send_button = tk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=2, padx=5)

        # Extra buttons (for listing accounts and deleting account)
        self.extra_frame = tk.Frame(self.chat_frame)
        self.extra_frame.pack(pady=5)
        self.list_button = tk.Button(self.extra_frame, text="List Accounts", command=self.list_accounts)
        self.delete_account_button = tk.Button(self.extra_frame, text="Delete Account", command=self.delete_account)
        self.list_button.pack(side="left", padx=5)
        self.delete_account_button.pack(side="left", padx=5)

    def send_request(self, request_code: int, fields: list) -> tuple:
        """
        Helper method to build a message using our protocol,
        send it via our socket, and return the response.
        """
        message = build_message(request_code, encode_fields(fields))
        self.sock.sendall(message)
        response = parse_message(self.sock)
        if response is None:
            messagebox.showerror("Error", "No response from server.")
            return None, None
        resp_code, payload = response
        return resp_code, decode_fields(payload)

    def create_account(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return
        pwd_hash = hash_password(password)
        resp_code, resp_fields = self.send_request(REQ_CREATE_ACCOUNT, [
            (FIELD_USERNAME, username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, pwd_hash)
        ])
        if resp_fields and FIELD_MESSAGE_CONTENT in resp_fields:
            msg = resp_fields[FIELD_MESSAGE_CONTENT].decode("utf-8")
            if "created" in msg.lower():
                self.current_user = username
                self.show_chat_interface()
            messagebox.showinfo("Response", msg)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return
        pwd_hash = hash_password(password)
        resp_code, resp_fields = self.send_request(REQ_LOGIN, [
            (FIELD_USERNAME, username.encode("utf-8")),
            (FIELD_PASSWORD_HASH, pwd_hash)
        ])
        if resp_fields:
            # Check if an error message is returned
            if FIELD_MESSAGE_CONTENT in resp_fields:
                msg = resp_fields[FIELD_MESSAGE_CONTENT].decode("utf-8")
                if "incorrect" in msg.lower() or "does not exist" in msg.lower():
                    messagebox.showerror("Error", msg)
                    return
            if FIELD_UNREAD_COUNT in resp_fields:
                unread_count = struct.unpack("<H", resp_fields[FIELD_UNREAD_COUNT])[0]
                self.current_user = username
                self.unread_count = unread_count
                self.show_chat_interface()
                self.update_unread_label()
        else:
            messagebox.showerror("Error", "No response from server.")

    def show_chat_interface(self):
        # Hide login frame and display chat frame.
        self.login_frame.pack_forget()
        self.info_label.config(text=f"Logged in as: {self.current_user}")
        self.chat_frame.pack()

    def update_unread_label(self):
        self.unread_label.config(text=f"Unread messages: {self.unread_count}")

    def send_message(self):
        recipient = self.recipient_entry.get().strip()
        message_text = self.message_entry.get().strip()
        if not recipient or not message_text:
            messagebox.showerror("Error", "Recipient and message cannot be empty.")
            return
        # For sending, we include the sender, recipient, and message content.
        resp_code, resp_fields = self.send_request(REQ_SEND_MESSAGE, [
            (FIELD_SENDER, self.current_user.encode("utf-8")),
            (FIELD_RECIPIENT, recipient.encode("utf-8")),
            (FIELD_MESSAGE_CONTENT, message_text.encode("utf-8"))
        ])
        if resp_fields and FIELD_MESSAGE_CONTENT in resp_fields:
            msg = resp_fields[FIELD_MESSAGE_CONTENT].decode("utf-8")
            # Optionally, retrieve and display the returned message ID if needed.
            self.append_chat_message(f"You to {recipient}: {message_text}")
            messagebox.showinfo("Info", msg)
            self.message_entry.delete(0, tk.END)

    def load_messages(self):
        try:
            count = int(self.load_count_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Enter a valid number for messages to load.")
            return
        resp_code, resp_fields = self.send_request(REQ_READ_MESSAGES, [
            (FIELD_PAGE_SIZE, struct.pack("<H", count))
        ])
        if resp_fields and FIELD_MESSAGE_CONTENT in resp_fields:
            combined = resp_fields[FIELD_MESSAGE_CONTENT]
            # Our simple encoding uses "||" as a separator between composite message objects.
            messages = combined.split(b"||")
            for m in messages:
                if m:
                    # In a real app, you’d decode the composite TLV object; here we simply display the raw text
                    try:
                        # Attempt to extract the inner message content from the composite object
                        inner_fields = decode_fields(m)
                        if FIELD_MESSAGE_CONTENT in inner_fields:
                            content = inner_fields[FIELD_MESSAGE_CONTENT].decode("utf-8")
                        else:
                            content = m.decode("utf-8", errors="ignore")
                    except Exception:
                        content = m.decode("utf-8", errors="ignore")
                    self.append_chat_message(content)
            self.unread_count = max(0, self.unread_count - count)
            self.update_unread_label()

    def list_accounts(self):
        pattern = simpledialog.askstring("List Accounts", "Enter search pattern:")
        if pattern is None:
            return
        try:
            page_num = int(simpledialog.askstring("Page Number", "Enter page number (starting from 1):"))
            page_size = int(simpledialog.askstring("Page Size", "Enter page size:"))
        except (TypeError, ValueError):
            messagebox.showerror("Error", "Invalid page number or size.")
            return
        resp_code, resp_fields = self.send_request(REQ_LIST_ACCOUNTS, [
            (FIELD_SEARCH_PATTERN, pattern.encode("utf-8")),
            (FIELD_PAGE_NUMBER, struct.pack("<H", page_num)),
            (FIELD_PAGE_SIZE, struct.pack("<H", page_size))
        ])
        if resp_fields and FIELD_MESSAGE_CONTENT in resp_fields:
            accounts_str = resp_fields[FIELD_MESSAGE_CONTENT].decode("utf-8")
            messagebox.showinfo("Accounts", accounts_str)

    def delete_account(self):
        confirm = messagebox.askyesno("Delete Account", "Are you sure you want to delete your account? This action cannot be undone.")
        if confirm:
            resp_code, resp_fields = self.send_request(REQ_DELETE_ACCOUNT, [])
            if resp_fields and FIELD_MESSAGE_CONTENT in resp_fields:
                msg = resp_fields[FIELD_MESSAGE_CONTENT].decode("utf-8")
                messagebox.showinfo("Response", msg)
                self.master.destroy()

    def append_chat_message(self, text):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, text + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

def main():
    HOST = "127.0.0.1"
    PORT = 9000
    try:
        # Establish a persistent socket connection to the server.
        sock = socket.create_connection((HOST, PORT))
    except Exception as e:
        print("Failed to connect to server:", e)
        return

    root = tk.Tk()
    app = ChatClientApp(root, sock)
    root.mainloop()
    # When the UI window closes, close the socket.
    sock.close()

if __name__ == "__main__":
    main()
