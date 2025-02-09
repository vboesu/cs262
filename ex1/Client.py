import socket
import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext

from src.request import send as _send

import config


def hash_password(password: str) -> bytes:
    """
    Deterministically hash the password using SHA-256.
    Returns a 32-byte digest.
    """
    return hashlib.sha256(password.encode("utf-8")).digest()


class Client:
    def __init__(self, master, sock: socket.socket):
        self.master = master
        self.sock = sock  # the persistent socket connection
        self.token = None
        self.current_user = None
        self.unread_count = 0

        master.title("CS 262 BVC (Bright-Vincent-Chat)")

        # Create Login Frame (first screen)
        self.login_frame = tk.Frame(master)
        self.login_frame.pack(padx=10, pady=10)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, sticky="e")
        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, sticky="e")
        self.username_entry = tk.Entry(self.login_frame)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.username_entry.grid(row=0, column=1)
        self.password_entry.grid(row=1, column=1)

        self.create_button = tk.Button(
            self.login_frame, text="Create Account", command=self.create_account
        )
        self.login_button = tk.Button(
            self.login_frame, text="Login", command=self.login
        )
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
        tk.Label(self.load_frame, text="Load unread messages (count):").pack(
            side="left"
        )
        self.load_count_entry = tk.Entry(self.load_frame, width=5)
        self.load_count_entry.pack(side="left")
        self.load_button = tk.Button(
            self.load_frame, text="Load", command=self.load_messages
        )
        self.load_button.pack(side="left", padx=5)

        # Chat display: scrollable text widget to show messages
        self.chat_display = scrolledtext.ScrolledText(
            self.chat_frame, wrap=tk.WORD, state=tk.DISABLED, width=50, height=15
        )
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
        self.send_button = tk.Button(
            self.input_frame, text="Send", command=self.send_message
        )
        self.send_button.grid(row=1, column=2, padx=5)

        # Extra buttons (for listing accounts and deleting account)
        self.extra_frame = tk.Frame(self.chat_frame)
        self.extra_frame.pack(pady=5)
        self.list_button = tk.Button(
            self.extra_frame, text="List Accounts", command=self.list_accounts
        )
        self.delete_account_button = tk.Button(
            self.extra_frame, text="Delete Account", command=self.delete_account
        )
        self.list_button.pack(side="left", padx=5)
        self.delete_account_button.pack(side="left", padx=5)

    ### HELPER FUNCTIONS
    def send(self, operation: str, data: dict | None = None):
        if self.token:
            if data is None:
                data = {"token": self.token}
            else:
                data["token"] = self.token

        return _send(self.sock, operation=operation, data=data)

    def create_account(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return

        pwd_hash = hash_password(password)

        response = self.send(
            "register", {"username": username, "password_hash": pwd_hash}
        )

        if response.request_code == 100:
            self.token = response.data.get("token")
            self.current_user = username
            self.show_chat_interface()
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return

        pwd_hash = hash_password(password)

        response = self.send("login", {"username": username, "password_hash": pwd_hash})

        if response.request_code == 100:
            self.token = response.data.get("token", None)
            self.current_user = username
            self.unread_count = response.data.get("unread", 0)
            self.show_chat_interface()
            self.update_unread_label()
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

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

        response = self.send("message", {"to": recipient, "content": message_text})

        if response.request_code == 100:
            self.append_chat_message(f"You to {recipient}: {message_text}")
            self.message_entry.delete(0, tk.END)
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

    def load_messages(self):
        try:
            count = int(self.load_count_entry.get().strip())
            if count <= 0:
                raise ValueError()

        except ValueError:
            messagebox.showerror("Error", "Enter a valid number for messages to load.")
            return

        response = self.send("unread_messages", {"per_page": count})

        if response.request_code == 100:
            for message in response.data.get("items", []):
                if message["from"] == self.current_user:
                    self.append_chat_message(
                        f"You to {message['to']}: {message['content']}"
                    )
                elif message["to"] == self.current_user:
                    self.append_chat_message(
                        f"{message['from']} to you: {message['content']}"
                    )
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

        self.unread_count = max(0, self.unread_count - count)
        self.update_unread_label()

    def list_accounts(self):
        pattern = simpledialog.askstring("List Accounts", "Enter search pattern:")
        response = self.send("accounts", {"pattern": pattern})  # todo: paginate

        if response.request_code == 100:
            print("accounts data", response.data)
            for account in response.data.get("items", []):
                # self.append_account(account)
                print(account)
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

    def delete_account(self):
        confirm = messagebox.askyesno(
            "Delete Account",
            "Are you sure you want to delete your account? This action cannot be undone.",
        )
        if confirm:
            response = self.send("delete_account")
            if response.request_code == 100:
                self.master.destroy()
            else:
                messagebox.showerror(
                    f"Error: {response.request_code}",
                    response.data.get("error", "Unknown error."),
                )

    def append_chat_message(self, text):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, text + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)


def main():
    try:
        # Establish a persistent socket connection to the server.
        sock = socket.create_connection((config.HOST, int(config.PORT)))
    except Exception as e:
        print("Failed to connect to server:", e)
        return

    root = tk.Tk()
    app = Client(root, sock)
    root.mainloop()
    # When the UI window closes, close the socket.
    sock.close()


if __name__ == "__main__":
    main()
