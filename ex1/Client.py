from datetime import datetime
import socket
import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext

from src.lib import TIMESTAMP_FORMAT
from src.request import send as _send

import config


### HELPER FUNCTIONS
def hash_password(password: str) -> bytes:
    """
    Deterministically hash the password using SHA-256.
    Returns a 32-byte digest.
    """
    return hashlib.sha256(password.encode("utf-8")).digest()


### CUSTOM VIEW ELEMENTS
class PlaceholderEntry(tk.Entry):
    """
    A subclass of tk.Entry that includes placeholder text functionality.
    """

    def __init__(self, master=None, placeholder="PLACEHOLDER", color="grey", **kwargs):
        super().__init__(master, **kwargs)

        self.placeholder = placeholder
        self.placeholder_color = color
        self.default_fg_color = self["fg"]

        self.bind("<FocusIn>", self.foc_in)
        self.bind("<FocusOut>", self.foc_out)

        self.put_placeholder()

    def put_placeholder(self):
        """Insert placeholder text and set the color to placeholder color."""
        self.insert(0, self.placeholder)
        self["fg"] = self.placeholder_color

    def foc_in(self, *args):
        """Remove placeholder text when focus is gained."""
        if self["fg"] == self.placeholder_color:
            self.delete("0", "end")
            self["fg"] = self.default_fg_color

    def foc_out(self, *args):
        """Re-insert placeholder text if entry is empty when focus is lost."""
        if not self.get():
            self.put_placeholder()


class Client:
    def __init__(self, master, sock: socket.socket):
        self.master = master
        self.sock = sock  # the persistent socket connection
        self.token = None
        self.current_user = None
        self.unread_count = 0

        # Pagination attributes
        self.messages_offset = 0
        self.messages_per_page = 2
        self.is_loading_messages = False
        self.has_more_messages = True

        self.accounts_page = 1
        self.accounts_per_page = 10
        self.accounts_search = ""

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

        # Use PanedWindow to split left and right panes
        self.paned_window = tk.PanedWindow(
            self.chat_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED
        )
        self.paned_window.pack(fill=tk.BOTH, expand=1)

        # Left pane for messages
        self.messages_frame = tk.Frame(self.paned_window)
        self.paned_window.add(self.messages_frame, minsize=400)

        # Right pane for accounts
        self.accounts_frame = tk.Frame(self.paned_window, width=200)
        self.paned_window.add(self.accounts_frame)

        # ---------------------- Messages Pane ----------------------

        # Info label: shows logged in user and unread count
        self.info_label = tk.Label(self.messages_frame, text="Logged in as: ")
        self.info_label.pack(anchor="w")
        self.unread_label = tk.Label(self.messages_frame, text="Unread messages: 0")
        self.unread_label.pack(anchor="w")

        # Unread messages loading: user specifies number of messages to load
        self.load_frame = tk.Frame(self.messages_frame)
        self.load_frame.pack(pady=5, fill="x")
        tk.Label(self.load_frame, text="Load unread messages (count):").pack(
            side="left"
        )
        self.load_count_entry = tk.Entry(self.load_frame, width=5)
        self.load_count_entry.pack(side="left")
        self.load_button = tk.Button(
            self.load_frame, text="Load", command=self.load_unread
        )
        self.load_button.pack(side="left", padx=5)

        # Chat display: scrollable text widget to show messages
        self.chat_display = scrolledtext.ScrolledText(
            self.messages_frame, wrap=tk.WORD, state=tk.DISABLED, width=50, height=15
        )
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Bind the yscrollcommand to a custom method for scroll detection
        self.chat_display.config(yscrollcommand=self.on_scroll)

        # Input frame for sending messages
        self.input_frame = tk.Frame(self.messages_frame)
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

        # Extra buttons (for deleting account)
        self.extra_frame = tk.Frame(self.messages_frame)
        self.extra_frame.pack(pady=5)
        self.delete_account_button = tk.Button(
            self.extra_frame, text="Delete Account", command=self.delete_account
        )
        self.delete_account_button.pack(side="left", padx=5)

        # ---------------------- Accounts Pane ----------------------

        # Title for Accounts Pane
        self.accounts_title = tk.Label(
            self.accounts_frame, text="Accounts", font=("Helvetica", 14, "bold")
        )
        self.accounts_title.pack(pady=(10, 5))

        # Search bar
        self.search_frame = tk.Frame(self.accounts_frame)
        self.search_frame.pack(pady=5, padx=5, fill="x")

        # Use PlaceholderEntry for search with placeholder text
        self.search_entry = PlaceholderEntry(
            self.search_frame, placeholder="Search accounts...", width=20
        )
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_button = tk.Button(
            self.search_frame, text="Search", command=self.search_accounts
        )
        self.search_button.pack(side="left", padx=5)

        # Accounts list
        self.accounts_listbox = tk.Listbox(self.accounts_frame)
        self.accounts_scrollbar = tk.Scrollbar(
            self.accounts_frame, orient=tk.VERTICAL, command=self.accounts_listbox.yview
        )
        self.accounts_listbox.config(yscrollcommand=self.accounts_scrollbar.set)
        self.accounts_listbox.pack(
            side="left", fill="both", expand=True, padx=(5, 0), pady=5
        )
        self.accounts_scrollbar.pack(side="left", fill="y", pady=5)

        # Pagination controls for accounts (moved below the list view)
        self.accounts_pagination_frame = tk.Frame(self.accounts_frame)
        self.accounts_pagination_frame.pack(pady=5)

        self.prev_accounts_button = tk.Button(
            self.accounts_pagination_frame,
            text="Previous",
            command=self.prev_accounts_page,
        )
        self.prev_accounts_button.pack(side="left", padx=5)

        self.next_accounts_button = tk.Button(
            self.accounts_pagination_frame, text="Next", command=self.next_accounts_page
        )
        self.next_accounts_button.pack(side="left", padx=5)

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
            self.update_unread_label()
            self.load_previous_messages_page(1)
            self.load_accounts_page(1)
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
            self.load_previous_messages_page(1)
            self.load_accounts_page(1)
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
            self.prepend_chat_message(
                f"You to {recipient} ({datetime.utcnow().strftime(TIMESTAMP_FORMAT)}): {message_text}"
            )
            self.message_entry.delete(0, tk.END)
            self.messages_offset += 1  # keep track of this message
            # Optionally, refresh messages
            # self.load_messages_page(self.messages_page)
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

    def load_unread(self):
        try:
            count = int(self.load_count_entry.get().strip())
            if count <= 0:
                raise ValueError()

        except ValueError:
            messagebox.showerror("Error", "Enter a valid number for messages to load.")
            return

        # Reset to first page when loading specific count
        self.load_unread_messages(count)

    def load_previous_messages_page(self, page: int = 1):
        if not self.has_more_messages or self.is_loading_messages:
            return

        self.is_loading_messages = True

        response = self.send(
            "read_messages", {"page": page, "per_page": self.messages_per_page}
        )

        if response.request_code == 100:
            messages = response.data.get("items", [])
            if not messages:
                self.has_more_messages = False
                self.is_loading_messages = False
                return

            # Figure out where this page is supposed to start.
            # The reason we need to do this is that we may have
            # sent or received individual messages in-between loading
            # of previous messages, and so the pages of the last load
            # do not necessarily correspond to the pages of the current load
            page_offset = (page - 1) * self.messages_per_page
            for message in messages:
                # skip until we get to new messages
                if page_offset < self.messages_offset:
                    page_offset += 1
                    continue

                if message["from"] == self.current_user:
                    display_text = f"You to {message['to']} ({message['timestamp']}): {message['content']}"
                elif message["to"] == self.current_user:
                    display_text = f"{message['from']} to you ({message['timestamp']}): {message['content']}"
                self.append_chat_message(display_text)

            self.messages_offset += len(messages)

            # Determine if there are more messages to load
            if len(messages) < self.messages_per_page:
                self.has_more_messages = False
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

        self.is_loading_messages = False

    def load_unread_messages(self, count: int = 1):
        self.is_loading_messages = True

        response = self.send("unread_messages", {"per_page": count})

        if response.request_code == 100:
            messages = response.data.get("items", [])
            if not messages:
                self.is_loading_messages = False
                return

            for message in messages:
                if message["from"] == self.current_user:
                    display_text = f"You to {message['to']} ({message['timestamp']}): {message['content']}"
                elif message["to"] == self.current_user:
                    display_text = f"{message['from']} to you ({message['timestamp']}): {message['content']}"
                self.prepend_chat_message(display_text)

            self.unread_count -= len(messages)
            self.messages_offset += len(messages)
            self.update_unread_label()
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

        self.is_loading_messages = False

    def on_scroll(self, first, last):
        try:
            first_float = float(first)
            last_float = float(last)
        except ValueError:
            return

        if last_float >= 1.0:
            # User has scrolled to the bottom, load next page of messages
            if self.has_more_messages and not self.is_loading_messages:
                next_page = (self.messages_offset // self.messages_per_page) + 1
                print("loading next messages", self.messages_offset, next_page)
                self.load_previous_messages_page(next_page)

        # Update the scrollbar position
        self.chat_display.yview_moveto(first)

    def search_accounts(self):
        pattern = self.search_entry.get().strip()
        self.accounts_search = pattern
        self.accounts_page = 1
        self.load_accounts_page(self.accounts_page)

    def load_accounts_page(self, page: int):
        response = self.send(
            "accounts",
            {
                "pattern": self.accounts_search,
                "page": page,
                "per_page": self.accounts_per_page,
            },
        )

        if response.request_code == 100:
            accounts = response.data.get("items", [])
            self.accounts_listbox.delete(0, tk.END)
            for account in accounts:
                self.accounts_listbox.insert(tk.END, account["username"])
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

    def prev_accounts_page(self):
        if self.accounts_page > 1:
            self.accounts_page -= 1
            self.load_accounts_page(self.accounts_page)

    def next_accounts_page(self):
        self.accounts_page += 1
        self.load_accounts_page(self.accounts_page)

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

    def append_chat_message(self, text: str):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"{text}\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def prepend_chat_message(self, text: str):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(1.0, f"{text}\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(1.0)


def main():
    try:
        # Establish a persistent socket connection to the server.
        sock = socket.create_connection((config.HOST, int(config.PORT)))
    except Exception as e:
        print("Failed to connect to server:", e)
        return

    root = tk.Tk()
    root.geometry("900x600")  # default window size
    app = Client(root, sock)
    root.mainloop()
    # When the UI window closes, close the socket.
    sock.close()


if __name__ == "__main__":
    main()
