import logging
import math
import queue
import selectors
import socket
import threading
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable

from src.lib import OP_TO_CODE
from src.request import (
    Request,
    REQUEST_ERROR_CODE,
    REQUEST_PUSH_CODE,
    REQUEST_SUCCESS_CODE,
    push,
    send as _send,
)

import config

# Set up logging
logging.basicConfig(
    format="%(module)s %(asctime)s %(funcName)s:%(lineno)d %(levelname)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


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


class SocketHandler:
    def __init__(self, sock: socket.socket, push_handler: Callable):
        self.sock = sock

        # Default data to be transmitted with each request
        self.default_data = {}
        self.req_id = 1

        # Initialize locks
        self.req_id_lock = threading.Lock()
        self.pending_lock = threading.Lock()

        # Initialize queues
        self.pending: dict[int, queue.Queue] = {}
        self.push_queue = queue.Queue()

        # Set up push handling
        self.push_handler = push_handler

        # Start listening
        self.lthread = threading.Thread(target=self.listen, daemon=True)
        self.lthread.start()

        self.pthread = threading.Thread(target=self.receive_push, daemon=True)
        self.pthread.start()

    def listen(self):
        """
        Listen to all data coming from the server to the socket `sock`,
        interpret it as a `Request` and direct it either to a queue of
        push notifications (if no `request_id` is provided) or to a queue
        corresponding to the thread waiting for this response.
        """
        try:
            while True:
                req = Request.receive(self.sock)
                if req.request_id == 0:
                    # Any request that does not have a request_id is assumed
                    # to be a push from the server
                    self.push_queue.put(req)
                else:
                    # Someone is waiting for this response (hopefully), so let's
                    # give it to them!
                    with self.pending_lock:
                        target_queue = self.pending.pop(req.request_id, None)

                    if not target_queue:
                        logging.info(f"Got response with unknown request_id: {req}")
                        continue

                    target_queue.put(req)

        except OSError as e:
            logging.error("Lost connection to the server: %s", str(e))

        except Exception as e:
            logging.error("%s: %s", e.__class__.__name__, str(e))

        finally:
            logging.info("Closing connection to the server.")
            self.lthread = None  # basically: remove self after finishing
            self.close()

    def receive_push(self):
        """
        Wait for `listen` to add something to the `push_queue`, then
        trigger the `push_handler` with the request that came in.
        """
        while True:
            req = self.push_queue.get()
            self.push_handler(req)

    def send(
        self, operation: str, data: dict | None = None, timeout: int = 30
    ) -> queue.Queue[Request]:
        """
        Send a request to the server over the socket, specifying
        the operation and data to be transmitted. Automatically generates
        a `request_id` to be sent to the server for identification of
        the response.

        Parameters
        ----------
        operation : str
            Name of the operation requested on the server
        data : dict, optional
            Key-value pairs with data. To this, the `default_data` of the
            `SocketHandler` is added, by default None
        timeout : int, optional
            Timeout for request in seconds, by default 30

        Returns
        -------
        queue.Queue
            Queue which will contain the response from the server, once received.
        """
        if operation not in OP_TO_CODE:
            raise ValueError(f"Unknown operation: {operation}")

        # Generate (sort of) unique request ID
        req_id = 0
        with self.req_id_lock:
            self.req_id = (self.req_id % 65536) + 1
            req_id = self.req_id

        # Prepare request data
        if data is None and self.default_data:
            data = self.default_data
        elif data is not None:
            data = {**self.default_data, **data}  # `data` should overwrite

        # Create request object
        req = Request(OP_TO_CODE[operation], data, req_id)

        # Prepare response queue
        response_queue = queue.Queue()

        with self.pending_lock:
            self.pending[req_id] = response_queue

        # Push request to server
        push(self.sock, req)

        return response_queue

    def close(self):
        """
        Clean-up of threads and socket.
        """
        # Close the socket
        try:
            self.sock.close()
        except Exception as e:
            logging.error("%s: %s", e.__class__.__name__, str(e))

        if self.lthread is not None:
            self.lthread.join(timeout=1)

        if self.pthread is not None:
            self.pthread.join(timeout=1)


class Client:
    def __init__(self, master, sock: socket.socket):
        self.master = master
        self.token = None
        self.current_user = None
        self.unread_count = 0

        # Connection
        self.sock = sock  # the persistent socket connection
        self.socket_handler = SocketHandler(sock, self.on_push)

        # Pagination attributes
        self.messages_offset = 0
        self.messages_per_page = 10
        self.is_loading_messages = False
        self.has_more_messages = True

        self.accounts_page = 1
        self.accounts_per_page = 10
        self.accounts_search = ""
        self.accounts_total_pages = 1  # Initialize total pages

        self.master.title("CS 262 BVC (Bright-Vincent-Chat)")
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

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

        # Chat display: Treeview widget to show messages
        self.chat_treeview = ttk.Treeview(
            self.messages_frame,
            columns=("id", "message"),
            show="headings",
            selectmode="extended",
        )
        self.chat_treeview.heading("message", text="Messages")
        self.chat_treeview.column("id", width=0, stretch=False)  # Hidden column
        self.chat_treeview.column("message", anchor="w")

        # Add vertical scrollbar to Treeview
        self.chat_scrollbar = ttk.Scrollbar(
            self.messages_frame, orient=tk.VERTICAL, command=self.chat_treeview.yview
        )
        self.chat_treeview.configure(yscrollcommand=self.chat_scrollbar.set)
        self.chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_treeview.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Bind the yscrollcommand to a custom method for scroll detection
        self.chat_treeview.config(yscrollcommand=self.on_scroll)

        # Bind the delete key to the delete handler
        self.chat_treeview.bind("<BackSpace>", self.on_delete_key)

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

        # Bind the selection event to handler
        self.accounts_listbox.bind("<<ListboxSelect>>", self.on_account_select)

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
    def create_account(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return

        pwd_hash = hash_password(password)

        req_data = {"username": username, "password_hash": pwd_hash}
        response = self.socket_handler.send("register", req_data).get()

        if response.request_code == 100:
            self.token = response.data.get("token")
            self.current_user = username
            self.socket_handler.default_data["token"] = self.token
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

        req_data = {"username": username, "password_hash": pwd_hash}
        response = self.socket_handler.send("login", req_data).get()

        if response.request_code == 100:
            self.token = response.data.get("token", None)
            self.current_user = username
            self.unread_count = response.data.get("unread", 0)
            self.socket_handler.default_data["token"] = self.token
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

        req_data = {"to": recipient, "content": message_text}
        response = self.socket_handler.send("message", req_data).get()

        if response.request_code == 100:
            message = response.data.get("message")
            assert message is not None
            self.prepend_chat_message(message)
            self.message_entry.delete(0, tk.END)
            self.messages_offset += 1  # keep track of this message
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

        req_data = {"page": page, "per_page": self.messages_per_page}
        response = self.socket_handler.send("read_messages", req_data).get()

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

                self.append_chat_message(message)

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
        """
        Load a specified number of messages that were sent to us
        while we were not online.

        Parameters
        ----------
        count : int, optional
            Number of undelivered messages to load, by default 1
        """
        self.is_loading_messages = True

        req_data = {"per_page": count}
        response = self.socket_handler.send("unread_messages", req_data).get()

        if response.request_code == 100:
            messages = response.data.get("items", [])
            if not messages:
                self.is_loading_messages = False
                return

            for message in messages:
                self.prepend_chat_message(message)

            self.unread_count -= len(messages)
            self.messages_offset += len(messages)
            self.update_unread_label()
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

        self.is_loading_messages = False

    def search_accounts(self):
        pattern = self.search_entry.get().strip()
        if (
            pattern == self.search_entry.placeholder
            and self.search_entry["fg"] == self.search_entry.placeholder_color
        ):
            pattern = ""
        self.accounts_search = pattern
        self.accounts_page = 1
        self.load_accounts_page(1)

    def load_accounts_page(self, page: int):
        req_data = {
            "pattern": self.accounts_search,
            "page": page,
            "per_page": self.accounts_per_page,
        }
        response = self.socket_handler.send("accounts", req_data).get()

        if response.request_code == 100:
            accounts = response.data.get("items", [])
            total_count = response.data.get("total_count", 0)
            self.accounts_total_pages = (
                math.ceil(total_count / self.accounts_per_page)
                if self.accounts_per_page > 0
                else 1
            )

            # Clear accounts and re-add
            self.accounts_listbox.delete(0, tk.END)
            for account in accounts:
                self.accounts_listbox.insert(tk.END, account["username"])

            # Update pagination buttons
            self.update_accounts_pagination_buttons()
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

    def update_accounts_pagination_buttons(self):
        # Disable "Previous" button if on first page
        if self.accounts_page <= 1:
            self.prev_accounts_button.config(state=tk.DISABLED)
        else:
            self.prev_accounts_button.config(state=tk.NORMAL)

        # Disable "Next" button if on last page
        if self.accounts_page >= self.accounts_total_pages:
            self.next_accounts_button.config(state=tk.DISABLED)
        else:
            self.next_accounts_button.config(state=tk.NORMAL)

    def prev_accounts_page(self):
        if self.accounts_page > 1:
            self.accounts_page -= 1
            self.load_accounts_page(self.accounts_page)

    def next_accounts_page(self):
        if self.accounts_page < self.accounts_total_pages:
            self.accounts_page += 1
            self.load_accounts_page(self.accounts_page)

    def delete_account(self):
        confirm = messagebox.askyesno(
            "Delete Account",
            "Are you sure you want to delete your account? This action cannot be undone.",
        )
        if confirm:
            response = self.socket_handler.send("delete_account").get()
            if response.request_code == 100:
                self.on_close()
            else:
                messagebox.showerror(
                    f"Error: {response.request_code}",
                    response.data.get("error", "Unknown error."),
                )

    def append_chat_message(self, message: dict):
        """
        Append a message to the end of the Treeview.
        """
        if message["from"] == self.current_user:
            display_text = (
                f"You to {message['to']} ({message['timestamp']}): {message['content']}"
            )
        elif message["to"] == self.current_user:
            display_text = f"{message['from']} to you ({message['timestamp']}): {message['content']}"

        self.chat_treeview.insert("", "end", values=(message["id"], display_text))
        # self.chat_treeview.yview_moveto(1.0)  # Scroll to the bottom

    def prepend_chat_message(self, message: dict):
        """
        Prepend a message to the beginning of the Treeview.
        """
        if message["from"] == self.current_user:
            display_text = (
                f"You to {message['to']} ({message['timestamp']}): {message['content']}"
            )
        elif message["to"] == self.current_user:
            display_text = f"{message['from']} to you ({message['timestamp']}): {message['content']}"

        self.chat_treeview.insert("", "0", values=(message["id"], display_text))
        self.chat_treeview.yview_moveto(0.0)  # Scroll to the top

    ### EVENT HANDLERS
    def on_push(self, request: Request):
        """
        Handle push notifications from the server. For now,
        this is just incoming messages.

        Parameters
        ----------
        request : Request
            Request pushed from the server
        """
        if "message" in request.data:
            self.prepend_chat_message(request.data["message"])

    def on_scroll(self, first, last):
        """
        Event handler for scroll in the messages box, used for
        infinite scroll of previous messages.
        """
        try:
            last_float = float(last)
        except ValueError:
            return

        if last_float >= 1.0:
            # User has scrolled to the bottom, load next page of messages
            if self.has_more_messages and not self.is_loading_messages:
                next_page = (self.messages_offset // self.messages_per_page) + 1
                self.load_previous_messages_page(next_page)

    def on_account_select(self, *args):
        """
        Event handler for when an account is selected in the accounts listbox.
        Automatically inputs the selected account's username into the recipient entry field.
        """
        # Get the index of the selected item
        selection = self.accounts_listbox.curselection()
        if selection:
            index = selection[0]
            username = self.accounts_listbox.get(index)
            # Insert the username into the recipient entry
            self.recipient_entry.delete(0, tk.END)
            self.recipient_entry.insert(0, username)

    def on_delete_key(self, *args):
        """
        Handler for the Delete key to delete selected messages.
        """
        selected_items = self.chat_treeview.selection()
        if not selected_items:
            return  # No selection to delete

        confirm = messagebox.askyesno(
            "Delete Messages",
            f"Are you sure you want to delete the selected {len(selected_items)} message(s)?",
        )
        if not confirm:
            return

        message_ids = []
        for item in selected_items:
            message_id = self.chat_treeview.item(item, "values")[0]
            message_ids.append(int(message_id))

        # Send delete request to the server
        req_data = {"messages": message_ids}
        response = self.socket_handler.send("delete_messages", req_data).get()

        if response.request_code == 100:
            # Deletion successful, remove items from Treeview
            for item in selected_items:
                self.chat_treeview.delete(item)
            messagebox.showinfo("Success", "Selected messages have been deleted.")
        else:
            messagebox.showerror(
                f"Error: {response.request_code}",
                response.data.get("error", "Unknown error."),
            )

    def on_close(self):
        """
        Clean up sockets, threads, and windows.
        """
        self.master.destroy()
        self.socket_handler.close()


def main():
    root = tk.Tk()
    root.geometry("900x600")  # default window size

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((config.HOST, int(config.PORT)))
        app = Client(root, sock)
        root.mainloop()


if __name__ == "__main__":
    main()
