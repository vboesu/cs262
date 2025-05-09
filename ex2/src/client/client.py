import logging
import math
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

import grpc

from src.common import (
    protocol_pb2_grpc,
    hash_password,
    ListAccountsRequest,
    GenericRequest,
    LoginRequest,
    PaginatedRequest,
    Header,
    MessageRequest,
    DeleteMessagesRequest,
    UnreadMessagesRequest,
)

from .views import PlaceholderEntry

logger = logging.getLogger(__name__)


class Client:
    def __init__(self, host, port):
        self.root = tk.Tk()
        self.token = None
        self.current_user = None
        self.unread_count = 0

        # Connection
        self.host = host
        self.port = port
        self.channel = grpc.insecure_channel(f"{host}:{port}")
        self.stub = protocol_pb2_grpc.BVChatStub(self.channel)
        self.header = Header(login_token=b"")

        # Store messages in a dictionary keyed by message id
        # so we can unify read/unread/pushed messages and reorder them properly.
        self.messages_by_id = {}
        self.messages_per_page = 10
        self.messages_page = 0
        self.is_loading_messages = False
        self.has_more_messages = True

        # By design, read_messages are newest->oldest, unread_messages are oldest->newest
        # We'll unify them by actual timestamp or message id, sorted in descending timestamp
        # so that "newest" is at the top of the UI.
        self.newest_at_top = True  # or False if you prefer newest at the bottom

        self.accounts_page = 1
        self.accounts_per_page = 10
        self.accounts_search = ""
        self.accounts_total_pages = 1  # Initialize total pages

        # UI setup
        self.root.title("CS 262 BVC (Bright-Vincent-Chat)")
        # TODO: self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.streaming_thread = None
        self.streaming_active = False

        # Create frames
        self.login_frame = tk.Frame(self.root)
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

        self.chat_frame = tk.Frame(self.root)
        self.paned_window = tk.PanedWindow(
            self.chat_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED
        )
        self.paned_window.pack(fill=tk.BOTH, expand=1)

        # Left: messages
        self.messages_frame = tk.Frame(self.paned_window)
        self.paned_window.add(self.messages_frame, minsize=400)

        # Right: accounts
        self.accounts_frame = tk.Frame(self.paned_window, width=200)
        self.paned_window.add(self.accounts_frame)

        # Info labels
        self.info_label = tk.Label(self.messages_frame, text="Logged in as: ")
        self.info_label.pack(anchor="w")
        self.unread_label = tk.Label(self.messages_frame, text="Unread messages:")
        self.unread_label.pack(anchor="w")

        # Unread loader
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

        # Treeview
        self.chat_treeview = ttk.Treeview(
            self.messages_frame,
            columns=("id", "message"),
            show="headings",
            selectmode="extended",
        )
        self.chat_treeview.heading("message", text="Messages")
        self.chat_treeview.column("id", width=0, stretch=False)
        self.chat_treeview.column("message", anchor="w")

        self.chat_scrollbar = ttk.Scrollbar(
            self.messages_frame, orient=tk.VERTICAL, command=self.chat_treeview.yview
        )
        self.chat_treeview.configure(yscrollcommand=self.chat_scrollbar.set)
        self.chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_treeview.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Bind a scroll callback
        self.chat_treeview.config(yscrollcommand=self.on_scroll)

        # Delete messages with BackSpace
        self.chat_treeview.bind("<BackSpace>", self.on_delete_key)

        # Send message UI
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

        # Extra
        self.extra_frame = tk.Frame(self.messages_frame)
        self.extra_frame.pack(pady=5)
        self.delete_account_button = tk.Button(
            self.extra_frame, text="Delete Account", command=self.delete_account
        )
        self.delete_account_button.pack(side="left", padx=5)

        # Accounts UI
        self.accounts_title = tk.Label(
            self.accounts_frame, text="Accounts", font=("Helvetica", 14, "bold")
        )
        self.accounts_title.pack(pady=(10, 5))

        self.search_frame = tk.Frame(self.accounts_frame)
        self.search_frame.pack(pady=5, padx=5, fill="x")

        self.search_entry = PlaceholderEntry(
            self.search_frame, placeholder="Search accounts...", width=20
        )
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_button = tk.Button(
            self.search_frame, text="Search", command=self.search_accounts
        )
        self.search_button.pack(side="left", padx=5)

        self.accounts_listbox = tk.Listbox(self.accounts_frame)
        self.accounts_scrollbar = tk.Scrollbar(
            self.accounts_frame, orient=tk.VERTICAL, command=self.accounts_listbox.yview
        )
        self.accounts_listbox.config(yscrollcommand=self.accounts_scrollbar.set)
        self.accounts_listbox.pack(
            side="left", fill="both", expand=True, padx=(5, 0), pady=5
        )
        self.accounts_scrollbar.pack(side="left", fill="y", pady=5)

        self.accounts_listbox.bind("<<ListboxSelect>>", self.on_account_select)

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

        request = LoginRequest(username=username, password_hash=pwd_hash)
        response = self.stub.Register(request)

        if not response.HasField("error"):
            self.token = response.login_token
            self.current_user = username
            self.header.login_token = self.token
            # added
            self.start_listening_for_messages()
            self.show_chat_interface()
            self.update_unread_label()
            # Load read messages (newest first) to fill the view
            self.load_previous_messages_page()
            self.load_accounts_page(1)
        else:
            messagebox.showerror("Error", response.error.message)

    def login(self):
        pass

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return

        pwd_hash = hash_password(password)

        request = LoginRequest(username=username, password_hash=pwd_hash)
        response = self.stub.Login(request)

        if not response.HasField("error"):
            self.token = response.login_token
            self.unread_count = response.unread_count
            self.current_user = username
            self.header.login_token = self.token
            self.start_listening_for_messages()
            self.show_chat_interface()
            self.update_unread_label()
            # Load read messages (newest first) to fill the view
            self.load_previous_messages_page()
            self.load_accounts_page(1)
        else:
            messagebox.showerror("Error", response.error.message)

    def start_listening_for_messages(self):
        """
        Spawns a background thread that calls the streaming RPC
        ListenForMessages, receiving messages in real-time.
        """
        if self.streaming_active:
            return

        self.streaming_active = True

        def listen(self):
            print("STARTING TO LISTEN")
            try:
                request = GenericRequest(header=self.header)
                for message in self.stub.ListenForMessages(request):
                    print("RECEIVED MESSAGE", message)
                    self.update_message_store([message])
                    self.refresh_chat_view()

            except grpc.RpcError as e:
                logger.error(f"ListenForMessages ended: {e}")
            finally:
                self.streaming_active = False

        self.streaming_thread = threading.Thread(
            target=listen, args=(self,), daemon=True
        )
        self.streaming_thread.start()

    # def handle_incoming_message(self, msg):
    #     """
    #     Take the newly arrived message (type = Message), store it,
    #     and refresh the UI on the main thread.
    #     """
    #     # Convert to the same form as the other messages we have in local store
    #     # or you can store it directly. We just need to keep it consistent with
    #     # how 'self.messages_by_id' is used.
    #     # We can do a mini 'to_dict':
    #     fake_id = msg.id
    #     # Create a synthetic object or protocol buffer "Message" for storage:
    #     # or just store it in your dictionary as is
    #     self.messages_by_id[fake_id] = msg

    #     # Because Tkinter is single-threaded, schedule UI updates via .after():
    #     self.root.after(0, self.refresh_chat_view)

    def show_chat_interface(self):
        self.login_frame.pack_forget()
        self.info_label.config(text=f"Logged in as: {self.current_user}")
        self.chat_frame.pack()

    def update_unread_label(self):
        self.unread_label.config(text=f"Unread messages: {self.unread_count}")

    ### MESSAGES & LOADING
    def send_message(self):
        recipient = self.recipient_entry.get().strip()
        content = self.message_entry.get().strip()
        if not recipient or not content:
            messagebox.showerror("Error", "Recipient and message cannot be empty.")
            return

        request = MessageRequest(
            header=self.header, recipient=recipient, content=content
        )
        response = self.stub.SendMessage(request)

        if not response.HasField("error"):
            assert len(response.messages)
            self.update_message_store(response.messages)
            self.refresh_chat_view()
            self.message_entry.delete(0, tk.END)

        else:
            messagebox.showerror("Error", response.error.message)

    def load_unread(self):
        try:
            count = int(self.load_count_entry.get().strip())
            if count <= 0:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Enter a valid number for messages to load.")
            return

        # Load the specified number of unread messages
        self.load_unread_messages(count)

    def load_previous_messages_page(self):
        if not self.has_more_messages or self.is_loading_messages:
            return

        self.is_loading_messages = True
        self.messages_page += 1

        request = GenericRequest(
            header=self.header,
            pagination=PaginatedRequest(
                page=self.messages_page, per_page=self.messages_per_page
            ),
        )
        response = self.stub.GetMessages(request)

        if not response.HasField("error"):
            if len(response.messages):
                self.update_message_store(response.messages)
                self.refresh_chat_view()
            else:
                self.has_more_messages = False

        else:
            messagebox.showerror("Error", response.error.message)

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

        request = UnreadMessagesRequest(header=self.header, count=count)
        response = self.stub.GetUnreadMessages(request)

        if not response.HasField("error"):
            if len(response.messages):
                self.update_message_store(response.messages)
                # unread_count goes down by however many we retrieved
                self.unread_count = max(0, self.unread_count - len(response.messages))
                self.update_unread_label()
                self.refresh_chat_view()

        else:
            messagebox.showerror("Error", response.error.message)

        self.is_loading_messages = False

    ### MERGING & REFRESHING
    def update_message_store(self, incoming_messages):
        """
        Merge `incoming_messages` into our local dictionary,
        keyed by `id`. This ensures no duplicates.
        """
        for msg in incoming_messages:
            self.messages_by_id[msg.id] = msg

    def refresh_chat_view(self):
        """
        Clears the Treeview, sorts self.messages_by_id by actual timestamp,
        and re-renders in the desired order (newest at top if self.newest_at_top).
        """
        # First, extract all messages from the dict
        messages = list(self.messages_by_id.values())

        # Sort by timestamp descending if newest_at_top is True
        # If your timestamps are not string-sortable, parse them or use ID
        # For demonstration, let's do ID descending as a fallback if times are the same
        messages.sort(key=lambda m: (m.timestamp, m.id), reverse=self.newest_at_top)

        # Clear the tree
        for item in self.chat_treeview.get_children():
            self.chat_treeview.delete(item)

        # Now insert items in order
        for msg in messages:
            self.insert_message_into_treeview(msg)

    def insert_message_into_treeview(self, msg):
        """
        Renders one message in the Treeview.
        """
        if msg.sender == self.current_user:
            display_text = f"You to {msg.recipient} ({msg.timestamp}): {msg.content}"
        elif msg.recipient == self.current_user:
            display_text = f"{msg.sender} to you ({msg.timestamp}): {msg.content}"
        else:
            # In the future, if there's a group chat or something else
            display_text = (
                f"{msg.sender} to {msg.recipient} ({msg.timestamp}): {msg.content}"
            )

        # We'll simply insert at "end"; because the list is already sorted
        # in the order we want (descending or ascending).
        self.chat_treeview.insert("", "end", values=(msg.id, display_text))

    ### ACCOUNTS
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
        request = ListAccountsRequest(
            header=self.header,
            pattern=self.accounts_search,
            pagination=PaginatedRequest(page=page, per_page=self.accounts_per_page),
        )
        response = self.stub.ListAccounts(request)

        if not response.HasField("error"):
            accounts = response.accounts
            total_count = response.pagination.total_count
            self.accounts_total_pages = (
                math.ceil(total_count / self.accounts_per_page)
                if self.accounts_per_page > 0
                else 1
            )

            # Clear accounts and re-add
            self.accounts_listbox.delete(0, tk.END)
            for account in accounts:
                self.accounts_listbox.insert(tk.END, account.username)

            # Update pagination buttons
            self.update_accounts_pagination_buttons()
        else:
            messagebox.showerror("Error", response.error.message)

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
            request = GenericRequest(header=self.header)
            response = self.stub.DeleteAccount(request)
            if response.HasField("error"):
                messagebox.showerror("Error", response.error.message)
            else:
                self.on_close()

    # ### EVENT HANDLERS
    # def on_push(self, request: Request):
    #     """
    #     Handle push notifications from the server. Typically new messages
    #     from other users.
    #     """
    #     if "message" in request.data:
    #         new_msg = request.data["message"]
    #         self.update_message_store([new_msg])
    #         self.refresh_chat_view()

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
            # User has scrolled to the bottom, load more messages
            if self.has_more_messages and not self.is_loading_messages:
                self.load_previous_messages_page()

    def on_account_select(self, *args):
        selection = self.accounts_listbox.curselection()
        if selection:
            index = selection[0]
            username = self.accounts_listbox.get(index)
            self.recipient_entry.delete(0, tk.END)
            self.recipient_entry.insert(0, username)

    def on_delete_key(self, *args):
        """
        Handle 'BackSpace' to delete selected messages.
        """
        selected_items = self.chat_treeview.selection()
        if not selected_items:
            return
        confirm = messagebox.askyesno(
            "Delete Messages",
            f"Are you sure you want to delete the selected {len(selected_items)} message(s)?",
        )
        if not confirm:
            return

        message_ids = []
        for item in selected_items:
            mid = self.chat_treeview.item(item, "values")[0]
            message_ids.append(int(mid))

        request = DeleteMessagesRequest(header=self.header, message_ids=message_ids)
        response = self.stub.DeleteMessages(request)

        if not response.HasField("error"):
            # Remove them from local store
            for mid in message_ids:
                self.messages_by_id.pop(mid, None)
            self.refresh_chat_view()

        else:
            messagebox.showerror("Error", response.error.message)

    def on_close(self):
        self.root.destroy()
        # self.socket_handler.close()
