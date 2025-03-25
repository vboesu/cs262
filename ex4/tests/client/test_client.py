import pytest
import tkinter as tk
from copy import copy

from src.client import Client
from src.common import OP_TO_CODE, RequestCode, hash_password


### DUMMIES
class DummyQueue:
    def get(self, timeout=None):
        class DummyResponse:
            request_code = RequestCode.success
            data = {}

        return DummyResponse()


### FIXTURES
@pytest.fixture
def client():
    remote_hosts = [("127.0.0.1", 8000), ("127.0.0.1", 8001)]
    client = Client("127.0.0.1", remote_hosts.copy())
    client.root.withdraw()  # hide window

    yield client

    # in case the window has not been destroyed yet
    try:
        client.root.destroy()

    except Exception:
        pass


### TEST REQUESTS
def test_create_account_sends_register_request(client):
    send_calls = []

    def fake_send(remote_hosts, op_code, data, await_response=True):
        # Record the call parameters.
        send_calls.append((remote_hosts.copy(), op_code, data, await_response))
        return (remote_hosts[0], DummyQueue())

    client.sh.send = fake_send

    # Set valid username and password.
    client.username_entry.delete(0, tk.END)
    client.username_entry.insert(0, "testuser")
    client.password_entry.delete(0, tk.END)
    client.password_entry.insert(0, "password")

    client.create_account()

    # Ensure that a "register" request was sent.
    assert len(send_calls) >= 1, "No request sent"
    _, op_code, data, _ = send_calls[0]
    assert op_code == OP_TO_CODE["register"]
    expected_data = {"username": "testuser", "password_hash": hash_password("password")}
    assert data == expected_data


def test_create_account_empty_fields_does_not_send(client, monkeypatch):
    send_calls = []

    def fake_send(remote_hosts, op_code, data, await_response=True):
        send_calls.append((remote_hosts.copy(), op_code, data, await_response))
        return (remote_hosts[0], DummyQueue())

    client.sh.send = fake_send

    # Leave username and password empty.
    client.username_entry.delete(0, tk.END)
    client.password_entry.delete(0, tk.END)

    # suppress alert box
    monkeypatch.setattr("tkinter.messagebox.showerror", lambda x, y: True)

    client.create_account()
    # Since fields are empty, no send request should be made.
    assert len(send_calls) == 0


def test_login_sends_login_request(client):
    send_calls = []

    def fake_send(remote_hosts, op_code, data, await_response=True):
        send_calls.append((remote_hosts.copy(), op_code, data, await_response))

        # Simulate a response with an "unread" count.
        class DummyQueueWithUnread:
            def get(self, timeout=None):
                class DummyResponse:
                    request_code = RequestCode.success
                    data = {"unread": 5}

                return DummyResponse()

        return (remote_hosts[0], DummyQueueWithUnread())

    client.sh.send = fake_send

    client.username_entry.delete(0, tk.END)
    client.username_entry.insert(0, "testuser")
    client.password_entry.delete(0, tk.END)
    client.password_entry.insert(0, "password")

    client.login()

    assert len(send_calls) >= 1
    _, op_code, data, _ = send_calls[0]
    assert op_code == OP_TO_CODE["login"]
    expected_data = {"username": "testuser", "password_hash": hash_password("password")}
    assert data == expected_data


def test_send_message_sends_message_request(client):
    send_calls = []

    def fake_send(remote_hosts, op_code, data, await_response=True):
        send_calls.append((remote_hosts.copy(), op_code, data, await_response))

        # Simulate a response that returns a new message.
        class DummyQueueWithMessage:
            def get(self, timeout=None):
                class DummyResponse:
                    request_code = RequestCode.success
                    data = {
                        "message": {
                            "id": 1,
                            "from": "testuser",
                            "to": "otheruser",
                            "timestamp": "2025-03-25T12:00:00",
                            "content": "Hello",
                        }
                    }

                return DummyResponse()

        return (remote_hosts[0], DummyQueueWithMessage())

    client.sh.send = fake_send

    # Set the current user so that any message formatting (if reached) works.
    client.current_user = "testuser"
    client.recipient_entry.delete(0, tk.END)
    client.recipient_entry.insert(0, "otheruser")
    client.message_entry.delete(0, tk.END)
    client.message_entry.insert(0, "Hello")

    client.send_message()

    assert len(send_calls) >= 1
    _, op_code, data, _ = send_calls[0]
    assert op_code == OP_TO_CODE["message"]
    expected_data = {"to": "otheruser", "content": "Hello"}
    assert data == expected_data


def test_load_unread_sends_unread_messages_request(client):
    send_calls = []

    def fake_send(remote_hosts, op_code, data, await_response=True):
        send_calls.append((remote_hosts.copy(), op_code, data, await_response))

        class DummyQueueWithItems:
            def get(self, timeout=None):
                class DummyResponse:
                    request_code = RequestCode.success
                    data = {
                        "items": [
                            {
                                "id": 2,
                                "from": "otheruser",
                                "to": "testuser",
                                "timestamp": "2025-03-25T12:05:00",
                                "content": "Hi",
                            }
                        ]
                    }

                return DummyResponse()

        return (remote_hosts[0], DummyQueueWithItems())

    client.sh.send = fake_send

    client.load_count_entry.delete(0, tk.END)
    client.load_count_entry.insert(0, "3")

    client.load_unread()

    # Verify that a request for unread messages was sent with per_page=3.
    assert any(
        call[1] == OP_TO_CODE["unread_messages"] and call[2] == {"per_page": 3}
        for call in send_calls
    )


def test_load_previous_messages_page_sends_read_messages_request(client):
    send_calls = []

    def fake_send(remote_hosts, op_code, data, await_response=True):
        send_calls.append((remote_hosts.copy(), op_code, data, await_response))

        class DummyQueueWithEmpty:
            def get(self, timeout=None):
                class DummyResponse:
                    request_code = RequestCode.success
                    data = {"items": []}

                return DummyResponse()

        return (remote_hosts[0], DummyQueueWithEmpty())

    client.sh.send = fake_send

    client.has_more_messages = True
    client.is_loading_messages = False
    current_page = client.messages_page

    client.load_previous_messages_page()

    expected_req = {"page": current_page + 1, "per_page": client.messages_per_page}
    assert any(
        call[1] == OP_TO_CODE["read_messages"] and call[2] == expected_req
        for call in send_calls
    )


def test_load_accounts_page_sends_accounts_request(client):
    send_calls = []

    def fake_send(remote_hosts, op_code, data, await_response=True):
        send_calls.append((remote_hosts.copy(), op_code, data, await_response))

        class DummyQueueWithAccounts:
            def get(self, timeout=None):
                class DummyResponse:
                    request_code = RequestCode.success
                    data = {
                        "items": [{"username": "user1"}, {"username": "user2"}],
                        "total_count": 2,
                    }

                return DummyResponse()

        return (remote_hosts[0], DummyQueueWithAccounts())

    client.sh.send = fake_send

    client.accounts_search = "user"
    client.accounts_per_page = 10

    client.load_accounts_page(2)

    expected_req = {"pattern": "user", "page": 2, "per_page": client.accounts_per_page}
    assert any(
        call[1] == OP_TO_CODE["accounts"] and call[2] == expected_req
        for call in send_calls
    )


def test_delete_account_sends_delete_account_request(client, monkeypatch):
    send_calls = []

    def fake_send(remote_hosts, op_code, data=None, await_response=True):
        send_calls.append((remote_hosts.copy(), op_code, data or {}, await_response))
        return (remote_hosts[0], DummyQueue())

    client.sh.send = fake_send
    # Force confirmation to True.
    monkeypatch.setattr("tkinter.messagebox.askyesno", lambda title, msg: True)

    client.delete_account()

    assert any(call[1] == OP_TO_CODE["delete_account"] for call in send_calls)


def test_on_push_sends_mark_as_read_request(client):
    send_calls = []

    # Patch the client.send method (used in on_push) rather than sh.send.
    def fake_send(operation, data, await_response=True):
        send_calls.append((operation, data, await_response))
        return DummyQueue()

    client.send = fake_send

    fake_message = {
        "id": 3,
        "from": "otheruser",
        "to": "testuser",
        "timestamp": "2025-03-25T12:10:00",
        "content": "Push message",
    }
    FakeRequest = type("FakeRequest", (object,), {"data": {"message": fake_message}})
    client.on_push(FakeRequest())

    assert any(op == "mark_as_read" and data == {"id": 3} for op, data, _ in send_calls)


def test_on_delete_key_sends_delete_messages_request(client, monkeypatch):
    send_calls = []

    def fake_send(operation, data, await_response=True):
        send_calls.append((operation, data, await_response))
        return DummyQueue()

    client.send = fake_send

    # Force confirmation to True.
    monkeypatch.setattr("tkinter.messagebox.askyesno", lambda title, msg: True)
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda x, y: True)

    # Simulate that one message is selected with id 10.
    fake_item = "fake_item"
    client.chat_treeview.selection = lambda: [fake_item]
    # Simulate that the Treeview returns a tuple with the id as the first element.
    client.chat_treeview.item = (
        lambda item, option: (10, "dummy") if option == "values" else None
    )

    client.on_delete_key()

    assert any(
        op == "delete_messages" and data == {"messages": [10]}
        for op, data, _ in send_calls
    )


def test_send_method_reorders_remote_hosts(client, monkeypatch):
    send_calls = []

    def fake_send(remote_hosts, op_code, data, await_response=True):
        send_calls.append((remote_hosts.copy(), op_code, data, await_response))
        # Simulate that the used remote host is the second one.
        used_host = client.remote_hosts[1]

        class DummyQueueReorder:
            def get(self, timeout=None):
                class DummyResponse:
                    request_code = RequestCode.success
                    data = {}

                return DummyResponse()

        return (used_host, DummyQueueReorder())

    client.sh.send = fake_send
    initial_hosts = client.remote_hosts.copy()

    # Call the send method of the Client.
    monkeypatch.setitem(OP_TO_CODE, "dummy_op", 99)

    client.send("dummy_op", {"key": "value"})
    # The remote host that responded (initial_hosts[1]) should have been moved to the front.
    assert client.remote_hosts[0] == initial_hosts[1]
