import pytest
from unittest.mock import MagicMock
import tkinter as tk

# Import the Client class and Protobuf message types you need
from src.client.client import Client
from src.common.protocol_pb2 import (
    LoginResponse,
    RegisterResponse,
    MessageResponse,
    Message,
    ErrorResponse,
)
from src.common.protocol_pb2 import GenericRequest, MessageRequest


@pytest.fixture
def client_with_mock_stub(mocker):
    """
    Fixture that creates a Client instance with a mocked gRPC stub.
    We patch Tkinter's mainloop to avoid actually starting the GUI.
    """
    # Patch Tkinter's mainloop to prevent blocking
    mocker.patch.object(tk.Tk, "mainloop", return_value=None)

    # Create the Client instance
    client = Client("localhost", 50051)
    client.stub = mocker.Mock()  # Replace the real stub with a mock
    return client


def test_create_account_success(client_with_mock_stub):
    """
    Verify that create_account calls the Register RPC correctly and updates the client state.
    """
    client = client_with_mock_stub

    # Prepare a fake successful RegisterResponse
    fake_response = RegisterResponse()
    fake_response.login_token = b"fake_token"
    client.stub.Register.return_value = fake_response

    # Simulate user input
    client.username_entry.insert(0, "testuser")
    client.password_entry.insert(0, "testpass")

    # Call create_account()
    client.create_account()

    # Check that Register was called once
    assert client.stub.Register.call_count == 1
    request_sent = client.stub.Register.call_args[0][0]
    assert request_sent.username == "testuser"

    # Verify the client state was updated
    assert client.token == b"fake_token"
    assert client.current_user == "testuser"


def test_create_account_error(client_with_mock_stub, mocker):
    """
    Verify that create_account shows an error when the server returns an error.
    """
    client = client_with_mock_stub

    # Prepare a fake error response for Register
    error_resp = ErrorResponse(message="User already exists.")
    fake_response = RegisterResponse(error=error_resp)
    client.stub.Register.return_value = fake_response

    # Patch the messagebox.showerror to capture the error message
    mock_showerror = mocker.patch("tkinter.messagebox.showerror")

    # Simulate user input
    client.username_entry.insert(0, "existing_user")
    client.password_entry.insert(0, "somepass")

    client.create_account()

    # Verify that showerror was called with the appropriate error message
    mock_showerror.assert_called_once()


def test_send_message_success(client_with_mock_stub):
    """
    Verify that send_message sends the correct RPC and updates the local message store.
    """
    client = client_with_mock_stub

    # Prepare a fake Message and MessageResponse for SendMessage
    fake_msg = Message(
        id=42,
        sender="loginuser",
        recipient="otheruser",
        content="Hello!",
        timestamp="2025-02-26 10:00:00",
    )
    fake_response = MessageResponse(messages=[fake_msg])
    client.stub.SendMessage.return_value = fake_response

    # Set up client state to simulate a logged in user
    client.current_user = "loginuser"
    client.header.login_token = b"login_token"

    # Simulate user input for sending a message
    client.recipient_entry.insert(0, "otheruser")
    client.message_entry.insert(0, "Hello!")

    # Call send_message()
    client.send_message()

    # Check that SendMessage was called with a request that contains the expected data
    assert client.stub.SendMessage.call_count == 1
    request_sent = client.stub.SendMessage.call_args[0][0]
    assert request_sent.header.login_token == b"login_token"
    assert request_sent.recipient == "otheruser"
    assert request_sent.content == "Hello!"

    # Verify that the new message is stored locally
    assert 42 in client.messages_by_id
    stored_msg = client.messages_by_id[42]
    assert stored_msg.content == "Hello!"


def test_send_message_error(client_with_mock_stub, mocker):
    """
    Verify that send_message shows an error when the server returns an error.
    """
    client = client_with_mock_stub

    # Prepare a fake error response for SendMessage
    error_resp = ErrorResponse(message="Recipient does not exist.")
    fake_response = MessageResponse(error=error_resp)
    client.stub.SendMessage.return_value = fake_response

    # Patch the messagebox.showerror to capture the error
    mock_showerror = mocker.patch("tkinter.messagebox.showerror")

    # Simulate user input
    client.recipient_entry.insert(0, "nonexistent")
    client.message_entry.insert(0, "Hello???")

    # Call send_message()
    client.send_message()

    # Verify that showerror was called with the correct error message
    mock_showerror.assert_called_once()

    # Ensure no message was added to the local store
    assert len(client.messages_by_id) == 0
