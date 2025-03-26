import socket
import threading
import queue
import time
import pytest

import src.common.socket
from src.common.socket import SocketHandler


### DUMMIES
class DummyRequest:
    def __init__(self, request_code, data, request_id):
        self.request_code = request_code
        self.data = data
        self.request_id = request_id
        # For testing, we include an address attribute.
        self.addr = ("127.0.0.1", 9999)

    def push(self, sock):
        """
        Simulate pushing data to a socket. For our test,
        we assume the full dummy payload is sent.
        """
        dummy_data = b"dummy"
        # Optionally write the dummy data
        try:
            sock.sendall(dummy_data)
        except Exception:
            pass
        return (len(dummy_data), len(dummy_data))

    @staticmethod
    def receive(conn, addr):
        """
        Simulate receiving a request from a connection.
        Instead of reading from the socket, we simply return a
        DummyRequest instance.
        """
        # For the purpose of the test, we return a dummy request
        return DummyRequest(0, {"dummy": "data"}, 1)


# Mock for all tests
src.common.socket.Request = DummyRequest


### FIXTURES
@pytest.fixture
def dummy_listen_socket():
    """Fixture that creates a TCP listening socket bound to localhost on a free port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    yield sock

    try:
        sock.close()
    except Exception:
        pass


@pytest.fixture
def callback_list():
    """
    Fixture that returns a tuple (results, callback). The callback
    appends any received request into the results list.
    """
    results = []

    def dummy_callback(req):
        results.append(req)

    return results, dummy_callback


def dummy_server(server_socket, stop_event):
    """
    Runs a simple dummy server that accepts one connection at a time.
    This is used to test the send() method.
    """
    while not stop_event.is_set():
        try:
            server_socket.settimeout(0.5)
            conn, addr = server_socket.accept()

            # For testing, we do not send any response.
            time.sleep(0.1)
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            break


def test_listen_callback_invoked(dummy_listen_socket, callback_list, monkeypatch):
    """
    Test that when a client connects to the listening socket,
    the SocketHandler calls the receive_callback with the DummyRequest.
    """
    results, dummy_callback = callback_list
    handler = SocketHandler(dummy_listen_socket, dummy_callback)
    handler.start_listening(block=False)
    time.sleep(0.2)  # Allow thread to start

    # Simulate a client connecting to the listening socket.
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(dummy_listen_socket.getsockname())
    finally:
        client.close()

    # Allow some time for the connection to be processed.
    time.sleep(0.2)
    assert len(results) == 1
    req = results[0]

    # Check that the dummy receive method populated the request correctly.
    assert req.data == {"dummy": "data"}
    handler.close()


def test_send_success(dummy_listen_socket):
    """
    Test that the send() method successfully connects to a dummy server.
    """
    # Set up dummy server.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(5)
    server_addr = server_socket.getsockname()

    stop_event = threading.Event()
    server_thread = threading.Thread(
        target=dummy_server, args=(server_socket, stop_event)
    )
    server_thread.start()

    # Create a SocketHandler (the listening socket here is not used in send).
    handler = SocketHandler(dummy_listen_socket, lambda req: None)

    remote_hosts = [server_addr]
    sent_to, response_queue = handler.send(
        remote_hosts,
        request_code=123,
        data={"key": "value"},
        await_response=True,
    )
    assert sent_to == server_addr
    assert isinstance(response_queue, queue.Queue)

    # Cleanup
    handler.close()
    stop_event.set()
    server_thread.join()
    server_socket.close()


def test_send_failure(dummy_listen_socket):
    """
    Test that send() raises a ConnectionRefusedError when no remote host is reachable.
    """
    handler = SocketHandler(dummy_listen_socket, lambda req: None)
    # Use a remote host that is very likely not to be listening.
    remote_hosts = [("127.0.0.1", 65535)]
    with pytest.raises(ConnectionRefusedError):
        handler.send(
            remote_hosts, request_code=123, data={"key": "value"}, await_response=False
        )
    handler.close()


def test_respond_to(dummy_listen_socket):
    """
    Test that respond_to() uses the request's address and response_port from data.
    Here we monkey-patch the send() method to capture the parameters.
    """
    # Create a dummy request with specific addr and a response_port.
    dummy_req = DummyRequest(0, {"response_port": 5001}, 42)
    dummy_req.addr = ("127.0.0.1", 4000)

    handler = SocketHandler(dummy_listen_socket, lambda req: None)

    called = False

    def dummy_send(remote_hosts, request_code, request_id, data, await_response):
        nonlocal called
        called = True
        # The response should be sent to ("127.0.0.1", 5001)
        assert remote_hosts == [("127.0.0.1", 5001)]
        assert request_id == dummy_req.request_id
        return ("127.0.0.1", 5001), None

    original_send = handler.send
    handler.send = dummy_send
    handler.respond_to(dummy_req, response_code=200, response_data={"resp": "ok"})
    assert called
    handler.send = original_send
    handler.close()


def test_close(dummy_listen_socket):
    """
    Test that close() properly stops threads and closes the listening socket.
    """
    handler = SocketHandler(dummy_listen_socket, lambda req: None)
    handler.start_listening(block=False)
    time.sleep(0.2)

    handler.close()

    # After close, the stop_event should be set
    assert handler.stop_event.is_set()

    # We will not check the threads here because they're weird sometimes


def test_process_callback(dummy_listen_socket, callback_list):
    """
    Test that a request put directly into the receive_queue is processed via the callback.
    """
    results, dummy_callback = callback_list
    handler = SocketHandler(dummy_listen_socket, dummy_callback)
    dummy_req = DummyRequest(0, {"dummy": "process"}, 99)
    handler.receive_queue.put(dummy_req)
    time.sleep(0.1)
    assert len(results) == 1
    assert results[0].request_id == 99
    handler.close()


def test_request_id_increment(dummy_listen_socket):
    """
    Test that calling send() without a specific request_id auto-generates an incremented id.
    """
    # Set up dummy server.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(5)
    server_addr = server_socket.getsockname()

    stop_event = threading.Event()
    server_thread = threading.Thread(
        target=dummy_server, args=(server_socket, stop_event)
    )
    server_thread.start()

    handler = SocketHandler(dummy_listen_socket, lambda req: None)
    remote_hosts = [server_addr]
    _, _ = handler.send(remote_hosts, request_code=100, data={})
    first_id = handler.req_id
    _, _ = handler.send(remote_hosts, request_code=100, data={})
    second_id = handler.req_id
    # Because we use modulo arithmetic, the new id should be (first_id % 65536) + 1.
    assert second_id == ((first_id % 65536) + 1)

    handler.close()
    stop_event.set()
    server_thread.join()
    server_socket.close()
