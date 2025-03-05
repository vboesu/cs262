import json
import socket
import time
import queue
import pytest

from simulate import Machine


# A fake socket class to capture sent data.
class FakeSocket:
    def __init__(self, *args, **kwargs):
        self.data_sent = None
        self.address = None

    def connect(self, address):
        self.address = address

    def sendall(self, data):
        self.data_sent = data

    def bind(self, address):
        self.address = address

    def listen(self, *args, **kwargs):
        pass

    def settimeout(self, *args, **kwargs):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# Fixture to speed up tests by bypassing sleep delays.
@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda s: None)


# Fixture to redirect log output to a temporary directory.
@pytest.fixture(autouse=True)
def use_temp_logs(tmp_path, monkeypatch):
    # Override the global LOGS_FOLDER used in Machine.
    monkeypatch.setattr("simulate.LOGS_FOLDER", tmp_path)


# Prevent the machine from automatically starting its threads and run loop.
@pytest.fixture(autouse=True)
def disable_start(monkeypatch):
    monkeypatch.setattr(Machine, "start", lambda self: None)


# Prevent the usage of real sockets
@pytest.fixture(autouse=True)
def disable_sockets(monkeypatch):
    monkeypatch.setattr(socket, "socket", FakeSocket)


def test_generate_event_rec():
    """
    Test that if the machine’s message queue is non-empty, generate_event returns "REC".
    """
    m = Machine(0, tick_speed=0.1, runtime=1)
    # Put a dummy message in the queue.
    m.messages.put({"sender": 1, "ts": 10})
    event = m.generate_event()
    assert event == "REC"


def test_generate_event_non_rec():
    """
    Test that when no message is waiting, generate_event returns one of the expected events.
    """
    m = Machine(0, tick_speed=0.1, runtime=1)
    # Ensure the queue is empty.
    with pytest.raises(queue.Empty):
        m.messages.get_nowait()

    event = m.generate_event()
    # The non-"REC" events.
    valid_events = {"SE1", "SE2", "SEA", "INT"}
    assert event in valid_events


def test_send_message(monkeypatch):
    """
    Test that send_message correctly sends a JSON message via a socket.
    We'll intercept socket.socket to use our FakeSocket.
    """
    # Capture all FakeSocket instances created.
    fake_sockets = []

    def fake_socket_constructor(*args, **kwargs):
        sock = FakeSocket(*args, **kwargs)
        fake_sockets.append(sock)
        return sock

    monkeypatch.setattr(socket, "socket", fake_socket_constructor)

    m = Machine(0, tick_speed=0.1, runtime=1)
    m.clock = 5
    target = 1
    m.send_message([target])

    # We expect two FakeSockets to have been created.
    assert len(fake_sockets) == 2
    fake_sock = fake_sockets[1]
    # Check that the socket connected to the right address.
    expected_address = (m.host, m.base_port + target)
    assert fake_sock.address == expected_address

    # Check that the sent data is a valid JSON message containing the sender and clock.
    sent_message = json.loads(fake_sock.data_sent.decode())
    assert sent_message["sender"] == m.id
    assert sent_message["ts"] == m.clock
