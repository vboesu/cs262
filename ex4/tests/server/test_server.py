import time
import threading
import queue
import pytest
import socket

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.common import Request, RequestCode, OP_TO_CODE, CODE_TO_OP
from src.models import Log, Base
from src.server import Server, db as db_module
from src.server.utils import routing_registry


### DUMMIES
class DummyRequest(Request):
    def __init__(self, request_code, data, request_id, addr=("127.0.0.1", 5000)):
        self.request_code = request_code
        self.data = data
        self.request_id = request_id
        self.addr = addr

    def serialize(self):
        # For testing, we simply convert our attributes to a string.
        return f"{self.request_code}|{self.data}|{self.request_id}".encode()

    @staticmethod
    def parse(serialized):
        parts = serialized.split("|")
        return DummyRequest(int(parts[0]), eval(parts[1]), int(parts[2]))


class DummySocketHandler:
    def __init__(self):
        self.sent_requests = []  # Records every call to send()
        self.respond_calls = []  # Records every call to respond_to()

    def send(self, remote_hosts, request_code, data, await_response=True):
        self.sent_requests.append((remote_hosts, request_code, data, await_response))
        # Create a dummy queue to simulate a response.
        dummy_queue = queue.Queue()
        # For certain operation codes, simulate a proper response.
        if request_code == OP_TO_CODE.get("internal_log"):
            # Simulate that the replica acknowledges the log entry.
            dummy_resp = DummyRequest(OP_TO_CODE.get("internal_ok"), {}, 0)
            dummy_queue.put(dummy_resp)
        elif request_code == OP_TO_CODE.get("internal_election"):
            dummy_resp = DummyRequest(OP_TO_CODE.get("internal_ok"), {}, 0)
            dummy_queue.put(dummy_resp)
        else:
            # Default response: internal_ok
            dummy_resp = DummyRequest(OP_TO_CODE.get("internal_ok"), {}, 0)
            dummy_queue.put(dummy_resp)
        return remote_hosts[0], dummy_queue

    def respond_to(self, request, response_code, response_data):
        self.respond_calls.append((request, response_code, response_data))


def dummy_op(server, **kwargs):
    return {"result": "ok"}


dummy_op_code = 9999


### FIXTURES
@pytest.fixture
def op(monkeypatch):
    monkeypatch.setitem(OP_TO_CODE, "dummy_op", dummy_op_code)
    monkeypatch.setitem(CODE_TO_OP, dummy_op_code, "dummy_op")
    routing_registry[dummy_op_code] = dummy_op


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    db_module.session = session
    yield session
    session.close()


@pytest.fixture
def dummy_server_instance(monkeypatch, test_db):
    # Force db.create_session (called in Server.__init__) to return our in‑memory session.
    from src.server import db as db_module

    monkeypatch.setattr(db_module, "create_session", lambda db_url, echo: test_db)
    # Set up a replicas dictionary. (For example, two replicas with IDs 1 and 2.)
    replicas = {
        1: {"host": "127.0.0.1", "port": 5001, "internal_port": 5011},
        2: {"host": "127.0.0.1", "port": 5002, "internal_port": 5012},
    }
    # Create a server instance. (For many tests we adjust its role.)
    server = Server(
        id=2,
        host="0.0.0.0",
        port=replicas[2]["port"],
        internal_port=replicas[2]["internal_port"],
        db_url="sqlite:///:memory:",
        replicas=replicas,
        heartbeat_interval=0.2,
        verbose=0,
    )

    # Override the SocketHandlers with our dummy versions.
    server.sh = DummySocketHandler()
    server.internal_sh = DummySocketHandler()
    server.election_lock = threading.RLock()
    server.clock_lock = threading.RLock()
    server.clock = 0
    server.last_heartbeat = time.time()
    return server


def test_write_and_get_log(op, dummy_server_instance, test_db):
    server = dummy_server_instance
    dummy_req = DummyRequest(dummy_op_code, {"foo": "bar"}, 1)
    with server.clock_lock:
        server.clock = 1
    server.write_to_log(dummy_req)
    log_entry = server.get_log(1)
    assert log_entry is not None
    assert log_entry.request == dummy_req.serialize()


def test_process_replication_success(op, dummy_server_instance, test_db):
    server = dummy_server_instance
    # Make the server act as leader.
    with server.election_lock:
        server.is_leader = True

    # Create a dummy request that will be processed by our dummy operation.
    dummy_req = DummyRequest(dummy_op_code, {"username": "testuser", "foo": "bar"}, 1)
    server.sh.respond_calls = []
    server.process(dummy_req)
    # Check that replication was attempted (i.e. internal_sh.send was called).
    assert len(server.internal_sh.sent_requests) > 0
    # And that a response was sent back to the client.
    assert len(server.sh.respond_calls) == 1
    # Also verify that the server’s clock was incremented.
    assert server.clock == 1


def test_process_replication_failure(op, dummy_server_instance, test_db, monkeypatch):
    server = dummy_server_instance
    with server.election_lock:
        server.is_leader = True
    dummy_req = DummyRequest(dummy_op_code, {"username": "testuser", "foo": "bar"}, 1)

    # Monkey-patch internal_sh.send to simulate a timeout (i.e. no response).
    def send_timeout(remote_hosts, request_code, data, await_response=True):
        q = queue.Queue()  # empty queue; get() will eventually timeout.
        return remote_hosts[0], q

    monkeypatch.setattr(server.internal_sh, "send", send_timeout)
    server.sh.respond_calls = []
    server.process(dummy_req)
    # An error response should be sent back.
    assert len(server.sh.respond_calls) == 1
    req, resp_code, resp_data = server.sh.respond_calls[0]
    assert resp_data.get("error")  # contains an error message


def test_receive_as_follower(op, dummy_server_instance):
    server = dummy_server_instance
    with server.election_lock:
        server.is_leader = False
    called = False

    def dummy_forward(request):
        nonlocal called
        called = True

    server.forward_to_leader = dummy_forward
    dummy_req = DummyRequest(dummy_op_code, {"username": "testuser"}, 1)
    server.receive(dummy_req)
    assert called is True


def test_receive_internal_heartbeat(dummy_server_instance):
    server = dummy_server_instance
    old_time = server.last_heartbeat
    heartbeat_req = DummyRequest(OP_TO_CODE["internal_heartbeat"], {"leader": 1}, 1)
    server.receive_internal(heartbeat_req)
    assert server.last_heartbeat > old_time
    assert server.leader_id == 1


def test_call_election_self_elected(dummy_server_instance, monkeypatch):
    server = dummy_server_instance
    # Simulate heartbeat timeout.
    with server.election_lock:
        server.last_heartbeat = time.time() - server.election_timeout - 1
        server.in_election = False

    # Make internal_sh.send always fail.
    def send_fail(remote_hosts, request_code, data=None, await_response=True):
        raise ConnectionRefusedError

    monkeypatch.setattr(server.internal_sh, "send", send_fail)
    server.call_election()
    with server.election_lock:
        assert server.leader_id == server.id
        assert server.is_leader is True


def test_call_election_wait_for_announcement(dummy_server_instance, monkeypatch):
    server = dummy_server_instance
    # Simulate heartbeat timeout.
    with server.election_lock:
        server.last_heartbeat = time.time() - server.election_timeout - 1
        server.in_election = False
        server.is_leader = False
        server.leader_id = None

    # Simulate a response from a lower‑ID peer.
    def send_election_success(
        remote_hosts, request_code, data=None, await_response=True
    ):
        dummy_q = queue.Queue()
        dummy_resp = DummyRequest(OP_TO_CODE["internal_ok"], {}, 0)
        dummy_q.put(dummy_resp)
        return remote_hosts[0], dummy_q

    monkeypatch.setattr(server.internal_sh, "send", send_election_success)
    server.call_election()
    with server.election_lock:
        # Since a lower‑ID peer responded, this server should not elect itself.
        assert server.leader_id is None or server.leader_id != server.id
        assert server.is_leader is False


def test_send_heartbeats(dummy_server_instance, monkeypatch):
    server = dummy_server_instance
    with server.election_lock:
        server.is_leader = True
    call_count = [0]

    def dummy_broadcast(request_code, data):
        call_count[0] += 1
        # Stop the loop by raising an exception.
        raise KeyboardInterrupt

    monkeypatch.setattr(server, "broadcast_to_peers", dummy_broadcast)
    try:
        server.send_heartbeats()
    except KeyboardInterrupt:
        pass
    assert call_count[0] >= 1


def test_forward_to_leader(op, dummy_server_instance, monkeypatch):
    server = dummy_server_instance
    with server.election_lock:
        server.is_leader = False
        server.leader_id = 1
    called = False

    def dummy_push_to_leader(request_code, data):
        nonlocal called
        called = True

    monkeypatch.setattr(server, "push_to_leader", dummy_push_to_leader)
    dummy_req = DummyRequest(dummy_op_code, {"username": "testuser"}, 1)
    server.forward_to_leader(dummy_req)
    assert called is True


def test_teach_replica(op, dummy_server_instance, test_db, monkeypatch):
    server = dummy_server_instance
    # Insert a dummy log entry into the database.
    dummy_req_1 = DummyRequest(dummy_op_code, {"foo": "bar"}, 1)
    dummy_req_2 = DummyRequest(dummy_op_code, {"bar": "foo"}, 1)
    with server.clock_lock:
        server.clock = 1
        server.write_to_log(dummy_req_1)
        server.clock = 2
        server.write_to_log(dummy_req_2)

    send_calls = []

    def dummy_send(remote_hosts, request_code, data, await_response=True):
        send_calls.append((remote_hosts, request_code, data, await_response))
        q = queue.Queue()
        dummy_resp = DummyRequest(OP_TO_CODE["internal_ok"], {}, 0)
        q.put(dummy_resp)
        return remote_hosts[0], q

    monkeypatch.setattr(server.internal_sh, "send", dummy_send)
    server.teach_replica(1, 1)
    assert len(send_calls) == 2  # for entries 1 and 2
