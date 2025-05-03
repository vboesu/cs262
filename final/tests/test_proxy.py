import time
import threading
import socket
from queue import Queue
import pytest

import dns
from src.query import Query, Operation
from src.proxy import Proxy, SocketData, MAGIC, PROTOCOL_VERSION


class DummyDB:
    def __init__(self):
        self.written = []
        self.executed = []

    def try_execute(self, query, params=None):
        self.executed.append((query, params))
        # default success with empty result
        return 0, []

    def write_query(
        self, query, log, transaction_id=None, logical_timestamp=None, timestamp=None
    ):
        self.written.append((query, log, transaction_id, logical_timestamp, timestamp))
        # simulate success
        return 0, query


@pytest.fixture(autouse=True)
def env_setup(tmp_path, monkeypatch):
    # Set required env vars
    monkeypatch.setenv("N_REPLICAS", "3")
    monkeypatch.setenv("SERVICE_DNS", "svc.local")
    monkeypatch.setenv("INTERNAL_PORT", "9001")
    monkeypatch.setenv("EXTERNAL_PORT", "9002")
    monkeypatch.setenv("SERVER_ID", "1")

    monkeypatch.setattr(dns, "resolver", pytest.MonkeyPatch())
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: None)
    yield


@pytest.fixture
def proxy():
    # minimal replica_config and api_config
    rc = {
        "STRONG_CONSISTENCY": ["t.*"],
        "HEARTBEAT_INTERVAL_MS": 50,
        "ELECTION_TIMEOUT_MS": 500,
    }
    ac = {}
    p = Proxy(rc, ac)
    # inject dummy DB
    p.db = DummyDB()
    # override peers discovery
    p.discover_peers = lambda: set()
    # override ips
    p.__dict__["ips"] = {"127.0.0.1"}
    return p


def test_dispatch_get_success(proxy):
    proxy.db = DummyDB()
    proxy.db.try_execute = lambda q, p=None: (0, [{"a": 1}])
    result, status = proxy.dispatch("GET", "tbl", {}, None)
    assert status == 200
    assert result == [{"a": 1}]


def test_dispatch_get_error(proxy):
    proxy.db.try_execute = lambda q, p=None: (1, None)
    result, status = proxy.dispatch("GET", "tbl", {}, None)
    assert status == 400
    assert "error" in result


def test_dispatch_post_weak(proxy, monkeypatch):
    # no strong tables => weak
    proxy.strong_tables = set()
    recorded = {}

    def fake_write(q, log):
        recorded["write"] = (q, log)
        return 0, q

    proxy.db.write_query = fake_write
    calls = []
    proxy._broadcast = lambda cmd, pl: calls.append((cmd, pl))

    result, status = proxy.dispatch("POST", "tbl", {"x": 5}, None)
    assert status == 200
    # write_query called with eventual log
    assert "write" in recorded and recorded["write"][1] == "eventual"
    # broadcast of weak query
    assert calls and calls[0][0] == b"A"


@pytest.mark.parametrize(
    "method,data,should_be_strong",
    [
        ("PATCH", {"x": 1}, True),
        ("PATCH", {"y": 2}, False),
    ],
)
def test_dispatch_patch(proxy, monkeypatch, method, data, should_be_strong):
    # create table t with column x strong
    proxy.strong_columns = {"t.x"}
    # stub db.select to return one row
    proxy.db.try_execute = lambda q, p=None: (0, [{list(data.keys())[0]: 0}])
    # stub leader forwarding
    status_calls = []
    proxy.send_query_to_leader = lambda q: status_calls.append(True) or 0
    res, status = proxy.dispatch("PATCH", "t", data, "row1")
    assert status == 200
    if should_be_strong:
        assert status_calls
    else:
        # weak if no strong match
        assert proxy.db.write_query.__name__


def test_initiate_and_receive_handshake(proxy):
    data = SocketData("host", None)
    proxy.clock = 7
    proxy.status = "leader"
    proxy.leader = None

    # patch _prepare_send
    called = []
    proxy._prepare_send = lambda data, cmd, pl: called.append(cmd)
    proxy._Proxy__initiate_handshake(data)

    assert b"I" in called

    # now receiver updates leader
    # simulate payload: clock 7 + is_leader flag
    payload = proxy.clock.to_bytes(4, "big") + b"\x01"
    proxy._Proxy__receive_handshake(data, payload)
    assert proxy.leader == "host"

    # check that replica starts learning if it's behind
    fn_called = []
    proxy.leader = None
    proxy._start_learning = lambda: fn_called.append(1)
    clock_ahead = proxy.clock + 1
    payload = clock_ahead.to_bytes(4, "big") + b"\x01"
    proxy._Proxy__receive_handshake(data, payload)
    assert fn_called == [1]


def make_message(cmd, payload):
    return (
        MAGIC
        + PROTOCOL_VERSION.to_bytes(1, "big")
        + cmd
        + len(payload).to_bytes(4, "big")
        + payload
    )


def test_receive_partial_and_multiple(proxy):
    data = SocketData("h", None)
    msg1 = make_message(b"A", b"123")
    # feed partial
    data.inb = msg1[:5]
    assert proxy._receive(data) is None
    # feed rest
    data.inb += msg1[5:]
    cmd, pl = proxy._receive(data)
    assert cmd == b"A" and pl == b"123"
    # multiple
    msg2 = make_message(b"B", b"xy")
    data.inb = msg1 + msg2
    first = proxy._receive(data)
    second = proxy._receive(data)
    assert first == (b"A", b"123") and second == (b"B", b"xy")


def test_wait_for_queues(proxy):
    q1 = b"k1"
    q2 = b"k2"
    proxy.queues[q1] = Queue()
    proxy.queues[q2] = Queue()

    # put items after delay
    def put_items():
        time.sleep(0.05)
        proxy.queues[q1].put(1)
        proxy.queues[q2].put(2)

    threading.Thread(target=put_items, daemon=True).start()
    results = proxy._wait_for_queues([q1, q2], timeout=1)
    assert results == {q1: 1, q2: 2}
    # queues cleaned
    assert q1 not in proxy.queues and q2 not in proxy.queues


def test_propose_query_leader(proxy):
    proxy.status = "leader"
    proxy.clock = 1
    proxy.connections = {"p1", "p2"}
    proxy.db.write_query = lambda q, log, logical_timestamp=None: (0, q)
    proxy.discover_peers = lambda: proxy.connections
    proxy._wait_for_queues = lambda keys, timeout: {k: 0 for k in keys}

    called = []
    proxy._broadcast = lambda cmd, pl: called.append(cmd)
    q = Query([Operation(b"I", "tbl", data={"x": 1})])
    q.logical_timestamp = proxy.clock

    status, outq = proxy.propose_query(q)
    assert status == 0 and outq == q
    assert proxy.clock == 2

    proxy.clock = 1
    proxy._wait_for_queues = lambda keys, timeout: {k: 1 for k in keys}
    status2, _ = proxy.propose_query(q)
    assert status2 == 1
    assert proxy.clock == 1


def test_send_query_to_leader_follower(proxy):
    proxy.status = "follower"
    proxy.leader = "peer"
    # prepare queue for req
    proxy.queues = {1: Queue()}

    # simulate sending: override _send_to_peer to immediately put response
    def fake_send(host, cmd, payload, raise_exc=False):
        # simulate remote sending back status
        proxy.queues[1].put(99)

    proxy._send_to_peer = fake_send
    # initial req_id = 1
    q = Query([Operation(b"I", "tbl", data={"x": 1})])
    status = proxy.send_query_to_leader(q)
    assert status == 99


def test_call_election_no_peers(proxy, monkeypatch):
    proxy.discover_peers = lambda: set()
    recorded = []
    proxy._broadcast = lambda cmd, pl: recorded.append(cmd)
    proxy.ips = {"ip1"}
    proxy.call_election()
    assert proxy.status == "leader"
    assert recorded == [b"E", b"W"]  # call election, declare winner


def test_process_strong_query(proxy, monkeypatch):
    proxy.status = "follower"
    proxy.clock = 1
    fn_called = []
    proxy._prepare_send = lambda data, cmd, pl: fn_called.append(cmd)
    data = SocketData("h", None)

    # build payload: term bytes (ignored) + query encoded
    q = Query([Operation(b"I", "t", data={"x": 1})])
    q.transaction_id = b"\x01" * 16
    q.logical_timestamp = 1
    payload = q.encode()
    proxy._Proxy__process_strong_query(data, payload)
    assert fn_called == [b"R"]


def test_process_strong_query_missing(proxy, monkeypatch):
    proxy.status = "follower"
    proxy.clock = 1
    fn_called, called = [], []
    proxy._prepare_send = lambda data, cmd, pl: fn_called.append(cmd)
    proxy._start_learning = lambda: called.append(1)
    data = SocketData("h", None)

    # build payload: term bytes (ignored) + query encoded
    q = Query([Operation(b"I", "t", data={"x": 1})])
    q.transaction_id = b"\x01" * 16
    q.logical_timestamp = 2
    payload = q.encode()
    proxy._Proxy__process_strong_query(data, payload)
    assert fn_called == [b"R"]
    assert called == [1]


def test_teach_and_learn(proxy, monkeypatch):
    # teach with existing entry
    payload_clock = (2).to_bytes(4, "big")
    # fake DB to return one row
    row = {
        "command": ord(b"I"),
        "schema": "tbl",
        "column": None,
        "row": None,
        "old_value": None,
        "new_value": None,
        "data": b"",
        "timestamp": None,
        "logical_timestamp": 2,
    }
    proxy.db.try_execute = lambda q, p=None: (0, [row])
    # stub Operation.from_sql and Query.encode
    monkeypatch.setattr(
        Operation, "from_sql", lambda r: Operation(b"I", "tbl", data={"x": 1})
    )
    monkeypatch.setattr(Query, "encode", lambda self: b"body")
    data = SocketData("h", None)
    proxy.clock = 5  # > clock in payload
    fn_called = []
    proxy._prepare_send = lambda data, cmd, pl: fn_called.append(cmd)
    proxy._Proxy__teach(data, payload_clock)
    assert fn_called == [b"L"]

    # learn places payload into queue
    key = payload_clock
    proxy.queues[key] = Queue()
    body_payload = key + b"binary"
    proxy._Proxy__learn(data, body_payload)
    assert proxy.queues[key].get() == b"binary"
