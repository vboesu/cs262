import pytest
from datetime import datetime

import src.query
from src.query import Operation, Query


# Dummy encoders for monkeypatching
class DummyEncoder:
    def __init__(self, encode_map=None, decode_map=None):
        self._encode_map = encode_map or {}
        self._decode_map = decode_map or {}
        self.last_obj = None

    def encode(self, obj):
        self.last_obj = obj
        return self._encode_map.get(id(obj), b"data")

    def decode(self, b):
        if b in self._decode_map:
            return self._decode_map[b]
        # assume round-trip of last encoded
        return [self.last_obj]


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(cmd=b"X", schema="s", data={"a": 1}),
        dict(cmd=b"I", schema=""),
        dict(cmd=b"I", schema="schémå", data={"a": 1}),
        dict(cmd=b"U", schema="s", column=None, row=1, old_value=1, new_value=2),
        dict(cmd=b"U", schema="s", column="colé", row=1, old_value=1, new_value=2),
        dict(cmd=b"U", schema="s", column="col", row=None, old_value=1, new_value=2),
        dict(cmd=b"I", schema="s"),
        dict(cmd=b"D", schema="s", row=None),
    ],
)
def test_operation_validate_errors(kwargs):
    with pytest.raises(AssertionError):
        Operation(**kwargs)


@pytest.mark.parametrize(
    "cmd, sql_fn, expected",
    [
        (
            b"U",
            "_update_as_sql",
            ("UPDATE s SET c = ? WHERE id = ? AND c = ?", [3, 1, 2]),
        ),
        (b"I", "_insert_as_sql", ("INSERT INTO s (a, b) VALUES (?, ?)", [1, 2])),
        (b"D", "_delete_as_sql", ("DELETE FROM s WHERE id = ?", [1])),
    ],
)
def test_sql_fragments(cmd, sql_fn, expected):
    if cmd == b"U":
        op = Operation(cmd, schema="s", column="c", row=1, old_value=2, new_value=3)
    elif cmd == b"I":
        op = Operation(cmd, schema="s", data={"a": 1, "b": 2})
    else:
        op = Operation(cmd, schema="s", row=1)
    fn = getattr(op, sql_fn)
    assert fn() == expected
    assert op.as_sql() == expected


def test_to_sql_without_strong(monkeypatch):
    ts = datetime(2025, 5, 2, 12, 0)
    dummy = DummyEncoder(encode_map={})
    monkeypatch.setattr(src.query, "default_encoder", dummy)
    op = Operation(
        cmd=b"I",
        schema="s",
        data={"x": 9},
        logical_timestamp=7,
        timestamp=ts,
        transaction_id=b"tid",
    )
    query, params = op.to_sql("log", operation_id=4, strong=False)
    expected_params = [b"tid", 5, ord(b"I"), "s", None, None, None, None, b"data", ts]
    assert query.startswith("INSERT INTO log")
    assert params == expected_params


def test_to_sql_with_strong(monkeypatch):
    ts = datetime(2025, 5, 2, 13, 0)
    dummy = DummyEncoder(encode_map={})
    monkeypatch.setattr(src.query, "default_encoder", dummy)
    op = Operation(
        cmd=b"U",
        schema="s",
        column="c",
        row=1,
        old_value="o",
        new_value="n",
        data={},
        logical_timestamp=42,
        timestamp=ts,
        transaction_id=None,
    )
    query, params = op.to_sql("log", operation_id=0, strong=True)
    # data=dict is empty so encode default returns b'data'
    expected_params = [None, 1, ord(b"U"), "s", "c", 1, "o", "n", b"data", ts, 42]
    assert params == expected_params


def test_encode_decode_roundtrip(monkeypatch):
    # stub encoder to echo and remember the obj
    stub = DummyEncoder()
    monkeypatch.setattr(src.query, "default_encoder", stub)
    op = Operation(cmd=b"D", schema="tbl", row=10)
    raw = op.encode()
    decoded = Operation.decode(raw)
    assert isinstance(decoded, Operation)
    for field in [
        "cmd",
        "schema",
        "column",
        "row",
        "old_value",
        "new_value",
        "data",
        "logical_timestamp",
        "timestamp",
        "transaction_id",
    ]:
        assert getattr(decoded, field) == getattr(op, field)


def test_from_sql(monkeypatch):
    ts = datetime(2025, 5, 2, 14, 0)
    encoded_data = b"xyz"
    decoded_data = {"k": 1}
    stub = DummyEncoder(decode_map={encoded_data: [decoded_data]})
    monkeypatch.setattr(src.query, "default_encoder", stub)
    row = {
        "command": ord(b"I"),
        "schema": "s",
        "column": None,
        "row": None,
        "old_value": None,
        "new_value": None,
        "data": encoded_data,
        "timestamp": ts,
        "operation_id": 99,
    }
    op = Operation.from_sql(row)
    assert op.cmd == b"I"
    assert op.data == decoded_data
    assert op.schema == "s" and op.timestamp == ts


def test_query_getattr_and_setattr():
    ts1 = datetime(2025, 5, 1)
    ts2 = datetime(2025, 5, 2)
    op1 = Operation(cmd=b"I", schema="s", data={"a": 1}, timestamp=ts1)
    op2 = Operation(cmd=b"I", schema="s", data={"a": 1}, timestamp=ts1)
    q = Query([op1, op2])
    assert q.timestamp == ts1
    assert q.logical_timestamp == -1
    assert q.transaction_id is None
    q.timestamp = ts2
    assert op1.timestamp == ts2 and op2.timestamp == ts2
    assert q.timestamp == ts2
    # mismatch
    op2.transaction_id = b"x"
    assert q.transaction_id is None
