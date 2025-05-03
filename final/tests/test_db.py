import pytest
import threading
from datetime import datetime
from uuid import uuid4

from src.db import SQLiteDatabase
from src.query import Query, Operation


@pytest.fixture
def script(tmp_path):
    path = tmp_path / "setup.sql"
    path.write_text("""
    CREATE TABLE t (
        id INTEGER PRIMARY KEY,
        x INTEGER
    );
    """)
    return str(path)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "test.db"
    return SQLiteDatabase(str(path))


@pytest.fixture
def db_with_t(tmp_path, script):
    path = tmp_path / "t.db"
    return SQLiteDatabase(str(path), setup_script=script)


def test_init_without_setup(tmp_path):
    db0 = SQLiteDatabase(str(tmp_path / "db0.db"))
    assert db0.tables == []


def test_init_with_setup(tmp_path, script):
    db1 = SQLiteDatabase(str(tmp_path / "db1.db"), setup_script=script)
    assert set(db1.tables) == {"t"}


def test_public_tables_after_creation(db):
    db.conn.execute("CREATE TABLE u(id);")
    db.conn.commit()
    names = db._public_tables()
    assert "u" in names


def test_dict_factory_and_try_execute(db):
    status, rows = db.try_execute("SELECT 1 AS a, 'foo' AS b", [])
    assert status == 0
    assert rows == [{"a": 1, "b": "foo"}]


def test_try_execute_error(db):
    status, rows = db.try_execute("SELECT * FROM missing", [])
    assert status != 0
    assert rows == []


def test_write_query_eventual_success(db_with_t):
    op = Operation(cmd=b"I", schema="t", data={"id": 1, "x": 2})
    q = Query([op])
    status, q2 = db_with_t.write_query(q)
    assert status == 0
    assert isinstance(q2.transaction_id, bytes)
    assert isinstance(q2.timestamp, datetime)
    assert q2.logical_timestamp == -1
    s, rows = db_with_t.try_execute("SELECT id, x FROM t", [])
    assert s == 0
    assert rows == [{"id": 1, "x": 2}]
    s2, logs = db_with_t.try_execute(
        "SELECT COUNT(*) AS cnt FROM internal_eventual_log WHERE transaction_id=?",
        [q2.transaction_id],
    )
    assert s2 == 0
    assert logs[0]["cnt"] == 1


def test_write_query_strong_success(db_with_t):
    tid = uuid4().bytes
    logical_ts = 10
    ts = datetime(2025, 5, 2, 15, 0)
    op = Operation(cmd=b"I", schema="t", data={"id": 3, "x": 4})
    q = Query([op])
    status, q2 = db_with_t.write_query(
        q, log="strong", transaction_id=tid, logical_timestamp=logical_ts, timestamp=ts
    )
    assert status == 0
    assert q2.transaction_id == tid
    assert q2.logical_timestamp == logical_ts
    assert q2.timestamp == ts
    s, logs = db_with_t.try_execute(
        "SELECT logical_timestamp FROM internal_strong_log WHERE transaction_id=?",
        [tid],
    )
    assert s == 0
    assert logs[0]["logical_timestamp"] == logical_ts


def test_update_and_delete_ops(db_with_t):
    db_with_t.conn.execute("INSERT INTO t (id, x) VALUES (?, ?)", (1, 100))
    db_with_t.conn.commit()
    op_up = Operation(
        cmd=b"U", schema="t", column="x", row=1, old_value=100, new_value=200
    )
    q_up = Query([op_up])
    status_u, _ = db_with_t.write_query(q_up)
    assert status_u == 0
    s_up, rows_up = db_with_t.try_execute("SELECT x FROM t WHERE id=?", [1])
    assert s_up == 0 and rows_up[0]["x"] == 200
    op_del = Operation(cmd=b"D", schema="t", row=1)
    q_del = Query([op_del])
    status_d, _ = db_with_t.write_query(q_del)
    assert status_d == 0
    s_d, rows_d = db_with_t.try_execute("SELECT * FROM t WHERE id=?", [1])
    assert s_d == 0 and rows_d == []


def test_write_query_failure_no_table(db_with_t):
    op = Operation(cmd=b"I", schema="nope", data={"id": 5})
    q = Query([op])
    status, q2 = db_with_t.write_query(q)
    assert status != 0
    assert q2.transaction_id is None
    s, logs = db_with_t.try_execute(
        "SELECT COUNT(*) AS cnt FROM internal_eventual_log", []
    )
    assert s == 0
    assert logs[0]["cnt"] == 0


# Concurrency tests to detect race conditions


def test_concurrent_inserts(db_with_t):
    def insert_row(i):
        op = Operation(cmd=b"I", schema="t", data={"id": i, "x": i})
        q = Query([op])
        status, _ = db_with_t.write_query(q)
        assert status == 0

    threads = [threading.Thread(target=insert_row, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    status, rows = db_with_t.try_execute("SELECT COUNT(*) AS cnt FROM t", [])
    assert status == 0
    assert rows[0]["cnt"] == 10

    status, logs = db_with_t.try_execute(
        "SELECT COUNT(*) AS cnt FROM internal_eventual_log", []
    )
    assert status == 0
    assert logs[0]["cnt"] == 10


def test_concurrent_reads(db_with_t):
    # prepare data
    for i in range(5):
        db_with_t.conn.execute("INSERT INTO t (id, x) VALUES (?, ?)", (i, i))
    db_with_t.conn.commit()

    results = []

    def read_count():
        status, rows = db_with_t.try_execute("SELECT COUNT(*) AS cnt FROM t", [])
        assert status == 0
        results.append(rows[0]["cnt"])

    threads = [threading.Thread(target=read_count) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(count == 5 for count in results)


def test_mixed_concurrent_operations(db_with_t):
    # start with empty table
    def writer(i):
        op = Operation(cmd=b"I", schema="t", data={"id": i, "x": i})
        q = Query([op])
        status, _ = db_with_t.write_query(q)
        assert status == 0

    def reader():
        status, rows = db_with_t.try_execute("SELECT COUNT(*) AS cnt FROM t", [])
        assert status == 0

    threads = []
    for i in range(5):
        threads.append(threading.Thread(target=writer, args=(i,)))
        threads.append(threading.Thread(target=reader))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    status, rows = db_with_t.try_execute("SELECT COUNT(*) AS cnt FROM t", [])
    assert status == 0
    assert rows[0]["cnt"] == 5
