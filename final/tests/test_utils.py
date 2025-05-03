import pytest
import threading
import time
from collections import deque

from src.utils import Timer, build_sql_filters, build_select_query


def test_timer_basic_invocation():
    called = deque()

    def cb(x):
        called.append(x)

    timer = Timer(0.05, cb, "hello")
    timer.start()
    time.sleep(0.1)
    assert list(called) == ["hello"]


@pytest.mark.parametrize(
    "action_sequence,expected_calls",
    [
        (["start", "start", "start"], 1),
        (["start", "cancel"], 0),
        (["start", "start", "cancel"], 0),
    ],
)
def test_timer_restart_and_cancel(action_sequence, expected_calls):
    called = []

    def cb():
        called.append(True)

    timer = Timer(0.05, cb)
    for action in action_sequence:
        getattr(timer, action)()
        # small gap between actions
        time.sleep(0.01)
    time.sleep(0.1)
    assert len(called) == expected_calls


def test_timer_thread_safety_under_concurrent_start_and_cancel():
    called = []

    def cb():
        called.append(True)

    timer = Timer(0.05, cb)

    def worker_cycle():
        for _ in range(10):
            timer.start()
            time.sleep(0.005)
            timer.cancel()

    threads = [threading.Thread(target=worker_cycle) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # give any pending timer chance to fire
    time.sleep(0.1)
    # at most one callback due to race of restarts/cancels
    assert len(called) <= 1


def test_timer_restart_alias_behaves_same():
    called = []

    def cb():
        called.append(True)

    timer = Timer(0.05, cb)
    timer.start()
    timer.restart()
    time.sleep(0.1)
    assert len(called) == 1


def test_build_sql_filters_empty():
    q, params = build_sql_filters({}, None)
    assert q == "" and params == []


@pytest.mark.parametrize(
    "data,row_id,exp_q,exp_params",
    [
        ({"filters": {"a": 1, "b": 2}}, None, " WHERE a = ? AND b = ?", [1, 2]),
        ({}, "10", " WHERE id = ?", ["10"]),
        ({"filters": {"x": 9}}, "20", " WHERE x = ? AND id = ?", [9, "20"]),
    ],
)
def test_build_sql_filters_various(data, row_id, exp_q, exp_params):
    q, params = build_sql_filters(data, row_id)
    assert q == exp_q
    assert params == exp_params


def test_build_select_query_default_columns():
    q, params = build_select_query("tbl", {}, None)
    assert q == "SELECT tbl.* FROM tbl"
    assert params == []


def test_build_select_query_with_columns_and_filters():
    data = {"columns": ["id", "x"], "filters": {"x": 5}}
    q, params = build_select_query("t", data, None)
    assert q.startswith("SELECT t.id, t.x FROM t WHERE x = ?")
    assert params == [5]


def test_build_select_query_with_row_id_and_columns():
    data = {"columns": ["col1"]}
    q, params = build_select_query("s", data, "row42")
    assert q == "SELECT s.col1 FROM s WHERE id = ?"
    assert params == ["row42"]
