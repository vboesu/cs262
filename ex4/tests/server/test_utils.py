import pytest

from src.common import OP_TO_CODE
from src.server.utils import op, error_, soft_commit, routing_registry


### DUMMIES
class DummySessionSuccess:
    """Simulates a session where commit succeeds."""

    def __init__(self):
        self.committed = False
        self.rolled_back = False

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


class DummySessionFailure:
    """Simulates a session where commit fails."""

    def __init__(self):
        self.committed = False
        self.rolled_back = False

    def commit(self):
        self.committed = True
        raise Exception("Commit failed")

    def rollback(self):
        self.rolled_back = True


### FIXTURES
@pytest.fixture()
def setup_op_to_code(monkeypatch):
    """
    Override the imported OP_TO_CODE with a dummy dictionary and
    clear the routing_registry before and after each test.
    """
    monkeypatch.setitem(OP_TO_CODE, "valid_key", 99)

    routing_registry.clear()
    yield
    routing_registry.clear()


def dummy_function(*args, **kwargs):
    return "dummy response"


### TESTS
def test_op_valid_registration(setup_op_to_code):
    """
    Test that applying @op with a valid operation registers the function.
    """
    decorated = op("valid_key")(dummy_function)
    # The decorator should return the original function.
    assert decorated == dummy_function

    # The routing_registry should now have an entry with the key from OP_TO_CODE.
    assert routing_registry.get(99) == dummy_function


def test_op_invalid_operation(setup_op_to_code):
    """
    Test that using @op with an unknown operation raises a ValueError.
    """
    with pytest.raises(ValueError, match="Unknown operation: unknown."):
        op("unknown")(dummy_function)


def test_error_function():
    """
    Test that error_ raises a ValueError with the given message.
    """
    with pytest.raises(ValueError, match="Test error message"):
        error_("Test error message")


def test_soft_commit_success():
    """
    Test that soft_commit successfully commits and does not rollback or call on_rollback.
    """
    session = DummySessionSuccess()
    callback_called = False

    def on_rollback():
        nonlocal callback_called
        callback_called = True

    soft_commit(session, on_rollback=on_rollback)
    assert session.committed is True
    assert session.rolled_back is False
    assert callback_called is False


def test_soft_commit_failure_with_callback():
    """
    Test that when commit fails, soft_commit calls rollback and invokes the on_rollback callback.
    """
    session = DummySessionFailure()
    callback_called = False

    def on_rollback():
        nonlocal callback_called
        callback_called = True

    soft_commit(session, on_rollback=on_rollback)
    assert session.committed is True
    assert session.rolled_back is True
    assert callback_called is True


def test_soft_commit_failure_without_callback():
    """
    Test that when commit fails, soft_commit calls rollback even if no on_rollback callback is provided.
    """
    session = DummySessionFailure()
    soft_commit(session)
    assert session.committed is True
    assert session.rolled_back is True
