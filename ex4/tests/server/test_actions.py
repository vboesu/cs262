import threading
from datetime import datetime

import pytest
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from src.common import hash_password, RequestCode
from src.models import Base, User, Message

from src.server import db as db_module
from src.server.actions import (
    login_required,
    username_exists,
    register,
    login,
    list_accounts,
    unread_messages,
    read_messages,
    send_message,
    delete_messages,
    mark_as_read,
    delete_account,
)


### DUMMIES
class DummySender:
    def __init__(self):
        self.sent = False
        self.last_request = None

    def send(self, remote_hosts, request_code, request_id, data, await_response):
        self.sent = True
        self.last_request = {
            "remote_hosts": remote_hosts,
            "request_code": request_code,
            "request_id": request_id,
            "data": data,
            "await_response": await_response,
        }
        # Simulate a successful send by returning the first remote host.
        return remote_hosts[0], None


class DummyServer:
    def __init__(self, is_leader=False):
        self.election_lock = threading.Lock()
        self.is_leader = is_leader
        self.connections_map = {}  # Maps recipient usernames to connection info.
        self.sh = DummySender()


### FIXTURES
@pytest.fixture
def db_session():
    """Set up an in-memory SQLite database and assign it to the global db.session."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    db_module.session = session
    yield session
    session.close()


@pytest.fixture
def dummy_server():
    """Return a dummy server with leadership enabled."""
    return DummyServer(is_leader=True)


### TESTS: LOGIN
def test_login_required_success(db_session):
    # Create a test user.
    password = "secret"
    user = User(username="testuser", password_hash=hash_password(password))
    db_session.add(user)
    db_session.commit()

    @login_required
    def dummy_action(*args, current_user=None, **kwargs):
        return current_user.username

    # Calling with correct credentials should return the username.
    result = dummy_action(username="testuser", password_hash=password)
    assert result == "testuser"


def test_login_required_missing_username(db_session):
    @login_required
    def dummy_action(*args, current_user=None, **kwargs):
        return True

    with pytest.raises(ValueError):
        dummy_action(password_hash="secret")


def test_login_required_missing_password(db_session):
    @login_required
    def dummy_action(*args, current_user=None, **kwargs):
        return True

    with pytest.raises(ValueError):
        dummy_action(username="testuser", password_hash="")


def test_login_required_invalid_credentials(db_session):
    @login_required
    def dummy_action(*args, current_user=None, **kwargs):
        return True

    with pytest.raises(ValueError):
        dummy_action(username="nonexistent", password_hash="secret")


### TESTS: ACTIONS
def test_username_exists_true(db_session):
    user = User(username="exists", password_hash=hash_password("pass"))
    db_session.add(user)
    db_session.commit()
    result = username_exists(None, username="exists")
    assert result["exists"] is True


def test_username_exists_false(db_session):
    result = username_exists(None, username="nonexistent")
    assert result["exists"] is False


def test_username_exists_missing_username(db_session):
    with pytest.raises(ValueError):
        username_exists(None, username="")


def test_register_success(db_session):
    register(None, username="newuser", password_hash="newpass")
    user = db_session.query(User).filter_by(username="newuser").first()
    assert user is not None
    assert user.password_hash == hash_password("newpass")


def test_register_missing_username(db_session):
    with pytest.raises(ValueError):
        register(None, username="", password_hash="pass")


def test_register_missing_password(db_session):
    with pytest.raises(ValueError):
        register(None, username="user", password_hash="")


def test_login_unread_messages(db_session):
    password = "loginpass"
    user = User(username="loginuser", password_hash=hash_password(password))
    db_session.add(user)
    db_session.commit()

    # Create three unread messages for the user.
    for i in range(3):
        msg = Message(
            from_id=1,
            to_id=user.id,
            content=f"msg {i}",
            read_at=None,
            timestamp=datetime.now(),
        )
        db_session.add(msg)
    db_session.commit()

    result = login(None, username="loginuser", password_hash=password)
    # Expect three unread messages.
    assert result["unread"] == 3


def test_list_accounts(db_session):
    # Create several users.
    users = [
        User(username="user1", password_hash=hash_password("pass1")),
        User(username="user2", password_hash=hash_password("pass2")),
        User(username="test", password_hash=hash_password("pass3")),
    ]
    db_session.add_all(users)
    db_session.commit()

    # Use one user for login (login_required) purposes.
    result = list_accounts(None, username="user1", password_hash="pass1")
    assert "items" in result
    assert result["page"] == 1
    assert result["per_page"] == 20
    total = result["total_count"]
    # Total count should be at least the number of users created.
    assert total >= 3

    # Test pattern filtering; e.g. '%user%' should match "user1" and "user2"
    result_pattern = list_accounts(
        None, username="user1", password_hash="pass1", pattern="%user%"
    )
    assert result_pattern["total_count"] == 2


def test_unread_messages(db_session):
    password = "upass"
    user = User(username="umsg", password_hash=hash_password(password))
    db_session.add(user)
    db_session.commit()

    # Create two unread messages.
    for i in range(2):
        msg = Message(
            from_id=1,
            to_id=user.id,
            content=f"unread {i}",
            read_at=None,
            timestamp=datetime.now(),
        )
        db_session.add(msg)
    db_session.commit()

    result = unread_messages(None, username="umsg", password_hash=password, per_page=10)
    assert "items" in result
    assert len(result["items"]) == 2

    # Verify that the messages have now been marked as read.
    messages = db_session.query(Message).filter_by(to_id=user.id).all()
    for msg in messages:
        assert msg.read_at is not None


def test_read_messages(db_session):
    password = "rpass"
    user = User(username="readuser", password_hash=hash_password(password))
    from_user = User(username="from_user", password_hash=hash_password("fpass"))
    db_session.add(user)
    db_session.add(from_user)
    db_session.commit()

    # Create three read messages.
    for i in range(3):
        msg = Message(
            from_id=from_user.id,
            to_id=user.id,
            content=f"read {i}",
            read_at=datetime.now(),
            timestamp=datetime.now(),
        )
        db_session.add(msg)
    db_session.commit()

    result = read_messages(
        None,
        username="readuser",
        password_hash=password,
        page=1,
        per_page=10,
    )

    assert result["total_count"] == 3
    assert isinstance(result["items"], list)


def test_send_message_success(db_session, dummy_server):
    # Create sender and recipient.
    sender = User(username="sender", password_hash=hash_password("sendpass"))
    recipient = User(username="recipient", password_hash=hash_password("recvpass"))
    db_session.add_all([sender, recipient])
    db_session.commit()

    # Simulate that the recipient is online.
    dummy_server.connections_map["recipient"] = ("127.0.0.1", 9999)

    result = send_message(
        dummy_server,
        username="sender",
        password_hash="sendpass",
        to="recipient",
        content="Hello there",
    )
    # Check that a message was created.
    msg = db_session.query(Message).filter_by(content="Hello there").first()
    assert msg is not None
    # Verify that DummySender.send was called.
    assert dummy_server.sh.sent is True
    assert "message" in result


def test_send_message_self(db_session, dummy_server):
    user = User(username="self", password_hash=hash_password("selfpass"))
    db_session.add(user)
    db_session.commit()

    with pytest.raises(ValueError):
        send_message(
            dummy_server,
            username="self",
            password_hash="selfpass",
            to="self",
            content="Hi",
        )


def test_send_message_recipient_not_found(db_session, dummy_server):
    user = User(username="sender2", password_hash=hash_password("pass"))
    db_session.add(user)
    db_session.commit()

    with pytest.raises(ValueError):
        send_message(
            dummy_server,
            username="sender2",
            password_hash="pass",
            to="nonexistent",
            content="Hi",
        )


def test_delete_messages_success(db_session):
    # Create a user and a message that belongs to that user.
    user = User(username="deleter", password_hash=hash_password("delpass"))
    db_session.add(user)
    db_session.commit()
    msg = Message(
        from_id=user.id,
        to_id=user.id,
        content="delete me",
        read_at=datetime.now(),
        timestamp=datetime.now(),
    )
    db_session.add(msg)
    db_session.commit()

    delete_messages(
        None, username="deleter", password_hash="delpass", messages=[msg.id]
    )
    deleted_msg = db_session.query(Message).filter_by(id=msg.id).first()
    assert deleted_msg is None


def test_delete_messages_invalid(db_session):
    user = User(username="deleter2", password_hash=hash_password("delpass"))
    other = User(username="other", password_hash=hash_password("otherpass"))
    db_session.add_all([user, other])
    db_session.commit()
    msg = Message(
        from_id=other.id,
        to_id=other.id,
        content="not yours",
        read_at=datetime.now(),
        timestamp=datetime.now(),
    )
    db_session.add(msg)
    db_session.commit()

    with pytest.raises(ValueError):
        delete_messages(
            None, username="deleter2", password_hash="delpass", messages=[msg.id]
        )


def test_mark_as_read(db_session):
    user = User(username="reader", password_hash=hash_password("readpass"))
    db_session.add(user)
    db_session.commit()
    msg = Message(
        from_id=1,
        to_id=user.id,
        content="mark read",
        read_at=None,
        timestamp=datetime.now(),
    )
    db_session.add(msg)
    db_session.commit()

    mark_as_read(None, username="reader", password_hash="readpass", id=msg.id)
    db_session.refresh(msg)
    assert msg.read_at is not None


def test_delete_account(db_session):
    user = User(username="delacc", password_hash=hash_password("accpass"))
    db_session.add(user)
    db_session.commit()

    delete_account(None, username="delacc", password_hash="accpass")
    deleted_user = db_session.query(User).filter_by(username="delacc").first()
    assert deleted_user is None
