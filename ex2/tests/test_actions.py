from time import sleep
import pytest
import queue
import secrets
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.common import (
    hash_password,
    Header,
    ListAccountsRequest,
    LoginRequest,
    PaginatedRequest,
    MessageRequest,
    UnreadMessagesRequest,
    DeleteMessagesRequest,
    GenericRequest,
)

from src.models import Base, User, Token, Message
from src.server import db
from src.server.actions import (
    register,
    login,
    list_accounts,
    unread_messages,
    read_messages,
    send_message,
    delete_messages,
    delete_account,
)


# Create an in-memory SQLite engine.
@pytest.fixture(scope="function")
def dummy_engine():
    engine = create_engine("sqlite:///:memory:")
    # Create all tables in the in-memory database.
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


# Create a new session for each test function.
@pytest.fixture(scope="function")
def dummy_db(dummy_engine):
    TestingSessionLocal = sessionmaker(bind=dummy_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# Override the real db.session with our dummy session for each test.
@pytest.fixture(autouse=True)
def override_db_session(dummy_db, monkeypatch):
    monkeypatch.setattr(db, "session", dummy_db)


# Fixture to create a new user in the database.
@pytest.fixture
def create_user():
    def _create_user(username, password_hash):
        user = User(username=username, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()
        return user

    return _create_user


# Fixture to create a token for a given user.
@pytest.fixture
def create_token():
    def _create_token(user):
        token_value = secrets.token_bytes(32)
        token = Token(user_id=user.id, value=token_value)
        db.session.add(token)
        db.session.commit()
        return token

    return _create_token


# Fixture to create a message record.
@pytest.fixture
def create_message():
    def _create_message(from_id, to_id, content, read_at=None):
        message = Message(
            from_id=from_id,
            to_id=to_id,
            content=content,
            read_at=read_at,
            timestamp=datetime.now(),
        )
        db.session.add(message)
        db.session.commit()
        return message

    return _create_message


class DummyContext:
    pass


class DummyServer:
    def __init__(self):
        self.notifications = {}


@pytest.fixture
def dummy_context():
    return DummyContext()


@pytest.fixture
def dummy_server():
    return DummyServer()


# 1. Tests for the register action
def test_register_success(dummy_context):
    req = LoginRequest(username="testuser", password_hash=b"passwordhash")
    response = register(None, req, dummy_context)
    assert "login_token" in response
    assert isinstance(response["login_token"], bytes)

    # Verify the user is now in the database.
    user = db.session.query(User).filter_by(username="testuser").first()
    assert user is not None


def test_register_missing_username(dummy_context):
    req = LoginRequest(username="", password_hash=b"passwordhash")
    with pytest.raises(ValueError):
        register(None, req, dummy_context)


def test_register_missing_password_hash(dummy_context):
    req = LoginRequest(username="testuser", password_hash=b"")
    with pytest.raises(ValueError):
        register(None, req, dummy_context)


# 2. Tests for the login action
def test_login_success(dummy_context, create_user):
    username = "loginuser"
    password_hash = b"passwordhash"

    user = create_user(username, hash_password(password_hash))
    req = LoginRequest(username=username, password_hash=password_hash)
    response = login(None, req, dummy_context)
    assert "login_token" in response
    assert "unread_count" in response


def test_login_invalid_credentials(dummy_context):
    req = LoginRequest(username="nonexistent", password_hash=b"wronghash")
    with pytest.raises(ValueError):
        login(None, req, dummy_context)


# 3. Tests for list_accounts (requires valid login)
def test_list_accounts(dummy_context, create_user, create_token):
    # Create a current user and associated token.
    current_user = create_user("current", b"hash")
    token = create_token(current_user)

    # Create additional users.
    create_user("alice", b"hash1")
    create_user("bob", b"hash2")

    req = ListAccountsRequest(
        header=Header(login_token=token.value),
        pagination=PaginatedRequest(page=1, per_page=10),
    )
    response = list_accounts(None, req, dummy_context)
    usernames = [acc.username for acc in response["accounts"]]

    assert "accounts" in response
    assert isinstance(response["accounts"], list)
    assert len(response["accounts"]) >= 1

    assert "alice" in usernames
    assert "bob" in usernames
    assert "current" in usernames


def test_list_accounts_with_pattern(dummy_context, create_user, create_token):
    current_user = create_user("current", b"hash")
    token = create_token(current_user)
    create_user("alice", b"hash1")
    create_user("bob", b"hash2")
    req = ListAccountsRequest(pattern="ali%", header=Header(login_token=token.value))
    response = list_accounts(None, req, dummy_context)
    usernames = [acc.username for acc in response["accounts"]]
    assert "alice" in usernames


# 4. Tests for unread_messages
def test_unread_messages(dummy_context, create_user, create_token, create_message):
    current_user = create_user("receiver", b"hash")
    token = create_token(current_user)
    sender = create_user("sender", b"hash")

    # Create two unread messages.
    create_message(sender.id, current_user.id, "Hello", read_at=None)
    create_message(sender.id, current_user.id, "Hi", read_at=None)
    req = UnreadMessagesRequest(count=5, header=Header(login_token=token.value))
    response = unread_messages(None, req, dummy_context)
    assert "messages" in response
    assert len(response["messages"]) == 2

    # Ensure messages are now marked as read.
    messages = db.session.query(Message).filter_by(to_id=current_user.id).all()
    for m in messages:
        assert m.read_at is not None


# 5. Tests for read_messages (previously read messages)
def test_read_messages(dummy_context, create_user, create_token, create_message):
    current_user = create_user("reader", b"hash")
    token = create_token(current_user)
    sender = create_user("other", b"hash")

    # Create messages that are marked as read.
    msg1 = create_message(
        sender.id, current_user.id, "Old message", read_at=datetime.now()
    )
    msg2 = create_message(
        current_user.id, sender.id, "Sent message", read_at=datetime.now()
    )
    req = GenericRequest(
        pagination=PaginatedRequest(page=1, per_page=10),
        header=Header(login_token=token.value),
    )
    response = read_messages(None, req, dummy_context)
    assert "messages" in response

    # Verify that the messages are returned in descending order.
    timestamps = [msg.timestamp for msg in response["messages"]]
    assert timestamps == sorted(timestamps, reverse=True)


# 6. Tests for send_message
def test_send_message_success(dummy_context, dummy_server, create_user, create_token):
    sender = create_user("sender", b"hash")
    token = create_token(sender)
    recipient = create_user("recipient", b"hash")

    # Initialize the notifications queue for the recipient.
    dummy_server.notifications[recipient.id] = queue.Queue()
    req = MessageRequest(
        recipient="recipient",
        content="Hello there",
        header=Header(login_token=token.value),
    )
    response = send_message(dummy_server, req, dummy_context)
    assert "messages" in response

    messages = db.session.query(Message).filter_by(from_id=sender.id).all()
    assert len(messages) > 0
    assert any([m.content == "Hello there" for m in messages])


def test_send_message_missing_recipient(dummy_context, create_user, create_token):
    sender = create_user("sender", b"hash")
    token = create_token(sender)
    req = MessageRequest(
        recipient="", content="Hello there", header=Header(login_token=token.value)
    )
    with pytest.raises(ValueError):
        send_message(None, req, dummy_context)


def test_send_message_missing_content(dummy_context, create_user, create_token):
    sender = create_user("sender", b"hash")
    token = create_token(sender)
    req = MessageRequest(
        recipient="recipient", content="", header=Header(login_token=token.value)
    )
    with pytest.raises(ValueError):
        send_message(None, req, dummy_context)


def test_send_message_to_self(dummy_context, create_user, create_token):
    user = create_user("selfuser", b"hash")
    token = create_token(user)
    req = MessageRequest(
        recipient="selfuser", content="Hello", header=Header(login_token=token.value)
    )
    with pytest.raises(ValueError):
        send_message(None, req, dummy_context)


def test_send_message_recipient_not_exist(dummy_context, create_user, create_token):
    sender = create_user("sender", b"hash")
    token = create_token(sender)
    req = MessageRequest(
        recipient="nonexistent", content="Hello", header=Header(login_token=token.value)
    )
    with pytest.raises(ValueError):
        send_message(None, req, dummy_context)


# 7. Tests for delete_messages
def test_delete_messages_success(
    dummy_context, create_user, create_token, create_message
):
    current_user = create_user("deleter", b"hash")
    token = create_token(current_user)
    sender = create_user("sender", b"hash")
    message = create_message(
        sender.id, current_user.id, "To be deleted", read_at=datetime.now()
    )
    req = DeleteMessagesRequest(
        message_ids=[message.id], header=Header(login_token=token.value)
    )
    delete_messages(None, req, dummy_context)

    # Confirm the message is deleted.
    deleted = db.session.query(Message).filter_by(id=message.id).first()
    assert deleted is None


def test_delete_messages_invalid(
    dummy_context, create_user, create_token, create_message
):
    current_user = create_user("deleter", b"hash")
    token = create_token(current_user)
    other = create_user("other", b"hash")
    message = create_message(other.id, other.id, "Not yours", read_at=datetime.now())
    req = DeleteMessagesRequest(
        message_ids=[message.id], header=Header(login_token=token.value)
    )
    with pytest.raises(ValueError):
        delete_messages(None, req, dummy_context)


# 8. Test for delete_account
def test_delete_account(dummy_context, create_user, create_token):
    current_user = create_user("todelete", b"hash")
    token = create_token(current_user)
    req = GenericRequest(header=Header(login_token=token.value))
    delete_account(None, req, dummy_context)
    user = db.session.query(User).filter_by(id=current_user.id).first()
    assert user is None
