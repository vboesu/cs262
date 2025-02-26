from datetime import datetime
import queue
import secrets
from typing import Callable

import grpc
from sqlalchemy.sql import func

from src.common import (
    hash_password,
    Account,
    AccountResponse,
    GenericResponse,
    ListAccountsRequest,
    LoginRequest,
    LoginResponse,
    Message as RPCMessage,
    PaginatedResponse,
    RegisterResponse,
    MessageRequest,
    MessageResponse,
    UnreadMessagesRequest,
    DeleteMessagesRequest,
    GenericRequest,
)

from src.models import Message, Token, User
from .utils import error_, op, soft_commit, EmptyGenerator
from . import db


def login_required(fn: Callable) -> Callable:
    """
    Decorator function to require a valid login token for access.

    This decorator queries the database for a matching token and validates
    that it has not expired before passing the request onto the handler.

    Parameters
    ----------
    fn : callable
        The function to decorate. This function must accept keyword arguments,
        as the token is passed via ``**kwargs``. The decorated function will
        receive an additional keyword argument ``current_user`` of type ``User``
        representing the validated user.

    Raises
    ------
    ValueError
        If the token is not provided, does not match any stored token, or has
        expired.

    Examples
    --------
    >>> @login_required
    ... def restricted_action(request: ExampleRequest, current_user: User, *args, **kwargs):
    ...     return f"Hello {current_user.name}"
    """

    def decorator(server, request, context: grpc.ServicerContext):
        if request.header.login_token == b"":
            raise ValueError("Unauthorized.")

        login_token = (
            db.session.query(Token).filter_by(value=request.header.login_token).first()
        )

        if not login_token:
            raise ValueError("Unauthorized.")

        return fn(server, request, context, current_user=login_token.user)

    return decorator


@op("Register", RegisterResponse, {"login_token": b""})
def register(
    server, request: LoginRequest, context: grpc.ServicerContext, *args, **kwargs
):
    """
    Creates a new account with the specified username and password_hash. Since the
    password is only received as a hash, it is up to the client to ensure that
    the password is only transmitted as a hash.
    """
    if request.username == "":
        raise ValueError("Missing username.")
    if request.password_hash == b"":
        raise ValueError("Missing password hash.")

    # Try adding user, hash password again just to be sure
    user = User(
        username=request.username,
        password_hash=hash_password(request.password_hash),
    )
    db.session.add(user)
    soft_commit(db.session, on_rollback=lambda: error_("User already exists."))

    # Generate login token
    token = Token(user_id=user.id, value=secrets.token_bytes(32))
    db.session.add(token)
    soft_commit(
        db.session, on_rollback=lambda: error_("Unable to generate login token.")
    )

    return {"login_token": token.value}


@op("Login", LoginResponse, {"login_token": b"", "unread_count": 0})
def login(
    server, request: LoginRequest, context: grpc.ServicerContext, *args, **kwargs
):
    """
    Attempts to log in a user based on the provided username and password_hash.
    """
    if request.username == "":
        raise ValueError("Missing username.")
    if request.password_hash == b"":
        raise ValueError("Missing password hash.")

    # Hash the password again just to be sure
    user = (
        db.session.query(User)
        .filter_by(
            username=request.username,
            password_hash=hash_password(request.password_hash),
        )
        .first()
    )
    if not user:
        raise ValueError("Invalid login credentials.")

    # Generate login token
    token = Token(user_id=user.id, value=secrets.token_bytes(32))
    db.session.add(token)
    soft_commit(
        db.session, on_rollback=lambda: error_("Unable to generate login token.")
    )

    # Get number of unread messages
    unread_query = db.session.query(func.count(Message.id)).filter_by(
        to_id=user.id, read_at=None
    )

    return {
        "login_token": token.value,
        "unread_count": db.session.execute(unread_query).scalar(),
    }


@op("ListAccounts", AccountResponse, {"accounts": []})
@login_required
def list_accounts(
    server, request: ListAccountsRequest, context: grpc.ServicerContext, *args, **kwargs
):
    """
    List all accounts, optionally matching some provided ``pattern`` which
    may use SQL-style wildcard search for fuzzy matches.
    """
    if request.pattern not in ["", "*"]:
        # case-insensitive search
        query = db.session.query(User).where(User.username.ilike(request.pattern))
        ct_query = db.session.query(func.count(User.id)).where(
            User.username.ilike(request.pattern)
        )
    else:
        query = db.session.query(User)
        ct_query = db.session.query(func.count(User.id))

    # Pagination
    page = max(request.pagination.page, 1)
    per_page = max(min(request.pagination.per_page, 100), 1)
    query = query.limit(per_page).offset((page - 1) * per_page)

    return {
        "accounts": [
            Account(**a.to_dict()) for a in db.session.execute(query).scalars()
        ],
        "pagination": PaginatedResponse(
            page=page,
            per_page=per_page,
            total_count=db.session.execute(ct_query).scalar(),
        ),
    }


@op("GetUnreadMessages", MessageResponse, {"messages": []})
@login_required
def unread_messages(
    server,
    request: UnreadMessagesRequest,
    context: grpc.ServicerContext,
    current_user: User,
    *args,
    **kwargs,
):
    """
    Retrieve up to ``per_page`` unread messages for the current user, oldest first.
    """
    # Get unread messages to user, oldest first
    query = (
        db.session.query(Message)
        .filter((Message.to_id == current_user.id) & (Message.read_at.is_(None)))
        .order_by(Message.timestamp.asc())
    )
    ct_query = db.session.query(func.count(Message.id)).filter_by(
        to_id=current_user.id, read_at=None
    )

    # Pagination
    per_page = max(min(request.count, 100), 1)
    query = query.limit(per_page)

    items = [i for i in db.session.execute(query).scalars()]

    # Mark as read
    for i in items:
        i.read_at = datetime.now()

    soft_commit(db.session)

    return {
        "messages": [RPCMessage(**m.to_dict()) for m in items],
        "pagination": PaginatedResponse(
            page=1,
            per_page=per_page,
            total_count=db.session.execute(ct_query).scalar(),
        ),
    }


@op("GetMessages", MessageResponse, {"messages": []})
@login_required
def read_messages(
    server,
    request: UnreadMessagesRequest,
    context: grpc.ServicerContext,
    current_user: User,
    *args,
    **kwargs,
):
    """
    Get previously read messages for the current user, newest first.
    """
    # Get all read messages with user, newest first
    query = (
        db.session.query(Message)
        .filter(
            ((Message.to_id == current_user.id) | (Message.from_id == current_user.id))
            & (Message.read_at.is_not(None))
        )
        .order_by(Message.timestamp.desc())
    )
    ct_query = db.session.query(func.count(Message.id)).filter_by(
        to_id=current_user.id, read_at=None
    )

    # Pagination
    page = max(request.pagination.page, 1)
    per_page = max(min(request.pagination.per_page, 100), 1)
    query = query.limit(per_page).offset((page - 1) * per_page)

    return {
        "messages": [
            RPCMessage(**m.to_dict()) for m in db.session.execute(query).scalars()
        ],
        "pagination": PaginatedResponse(
            page=page,
            per_page=per_page,
            total_count=db.session.execute(ct_query).scalar(),
        ),
    }


@op("SendMessage", MessageResponse, {"messages": []})
@login_required
def send_message(
    server,
    request: MessageRequest,
    context: grpc.ServicerContext,
    current_user: User,
    *args,
    **kwargs,
):
    """
    Send a message to another user, identified by their username. If the recipient
    is online, deliver the message immediately.
    """
    if request.recipient == "":
        raise ValueError("Missing recipient.")
    if request.content == "":
        raise ValueError("Missing message content.")

    to_user = db.session.query(User).filter_by(username=request.recipient).first()
    if not to_user:
        raise ValueError("Recipient does not exist.")

    if to_user.id == current_user.id:
        raise ValueError("You cannot send messages to yourself. Find some friends!")

    # Create message
    message = Message(
        from_id=current_user.id, to_id=to_user.id, content=request.content
    )
    db.session.add(message)
    soft_commit(
        db.session,
        on_rollback=lambda: error_("Unable to send message. Try again later."),
    )

    # Attempt to immediately deliver the message
    server.notifications[to_user.id].put({"event": "message", "data": message})

    # # server.notifications.put()
    # server.active_listeners[to_user.id].put(message)

    return {"messages": [RPCMessage(**message.to_dict())]}


@op("DeleteMessages", GenericResponse, {})
@login_required
def delete_messages(
    server,
    request: DeleteMessagesRequest,
    context: grpc.ServicerContext,
    current_user: User,
    *args,
    **kwargs,
):
    """
    Delete a set of messages. All messages must be valid messages which include
    either as sender or recipient the current user, otherwise the call fails
    and no messages are deleted.
    """
    for message_id in request.message_ids:
        message = db.session.query(Message).filter_by(id=message_id).first()
        if not message or current_user.id not in [message.from_id, message.to_id]:
            db.session.rollback()
            raise ValueError("Invalid message IDs.")

        db.session.delete(message)

    soft_commit(db.session)


@op("DeleteAccount", GenericResponse, {})
@login_required
def delete_account(
    server,
    request: GenericRequest,
    context: grpc.ServicerContext,
    current_user: User,
    *args,
    **kwargs,
):
    """
    Delete account of current user.
    """
    db.session.delete(current_user)
    soft_commit(db.session)


@op("ListenForMessages", EmptyGenerator, {})
@login_required
def listen_for_messages(
    server,
    request: GenericRequest,
    context: grpc.ServicerContext,
    current_user: User,
    *args,
    **kwargs,
):
    """
    Register current user as listening for messages.
    """
    print("RECEIVED LISTENING REQUEST FROM " + current_user.username)
    server.notifications[current_user.id] = queue.Queue()  # TODO: thread safety

    # TODO: this blocks the thread so there is a limit to how many clients we
    # can have connected at the same time. not ideal.

    while True:
        notification = server.notifications[current_user.id].get()
        assert notification["event"] == "message"  # for now

        # mark message as read
        message = notification["data"]
        message.read_at = datetime.now()
        soft_commit(db.session)

        yield RPCMessage(**message.to_dict())
