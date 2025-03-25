from datetime import datetime
from typing import Callable

from sqlalchemy.sql import func

from src.common import hash_password, RequestCode
from src.models import Message, User

# from .socket import ServerSocketHandler, connected_clients
from .utils import error_, op, soft_commit
from . import db


def login_required(func: Callable) -> Callable:
    """
    Decorator function to require valid login data for access.

    This decorator queries the database for the reqested user and validates
    that the password hashes match before passing the request onto the handler.

    Parameters
    ----------
    func : callable
        The function to decorate. This function must accept keyword arguments,
        as the authentication data is passed via ``**kwargs``. The decorated
        function will receive an additional keyword argument ``current_user``
        of type ``User`` representing the validated user.

    Raises
    ------
    ValueError
        If the authentication is unsuccessful.

    Examples
    --------
    >>> @login_required
    ... def restricted_action(current_user: User, *args, **kwargs):
    ...     return f"Hello {current_user.name}"
    """

    def decorator(*args, **kwargs):
        username = kwargs.get("username", "")
        password_hash = kwargs.get("password_hash", b"")

        if not username:
            raise ValueError("Missing username.")
        if not password_hash:
            raise ValueError("Missing password hash.")

        user = (
            db.session.query(User)
            .filter_by(username=username, password_hash=hash_password(password_hash))
            .first()
        )
        if not user:
            raise ValueError("Invalid login credentials.")

        return func(*args, current_user=user, **kwargs)

    return decorator


@op("username_exists")
def username_exists(server, username: str, *args, **kwargs):
    """
    Checks if an account with the specified username exists.
    """
    if not username:
        raise ValueError("Missing username.")

    return {
        "exists": (
            db.session.execute(
                db.session.query(func.count(User.id)).filter_by(username=username)
            ).scalar()
            > 0
        )
    }


@op("register")
def register(server, username: str, password_hash: bytes, *args, **kwargs):
    """
    Creates a new account with the specified username and password_hash. Since the
    password is only received as a hash, it is up to the client to ensure that
    the password is only transmitted as a hash.

    Parameters
    ----------
    username : str
        Username of the user attempting to log in.
    password_hash : bytes
        Password hash of the user.
    """
    if not username:
        raise ValueError("Missing username.")
    if not password_hash:
        raise ValueError("Missing password hash.")

    # Try adding user, hash password again just to be sure
    user = User(username=username, password_hash=hash_password(password_hash))
    db.session.add(user)
    soft_commit(db.session, on_rollback=lambda: error_("User already exists."))

    return


@op("login")
@login_required
def login(server, current_user: User, *args, **kwargs):
    """
    Attempts to log in user, returns number of undelivered messages.

    Returns
    -------
    dict[str]
        "unread": Number of undelivered and unread messages.
    """
    # Get number of unread messages
    unread_query = db.session.query(func.count(Message.id)).filter_by(
        to_id=current_user.id, read_at=None
    )

    return {"unread": db.session.execute(unread_query).scalar()}


@op("accounts")
@login_required
def list_accounts(
    server, *args, pattern: str = None, page: int = 1, per_page: int = 20, **kwargs
):
    """
    List all accounts, optionally matching some provided ``pattern`` which
    may use SQL-style wildcard search for fuzzy matches.

    Parameters
    ----------
    pattern : str, optional
        Search pattern, by default None
    page : int, optional
        Page number of results, by default 1
    per_page : int, optional
        Number of items per page, by default 20

    Returns
    -------
    dict[str]
        "items": Current page of user accounts that match the query.
        "page": Requested page.
        "per_page": Number of items returned for this page.
        "total_count": Total number of accounts that match the query.
    """
    if pattern:
        # case-insensitive search
        query = db.session.query(User).where(User.username.ilike(pattern))
        ct_query = db.session.query(func.count(User.id)).where(
            User.username.ilike(pattern)
        )
    else:
        query = db.session.query(User)
        ct_query = db.session.query(func.count(User.id))

    # Pagination
    page = max(page, 1)
    per_page = max(min(per_page, 100), 1)
    query = query.limit(per_page).offset((page - 1) * per_page)

    return {
        "items": [a.to_dict() for a in db.session.execute(query).scalars()],
        "page": page,
        "per_page": per_page,
        "total_count": db.session.execute(ct_query).scalar(),
    }


@op("unread_messages")
@login_required
def unread_messages(server, current_user: User, *args, per_page: int = 20, **kwargs):
    """
    Retrieve up to ``per_page`` unread messages for the current user, oldest first.

    Parameters
    ----------
    per_page : int, optional
        Number of items per page, by default 20

    Returns
    -------
    dict[str]
        "items": Current page of unread messages.
        "page": Requested page, always 1.
        "per_page": Number of items returned for this page.
        "total_count": Total number of unread messages, including the ones returned.
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
    per_page = max(min(per_page, 100), 1)
    query = query.limit(per_page)

    items = [i for i in db.session.execute(query).scalars()]

    # Mark as read
    for i in items:
        i.read_at = datetime.now()

    soft_commit(db.session)

    return {
        "items": [i.to_dict() for i in items],
        "page": 1,
        "per_page": per_page,
        "total_count": db.session.execute(ct_query).scalar(),
    }


@op("read_messages")
@login_required
def read_messages(
    server, current_user: User, *args, page: int = 1, per_page: int = 20, **kwargs
):
    """
    Get previously read messages for the current user, newest first.

    Parameters
    ----------
    page : int, optional
        Page number of results, by default 1
    per_page : int, optional
        Number of items per page, by default 20

    Returns
    -------
    dict[str]
        "items": Current page of messages.
        "page": Requested page.
        "per_page": Number of items returned for this page.
        "total_count": Total number of read messages.
    """
    # Get all read messages with user, newest first
    query = (
        db.session.query(Message)
        .filter(
            ((Message.to_id == current_user.id) & (Message.read_at.is_not(None)))
            | (Message.from_id == current_user.id)
        )
        .order_by(Message.timestamp.desc())
    )
    ct_query = db.session.query(func.count(Message.id)).filter_by(
        to_id=current_user.id, read_at=None
    )

    # Pagination
    page = max(page, 1)
    per_page = max(min(per_page, 100), 1)
    query = query.limit(per_page).offset((page - 1) * per_page)

    return {
        "items": [i.to_dict() for i in db.session.execute(query).scalars()],
        "page": page,
        "per_page": per_page,
        "total_count": db.session.execute(ct_query).scalar(),
    }


@op("message")
@login_required
def send_message(server, current_user: User, to: str, content: str, *args, **kwargs):
    """
    Send a message to another user, identified by their username. If the recipient
    is online, deliver the message immediately.

    Parameters
    ----------
    to : str
        Username of the recipient.
    content : str
        Content of the message.

    Returns
    -------
    dict[str]
        "message": Compiled message.
    """
    if not to:
        raise ValueError("Missing recipient.")
    if not content:
        raise ValueError("Missing message content.")

    to_user = db.session.query(User).filter_by(username=to).first()
    if not to_user:
        raise ValueError("Recipient does not exist.")

    if to_user.id == current_user.id:
        raise ValueError("You cannot send messages to yourself. Find some friends!")

    # Create message
    message = Message(from_id=current_user.id, to_id=to_user.id, content=content)
    db.session.add(message)
    soft_commit(
        db.session,
        on_rollback=lambda: error_("Unable to send message. Try again later."),
    )

    # If recipient is logged in, attempt to immediately deliver the message
    # but only if we are the leader (TODO: this seems like an awful hack to put here...)
    with server.election_lock:
        if server.is_leader and to in server.connections_map:
            try:
                sent_to, _ = server.sh.send(
                    [server.connections_map[to]],
                    request_code=RequestCode.push,
                    request_id=0,
                    data={"message": message.to_dict()},
                    await_response=False,
                )

            except ConnectionRefusedError:
                del server.connections_map[to]

    return {"message": message.to_dict()}


@op("delete_messages")
@login_required
def delete_messages(server, current_user: User, messages: list[int], *args, **kwargs):
    """
    Delete a set of messages. All messages must be valid messages which include
    either as sender or recipient the current user, otherwise the call fails
    and no messages are deleted.

    Parameters
    ----------
    messages : list[int]
        List of message IDs to delete.
    """
    for message_id in messages:
        message = db.session.query(Message).filter_by(id=message_id).first()
        if not message or current_user.id not in [message.from_id, message.to_id]:
            db.session.rollback()
            raise ValueError("Invalid message IDs.")

        db.session.delete(message)

    soft_commit(db.session)


@op("mark_as_read")
@login_required
def mark_as_read(server, current_user: User, id: int, *args, **kwargs):
    """
    Mark a message as read.

    Parameters
    ----------
    id : int
        ID of message to mark as read.
    """
    message = db.session.query(Message).filter_by(id=id).first()
    if not message or current_user.id not in [message.from_id, message.to_id]:
        db.session.rollback()
        raise ValueError("Invalid message IDs.")

    message.read_at = datetime.now()
    soft_commit(db.session)


@op("delete_account")
@login_required
def delete_account(server, current_user: User, *args, **kwargs):
    """
    Delete account of current user.
    """
    db.session.delete(current_user)

    soft_commit(db.session)
