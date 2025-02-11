import argparse
from datetime import datetime, timedelta
import secrets
import selectors
import socket
import logging
from typing import Callable

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.sql import func

from src.models import Base, User, Message, Token
from src.request import Request, RequestCode
from src.lib import CODE_TO_OP, OP_TO_CODE

import config

# Set up logging
logging.basicConfig(
    format="%(module)s %(asctime)s %(funcName)s:%(lineno)d %(levelname)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

sel = selectors.DefaultSelector()

# Connected clients: maps username -> connection
connected_clients: dict[str, "ServerSocketHandler"] = {}

OP_TO_ACTION: dict[str, Callable] = {}


class ServerSocketHandler:
    def __init__(
        self,
        sock: socket.socket,
        addr: str,
        port: int,
        selector: selectors.BaseSelector,
    ):
        self.sock = sock
        self.addr = addr
        self.port = port
        self.selector = selector

        self.outb: Request = None
        self.token = None

        # Mark connection as ready for reads
        self.selector.register(self.sock, selectors.EVENT_READ, data=self)

    def read(self) -> Request:
        req = Request.receive(self.sock)
        self.selector.modify(self.sock, selectors.EVENT_WRITE, data=self)
        return req

    def write(self, request: Request):
        total, sent = request.push(self.sock)
        if total != sent:
            raise RuntimeError("Unable to write full request.")

        self.selector.modify(self.sock, selectors.EVENT_READ, data=self)

    def close(self):
        self.selector.unregister(self.sock)
        self.sock.close()


### HELPER FUNCTIONS
def op(operation: str) -> Callable:
    """
    Decorator function to register an operation on the server.

    Parameters
    ----------
    operation : str
        The name of the operation to register. Must be a valid key
        in the `OP_TO_CODE` dictionary.

    Returns
    -------
    Callable
        A decorator that, when applied to a function, registers that function
        in the `OP_TO_ACTION` dictionary using the operation code from `OP_TO_CODE`.

    Raises
    ------
    ValueError
        If the provided `operation` is not found in `OP_TO_CODE`.

    Examples
    --------
    >>> @op("register")
    ... def register(connection: ServerSocketHandler, username: str, password_hash: bytes, *args, **kwargs):
    ...     print(f"Registering user: {username}")
    ...     # Implementation details here...
    """
    if operation not in OP_TO_CODE:
        raise ValueError(f"Unknown operation: {operation}.")

    def decorator(func):
        OP_TO_ACTION[OP_TO_CODE[operation]] = func
        return func

    return decorator


def route(connection: ServerSocketHandler, request: Request):
    """
    Route an incoming request to the appropriate operation handler and
    return a response.

    The function looks up the handler associated with the given request code in
    the global dictionaries ``CODE_TO_OP`` and ``OP_TO_ACTION``. If the code is
    unknown or not yet implemented, a corresponding error is logged and an error
    response is placed in ``connection.outb``. Otherwise, the matched handler is
    invoked and its result is returned to the client via ``connection.outb``.

    Parameters
    ----------
    connection : ServerSocketHandler
        The active connection object. This function updates its ``outb`` attribute
        with a ``Request`` object, representing either a success or error response.
    request : Request
        The incoming request object.

    Notes
    -----
    - If ``request.request_code`` is not found in ``CODE_TO_OP``, a ``ValueError`` is
      raised internally and an error response is sent back to the client.
    - If ``request.request_code`` is valid but the corresponding operation is not
      implemented in ``OP_TO_ACTION``, a ``NotImplementedError`` is raised internally
      and an error response is sent back to the client.
    - Any other exception that occurs during the operation is caught, logged, and
      returned to the client as an error response.
    """
    try:
        if request.request_code not in CODE_TO_OP:
            raise ValueError(f"Unknown request code {request.request_code}.")

        if request.request_code not in OP_TO_ACTION:
            raise NotImplementedError(
                f"Server has not implemented operation code {request.request_code}."
            )

        ret = OP_TO_ACTION[request.request_code](connection, **request.data)
        connection.outb = Request(RequestCode.success, ret, request.request_id)

    except Exception as e:
        logger.error("%s: %s", e.__class__, str(e))
        connection.outb = Request(
            RequestCode.error, {"error": str(e)}, request.request_id
        )


def login_required(func: Callable) -> Callable:
    """
    Decorator function to require a valid login token for access.

    This decorator queries the database for a matching token and validates
    that it has not expired before passing the request onto the handler.

    Parameters
    ----------
    func : callable
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
    ... def restricted_action(current_user: User, *args, **kwargs):
    ...     return f"Hello {current_user.name}"
    """

    def decorator(*args, **kwargs):
        token = kwargs.get("token", b"")

        login_token = session.query(Token).filter_by(value=token).first()
        if not login_token or (datetime.now() - login_token.timestamp) > timedelta(
            minutes=int(config.TOKEN_VALIDITY)
        ):
            raise ValueError("Unauthorized.")

        return func(*args, current_user=login_token.user, **kwargs)

    return decorator


def error_(message: str):
    raise ValueError(message)


def soft_commit(session: Session, on_rollback: Callable = None):
    try:
        session.commit()
    except Exception as e:
        logger.error("%s: %s", e.__class__.__name__, str(e))
        session.rollback()

        # Handling
        if on_rollback:
            on_rollback(session, e)


### SERVER ACTIONS
@op("username_exists")
def username_exists(connection: ServerSocketHandler, username: str, *args, **kwargs):
    """
    Checks if an account with the specified username exists.
    """
    if not username:
        raise ValueError("Missing username.")

    return {
        "exists": (
            session.execute(
                session.query(func.count(User.id)).filter_by(username=username)
            ).scalar()
            > 0
        )
    }


@op("register")
def register(
    connection: ServerSocketHandler,
    username: str,
    password_hash: bytes,
    *args,
    **kwargs,
):
    """
    Creates a new account with the specified username and password_hash. Since the
    password is only received as a hash, it is up to the client to ensure that
    the password is only transmitted as a hash.

    NOTE(vboesu): This is probably not a great idea, maybe we should re-hash it
    on the server just to be sure.

    Parameters
    ----------
    username : str
        Username of the user attempting to log in.
    password_hash : bytes
        Password hash of the user.

    Returns
    -------
    dict[str]
        "token": Login token, to be used in subsequent server calls for identification.
    """
    if not username:
        raise ValueError("Missing username.")
    if not password_hash:
        raise ValueError("Missing password hash.")

    # Try adding user
    user = User(username=username, password_hash=password_hash)
    session.add(user)
    soft_commit(session, on_rollback=lambda: error_("User already exists."))

    # Generate login token
    connected_clients[username] = connection
    token = Token(user_id=user.id, value=secrets.token_bytes(32))
    session.add(token)
    soft_commit(session, on_rollback=lambda: error_("Unable to generate login token."))

    return {"token": token.value}


@op("login")
def login(
    connection: ServerSocketHandler,
    username: str,
    password_hash: bytes,
    *args,
    **kwargs,
):
    """
    Attempts to log in a user based on the provided username and password_hash.

    Parameters
    ----------
    username : str
        Username of the user attempting to log in.
    password_hash : bytes
        Password hash of the user.

    Returns
    -------
    dict[str]
        "unread": Number of undelivered and unread messages.
        "token": Login token, to be used in subsequent server calls for identification.
    """
    if not username:
        raise ValueError("Missing username.")
    if not password_hash:
        raise ValueError("Missing password hash.")

    user = (
        session.query(User)
        .filter_by(username=username, password_hash=password_hash)
        .first()
    )
    if not user:
        raise ValueError("Invalid login credentials.")

    # Generate login token
    connected_clients[username] = connection
    token = Token(user_id=user.id, value=secrets.token_bytes(32))
    session.add(token)
    soft_commit(session, on_rollback=lambda: error_("Unable to generate login token."))

    # Get number of unread messages
    unread_query = session.query(func.count(Message.id)).filter_by(
        to_id=user.id, read_at=None
    )

    return {"unread": session.execute(unread_query).scalar(), "token": token.value}


@op("accounts")
@login_required
def list_accounts(
    connection: ServerSocketHandler,
    *args,
    pattern: str = None,
    page: int = 1,
    per_page: int = 20,
    **kwargs,
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
        query = session.query(User).where(User.username.ilike(pattern))
        ct_query = session.query(func.count(User.id)).where(
            User.username.ilike(pattern)
        )
    else:
        query = session.query(User)
        ct_query = session.query(func.count(User.id))

    # Pagination
    page = max(page, 1)
    per_page = max(min(per_page, 100), 1)
    query = query.limit(per_page).offset((page - 1) * per_page)

    return {
        "items": [a.to_dict() for a in session.execute(query).scalars()],
        "page": page,
        "per_page": per_page,
        "total_count": session.execute(ct_query).scalar(),
    }


@op("unread_messages")
@login_required
def unread_messages(
    connection: ServerSocketHandler,
    current_user: User,
    *args,
    per_page: int = 20,
    **kwargs,
):
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
        session.query(Message)
        .filter((Message.to_id == current_user.id) & (Message.read_at.is_(None)))
        .order_by(Message.timestamp.asc())
    )
    ct_query = session.query(func.count(Message.id)).filter_by(
        to_id=current_user.id, read_at=None
    )

    # Pagination
    per_page = max(min(per_page, 100), 1)
    query = query.limit(per_page)

    items = [i for i in session.execute(query).scalars()]

    # Mark as read
    for i in items:
        i.read_at = datetime.now()

    soft_commit(session)

    return {
        "items": [i.to_dict() for i in items],
        "page": 1,
        "per_page": per_page,
        "total_count": session.execute(ct_query).scalar(),
    }


@op("read_messages")
@login_required
def read_messages(
    connection: ServerSocketHandler,
    current_user: User,
    *args,
    page: int = 1,
    per_page: int = 20,
    **kwargs,
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
        session.query(Message)
        .filter(
            ((Message.to_id == current_user.id) | (Message.from_id == current_user.id))
            & (Message.read_at.is_not(None))
        )
        .order_by(Message.timestamp.desc())
    )
    ct_query = session.query(func.count(Message.id)).filter_by(
        to_id=current_user.id, read_at=None
    )

    # Pagination
    page = max(page, 1)
    per_page = max(min(per_page, 100), 1)
    query = query.limit(per_page).offset((page - 1) * per_page)

    return {
        "items": [i.to_dict() for i in session.execute(query).scalars()],
        "page": page,
        "per_page": per_page,
        "total_count": session.execute(ct_query).scalar(),
    }


@op("message")
@login_required
def send_message(
    connection: ServerSocketHandler,
    current_user: User,
    to: str,
    content: str,
    *args,
    **kwargs,
):
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

    to_user = session.query(User).filter_by(username=to).first()
    if not to_user:
        raise ValueError("Recipient does not exist.")

    if to_user.id == current_user.id:
        raise ValueError("You cannot send messages to yourself. Find some friends!")

    # Create message
    message = Message(from_id=current_user.id, to_id=to_user.id, content=content)
    session.add(message)
    soft_commit(
        session,
        on_rollback=lambda: error_("Unable to send message. Try again later."),
    )

    # If recipient is logged in, attempt to immediately deliver the message
    if to in connected_clients:
        try:
            req_data = {"message": message.to_dict()}
            connected_clients[to].write(Request(RequestCode.push, req_data))

            # mark message as read
            message.read_at = datetime.now()
            soft_commit(session)

        except Exception as e:
            logger.error("%s: %s", e.__class__.__name__, str(e))
            del connected_clients[to]

    return {"message": message.to_dict()}


@op("delete_messages")
@login_required
def delete_messages(
    connection: ServerSocketHandler,
    current_user: User,
    messages: list[int],
    *args,
    **kwargs,
):
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
        message = session.query(Message).filter_by(id=message_id).first()
        if not message or current_user.id not in [message.from_id, message.to_id]:
            session.rollback()
            raise ValueError("Invalid message IDs.")

        session.delete(message)

    soft_commit(session)


@op("delete_account")
@login_required
def delete_account(
    connection: ServerSocketHandler, current_user: User, *args, **kwargs
):
    """
    Delete account of current user.
    """
    del connected_clients[current_user.username]
    session.delete(current_user)

    soft_commit(session)


def accept_client(sock: socket.socket, selector: selectors.BaseSelector):
    """
    Create a new connection with a new client.
    """
    conn, addr = sock.accept()
    logger.info(f"Accepted connection from {addr}")
    conn.setblocking(False)
    ServerSocketHandler(conn, addr[0], addr[1], selector)


def handle_client(key, mask):
    """
    Handle communication with a connected client.
    Maintains the current logged in username for the session.
    """
    connection = key.data

    if mask & selectors.EVENT_READ:
        try:
            req = connection.read()
            logger.debug("Reading %s", req)
            route(connection, req)
        except Exception as e:
            logger.error("%s: %s", e.__class__.__name__, str(e))
            connection.close()

    if mask & selectors.EVENT_WRITE:
        if connection.outb:
            try:
                logger.debug("Writing %s", connection.outb)
                connection.write(connection.outb)
                connection.outb = None
            except Exception as e:
                logger.error("%s: %s", e.__class__.__name__, str(e))
                connection.close()


def start_server(host: str, port: int):
    # Set up sockets
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((host, port))
    server_sock.listen(5)
    logger.info("Server listening on %s:%d", host, port)

    # Get IP address on local network
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_sock:
        dns_sock.connect(("8.8.8.8", 80))
        logger.info("Local IP address: %s", dns_sock.getsockname()[0])

    # Set up database
    global session
    engine = create_engine(config.DATABASE_URL, echo=config.DEBUG)
    Base.metadata.create_all(engine)  # create tables if necessary
    session = sessionmaker(bind=engine)()

    sel.register(server_sock, selectors.EVENT_READ, data=None)
    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_client(key.fileobj, sel)
                else:
                    handle_client(key, mask)
    except KeyboardInterrupt:
        logger.info("Caught keyboard interrupt, exiting")
    finally:
        server_sock.close()
        sel.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the server")
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host/IP to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(config.PORT),
        help=f"Port number to bind to (default: {config.PORT})",
    )
    args = parser.parse_args()
    start_server(args.host, args.port)
