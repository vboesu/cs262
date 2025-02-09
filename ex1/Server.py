from datetime import datetime, timedelta
import secrets
import selectors
import socket

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

from src.models import Base, User, Message, Token
from src.connection import Connection
from src.request import Request, REQUEST_SUCCESS_CODE, REQUEST_ERROR_CODE
from src.lib import OP_TO_CODE

import config

sel = selectors.DefaultSelector()

# Connected clients: maps username -> connection
connected_clients = {}

OP_TO_ACTION = {}


### HELPER FUNCTIONS
def op(operation: str):
    if operation not in OP_TO_CODE:
        raise ValueError(f"Unknown operation: {operation}")

    def decorator(func):
        OP_TO_ACTION[OP_TO_CODE[operation]] = func
        return func

    return decorator


def route(connection: Connection, request: Request):
    fn = OP_TO_ACTION.get(request.request_code)
    try:
        if not fn:
            raise ValueError(f"Unknown request code {request.request_code}")

        ret = fn(connection, **request.data)
        connection.outb = Request(REQUEST_SUCCESS_CODE, ret)

    except Exception as e:
        connection.outb = Request(REQUEST_ERROR_CODE, {"error": str(e)})


def login_required(func):
    def decorator(*args, **kwargs):
        token = kwargs.get("token", b"")

        login_token = session.query(Token).filter_by(value=token).first()
        if not login_token or (datetime.now() - login_token.timestamp) > timedelta(
            minutes=int(config.TOKEN_VALIDITY)
        ):
            raise ValueError("Unauthorized.")

        return func(*args, current_user=login_token.user, **kwargs)

    return decorator


### SERVER ACTIONS
@op("register")
def register(
    connection: Connection, *args, username: str = None, password_hash: bytes = None
):
    if not username:
        raise ValueError("Missing username.")
    if not password_hash:
        raise ValueError("Missing password hash.")

    # Try adding user
    try:
        user = User(username=username, password_hash=password_hash)
        session.add(user)
        session.commit()
    except IntegrityError:
        session.rollback()
        raise ValueError("User already exists.")

    # Generate login token
    connected_clients[username] = connection
    try:
        token = Token(user_id=user.id, value=secrets.token_bytes(32))
        session.add(token)
        session.commit()
    except Exception as e:
        session.rollback()
        print(e)

    return {"token": token.value}


@op("login")
def login(
    connection: Connection, *args, username: str = None, password_hash: bytes = None
):
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
    try:
        token = Token(user_id=user.id, value=secrets.token_bytes(32))
        session.add(token)
        session.commit()
    except Exception as e:
        session.rollback()
        print(e)

    # Get number of unread messages
    unread_query = session.query(func.count(Message.id)).filter_by(
        to_id=user.id, read_at=None
    )

    return {"unread": session.execute(unread_query).scalar(), "token": token.value}


@op("accounts")
@login_required
def list_accounts(connection: Connection, *args, **kwargs):
    pattern = kwargs.get("pattern")
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
    page = max(kwargs.get("page", 1), 1)
    per_page = max(min(kwargs.get("per_page", 20), 100), 1)
    query = query.limit(per_page).offset((page - 1) * per_page)

    return {
        "items": [a.to_dict() for a in session.execute(query).scalars()],
        "page": page,
        "per_page": per_page,
        "total_count": session.execute(ct_query).scalar(),
    }


@op("unread_messages")
@login_required
def unread_messages(connection: Connection, current_user: User, *args, **kwargs):
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
    page = max(kwargs.get("page", 1), 1)
    per_page = max(min(kwargs.get("per_page", 20), 100), 1)
    query = query.limit(per_page).offset((page - 1) * per_page)

    return {
        "items": [i.to_dict() for i in session.execute(query).scalars()],
        "page": page,
        "per_page": per_page,
        "total_count": session.execute(ct_query).scalar(),
    }


@op("read_messages")
@login_required
def read_messages(connection: Connection, current_user: User, *args, **kwargs):
    # Get unread messages to user, oldest first
    query = (
        session.query(Message)
        .filter((Message.to_id == current_user.id) & (Message.read_at.is_not(None)))
        .order_by(Message.timestamp.asc())
    )
    ct_query = session.query(func.count(Message.id)).filter_by(
        to_id=current_user.id, read_at=None
    )

    # Pagination
    page = max(kwargs.get("page", 1), 1)
    per_page = max(min(kwargs.get("per_page", 20), 100), 1)
    query = query.limit(per_page).offset((page - 1) * per_page)

    return {
        "items": [i.to_dict() for i in session.execute(query).scalars()],
        "page": page,
        "per_page": per_page,
        "total_count": session.execute(ct_query).scalar(),
    }


@op("message")
@login_required
def message(
    connection: Connection, current_user: User, to: str, content: str, *args, **kwargs
):
    if not to:
        raise ValueError("Missing recipient.")
    if not content:
        raise ValueError("Missing message content.")

    to_user = session.query(User).filter_by(username=to).first()
    if not to_user:
        raise ValueError("Recipient does not exist.")

    # Create message
    try:
        message = Message(from_id=current_user.id, to_id=to_user.id, content=content)
        session.add(message)
        session.commit()
    except Exception as e:
        print(e)
        session.rollback()
        raise ValueError()

    # If recipient is logged in, attempt to immediately deliver the message
    if to in connected_clients:
        # TODO
        print("ATTEMPTING TO DELIVER")
        pass


@op("delete_account")
@login_required
def delete_account(connection: Connection, current_user: User, *args, **kwargs):
    try:
        del connected_clients[current_user.username]
        session.delete(current_user)
        session.commit()
    except Exception as e:
        print(e)
        session.rollback()
        connected_clients[current_user.username] = connection


def accept_client(sock: socket.socket, selector: selectors.BaseSelector):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    Connection(conn, addr[0], addr[1], selector)


def handle_client(key, mask):
    """
    Handle communication with a connected client.
    Maintains the current logged in username for the session.
    """
    connection = key.data

    if mask & selectors.EVENT_READ:
        try:
            req = connection.read()
            print("Read", req)
            route(connection, req)
        except Exception as e:
            print(e)
            connection.close()

    if mask & selectors.EVENT_WRITE:
        if connection.outb:
            print("Write", connection.outb)
            connection.write(connection.outb)
            connection.outb = None


def start_server():
    # Set up sockets
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((config.HOST, int(config.PORT)))
    server_sock.listen(5)
    print(f"Server listening on {config.HOST}:{config.PORT}")

    # Set up database
    global session
    engine = create_engine(config.DATABASE_URL, echo=True)
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
        print("Caught keyboard interrupt, exiting")
    finally:
        server_sock.close()
        sel.close()


if __name__ == "__main__":
    start_server()
