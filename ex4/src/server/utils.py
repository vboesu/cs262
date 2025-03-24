import logging
from typing import Callable

from sqlalchemy.orm.session import Session

from src.common import Request, RequestCode, CODE_TO_OP, OP_TO_CODE, SocketHandler

logger = logging.getLogger(__name__)

# Defines which local method serves which operation
routing_registry: dict[str, Callable] = {}


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
        routing_registry[OP_TO_CODE[operation]] = func
        return func

    return decorator


def route(socket_handler: SocketHandler, request: Request):
    """
    Route an incoming request to the appropriate operation handler and
    return a response.

    The function looks up the handler associated with the given request code in
    the global dictionaries ``CODE_TO_OP`` and ``OP_TO_ACTION``.

    Parameters
    ----------
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
    response = None
    try:
        if request.request_code not in CODE_TO_OP:
            raise ValueError(f"Unknown request code {request.request_code}.")

        if request.request_code not in routing_registry:
            raise NotImplementedError(
                f"Server has not implemented operation code {request.request_code}."
            )

        ret = routing_registry[request.request_code](**request.data)
        response = (RequestCode.success, ret, request.request_id)

    except Exception as e:
        logger.error("%s: %s", e.__class__, str(e))
        response = (RequestCode.error, {"error": str(e)}, request.request_id)

    finally:
        # Return response to client
        remote_host, remote_port = request.addr
        response_port = request.data.get("response_port")
        logger.info(
            f"Returning response to {remote_host}:{remote_port} at port {response_port}"
        )

        req_code, data, req_id = response

        try:
            sent_to, _ = socket_handler.send(
                [(remote_host, response_port)],
                request_code=req_code,
                request_id=req_id,
                data=data,
                await_response=False,
            )

        except ConnectionRefusedError:
            logger.info(f"Unable to return response to {remote_host}:{response_port}.")


def error_(message: str):
    raise ValueError(message)


def soft_commit(session: Session, on_rollback: Callable = None):
    """
    Attempt to commit, rollback on failure. Optionally perform
    more actions if rollback occurs.

    Parameters
    ----------
    session : Session
        Session object to commit.
    on_rollback : Callable, optional
        Callback for rollback, by default None
    """
    try:
        session.commit()
    except Exception as e:
        logger.error("%s: %s", e.__class__.__name__, str(e))
        session.rollback()

        # Handling
        if on_rollback:
            on_rollback()
