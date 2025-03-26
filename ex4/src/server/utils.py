import logging
from typing import Callable

from sqlalchemy.orm.session import Session

from src.common import OP_TO_CODE

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
    ... def register(username: str, password_hash: bytes, *args, **kwargs):
    ...     print(f"Registering user: {username}")
    ...     # Implementation details here...
    """
    if operation not in OP_TO_CODE:
        raise ValueError(f"Unknown operation: {operation}.")

    def decorator(func):
        routing_registry[OP_TO_CODE[operation]] = func
        return func

    return decorator


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
