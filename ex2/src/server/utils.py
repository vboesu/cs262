import logging
import types
from typing import Callable
from copy import deepcopy

from sqlalchemy.orm.session import Session

from src.common.protocol_pb2 import ErrorResponse

logger = logging.getLogger(__name__)

# Defines which local method serves which operation
routing_registry: dict[str, Callable] = {}


def op(operation: str, response_cls: type, response_defaults: dict) -> Callable:
    """
    Decorator function to register an operation on the server.

    Parameters
    ----------
    operation : str
        The name of the operation to register.
    template_response
        Template response with default values set.

    Returns
    -------
    Callable
        A decorator that, when applied to a function, registers that function
        in the `routing_registry` dictionary.

    Examples
    --------
    >>> @op("register", ExampleResponse, {"required_default_value": 0})
    ... def register(server, request, context, *args, **kwargs):
    ...     print(f"Registering user: {username}")
    ...     # Implementation details here...
    """

    def decorator(fn: Callable):
        routing_registry[operation] = (fn, response_cls, response_defaults)
        return fn

    return decorator


def route(
    server, fn: Callable, response_cls: type, response_defaults: dict
) -> Callable:
    def wrapper(*args, **kwargs):
        try:
            result = fn(server, *args, **kwargs)
            if isinstance(result, (response_cls, types.GeneratorType)):
                return result

            elif isinstance(result, dict):
                return response_cls(**{**response_defaults, **result})

            return response_cls(**response_defaults)

        except Exception as e:
            logger.error("%s: %s", e.__class__, str(e))
            return response_cls(
                error=ErrorResponse(message=str(e)),
                **response_defaults,
            )

    return wrapper


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


class EmptyGenerator(object):
    def __iter__(self):
        return self

    def __next__(self):
        raise StopIteration
