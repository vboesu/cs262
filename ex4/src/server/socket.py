import selectors
import socket

from src.common import Request


class ServerSocketHandler:
    """
    Class which takes care of the socket for the server. Supports
    reading and writing ``Request`` objects to and from sockets.
    """

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


# Connected clients: maps some identifier to connection
connected_clients: dict[str, ServerSocketHandler] = {}
