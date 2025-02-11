import selectors
import socket

from src.request import Request, push


class Connection:
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
        push(self.sock, request)
        self.selector.modify(self.sock, selectors.EVENT_READ, data=self)

    def close(self):
        self.selector.unregister(self.sock)
        self.sock.close()
