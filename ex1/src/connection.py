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
        try:
            req = Request.receive(self.sock)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=self)
            return req
        except ConnectionResetError:
            self.close()

        return Request(0)

    def write(self, request: Request):
        try:
            push(self.sock, request)
            self.selector.modify(self.sock, selectors.EVENT_READ, data=self)
        except BrokenPipeError:
            self.close()

    def close(self):
        self.selector.unregister(self.sock)
        self.sock.close()
