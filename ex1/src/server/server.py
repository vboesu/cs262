import logging
import selectors
import socket

from .socket import ServerSocketHandler
from .utils import route
from . import db, actions  # noqa: F401

logger = logging.getLogger(__name__)


class Server:
    def __init__(self, host: str, port: int, db_url: str, verbose: bool = False):
        # Server information
        self.host = host
        self.port = port
        self.verbose = verbose
        self.db_url = db_url

        # Sockets
        self.connections = selectors.DefaultSelector()
        self.server_sock: socket.socket = None

        # Set up database
        db.session = db.create_session(self.db_url, self.verbose)

    def accept(self, sock: socket.socket):
        """
        Handle a new connection.

        Parameters
        ----------
        sock : socket.socket
            Initial socket of new client.
        """
        conn, addr = sock.accept()
        conn.setblocking(False)
        logger.info("Accepted connection from %s", addr)

        # Register socket for future reads/writes
        ServerSocketHandler(conn, addr[0], addr[1], self.connections)

    def handle(self, key, mask):
        """
        Handle an established connection.

        Parameters
        ----------
        key : _type_
            _description_
        mask : _type_
            _description_
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
            # Check if any data is outbound, flush if yes
            if connection.outb:
                try:
                    logger.debug("Writing %s", connection.outb)
                    connection.write(connection.outb)
                    connection.outb = None
                except Exception as e:
                    logger.error("%s: %s", e.__class__.__name__, str(e))
                    connection.close()

    def start(self):
        # Set up sockets
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(5)
        logger.info("Server listening on %s:%d", self.host, self.port)

        # Get IP address on local network
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_sock:
            dns_sock.connect(("8.8.8.8", 80))
            logger.info("Local IP address: %s", dns_sock.getsockname()[0])

        # Register server socket which accepts new connections as read-only
        self.connections.register(self.server_sock, selectors.EVENT_READ, data=None)

        # Main server loop
        try:
            while True:
                events = self.connections.select()  # blocks
                for key, mask in events:
                    if key.data is None:
                        self.accept(key.fileobj)
                    else:
                        self.handle(key, mask)

        except KeyboardInterrupt:
            logger.info("Caught keyboard interrupt, exiting")
        finally:
            self.server_sock.close()
            self.connections.close()
