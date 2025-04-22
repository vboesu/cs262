import secrets
import selectors
import socket
import logging
import time
import weakref

from pathlib import Path
from threading import Thread, Lock, RLock, Event
from typing import Literal
from selectors import EVENT_READ as RD, EVENT_WRITE as WR

from flask import Flask, g

from api import api as api_bp
from consensus import Timer
from db import SQLiteDatabase

logger = logging.getLogger(__name__)

MAGIC = b"BVBV"
PROTOCOL_VERSION = 1


class SocketData:
    def __init__(self, addr: str, inb: bytes = b"", outb: bytes = b""):
        self.addr = addr
        self.inb = inb
        self.outb = outb
        self.sender_id = None


class Proxy:
    """
    Database proxy replica.

    Parameters
    ----------
    api_config : str | dict | object
            Configuration file, mapping or object for the Flask API.
    """

    def __init__(
        self,
        replica_config: dict,
        api_config: str | dict | object,
    ):
        self.rc = replica_config
        self.ac = api_config

        # Internal replica setup
        self.instance_path = Path(self.rc.get("instance_path", "instance"))
        self.instance_path.mkdir(0o755, parents=True, exist_ok=True)
        self.replicas: dict[int, dict] = self.rc.get("replicas", {})
        self.server_id: int = self.rc.get("id", 1)

        # Election setup
        self.hb_int = self.rc.get("heartbeat_interval", 100)  # in ms
        self.election_timeout = self.rc.get("election_timeout", 1000)  # in ms
        self.election_lock: Lock = None
        self.election_timer: Timer = None
        self.in_election: bool = False
        self.last_heartbeat: int = 0
        self.status: Literal["leader", "follower", "learner"] = "learner"
        self.leader = None

        # Query logging
        self.db = SQLiteDatabase(self.instance_path / "database.db")
        self.sync_log = open(self.instance_path / "sync.log", "a+")
        self.async_log = open(self.instance_path / "async.log", "a+")
        self.async_transaction_ids = set()

        self.clock_lock: Lock = None
        self.clock: int = 0

        # Socket connections to other replicas
        self.listen_sock: socket.socket = None
        self.connections: dict[int, weakref.ref[SocketData]] = {}
        self.stop_event: Event = None

        # Start "internal" API
        # self.start_internal()

        # Start external API
        # self.start_api()
        # self.api_thread = Thread(target=self.start_api, args=(api_config,), daemon=True)
        # self.api_thread.start()

    ### SETUP & START
    def start(self):
        self.internal_thread = Thread(target=self.start_internal, daemon=True)
        self.api_thread = Thread(target=self.start_api, daemon=True)

        self.internal_thread.start()
        self.api_thread.start()

        self.internal_thread.join()

    def start_internal(self):
        """
        Start the internal API for handling communication between replicas.
        """
        self.election_lock = RLock()
        self.clock_lock = RLock()
        self.stop_event = Event()
        self.selector = selectors.DefaultSelector()

        # Set up socket for communication between replicas
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind(("0.0.0.0", int(self.rc.get("PORT", 40004))))
        self.listen_sock.settimeout(1)  # block, release every second
        self.listen_sock.listen(self.rc.get("BACKLOG", 5))
        self.selector.register(self.listen_sock, RD, data=None)

        logger.info(f"Started internal server at {self.listen_sock.getsockname()}")

        with self.election_lock:
            self.last_heartbeat = time.time()
            # self.election_timer = Timer(self.election_timeout, self.call_election)

        with self.clock_lock:
            # TODO: Get latest entries from sync and async logs
            pass

        # Main loop for server, blocking
        try:
            while True:
                events = self.selector.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        self._accept(key.fileobj)
                    else:
                        self._service(key, mask)

        except KeyboardInterrupt:
            print("Caught keyboard interrupt, exiting")

        finally:
            self.selector.close()

    def start_api(self):
        """
        Start the external Flask API for handling queries.
        """
        self.api = Flask(__name__)
        self.api.before_request(self._before_api_request)

        # Load configuration
        if isinstance(self.ac, dict):
            self.api.config.from_mapping(self.ac)
        elif isinstance(self.ac, (str, object)):
            self.api.config.from_object(self.ac)

        self.api.secret_key = secrets.token_hex(32)

        self.api.register_blueprint(api_bp)
        self.api.run(use_reloader=False)

    ### EXTERNAL API HELPERS
    def _before_api_request(self):
        """
        Make proxy and database available to API endpoints.
        """
        g.proxy = self
        g.db = self.db

    ### INTERNAL
    def _receive(self, data: SocketData) -> tuple[int, str]:
        assert len(data.inb) >= 10

        magic = data.inb[:4]
        assert magic == MAGIC

        version = int.from_bytes(data.inb[4:5])
        assert version == PROTOCOL_VERSION

        command = data.inb[5:6]
        assert command

        payload_length = int.from_bytes(data.inb[6:10], "big", signed=False)
        payload = data.inb[10:]
        assert len(payload) == payload_length

        # If we made it here, we received a complete request. Consume all of the
        # data of this request, and return the extracted command + payload
        data.inb = data.inb[10 + len(payload) :]

        return command, payload

    def _prepare_send(self, data: SocketData, command: bytes, payload: bytes):
        """
        Store outgoing message in a `SocketData` object.
        """
        assert isinstance(command, bytes)
        assert isinstance(payload, bytes)
        assert len(command) == 1

        data.outb += (
            MAGIC
            + int.to_bytes(PROTOCOL_VERSION)
            + command
            + int.to_bytes(len(payload), 4, "big", signed=False)
            + payload
        )

    def _remove_connection(self, sock: socket.socket, data: SocketData):
        if data.sender_id is not None:
            _ = self.connections.pop(data.sender_id, None)

        logger.debug(f"Closing connection to {data.addr}")
        self.selector.unregister(sock)
        sock.close()

    def _accept(self, sock: socket.socket):
        conn, addr = sock.accept()
        logger.debug(f"Accepted connection {conn} from {addr}")
        conn.setblocking(False)

        self.selector.register(conn, RD | WR, data=SocketData(addr))

    def _service(self, key: selectors.SelectorKey, mask: int):
        sock: socket.socket = key.fileobj
        data: SocketData = key.data

        if mask & RD:
            recv = sock.recv(1024)  # receive in chunks of 1024 bytes
            if not recv:
                # Connection was closed by client
                self._remove_connection(sock, data)

            else:
                # We received some data; try to parse it
                data.inb += recv
                try:
                    cmd, payload = self._receive(data)
                    logger.debug(f"Request ({data.addr}): cmd={cmd}, payload={payload}")
                    self._handle(data, cmd, payload)
                except AssertionError:
                    pass

        if mask & WR and data.outb:
            logger.debug(f"Returning data {data.outb} to {data.addr}")
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]
            if sent == 0:
                self._remove_connection(sock, data)

    def _handle(self, data: SocketData, cmd: int, payload: bytes):
        if cmd == b"I":
            # The server is identifying itself
            sender_id = int.from_bytes(payload, "big", signed=False)
            self.connections[sender_id] = weakref.ref(data)

            # Return a handshake
            self._prepare_send(
                data, b"H", self.server_id.to_bytes(4, "big", signed=False)
            )

        elif cmd == b"H":
            # The server is returning a handshake
            sender_id = int.from_bytes(payload, "big", signed=False)
            self.connections[sender_id] = weakref.ref(data)
