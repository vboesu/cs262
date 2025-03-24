import logging
import socket
import time
import threading

from src.common import CODE_TO_OP, SocketHandler, Request, OP_TO_CODE

from .utils import route
from . import db, actions  # noqa: F401

logger = logging.getLogger(__name__)


class Server:
    def __init__(
        self,
        id: int,
        host: str,
        port: int,
        internal_port: int,
        db_url: str,
        replicas: list[tuple[str, int]],
        heartbeat_interval: float,
        verbose: int = 0,
    ):
        # Server information
        self.id = id
        self.host = host
        self.port = port
        self.internal_port = internal_port
        self.replicas = replicas
        self.verbose = verbose
        self.db_url = db_url
        self.heartbeat_interval = heartbeat_interval
        self.election_timeout = 3 * heartbeat_interval

        self.clock = 0
        self.log = []

        # Initially, the leader is chosen as the replica with the smallest id.
        self.leader_id = min(self.replicas.keys())
        self.is_leader = self.id == self.leader_id
        self.election_lock: threading.Lock = None
        self.election_timer: threading.Timer = None
        self.in_election = False
        self.last_heartbeat = 0

        # Connections
        self.listen_sock: socket.socket = None
        self.internal_sock: socket.socket = None
        self.sh: SocketHandler = None
        self.internal_sh: SocketHandler = None

        # Set up database
        db.session = db.create_session(self.db_url, self.verbose > 0)

    def receive(self, request: Request):
        # process in separate thread
        # threading.Thread(target=route, args=(self.sh, request), daemon=True).start()
        route(self.sh, request)

    def receive_internal(self, request: Request):
        logger.info(f"Received internal request {request}.")
        if request.request_code not in CODE_TO_OP:
            logger.warning(
                f"Received request with unknown operation code {request.request_code}."
            )
            return

        operation = CODE_TO_OP[request.request_code]

        if operation == "internal_heartbeat":
            with self.election_lock:
                self.last_heartbeat = time.time()
                self.leader_id = request.data.get("leader")

        elif operation == "internal_election":
            pass

        elif operation == "internal_leader_announce":
            with self.election_lock:
                self.last_heartbeat = time.time()
                self.leader_id = request.data.get("leader")

    def start(self):
        # Replica set up
        self.replica_setup()

        # Set up sockets
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.bind((self.host, self.port))
        self.listen_sock.listen(5)
        logger.info("Server listening on %s:%d", self.host, self.port)

        # Get IP address on local network
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_sock:
            dns_sock.connect(("8.8.8.8", 80))
            logger.info("Local IP address: %s", dns_sock.getsockname()[0])

        self.sh = SocketHandler(
            self.listen_sock,
            receive_callback=self.receive,
            timeout=2.0,
        )
        self.sh.default_data["response_port"] = self.port
        self.sh.start_listening(block=True)  # listen on main thread

    def replica_setup(self):
        self.election_lock = threading.Lock()
        with self.election_lock:
            self.last_heartbeat = time.time()
            self.election_timer = threading.Timer(
                self.election_timeout, self.call_election
            )
            self.election_timer.daemon = True

        # Set up socket for communication between replicas
        self.internal_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.internal_sock.bind((self.host, self.internal_port))
        self.internal_sock.listen(5)

        self.internal_sh = SocketHandler(
            self.internal_sock,
            receive_callback=self.receive_internal,
            timeout=self.heartbeat_interval / 2,
        )
        self.internal_sh.default_data["response_port"] = self.internal_port
        self.internal_sh.start_listening(block=False)  # listen on separate thread

        with self.election_lock:
            if self.is_leader:
                # Start sending out heartbeats
                threading.Thread(target=self.send_heartbeats, daemon=True).start()
            else:
                # Start monitoring for elections
                self.election_timer.start()

    def push(self, socket_handler: SocketHandler, *args, **kwargs):
        def _push(_socket_handler: SocketHandler, args, kwargs):
            try:
                _socket_handler.send(*args, **kwargs)

            except ConnectionRefusedError:
                pass

        kwargs["await_response"] = False
        threading.Thread(
            target=_push, args=(socket_handler, args, kwargs), daemon=True
        ).start()

    def broadcast_to_peers(self, request_code: int, data: dict | None = None):
        for peer_id, peer in self.replicas.items():
            if peer_id == self.id:
                continue

            # send asynchronously
            self.push(
                self.internal_sh,
                remote_hosts=[(peer["host"], peer["internal_port"])],
                request_code=request_code,
                data=data,
            )

    def send_heartbeats(self):
        # Leader sends heartbeat messages to all peers periodically.
        try:
            while True:
                self.broadcast_to_peers(
                    OP_TO_CODE["internal_heartbeat"], {"leader": self.id}
                )
                time.sleep(self.heartbeat_interval)

        except KeyboardInterrupt:
            pass

    def call_election(self):
        with self.election_lock:
            if self.in_election:
                return

            if time.time() - self.last_heartbeat <= self.election_timeout:
                self.election_timer = threading.Timer(
                    self.election_timeout, self.call_election
                )
                self.election_timer.daemon = True
                self.election_timer.start()
                return

            self.in_election = True
            self.leader_id = None  # TODO? what should happen during an election?

        logger.info("Calling an election!")

        # Leader election: elect leader with lowest ID
        to_message = [peer for id, peer in self.replicas.items() if id < self.id]
        responses = []

        for peer in to_message:
            try:
                sent_to, queue = self.internal_sh.send(
                    [(peer["host"], peer["internal_port"])],
                    OP_TO_CODE["internal_election"],
                )
                # if we get here, it means we were able to reach the peer
                responses.append(sent_to)

            except ConnectionRefusedError:
                pass

        if not responses:
            # No responses: declare self to be leader
            logger.info(f"Elected self ({self.id}) as leader.")
            self.leader_id = self.id
            self.is_leader = True

            # Broadcast leadership announcement
            self.broadcast_to_peers(
                OP_TO_CODE["internal_leader_announce"], {"leader": self.id}
            )

            # Start sending out heartbeats
            threading.Thread(target=self.send_heartbeats, daemon=True).start()

        else:
            logger.info(
                "Peer with lower ID responded, waiting for leader announcement."
            )

        with self.election_lock:
            self.in_election = False
