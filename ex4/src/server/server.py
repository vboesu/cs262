from collections import OrderedDict
import logging
import socket
import time
import threading
import queue

from src.common import CODE_TO_OP, SocketHandler, Request, RequestCode, OP_TO_CODE
from src.models import Log

from .utils import routing_registry, soft_commit, error_
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

        self.clock_lock: threading.Lock = None
        self.clock = 0

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

    def write_to_log(self, request: Request):
        with self.clock_lock:
            log_entry = Log(clock=self.clock, request=request.serialize())
            db.session.add(log_entry)
            soft_commit(db.session, on_rollback=lambda: error_("Database error."))

    def get_log(self, clock: int) -> Log | None:
        return db.session.query(Log).filter_by(clock=clock).first()

    def process(self, request: Request) -> tuple | None:
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
            logger.debug(f"Processed {request}, received response {response}.")

            with self.election_lock:
                if not self.is_leader:
                    return response

            # On success: broadcast to replicas. Keep track of every replica that
            # we were able to reach, and wait for their response acknowledging
            # the log entry.
            request_bytes = request.serialize()
            responses, queues = [], []
            n_reached = 0
            with self.clock_lock:
                self.clock += 1
                self.write_to_log(request)
                cclock = self.clock

            for peer_id, peer in self.replicas.items():
                if peer_id == self.id:
                    continue

                # send
                logger.debug(f"Attempting to broadcast to peer {peer_id}.")
                try:
                    sent_to, q = self.internal_sh.send(
                        [(peer["host"], peer["internal_port"])],
                        request_code=OP_TO_CODE["internal_log"],
                        data={"request": request_bytes, "clock": cclock},
                    )
                    queues.append(q)
                    n_reached += 1
                    logger.debug(f"Successfully broadcast to peer {peer_id}.")

                except ConnectionRefusedError:
                    logger.debug(f"Unable to broadcast to peer {peer_id}.")
                    continue

            # Wait for acknowledgements
            for q in queues:
                try:
                    logger.debug(f"Waiting for {q}.")
                    res = q.get(timeout=5)

                    logger.debug(f"Received response {res}.")

                    if res.request_code == OP_TO_CODE["internal_ok"]:
                        # Replica has made the change itself, all good
                        responses.append(res)

                    elif res.request_code == OP_TO_CODE["internal_request_log"]:
                        # Replica is still starting up, will make the change later;
                        # don't count it in the consensus process
                        n_reached -= 1

                        next_log = res.data.get("next")
                        # TODO: start pushing updates to this replica

                except queue.Empty:
                    continue

            logger.debug("Received all expected responses.")

            # Tally, raise error if no unanimous consent
            if len(responses) < len(queues):
                raise RuntimeError("Unable to process request. Please try again later.")

        except Exception as e:
            logger.error("%s: %s", e.__class__, str(e))
            response = (RequestCode.error, {"error": str(e)}, request.request_id)

        finally:
            logger.debug(f"Finishing up processing of {request}.")
            with self.election_lock:
                if not self.is_leader:
                    # We're a replica, we should not communicate with the client directly
                    return response

            # Return response to client
            logger.debug("Returning response to client.")
            response_code, response_data, _ = response
            self.sh.respond_to(request, response_code, response_data)

    def receive(self, request: Request):
        self.election_lock.acquire()
        if not self.is_leader:
            # If follower: forward request to leader, do not return a response
            # TODO: what happens if the request comes from within the network for the replica
            # but is sent to another network? It can't just return to 127.0.0.1 in that case
            self.election_lock.release()
            logger.debug("Forwarding request to leader...")
            self.forward_to_leader(request)
            return

        self.election_lock.release()
        self.process(request)

    def receive_internal(self, request: Request):
        logger.info(f"Received internal request {request}.")
        if request.request_code not in CODE_TO_OP:
            logger.warning(
                f"Received request with unknown operation code {request.request_code}."
            )
            return

        operation = CODE_TO_OP[request.request_code]

        if operation == "internal_heartbeat":
            logger.debug("Received heartbeat.")
            with self.election_lock:
                self.last_heartbeat = time.time()
                self.leader_id = request.data.get("leader")

        elif operation == "internal_election":
            pass

        elif operation == "internal_leader_announce":
            logger.debug("Received new leader announcement.")
            with self.election_lock:
                self.last_heartbeat = time.time()
                self.leader_id = request.data.get("leader")

        elif operation == "internal_log":
            logger.debug(f"Received internal log event with request {request}.")
            self.clock_lock.acquire()
            ts = request.data.get("clock")
            if ts > self.clock + 1:
                logger.debug(
                    f"Received log entry too far in the future ({ts}, currently at {self.clock})."
                )
                # We are missing data! Communicate this to the leader along with the next
                # log entry that we are missing
                self.internal_sh.respond_to(
                    request,
                    response_code=OP_TO_CODE["internal_request_log"],
                    response_data={"next": self.clock + 1},
                )
                self.clock_lock.release()

            elif ts == self.clock + 1:
                # This is the next log entry, so we can process it
                to_process = Request.parse(request.data.get("request"))
                self.clock = ts
                self.clock_lock.release()
                self.write_to_log(to_process)

                logger.debug(f"Request to process: {to_process}.")

                response_code, data, req_id = self.process(to_process)
                response_to_leader = (
                    OP_TO_CODE["internal_ok"]
                    if response_code == RequestCode.success
                    else OP_TO_CODE["internal_fail"]
                )

                logger.debug(f"Responding to leader with {response_to_leader}.")

                # Respond to leader on the leader's request, not the one from the client
                self.internal_sh.respond_to(request, response_code=response_to_leader)

    def start(self):
        # Replica set up
        self.replica_setup()

        # Set up sockets
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
        self.election_lock = threading.RLock()
        self.clock_lock = threading.RLock()

        with self.election_lock:
            self.last_heartbeat = time.time()
            self.election_timer = threading.Timer(
                self.election_timeout, self.call_election
            )
            self.election_timer.daemon = True

        # Set up socket for communication between replicas
        self.internal_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.internal_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.internal_sock.bind((self.host, self.internal_port))
        self.internal_sock.listen(5)

        self.internal_sh = SocketHandler(
            self.internal_sock,
            receive_callback=self.receive_internal,
            timeout=self.heartbeat_interval / 2,
        )
        self.internal_sh.default_data["response_port"] = self.internal_port
        self.internal_sh.start_listening(block=False)  # listen on separate thread

        self.election_lock.acquire()
        if self.is_leader:
            # Start sending out heartbeats
            self.election_lock.release()
            threading.Thread(target=self.send_heartbeats, daemon=True).start()
        else:
            # Start monitoring for elections
            self.election_timer.start()
            self.election_lock.release()

        # Set current clock time to latest one in the database
        with self.clock_lock:
            latest_log = db.session.query(Log).order_by(Log.clock.desc()).first()
            if latest_log:
                self.clock = latest_log.clock

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

    def push_to_leader(self, request_code: int, data: dict | None = None):
        with self.election_lock:
            if self.leader_id is None:
                raise ValueError("No leader set.")

            target = (
                self.replicas[self.leader_id]["host"],
                self.replicas[self.leader_id]["internal_port"],
            )

        self.push(
            self.internal_sh,
            remote_hosts=[target],
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
            with self.election_lock:
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

    def forward_to_leader(self, request: Request):
        request_bytes = request.serialize()
        self.push_to_leader(
            OP_TO_CODE["internal_forward_request"], {"request": request_bytes}
        )
