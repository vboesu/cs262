from collections.abc import Iterable
import random
import secrets
import selectors
import socket
import logging
import time
import weakref

from pathlib import Path
from queue import Queue, Empty
from threading import Thread, Lock, RLock, Event, Condition
from typing import Literal
from selectors import EVENT_READ as RD, EVENT_WRITE as WR

from flask import Flask, g

from api import api as api_bp
from consensus import Timer
from db import SQLiteDatabase
from query import Query
from utils import is_strong_query

logger = logging.getLogger(__name__)


### CONSTANTS
MAGIC = b"BVBV"
PROTOCOL_VERSION = 1


class SocketData:
    def __init__(
        self,
        addr: str,
        sock: socket.socket,
        inb: bytes = b"",
        outb: bytes = b"",
    ):
        self.addr = addr
        self.sock = sock
        self.inb = inb
        self.outb = outb
        self.id = None
        self.inb_lock: Lock = RLock()
        self.outb_lock: Lock = RLock()


class Proxy:
    """
    Database proxy replica.

    Parameters
    ----------
    api_config : str | dict | object
        Configuration mapping or object for the Flask API.
    """

    def __init__(
        self,
        replica_config: dict,
        api_config: str | dict | object,
    ):
        self.rc = replica_config
        self.ac = api_config

        # Internal replica setup
        self.instance_path = Path(self.rc.get("INSTANCE_PATH", "instance"))
        self.instance_path.mkdir(0o755, parents=True, exist_ok=True)
        self.replicas: dict[int, str] = self.rc.get("REPLICAS", {})
        self.server_id: int = self.rc.get("SERVER_ID", 1)
        assert self.server_id in self.replicas
        self.sc = self.replicas[self.server_id]  # server (self) config
        self.strong_columns = self.rc.get("STRONG_CONSISTENCY", [])
        self.max_peer_id = max(self.replicas.keys())

        # Election setup
        self.hb_int = self.rc.get("HEARTBEAT_INTERVAL_MS", 100)  # in ms
        self.max_election_timeout = self.rc.get("ELECTION_TIMEOUT_MS", 1000)  # in ms
        assert self.max_election_timeout > 5 * self.hb_int
        self.election_lock: Lock = None
        self.election_timer: Timer = None
        self.election_condition: Condition = None
        self.in_election: bool = False
        self.last_leader_heartbeat: float = 0.0
        self.status: Literal["leader", "follower", "learner"] = "follower"
        self.leader: int | None = None

        if self.server_id == self.leader:
            self.status = "leader"

        # Query logging
        self.db = SQLiteDatabase(self.instance_path / "database.db")
        self.async_transaction_ids = set()
        self.async_queue: Queue[Query] = Queue()

        self.clock_lock: Lock = None
        self.clock: int = 0

        # Queues
        self.queue_lock: Lock = None
        self.queues: dict[bytes, Queue] = {}

        # Socket connections to other replicas
        self.listen_sock: socket.socket = None
        self.connections_lock: Lock = None
        self.connections: dict[int, tuple[float, weakref.ref[SocketData]]] = {}
        self.stop_event: Event = None
        self.internal_started = Event()

    @property
    def term(self) -> int:
        with self.clock_lock:
            return self.clock * (self.max_peer_id + 1) + self.server_id

    ### SETUP & START
    def start(self):
        self.internal_thread = Thread(target=self.start_internal, daemon=True)
        self.api_thread = Thread(target=self.start_api, daemon=True)

        self.internal_thread.start()
        self.api_thread.start()

        self.internal_thread.join()
        self.api_thread.join()

    def start_internal(self):
        """
        Start the internal API for handling communication between replicas.
        """
        self.election_lock = RLock()
        self.clock_lock = RLock()
        self.queue_lock = RLock()
        self.connections_lock = RLock()
        self.stop_event = Event()
        self.selector = selectors.DefaultSelector()

        # Set up socket for communication between replicas
        _, port = self.sc.split(":")
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind(("0.0.0.0", int(port)))  # bind to all by default
        self.listen_sock.settimeout(1)
        self.listen_sock.listen(self.rc.get("BACKLOG", 5))
        self.selector.register(self.listen_sock, RD, data=None)

        logger.info(f"Started internal server at {self.listen_sock.getsockname()}")

        with self.election_lock:
            self.last_leader_heartbeat = time.time()
            self.election_timeout = random.uniform(
                5 * self.hb_int, self.max_election_timeout
            )
            self.election_timer = Timer(
                self.election_timeout / 1000, self.call_election
            )
            self.election_condition = Condition(self.election_lock)
            self.election_timer.start()

        with self.clock_lock:
            # Update logical clock from strong log in database
            q = Query(
                method="SELECT",
                query="SELECT MAX(id) AS max FROM internal_strong_log",
            )
            status, results = self.db.try_query(q)
            assert status == 0
            self.clock = results[0]["max"] or 0
            logger.debug(f"Started with logical clock {self.clock}")

            # TODO: Get latest entries from async logs

        # Start establishing connections to other replicas
        th = Thread(target=self._establish_connections, daemon=True)
        th.start()

        self.internal_started.set()

        # Main loop for server, blocking
        try:
            while not self.stop_event.is_set():
                events = self.selector.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        self._accept(key.fileobj)
                    else:
                        self._service(key, mask)

        except KeyboardInterrupt:
            self.stop_event.set()
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

        # Wait for internal API to have started up
        self.internal_started.wait()

        self.api.register_blueprint(api_bp)
        self.api.run(use_reloader=False)

    ### EXTERNAL API HELPERS
    def _before_api_request(self):
        """
        Make proxy and database available to API endpoints.
        """
        g.proxy = self
        g.db = self.db

    def dispatch(
        self,
        method: str,
        schema: str,
        query: str,
        params: list,
        columns: list[str],
    ):
        """
        Process a query from the external API.
        """
        # Determine the consistency requirement for the query
        strong = is_strong_query(columns, self.strong_columns)

        query = Query(method=method, schema=schema, query=query, params=params)
        logger.debug(f"DISPATCHING QUERY {query} (strong={strong})")

        if method == "SELECT":
            # SELECT queries can be performed consistently by any replica
            status, result = self.db.try_query(query)
            logger.debug(f"FINISHED QUERY WITH RESULT {result}")

            if status != 0:
                return {"error": f"Database error (code: {status})"}, 400

            return result, 200

        elif strong:
            # Forward strong queries to the leader
            status = self.send_query_to_leader(query)
            logger.debug(f"FINISHED QUERY WITH STATUS {status}")

            if status != 0:
                return {"error": f"Database error (code: {status})"}, 400

            return {}, 200

        else:
            # Implement weak queries ourselves
            status, result = self.db.try_query(query, "eventual")
            logger.debug(f"FINISHED QUERY WITH STATUS {status}")

            if status != 0:
                return {"error": f"Database error (code: {status})"}, 400

            # Send query to other replicas
            self._broadcast(b"A", query.encode())

            return {}, 200

    ### INTERNAL
    def _connect_to_peer(self, peer_id: int, raise_exc: bool = False):
        """
        Attempt to establish a socket connection to a peer if no connection
        exists, yet.
        """
        assert peer_id in self.replicas
        addr = self.replicas[peer_id]

        with self.connections_lock:
            if peer_id in self.connections:
                ts, data = self.connections[peer_id]
                time_since_last_hs = (time.time() - ts) * 1000
                if time_since_last_hs > 3 * self.hb_int:
                    # We haven't heard from this connection in a while,
                    # make sure that it still works
                    self.__initiate_handshake(data())

                return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host, port = addr.split(":")
            sock.connect((host, int(port)))

            # Store connection
            data = SocketData(addr, sock)
            data.id = peer_id
            self.selector.register(sock, RD, data=data)
            self._update_connection(data)

            # Tell the other replica about us
            self.__initiate_handshake(data)

        except Exception as e:
            # logger.debug(f"Unable to connect to {peer_id} ({addr}): {str(e)}")
            if raise_exc:
                raise e

    def _establish_connections(self):
        """
        Continuously try to establish connections to all other replicas.
        Should be run in a separate thread.
        """
        self.threads: dict[int, Thread] = {}
        while not self.stop_event.is_set():
            for peer_id in self.replicas:
                if peer_id == self.server_id:
                    continue

                if peer_id in self.threads and self.threads[peer_id].is_alive():
                    # Avoid spamming threads unnecessarily
                    continue

                th = Thread(target=self._connect_to_peer, args=(peer_id,), daemon=True)
                th.start()
                self.threads[peer_id] = th

            time.sleep(self.hb_int / 1000)

    def _receive(self, data: SocketData) -> tuple[bytes, bytes]:
        """
        Wait until we have received a full request from a client
        identified by a `SocketData` or until we can definitely
        say that we are receiving an invalid request.

        Parameters
        ----------
        data : SocketData
            SocketData object of the sending client.

        Returns
        -------
        tuple[bytes, bytes]
            Command, payload
        """
        with data.inb_lock:
            if len(data.inb) < 4:
                return b"", b""

            magic = data.inb[:4]
            if magic != MAGIC:
                raise ValueError("Invalid request type.")

            if len(data.inb) < 5:
                return b"", b""

            version = int.from_bytes(data.inb[4:5], "big", signed=False)
            if version != PROTOCOL_VERSION:
                raise ValueError("Unknown request version.")

            if len(data.inb) < 6:
                return b"", b""

            command = data.inb[5:6]

            if len(data.inb) < 10:
                return b"", b""

            payload_length = int.from_bytes(data.inb[6:10], "big", signed=False)
            payload = data.inb[10 : 10 + payload_length]
            if len(payload) < payload_length:
                return b"", b""

            # If we made it here, we received a complete request. Consume all of the
            # data of this request, and return the extracted command + payload
            data.inb = data.inb[10 + payload_length :]

        return command, payload

    def _prepare_send(self, data: SocketData, command: bytes, payload: bytes):
        """
        Store outgoing message in a `SocketData` object.
        """
        assert isinstance(command, bytes)
        assert isinstance(payload, bytes)
        assert len(command) == 1

        with data.outb_lock:
            data.outb += (
                MAGIC
                + PROTOCOL_VERSION.to_bytes(1, "big", signed=False)
                + command
                + len(payload).to_bytes(4, "big", signed=False)
                + payload
            )

        # Mark socket as writeable again so that `select` picks it up
        self.selector.modify(data.sock, RD | WR, data=data)

    def _remove_connection(self, sock: socket.socket, data: SocketData):
        """
        Remove a socket connection and its corresponding `SocketData`
        object from `connections` dictionary and the selector.
        """
        if data.id is not None:
            with self.connections_lock:
                _ = self.connections.pop(data.id, None)

        logger.debug(f"Closing connection to {data.addr}")

        try:
            self.selector.unregister(sock)
            sock.close()

        except Exception:
            pass

    def _send_to_peer(
        self, peer_id: int, command: bytes, payload: bytes, raise_exc: bool = False
    ):
        """
        Attempt to send a message to a peer.
        """
        assert peer_id in self.replicas
        addr = self.replicas[peer_id]

        self._connect_to_peer(peer_id, raise_exc=raise_exc)

        try:
            with self.connections_lock:
                ts, data = self.connections[peer_id]
                self._prepare_send(data(), command, payload)

            logger.debug(f"Message to {addr}: cmd={command}, pl={payload}")

        except Exception as e:
            # logger.warning(f"Unable to send message to {peer_id} ({addr}): {str(e)}")
            if raise_exc:
                raise e

    def _broadcast(self, command: bytes, payload: bytes):
        """
        Attempt to send a message to all peers (not including self).
        """
        for id in self.replicas:
            if id == self.server_id:
                continue

            self._send_to_peer(id, command, payload)

    def _accept(self, sock: socket.socket):
        """
        Accept a new connection on a socket.
        """
        conn, addr = sock.accept()
        logger.debug(f"Accepted connection {conn} from {addr}")
        conn.setblocking(False)

        self.selector.register(conn, RD, data=SocketData(addr, conn))

    def _service(self, key: selectors.SelectorKey, mask: int):
        """
        Service an existing connection for reads & writes.
        """
        sock: socket.socket = key.fileobj
        data: SocketData = key.data

        if mask & RD:
            recv = b""
            try:
                recv = sock.recv(1024)  # receive in chunks of 1024 bytes
                if not recv:
                    raise ConnectionResetError

            except OSError:
                self._remove_connection(sock, data)
                return

            # We received some data; try to parse it
            with data.inb_lock:
                data.inb += recv

            try:
                cmd, payload = self._receive(data)
                if cmd:
                    logger.debug(f"Request ({data.addr}): cmd={cmd}, pl={payload}")
                    th = Thread(target=self._handle, args=(data, cmd, payload))
                    th.daemon = True
                    th.start()
                    # self._handle(data, cmd, payload)

            except ValueError as e:
                logger.warning(f"Invalid request ({data.addr}): {str(e)}")
                logger.error(e, exc_info=True)
                self._remove_connection(sock, data)

        with data.outb_lock:
            if mask & WR and data.outb:
                logger.debug(f"Returning data {data.outb} to {data.addr}")
                try:
                    sent = sock.send(data.outb)

                    if sent == 0:
                        raise ConnectionResetError

                    data.outb = data.outb[sent:]
                    if not data.outb:
                        # This avoids excessive polling
                        self.selector.modify(data.sock, RD, data=data)

                except OSError:
                    self._remove_connection(sock, data)
                    return
                    # TODO: does this avoid data loss??
                    # with self.connections_lock:
                    #     if data.id in self.connections:
                    #         self.connections[data.id]().outb += data.outb

    def _handle(self, data: SocketData, cmd: int, payload: bytes):
        """
        Handle a received request with some command and payload. If
        you want to return something to the sender, place the outgoing
        bytes into `data.outb`.
        """
        if cmd == b"I":
            # Another server initiated a handshake
            self.__receive_handshake(data, payload)
            self.__return_handshake(data)

        elif cmd == b"H":
            # Another server responded to a handshake
            self.__receive_handshake(data, payload)

        elif cmd == b"A":
            # We received an asynchronous/weak query
            self.__process_weak_query(data, payload)

        ## ACTIONS FOR LEADER
        elif cmd == b"Q":
            # A follower sent us a query to propose
            self.__distribute_query(data, payload)

        elif cmd == b"R":
            # A follower responded to a query we proposed
            self.__collect_query(data, payload)

        elif cmd == b"V":
            # A follower responded to our election call
            self.__process_vote(data, payload)

        elif cmd == b"T":
            # A follower requests entries from strong log
            self.__teach(data, payload)

        ## ACTIONS FOR FOLLOWER
        elif cmd == b"P":
            # The leader sent us a strong query to perform
            self.__process_strong_query(data, payload)

        elif cmd == b"S":
            # A query we sent to the leader has a final status
            self.__status_query(data, payload)

        elif cmd == b"E":
            # Another server started an election
            self.__process_election(data, payload)

        elif cmd == b"W":
            # Another server declared itself the winner
            self.__process_winner(data, payload)

        elif cmd == b"L":
            # The leader sent us an earlier entry to learn about
            self.__learn(data, payload)

        # elif cmd == b"K":
        #     # We received a keepalive
        #     self.__keepalive(data, payload)

    def _wait_for_queues(self, keys: Iterable, timeout: float = 5.0) -> dict:
        """
        Monitor `keys` for objects placed in the corresponding queues, return
        once all queues have received at least one object or timeout.
        """
        results = {}

        def _poll(keys: set):
            while not keys.issubset(results.keys()):
                for key in keys - results.keys():
                    try:
                        result = self.queues[key].get_nowait()
                        results[key] = result

                    except Empty:
                        pass

                time.sleep(0.01)  # reduce polling

        th = Thread(target=_poll, args=(set(keys),), daemon=True)
        th.start()
        th.join(timeout)

        # Clean up
        with self.queue_lock:
            for key in keys:
                self.queues.pop(key)

        return results

    def _update_connection(self, data: SocketData):
        if data.id is None:
            return

        with self.connections_lock:
            self.connections[data.id] = (time.time(), weakref.ref(data))

    def _handle_weak_queries(self):
        """
        Grab weak queries from the queue and process them. Should be
        run in a separate thread for concurrent processing.
        """
        while not self.stop_event.is_set():
            try:
                query = self.async_queue.get(timeout=1)
                if query.id in self.async_transaction_ids:
                    continue

                status, _ = self.db.try_query(query, "eventual")
                if status == 0:
                    self.async_transaction_ids.add(query.id)
                else:
                    logger.info(f"Query {query} failed, exited with status {status}.")

            except Empty:
                pass

    ### INTERNAL ACTIONS
    def __initiate_handshake(self, data: SocketData):
        """Identify self to other replica."""
        payload = self.server_id.to_bytes(4, "big", signed=False)

        with self.clock_lock:
            payload += self.clock.to_bytes(4, "big", signed=False)

        with self.election_lock:
            if self.status == "leader":
                payload += b"\x01"

        self._prepare_send(data, b"I", payload)

    def __receive_handshake(self, data: SocketData, payload: bytes):
        """Process identification from other replica."""
        data.id = int.from_bytes(payload[:4], "big", signed=False)
        self._update_connection(data)
        logger.debug(f"Received handshake from {data.id}.")

        clock = int.from_bytes(payload[4:8], "big", signed=False)

        is_leader = payload[8:]
        if is_leader == b"\x01":
            with self.election_lock:
                if not self.in_election:
                    logger.debug(f"Accepted leader {self.leader}.")
                    self.leader = data.id

        # TODO: check if this can create deadlock bc of ordering
        with self.election_lock:
            with self.clock_lock:
                if clock > self.clock + 1:
                    self.status = "learner"
                    self._start_learning()

    def __return_handshake(self, data: SocketData):
        """Identify self to other replica in response to handshake."""
        payload = self.server_id.to_bytes(4, "big", signed=False)

        with self.clock_lock:
            payload += self.clock.to_bytes(4, "big", signed=False)

        with self.election_lock:
            if self.status == "leader":
                payload += b"\x01"

        self._prepare_send(data, b"H", payload)

    def __process_election(self, data: SocketData, payload: bytes):
        """Process call for election."""
        term = int.from_bytes(payload, "big", signed=False)
        logger.debug(f"Received election with term {term}.")

        with self.election_lock:
            if self.status == "leader":
                # Reject the election, announce ourselves as leader
                self._prepare_send(data, b"V", payload + b"\x00")
                self._prepare_send(
                    data,
                    b"W",
                    self.server_id.to_bytes(4, "big", signed=False),
                )
                return

        if term < self.term:
            # This server definitely shouldn't be the leader
            self._prepare_send(data, b"V", payload + b"\x00")
            self.call_election(force=True)
            return

        with self.election_lock:
            # We accept this server as a possible leader (in the meantime,
            # we shouldn't propose any new queries)
            self.in_election = True
            self.leader = None
            self._prepare_send(data, b"V", payload + b"\x01")

    def __process_vote(self, data: SocketData, payload: bytes):
        """Process vote from other replica."""
        response = int.from_bytes(payload[8:9])
        logger.debug(f"Received vote from {payload[:8]}: {response}.")

        with self.queue_lock:
            self.queues[(payload[:8], data.id)].put(response)

    def __process_winner(self, data: SocketData, payload: bytes):
        """Process winner declaration from other replica."""
        with self.election_condition:
            self.leader = int.from_bytes(payload[:4], "big", signed=False)
            assert self.leader in self.replicas

            logger.info(f"Accepted {self.leader} as new leader.")

            # End election
            self.in_election = False
            self.election_condition.notify_all()

    def __process_strong_query(self, data: SocketData, payload: bytes):
        """Attempt a proposed strong query, return the status."""
        try:
            clock = int.from_bytes(payload[:4], "big", signed=False)
            query = Query.decode(payload[4:])
            r_payload = query.id

            logger.debug(f"Attempting strong query {query} @ {clock}.")

            with self.election_lock:
                if self.status == "learner":
                    self._prepare_send(data, b"R", r_payload + b"\xff")
                    return

            with self.clock_lock:
                if clock > self.clock + 1:
                    # We're missing some information but aren't learning yet
                    self._start_learning()
                    self._prepare_send(data, b"R", r_payload + b"\xff")
                    return

                assert clock >= self.clock

            status, _ = self.db.try_query(query, "strong")
            if status == 0:
                self.clock += 1

        except ValueError as e:
            logger.warning(f"Unable to parse query from payload {payload}")
            logger.error(e, exc_info=True)
            status = 99

        self._prepare_send(
            data, b"R", r_payload + status.to_bytes(1, "big", signed=False)
        )

    def __process_weak_query(self, data: SocketData, payload: bytes):
        """Process a weak query by putting it in the async queue."""
        try:
            query = Query.decode(payload)
            self.async_queue.put(query)

        except ValueError:
            pass

    def __status_query(self, data: SocketData, payload: bytes):
        """Update the status of a query."""
        query_id = payload[:16]
        query_status = int.from_bytes(payload[16:17])

        with self.queue_lock:
            if query_id not in self.queues:
                logger.warning("Received status of unknown query...")
            else:
                self.queues[query_id].put(query_status)

    def __distribute_query(self, data: SocketData, payload: bytes):
        """Send a query out to the other replicas."""
        status = self.propose_query(Query.decode(payload))  # blocks
        self._prepare_send(data, b"S", payload[:16] + status.to_bytes(1))

    def __collect_query(self, data: SocketData, payload: bytes):
        """Collect the response from a follower for the query."""
        query_id = payload[:16]
        query_status = int.from_bytes(payload[16:17])

        logger.debug(f"GOT QUERY RESULT query_id={query_id}, status={query_status}")

        with self.queue_lock:
            if (query_id, data.id) not in self.queues:
                logger.warning("Collected status of unknown query...")
            else:
                self.queues[(query_id, data.id)].put(query_status)

    def __teach(self, data: SocketData, payload: bytes):
        """Teach a follower about the requested query from the strong log."""
        query_id = int.from_bytes(payload[:4], "big", signed=False)

        self.clock_lock.acquire()
        if query_id <= self.clock:
            # There is still something left to learn
            self.clock_lock.release()
            q = Query(
                query="SELECT query FROM internal_strong_log WHERE id = ?",
                params=[query_id],
            )
            status, result = self.db.try_query(q)
            if status == 0 and len(result) > 0:
                # We got the log entry
                r_payload = payload[:4] + b"\x00" + result[0]["query"]
                self._prepare_send(data, b"L", r_payload)

            elif status == 0 and len(result) == 0:
                # This entry does not exist??
                self._prepare_send(data, b"L", payload[:4] + b"\x01")

        elif query_id > self.clock:
            # This replica already knows everything there is to know!
            self.clock_lock.release()
            self._prepare_send(data, b"L", payload[:4] + b"\x02")

    def __learn(self, data: SocketData, payload: bytes):
        """Process an earlier query from the strong log."""
        with self.queue_lock:
            self.queues[payload[:4]].put(payload[4:])

    def _start_learning(self):
        """
        Ask the leader for missing entries from the strong log. By construction,
        entry IDs are sequential and cannot skip an integer, so we can just
        continuously increase the counter.
        """
        with self.election_lock:
            if self.in_election or self.leader is None:
                return

            self.status = "learner"

        def _keep_learning():
            while True:
                with self.clock_lock:
                    next_log = (self.clock + 1).to_bytes(4, "big", signed=False)

                with self.queue_lock:
                    queue = Queue()
                    self.queues[next_log] = queue

                with self.election_lock:
                    if self.in_election or self.leader is None:
                        break

                    leader_id = self.leader

                with self.connections_lock:
                    _, data = self.connections[leader_id]
                    self._prepare_send(data(), b"T", next_log)

                # Wait for result
                result = queue.get()
                status = result[:1]

                # Clean up queues
                with self.queue_lock:
                    self.queues.pop(next_log)

                if status == b"\x00":
                    query = Query.decode(result[1:])
                    s, _ = self.db.try_query(query, "strong")
                    logger.debug(f"Learned about strong query {query.id}")

                    if s != 0:
                        logger.warning(f"Failed to implement query {query.id}.")

                    with self.clock_lock:
                        self.clock += 1

                elif status == b"\x01":
                    # error!
                    raise ValueError("Something is wrong with the queries...")

                elif status == b"\x02":
                    # We're up to date!
                    with self.election_lock:
                        self.status = "follower"

                    break

        # Learn in parallel to everything else
        Thread(target=_keep_learning, daemon=True).start()

    ### CONSENSUS
    def call_election(self, force: bool = False):
        """
        Start the process of a leader election.

        Parameters
        ----------
        force : bool, optional
            Call election disregarding last heartbeat from leader, by default False.
        """
        logger.debug("Testing election...")
        with self.election_condition:
            logger.debug(f"Old leader: {self.leader}")
            if self.in_election or self.status != "follower":
                return

            with self.connections_lock:
                if self.leader in self.connections:
                    ts, _ = self.connections[self.leader]
                    if (time.time() - ts) * 1000 <= self.election_timeout:
                        # No need to call an election just yet...
                        logger.debug("no need for election just yet...")
                        self.election_timer.restart()
                        if not force:
                            return

            self.in_election = True
            self.leader = None

            # Prepare response queues for current term
            with self.clock_lock:
                t = self.term.to_bytes(8, "big", signed=False)
                logger.info(f"STARTING ELECTION WITH TERM {self.term}")

            for id in self.replicas:
                if id == self.server_id:
                    continue

                with self.queue_lock:
                    self.queues[(t, id)] = Queue()

            # Inform all replicas of our plans to become the new leader
            # with our proposed term
            self._broadcast(b"E", t)

            qs_to_watch = []
            with self.connections_lock:
                qs_to_watch = [(t, id) for id in self.connections]

            # Wait for votes and tally
            results = self._wait_for_queues(qs_to_watch, timeout=1)
            votes = sum(r for r in results.values())

            # Only declare self to be new leader if *all* currently online
            # replicas agree; to obtain stronger consistency guarantees, we
            # can require that the number of voting members has to be at least
            # half (plus one) of all possible replicas; this way we can never
            # miss a single strongly consistent queries, i.e.
            # if votes >= len(qs_to_watch) and votes > (len(self.replicas) // 2) + 1:
            if votes >= len(qs_to_watch):
                # We're the new leader!
                self.status = "leader"
                self.leader = self.server_id
                logger.info(
                    f"Server {self.server_id} is declaring itself the new leader!"
                )
                self._broadcast(b"W", self.server_id.to_bytes(4, "big", signed=False))
            else:
                # Keep checking for elections
                self.election_timer.restart()

            # End this election
            self.in_election = False
            self.election_condition.notify_all()

    ### LEADER
    def send_query_to_leader(self, query: Query) -> int:
        """
        Forward a binary query to the leader or distribute
        it among the replicas if we are the leader. Blocks until
        we have received a response from the leader/replicas.
        """
        self.election_condition.acquire()
        # Wait until leader election is complete
        while self.in_election or self.leader is None:
            logger.debug("Waiting for election to finish...")
            self.election_condition.wait()

        if self.status == "leader":
            self.election_condition.release()
            logger.debug("As leaser, we propose query directly")
            return self.propose_query(query)  # blocks

        self.election_condition.release()

        with self.queue_lock:
            self.queues[query.id] = Queue()

        self._send_to_peer(self.leader, b"Q", query.encode())
        result = self.queues[query.id].get()  # blocks

        # Clean up
        with self.queue_lock:
            self.queues.pop(query.id)

        return result

    def propose_query(self, query: Query) -> int:
        # Try query in leader
        status, result = self.db.try_query(query, "strong")
        if status != 0:
            return status

        logger.debug(f"Implemented in leader {query} with result {result}")

        with self.clock_lock:
            payload = self.clock.to_bytes(4, "big", signed=False) + query.encode()
            self.clock += 1

        # If leader is able to implement the query, then all of the
        # followers will be able to do it, too.

        # Create queues for responses
        for id in self.replicas:
            if id == self.server_id:
                continue

            with self.queue_lock:
                self.queues[(query.id, id)] = Queue()

        # Attempt to establish connection with all replicas
        self._broadcast(b"P", payload)

        logger.debug(f"Broadcasted {query}")

        with self.connections_lock:
            qs_to_watch = [(query.id, id) for id in self.connections]

        # Wait for all of the queries to return (up to some timeout)
        results = self._wait_for_queues(qs_to_watch, timeout=1)
        votes = sum(status == 0 for status in results.values())
        learners = sum(status == 255 for status in results.values())
        total = len(qs_to_watch) - learners

        logger.debug(f"Got all results {query}, {votes}/{total}")

        # Check that all available replicas have implemented the query.
        # It may be that there are no other replicas, in which case
        # we are trivially successful. We can again do an additional,
        # Raft-like check to ensure that we got a majority of votes.
        if votes >= total:
            return 0

        return 1
