from functools import cached_property
import os
import random
import secrets
import selectors
import socket
import logging
import time
import weakref

from collections.abc import Hashable, Iterable
from pathlib import Path
from queue import Queue, Empty
from selectors import EVENT_READ as RD, EVENT_WRITE as WR
from threading import Thread, Lock, RLock, Event, Condition
from typing import Literal

from dns import resolver
from flask import Flask, g

from api import api as api_bp
from db import SQLiteDatabase
from query import Operation, Query
from utils import Timer, build_select_query

logger = logging.getLogger(__name__)


### CONSTANTS
MAGIC = b"BVBV"
PROTOCOL_VERSION = 1


class SocketData:
    def __init__(
        self,
        host: str,
        sock: socket.socket,
        inb: bytes = b"",
        outb: bytes = b"",
    ):
        self.host = host
        self.sock = sock
        self.inb = inb
        self.outb = outb
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
        self.n_replicas = int(os.getenv("N_REPLICAS"))  # max number of replicas

        # Docker setup
        self.service_dns = os.getenv("SERVICE_DNS")  # how to find other replicas
        self.internal_port = int(os.getenv("INTERNAL_PORT", 8001))
        self.external_port = int(os.getenv("EXTERNAL_PORT", 8000))
        self.server_id = int(os.getenv("SERVER_ID"))
        self.peers: set[str] = set()  # IP addresses

        # Consistency markers
        self.strong_columns = set(self.rc.get("STRONG_CONSISTENCY", []))
        self.strong_tables = set(
            col.split(".")[0] for col in self.strong_columns if col.split(".")[1] == "*"
        )

        # Election setup
        self.hb_int = self.rc.get("HEARTBEAT_INTERVAL_MS", 100)  # in ms
        self.max_election_timeout = self.rc.get("ELECTION_TIMEOUT_MS", 1000)  # in ms
        assert self.max_election_timeout > 5 * self.hb_int
        self.election_lock = RLock()
        self.election_timer: Timer = None
        self.election_condition = Condition()
        self.in_election: bool = False
        self.status: Literal["leader", "follower", "learner"] = "follower"
        self.leader: str | None = None  # host of leader

        # Query logging
        self.db = SQLiteDatabase(
            self.instance_path / "database.db", self.rc.get("SETUP_SCRIPT")
        )
        self.async_transaction_ids = set()
        self.async_queue: Queue[Query] = Queue()

        self.clock_lock = RLock()
        self.clock: int = 0
        self.strong_query_in_progress = False
        self.clock_condition = Condition(self.clock_lock)

        # Queues
        self.queue_lock = RLock()
        self.queues: dict[bytes, Queue] = {}
        self.req_id: int = 1

        # Socket connections to other replicas
        self.listen_sock: socket.socket = None
        self.connections_lock = RLock()
        self.connections: dict[int, tuple[float, weakref.ref[SocketData]]] = {}
        self.stop_event = Event()
        self.internal_started = Event()
        self.selector_lock = RLock()
        self.selector = selectors.DefaultSelector()

        print("IPS", self.ips)

    @property
    def term(self) -> int:
        with self.clock_lock:
            return self.clock * (self.n_replicas + 1) + self.server_id

    @cached_property
    def ips(self):
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
        return set(addrs)

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
        # Set up socket for communication between replicas
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind(("0.0.0.0", self.internal_port))
        self.listen_sock.settimeout(1)
        self.listen_sock.listen(self.rc.get("BACKLOG", 5))
        self.selector.register(self.listen_sock, RD, data=None)

        logger.info(f"Started internal server at {self.listen_sock.getsockname()}")

        with self.election_lock:
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
            status, result = self.db.try_execute(
                "SELECT MAX(logical_timestamp) AS max FROM internal_strong_log"
            )
            assert status == 0
            self.clock = result[0]["max"] or 0
            self.clock += 1
            logger.debug(f"Started with logical clock {self.clock}")

            # TODO: Get latest entries from async logs

        # Start establishing connections to other replicas
        Thread(target=self._establish_connections, daemon=True).start()

        # Start processing weak queries
        Thread(target=self._handle_weak_queries, daemon=True).start()

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
        self.api.run(use_reloader=False, threaded=True)

    def discover_peers(self) -> set[str]:
        addrs = set(r.address for r in resolver.resolve(self.service_dns, "A"))
        addrs -= self.ips  # remove self
        return addrs

    ### EXTERNAL API HELPERS
    def _before_api_request(self):
        """
        Make proxy available to API endpoints.
        """
        g.proxy = self

    def dispatch(
        self,
        method: str,
        schema: str,
        data: dict = {},
        row_id: Hashable = None,
    ):
        """
        Process a query from the external API.
        """
        assert method in {"GET", "POST", "PATCH", "DELETE"}

        if method == "GET":
            # SELECT queries can be performed consistently by any replica
            query, params = build_select_query(schema, data, row_id)
            status, result = self.db.try_execute(query, params)

            if status != 0:
                return {"error": f"Database error (code: {status})"}, 400

            return result, 200

        elif method == "POST":
            # INSERT
            op = Operation(b"I", schema, data=data)
            query = Query([op])
            strong = schema in [col.split(".")[0] for col in self.strong_columns]

        elif method == "PATCH":
            # UPDATE
            assert row_id is not None

            # Strong query if any of the relevant columns are strong or the entire
            # table is marked as strong
            strong = schema in self.strong_tables
            strong |= bool(
                self.strong_columns & set(f"{schema}.{col}" for col in data.keys())
            )

            # First, we need to make sure that the element exists
            status, result = self.db.try_execute(
                f"SELECT {', '.join(data.keys())} FROM {schema} WHERE id = ?", [row_id]
            )
            if len(result) != 1:
                # This row does not (yet) exist. Error in the case of strong query,
                # temporary error/merge conflict (potentially wait for data to arrive)
                # in the case of weak query. For now, throw an error.
                # TODO: for updates, should it be part of the client's code to keep track
                # of what the old value is? Probably, since it is most likely that race
                # conditions happen between the client seeing a row and deciding to edit it
                # rather than telling the server to edit it (and the server just taking
                # whatever value it currently has as the one that the client last saw)
                return {"error": "Temporary error."}, 400

            # Next, we can update each field individually
            ops = [
                Operation(b"U", schema, col, row_id, result[0][col], data[col])
                for col in data.keys()
            ]
            query = Query(ops)

        elif method == "DELETE":
            # DELETE
            assert row_id is not None

            # Strong query if any of the affected columns are strong
            strong = schema in [col.split(".")[0] for col in self.strong_columns]

            # First, we need to make sure that the element exists
            status, result = self.db.try_execute(
                f"SELECT id FROM {schema} WHERE id = ?", [row_id]
            )
            if len(result) != 1:
                # Same note as in UPDATE
                return {"error": "Temporary error."}, 400

            query = Query([Operation(b"D", schema, row=row_id)])

        logger.debug(f"Prepared {query} for dispatch, {query.ops}")
        for op in query.ops:
            logger.debug(op)

        if strong:
            status = self.send_query_to_leader(query)
            logger.debug(f"FINISHED QUERY WITH STATUS {status}")

            if status != 0:
                return {"error": f"Database error (code: {status})"}, 400

            return {}, 200

        # Implement weak query directly
        status, query = self.db.write_query(query, "eventual")

        if status != 0:
            return {"error": f"Database error (code: {status})"}, 400

        # Broadcast query to other replicas
        self._broadcast(b"A", query.encode())

        return {}, 200

    ### INTERNAL
    def _connect_to_peer(self, host: str, raise_exc: bool = False):
        """
        Attempt to establish a socket connection to a peer if no connection
        exists, yet.
        """
        with self.connections_lock:
            conn = self.connections.get(host)

        if conn is not None:
            ts, data = conn
            time_since_last_hs = (time.time() - ts) * 1000
            if time_since_last_hs > 3 * self.hb_int:
                # We haven't heard from this connection in a while,
                # make sure that it still works
                self.__initiate_handshake(data())

            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, self.internal_port))

            # Store connection
            data = SocketData(host, sock)
            logger.debug(f"connecting..., {data}")
            with self.selector_lock:
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
        threads: dict[str, Thread] = {}

        while not self.stop_event.is_set():
            self.peers = self.discover_peers()
            for host in self.peers:
                if host in threads and threads[host].is_alive():
                    # Avoid spamming threads unnecessarily
                    continue

                th = Thread(target=self._connect_to_peer, args=(host,), daemon=True)
                th.start()
                threads[host] = th

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
                return

            magic = data.inb[:4]
            if magic != MAGIC:
                raise ValueError("Invalid request type.")

            if len(data.inb) < 5:
                return

            version = int.from_bytes(data.inb[4:5], "big", signed=False)
            if version != PROTOCOL_VERSION:
                raise ValueError("Unknown request version.")

            if len(data.inb) < 6:
                return

            command = data.inb[5:6]

            if len(data.inb) < 10:
                return

            payload_length = int.from_bytes(data.inb[6:10], "big", signed=False)
            payload = data.inb[10 : 10 + payload_length]
            if len(payload) < payload_length:
                return

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
        with self.selector_lock:
            self.selector.modify(data.sock, RD | WR, data=data)

    def _remove_connection(self, sock: socket.socket, data: SocketData):
        """
        Remove a socket connection and its corresponding `SocketData`
        object from `connections` dictionary and the selector.
        """
        if data.host is not None:
            with self.connections_lock:
                _ = self.connections.pop(data.host, None)

        logger.debug(f"Closing connection to {data.host}")

        try:
            with self.selector_lock:
                self.selector.unregister(sock)
            sock.close()

        except Exception:
            pass

    def _send_to_peer(
        self, host: str, command: bytes, payload: bytes, raise_exc: bool = False
    ):
        """
        Attempt to send a message to a peer.
        """
        self._connect_to_peer(host, raise_exc=raise_exc)

        try:
            with self.connections_lock:
                _, data = self.connections[host]

            self._prepare_send(data(), command, payload)

            logger.debug(f"Message to {host}: cmd={command}, pl={payload}")

        except Exception as e:
            # logger.warning(f"Unable to send message to {peer_id} ({addr}): {str(e)}")
            if raise_exc:
                raise e

    def _broadcast(self, command: bytes, payload: bytes):
        """
        Attempt to send a message to all peers (not including self).
        """
        for host in self.discover_peers():
            self._send_to_peer(host, command, payload)

    def _accept(self, sock: socket.socket):
        """
        Accept a new connection on a socket.
        """
        conn, addr = sock.accept()
        logger.debug(f"Accepted connection {conn} from {addr}")
        conn.setblocking(False)

        with self.selector_lock:
            self.selector.register(conn, RD, data=SocketData(addr[0], conn))

    def _service(self, key: selectors.SelectorKey, mask: int):
        """
        Service an existing connection for reads & writes.
        """
        sock: socket.socket = key.fileobj
        data: SocketData = key.data

        if mask & RD:
            recv = b""
            try:
                recv = sock.recv(4096)  # receive in chunks of 4096 bytes
                if not recv:
                    raise ConnectionResetError

            except OSError:
                self._remove_connection(sock, data)
                return

            # We received some data; try to parse it
            with data.inb_lock:
                data.inb += recv

            try:
                while res := self._receive(data):
                    cmd, payload = res
                    logger.debug(f"Request ({data.host}): cmd={cmd}, pl={payload}")
                    th = Thread(target=self._handle, args=(data, cmd, payload))
                    th.daemon = True
                    th.start()

            except ValueError as e:
                logger.warning(f"Invalid request ({data.host}): {str(e)}")
                logger.error(e, exc_info=True)
                self._remove_connection(sock, data)

        with data.outb_lock:
            if mask & WR and data.outb:
                logger.debug(f"Returning data {data.outb} to {data.host}")
                try:
                    sent = sock.send(data.outb)

                    if sent == 0:
                        raise ConnectionResetError

                    data.outb = data.outb[sent:]
                    if not data.outb:
                        # This avoids excessive polling
                        with self.selector_lock:
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

    def _wait_for_queues(self, keys: Iterable, timeout: float = 5.0) -> dict:
        """
        Monitor `keys` for objects placed in the corresponding queues, return
        once all queues have received at least one object or timeout.
        """
        results = {}
        stop = Event()
        logger.debug(f"Waiting for keys {keys}")

        def _poll(keys: set):
            while not keys.issubset(results.keys()) and not stop.is_set():
                for key in keys - results.keys():
                    try:
                        with self.queue_lock:
                            result = self.queues[key].get_nowait()
                        results[key] = result

                    except Empty:
                        pass

                time.sleep(0.01)  # reduce polling

        th = Thread(target=_poll, args=(set(keys),), daemon=True)
        th.start()
        th.join(timeout)
        stop.set()

        logger.debug(f"Done waiting for keys {keys}")

        # Clean up
        with self.queue_lock:
            for key in keys:
                logger.debug(f"Removing {key} from queues")
                self.queues.pop(key)

        logger.debug(f"Cleaned up keys {keys}")

        return results

    def _update_connection(self, data: SocketData):
        if data.host is None:
            return

        with self.connections_lock:
            self.connections[data.host] = (time.time(), weakref.ref(data))

        with self.election_lock:
            if data.host is not None and data.host == self.leader:
                self.election_timer.restart()

    def _handle_weak_queries(self):
        """
        Grab weak queries from the queue and process them. Should be
        run in a separate thread for concurrent processing.
        """
        while not self.stop_event.is_set():
            try:
                query = self.async_queue.get(timeout=1)
                logger.info(f"Got async query {query}")
                if query.transaction_id in self.async_transaction_ids:
                    continue

                # Write query with transaction ID and timestamp from other replica
                # for complete consistency
                status, query = self.db.write_query(
                    query,
                    "eventual",
                    query.transaction_id,
                    timestamp=query.timestamp,
                )

                if status == 0:
                    self.async_transaction_ids.add(query.transaction_id)
                else:
                    logger.info(f"Query {query} failed, exited with status {status}.")
                    # TODO: fix conflicts
                    # self.async_queue.put(query)

            except Empty:
                pass

    ### INTERNAL ACTIONS
    def __initiate_handshake(self, data: SocketData):
        """Identify self to other replica."""
        # payload = self.server_id.to_bytes(4, "big", signed=False)

        with self.clock_lock:
            payload = self.clock.to_bytes(4, "big", signed=False)

        with self.election_lock:
            if self.status == "leader":
                payload += b"\x01"

        self._prepare_send(data, b"I", payload)

    def __receive_handshake(self, data: SocketData, payload: bytes):
        """Process identification from other replica."""
        # data.id = int.from_bytes(payload[:4], "big", signed=False)
        self._update_connection(data)
        logger.debug(f"Received handshake from {data.host}.")

        clock = int.from_bytes(payload[4:8], "big", signed=False)

        is_leader = payload[8:]
        if is_leader == b"\x01":
            with self.election_lock:
                if not self.in_election:
                    self.leader = data.host
                    logger.debug(f"Accepted leader {self.leader}.")

        with self.clock_lock:
            if clock > self.clock:
                self._start_learning()

    def __return_handshake(self, data: SocketData):
        """Identify self to other replica in response to handshake."""
        # payload = self.server_id.to_bytes(4, "big", signed=False)

        with self.clock_lock:
            payload = self.clock.to_bytes(4, "big", signed=False)

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
                self._prepare_send(data, b"W", b"")
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
            if (payload[:8], data.host) not in self.queues:
                logger.info(
                    f"Received result from unknown election {(payload[:8], data.host)}"
                )
            else:
                logger.debug(f"Accessing queue {(payload[:8], data.host)}")
                self.queues[(payload[:8], data.host)].put(response)

    def __process_winner(self, data: SocketData, payload: bytes):
        """Process winner declaration from other replica."""
        with self.election_condition:
            self.leader = data.host
            # self.leader = int.from_bytes(payload[:4], "big", signed=False)
            # assert self.leader in self.replicas

            logger.info(f"Accepted {self.leader} as new leader.")

            # End election
            self.in_election = False
            self.election_condition.notify_all()

    def __process_strong_query(self, data: SocketData, payload: bytes):
        """Attempt a proposed strong query, return the status."""
        with self.clock_condition:
            while self.strong_query_in_progress:
                self.clock_condition.wait()

            self.strong_query_in_progress = True

        try:
            query = Query.decode(payload)
            r_payload = query.transaction_id

            logger.debug(
                f"Attempting strong query {query} @ {query.logical_timestamp}."
            )

            learner = False
            with self.election_lock:
                learner |= self.status == "learner"

            with self.clock_lock:
                learner |= query.logical_timestamp > self.clock

            if learner:
                self._start_learning()
                status = 255
                r_payload += status.to_bytes(2, "big", signed=False)
                self._prepare_send(data, b"R", r_payload)
                return

            # Use ID, logical timestamp, and timestamp from leader
            status, _ = self.db.write_query(
                query,
                "strong",
                query.transaction_id,
                query.logical_timestamp,
                query.timestamp,
            )

            with self.clock_condition:
                if status == 0:
                    self.clock += 1

                self.strong_query_in_progress = False
                self.clock_condition.notify_all()

        except ValueError as e:
            logger.warning(f"Unable to parse query from payload {payload}")
            logger.error(e, exc_info=True)
            status = 99

        r_payload += status.to_bytes(2, "big", signed=False)
        self._prepare_send(data, b"R", r_payload)

    def __process_weak_query(self, data: SocketData, payload: bytes):
        """Process a weak query by putting it in the async queue."""
        try:
            query = Query.decode(payload)
            logger.debug(f"Processing weak query {query}...")
            self.async_queue.put(query)

        except ValueError:
            pass

    def __status_query(self, data: SocketData, payload: bytes):
        """Update the status of a query."""
        req_id = int.from_bytes(payload[:2], "big", signed=False)
        query_status = int.from_bytes(payload[2:4], "big", signed=False)
        logger.debug(f"Received final query status {query_status} for {req_id}")

        with self.queue_lock:
            if req_id not in self.queues:
                logger.warning("Received status of unknown query...")
            else:
                logger.debug(f"Accessing queue {req_id}")
                self.queues[req_id].put(query_status)

    def __distribute_query(self, data: SocketData, payload: bytes):
        """Send a query out to the other replicas."""
        status, _ = self.propose_query(Query.decode(payload[2:]))  # blocks
        self._prepare_send(
            data, b"S", payload[:2] + status.to_bytes(2, "big", signed=False)
        )

    def __collect_query(self, data: SocketData, payload: bytes):
        """Collect the response from a follower for the query."""
        query_id = payload[:16]
        query_status = int.from_bytes(payload[16:17])

        logger.debug(f"GOT QUERY RESULT query_id={query_id}, status={query_status}")

        with self.queue_lock:
            if (query_id, data.host) not in self.queues:
                logger.warning("Collected status of unknown query...")
            else:
                logger.debug(f"Accessing queue {(query_id, data.host)}")
                self.queues[(query_id, data.host)].put(query_status)

    def __teach(self, data: SocketData, payload: bytes):
        """Teach a follower about the requested query from the strong log."""
        clock = int.from_bytes(payload[:4], "big", signed=False)

        self.clock_lock.acquire()
        if clock < self.clock:
            # There is still something left to learn
            self.clock_lock.release()

            # Get all operations from the database
            status, result = self.db.try_execute(
                "SELECT * FROM internal_strong_log WHERE logical_timestamp = ?",
                [clock],
            )
            if status == 0 and len(result) > 0:
                # We got the log entry
                ops = [Operation.from_sql(row) for row in result]
                r_payload = payload[:4] + b"\x00" + Query(ops).encode()
                self._prepare_send(data, b"L", r_payload)

            elif status == 0 and len(result) == 0:
                # This entry does not exist??
                self._prepare_send(data, b"L", payload[:4] + b"\x01")

        elif clock >= self.clock:
            # This replica already knows everything there is to know!
            self.clock_lock.release()
            self._prepare_send(data, b"L", payload[:4] + b"\x02")

    def __learn(self, data: SocketData, payload: bytes):
        """Process an earlier query from the strong log."""
        with self.queue_lock:
            logger.debug(f"Accessing queue {payload[:4]}")
            self.queues[payload[:4]].put(payload[4:])

    def _start_learning(self):
        """
        Ask the leader for missing entries from the strong log. By construction,
        entry IDs are sequential and cannot skip an integer, so we can just
        continuously increase the counter.
        """
        with self.election_lock:
            if self.in_election or self.leader is None or self.status != "follower":
                return

            logger.debug("BECOMING A LEARNER!")
            self.status = "learner"

        def _keep_learning():
            while True:
                with self.clock_lock:
                    next_log = self.clock.to_bytes(4, "big", signed=False)

                with self.queue_lock:
                    queue = Queue()
                    logger.debug(f"Creating queue {next_log}")
                    self.queues[next_log] = queue

                with self.election_lock:
                    if self.in_election or self.leader is None:
                        break

                    leader = self.leader

                with self.connections_lock:
                    _, data = self.connections[leader]

                self._prepare_send(data(), b"T", next_log)

                # Wait for result
                result = queue.get()
                status = result[:1]

                # Clean up queues
                with self.queue_lock:
                    logger.debug(f"Removing queue {next_log}")
                    self.queues.pop(next_log)

                if status == b"\x00":
                    query = Query.decode(result[1:])
                    s, r = self.db.write_query(
                        query,
                        "strong",
                        query.transaction_id,
                        query.logical_timestamp,
                        query.timestamp,
                    )
                    logger.debug(f"Learned about strong query {query.transaction_id}")

                    if s != 0:
                        logger.warning(
                            f"Failed to implement query {query.transaction_id}."
                        )

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
        with self.election_lock:
            logger.debug(
                f"Old leader: {self.leader}, status: {self.status}, in_election: {self.in_election}"
            )
            if self.in_election or self.status != "follower":
                return

        with self.connections_lock:
            leader_conn = self.connections.get(self.leader)

        if leader_conn is not None:
            ts, _ = leader_conn
            if (time.time() - ts) * 1000 <= self.election_timeout:
                # No need to call an election just yet...
                logger.debug("no need for election just yet...")
                self.election_timer.restart()  # thread-safe

                if not force:
                    return

        with self.election_lock:
            self.in_election = True
            self.leader = None

        logger.debug("Starting election soon...")

        # Prepare response queues for current term
        with self.clock_lock:
            t = self.term.to_bytes(8, "big", signed=False)
            logger.info(f"STARTING ELECTION WITH TERM {self.term}")

        for host in self.discover_peers():
            with self.queue_lock:
                logger.debug(f"Creating queue {(t, host)}")
                self.queues[(t, host)] = Queue()

        # Inform all replicas of our plans to become the new leader
        # with our proposed term
        self._broadcast(b"E", t)

        logger.debug("Broadcasted election")

        with self.connections_lock:
            qs_to_watch = [(t, host) for host in self.connections]

        # Wait for votes and tally
        results = self._wait_for_queues(qs_to_watch, timeout=1)
        votes = sum(r for r in results.values())

        with self.election_condition:
            # Only declare self to be new leader if *all* currently online
            # replicas agree; to obtain stronger consistency guarantees, we
            # can require that the number of voting members has to be at least
            # half (plus one) of all possible replicas; this way we can never
            # miss a single strongly consistent queries, i.e.
            # if votes >= len(qs_to_watch) and votes > (len(self.replicas) // 2) + 1:
            if votes >= len(qs_to_watch):
                # We're the new leader!
                self.status = "leader"
                self.leader = self.ips.copy().pop()
                logger.info(
                    f"Server {self.server_id} @ {self.ips} is declaring itself the new leader!"
                )
                self._broadcast(b"W", b"")
            else:
                # Keep checking for elections
                self.election_timer.restart()

            # End this election
            logger.debug("Quitting election")
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
            logger.debug("As leader, we propose query directly")
            status, query = self.propose_query(query)  # blocks
            return status

        self.election_condition.release()

        with self.queue_lock:
            req = self.req_id
            self.req_id = (self.req_id + 1) % (1 << 16)
            logger.debug(f"Creating queue {req}")
            self.queues[req] = Queue()

        self._send_to_peer(
            self.leader,
            b"Q",
            req.to_bytes(2, "big", signed=False) + query.encode(),
        )
        result = self.queues[req].get()  # blocks

        # Clean up
        with self.queue_lock:
            logger.debug(f"Deleting queue {req}")
            self.queues.pop(req)

        return result

    def propose_query(self, query: Query) -> tuple[int, Query]:
        with self.clock_condition:
            while self.strong_query_in_progress:
                self.clock_condition.wait()

            self.strong_query_in_progress = True
            status, query = self.db.write_query(
                query,
                "strong",
                logical_timestamp=self.clock,
            )

        if status != 0:
            return status

        logger.debug(f"Implemented in leader {query}")

        # If leader is able to implement the query, then all of the
        # followers will be able to do it, too.

        # Create queues for responses
        for host in self.discover_peers():
            with self.queue_lock:
                logger.debug(f"Creating queue {(query.transaction_id, host)}")
                self.queues[(query.transaction_id, host)] = Queue()

        # Attempt to establish connection with all replicas
        self._broadcast(b"P", query.encode())

        logger.debug(f"Broadcasted {query}")

        with self.connections_lock:
            qs_to_watch = [(query.transaction_id, host) for host in self.connections]

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
        with self.clock_condition:
            if votes >= total:
                # We only update the clock here to ensure that we
                #    a) don't block the clock_lock unnecessarily
                #    b) avoid situations where between executing the
                #       query in the leader and waiting for the responses
                #       of the followers, a replica thinks they have
                #       missed a query (namely, the current one)
                self.clock += 1

                self.strong_query_in_progress = False
                self.clock_condition.notify_all()
                return 0, query

            self.strong_query_in_progress = False
            self.clock_condition.notify_all()
            return 1, query
