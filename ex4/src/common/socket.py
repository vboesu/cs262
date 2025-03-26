from collections.abc import Callable

import threading
import queue
import socket

from src.common import Request

import logging

logger = logging.getLogger(__name__)


class SocketHandler:
    """
    Class which takes care of receiving requests on a socket and sending
    data to another socket using a temporary connection for every request.
    Can go through a list of remote hosts to send to and retry upon failure.

    Parameters
    ----------
    listen_sock : socket.socket
        Socket on which to listen for new connections.
    receive_callback : Callable
        Callback function upon receipt of request at `listen_sock`.
    timeout : float, optional
        Timeout for establishing new connections when sending data, by default 2.0.
    """

    def __init__(
        self,
        listen_sock: socket.socket,
        receive_callback: Callable,
        timeout: float = 2.0,
    ):
        self.listen_sock = listen_sock
        self.timeout = timeout
        self.lthread: threading.Thread = None

        # Default data to be transmitted with each request
        self.default_data = {}
        self.req_id = 1
        self.stop_event = threading.Event()

        # Initialize locks
        self.req_id_lock = threading.Lock()
        self.pending_lock = threading.Lock()
        self.thread_lock = threading.RLock()

        # Initialize queues
        self.pending: dict[int, queue.Queue] = {}
        self.receive_queue = queue.Queue()

        # Set up receiving
        self.receive_callback = receive_callback

        # Start processing
        with self.thread_lock:
            self.pthread = threading.Thread(target=self.process, daemon=True)
            self.pthread.start()

    def start_listening(self, block: bool = False):
        # Start listening
        if block:
            # Listen on main thread
            self.listen()

        else:
            # Listen on separate thread
            self.lthread = threading.Thread(target=self.listen, daemon=True)
            self.lthread.start()

    def listen(self):
        """
        Listen to requests coming in on the listening socket, and put them
        in the response queue for a specific request or the general queue
        for new/push requests.
        """
        self.listen_sock.listen(5)  # start accepting connections
        while not self.stop_event.is_set():
            try:
                # Block until new connection is received
                conn, addr = self.listen_sock.accept()
                logger.debug(f"Accepted connection {conn} from {addr}")

                # Block until request has been received in full
                req = Request.receive(conn, addr)
                logger.debug("Received %s", req)
                logger.debug("Data: %s", req.data)

                with self.pending_lock:
                    if req.request_id in self.pending:
                        # A response we've been waiting for!
                        target_queue = self.pending.pop(req.request_id, None)
                        target_queue.put(req)

                    else:
                        # A new request! Maybe a push notification or a new client
                        self.receive_queue.put(req)

                # Close connection every time
                conn.close()

            except KeyboardInterrupt:
                logger.info("Received ^C. Closing socket handler.")
                self.stop_event.set()

            except Exception as e:
                logger.error("%s: %s", e.__class__.__name__, str(e))

        with self.thread_lock:
            self.lthread = None  # basically: remove self after finishing

    def process(self):
        """Process the queue of new requests."""
        while not self.stop_event.is_set():
            try:
                # blocks, releases every 2 seconds
                req = self.receive_queue.get(timeout=2)
                self.receive_callback(req)

            except queue.Empty:
                pass

    def send(
        self,
        remote_hosts: list[tuple[str, int]],
        request_code: int = 0,
        request_id: int = -1,
        data: dict | None = None,
        await_response: bool = True,
    ) -> queue.Queue[Request] | None:
        """
        Send a request to a socket, specifying the operation and data to be
        transmitted. Automatically generates a `request_id` to be sent in the
        header of the request for identification of the response. Tries all
        `remote_hosts` in order until one of them succeeds, raises an error
        if all of them fail.

        Parameters
        ----------
        remote_hosts : list[tuple[str, int]]
            List of (host, port) tuples specifying remote hosts.
        request_code : int
            Operation code of request.
        data : dict, optional
            Key-value pairs with data, by default None.
        await_response : bool, optional
            Whether to set up a queue to wait for the response, by default True.

        Returns
        -------
        tuple[str, int]
            Tuple of (host, port) out of `remote_hosts` to which the request was
            successfully sent to (e.g. for appropriate re-ordering of list for
            future requets to minimize timeouts).

        queue.Queue | None
            Queue which will contain the response from the server, once received
            or none, if `await_response` is `False`.

        Examples
        --------
        >>> response = sh.send([("localhost", 5000)], 100, {"key": "value"}).get()
        ... # ^ blocks until we get a response
        """

        # Generate new request ID
        if request_id == -1:
            with self.req_id_lock:
                self.req_id = (self.req_id % 65536) + 1
                request_id = self.req_id

        # Merge default_data
        if data is None and self.default_data:
            data = self.default_data
        elif data is not None:
            data = {**self.default_data, **data}  # `data` should overwrite

        req = Request(request_code, data, request_id)

        # Prepare response queue
        if await_response:
            response_queue = queue.Queue()
            with self.pending_lock:
                self.pending[request_id] = response_queue

        # Push request to server
        # NOTE(vboesu): if we have to go through a long list of dead replicas,
        # this might take a while...
        sent_to = None
        for remote_host, remote_port in remote_hosts:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((remote_host, remote_port))

            except (socket.timeout, socket.error) as e:
                logger.debug(
                    f"Unable to connect to {remote_host}:{remote_port}. Exception: {str(e)}",
                )
                continue

            total, sent = req.push(sock)
            if sent != total:
                logger.error(
                    "Unable to send full request. Sent %d/%d bytes.", sent, total
                )
            sent_to = (remote_host, remote_port)
            sock.close()
            break

        if sent_to is None:
            raise ConnectionRefusedError(
                "Unable to send request to any of the remote hosts."
            )

        if await_response:
            return sent_to, response_queue

        return sent_to, None

    def respond_to(
        self,
        request: Request,
        response_code: int,
        response_data: dict | None = None,
    ) -> None:
        # Get response address from request
        response_host, _ = request.addr
        response_port = request.data.get("response_port", request.addr[1])

        logger.info(f"Attempting to respond to {response_host}:{response_port}.")

        try:
            self.send(
                [(response_host, response_port)],
                request_code=response_code,
                request_id=request.request_id,
                data=response_data,
                await_response=False,
            )

        except ConnectionRefusedError:
            logger.info(f"Unable to respond to {response_host}:{response_port}.")

    def close(self):
        """Clean-up of threads and socket."""
        self.stop_event.set()

        try:
            if self.listen_sock:
                self.listen_sock.close()

        except Exception as e:
            logger.error("%s: %s", e.__class__.__name__, str(e))

        with self.thread_lock:
            if self.lthread is not None:
                self.lthread.join(timeout=5)

            if self.pthread is not None:
                self.pthread.join(timeout=5)
