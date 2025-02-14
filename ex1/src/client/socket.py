from typing import Callable

import threading
import queue
import socket

from src.common import Request, RequestCode, OP_TO_CODE

import logging

logger = logging.getLogger(__name__)


class ClientSocketHandler:
    """
    Class which takes care of the socket for the client. Supports sending
    requests and waiting for a response from the server as well as push
    notifications from the server unprompted by any request from the client.
    """

    def __init__(self, sock: socket.socket, push_handler: Callable):
        self.sock = sock

        # Default data to be transmitted with each request
        self.default_data = {}
        self.req_id = 1

        # Initialize locks
        self.req_id_lock = threading.Lock()
        self.pending_lock = threading.Lock()

        # Initialize queues
        self.pending: dict[int, queue.Queue] = {}
        self.push_queue = queue.Queue()

        # Set up push handling
        self.push_handler = push_handler

        # Start listening
        self.lthread = threading.Thread(target=self.listen, daemon=True)
        self.lthread.start()

        self.pthread = threading.Thread(target=self.receive_push, daemon=True)
        self.pthread.start()

    def listen(self):
        """
        Listen to all data coming from the server to the socket ``sock``,
        interpret it as a ``Request``, and direct it either to a queue of
        push notifications (if no ``request_id`` is provided) or to a queue
        corresponding to the thread waiting for this response.
        """
        try:
            while True:
                req = Request.receive(self.sock)
                logger.debug("Received %s", req)
                logger.debug("Data: %s", req.data)
                if req.request_id == 0 and req.request_code == RequestCode.push:
                    # Any request that does not have a request_id is assumed
                    # to be a push from the server
                    self.push_queue.put(req)
                else:
                    # Someone is waiting for this response (hopefully), so let's
                    # give it to them!
                    with self.pending_lock:
                        target_queue = self.pending.pop(req.request_id, None)

                    if not target_queue:
                        logging.info(f"Got response with unknown request_id: {req}")
                        continue

                    target_queue.put(req)

        except OSError as e:
            logging.error("Lost connection to the server: %s", str(e))

        except Exception as e:
            logging.error("%s: %s", e.__class__.__name__, str(e))

        finally:
            logging.info("Closing connection to the server.")
            # NOTE(vboesu): this modification is definitely not thread-safe
            self.lthread = None  # basically: remove self after finishing
            self.close()

    def receive_push(self):
        """
        Wait for ``listen`` to add something to the ``push_queue``, then
        trigger the ``push_handler`` with the request that came in.
        """
        while True:
            req = self.push_queue.get()  # blocks
            self.push_handler(req)

    def send(self, operation: str, data: dict | None = None) -> queue.Queue[Request]:
        """
        Send a request to the server over the socket, specifying
        the operation and data to be transmitted. Automatically generates
        a `request_id` to be sent to the server for identification of
        the response.

        Parameters
        ----------
        operation : str
            Name of the operation requested on the server
        data : dict, optional
            Key-value pairs with data. To this, the `default_data` of the
            `ClientSocketHandler` is added, by default None

        Returns
        -------
        queue.Queue
            Queue which will contain the response from the server, once received.

        Examples
        --------
        >>> response = self.send("operation", {"key": "value"}).get()
        ... # ^ blocks until the server sends something in response
        """
        if operation not in OP_TO_CODE:
            raise ValueError(f"Unknown operation: {operation}")

        with self.req_id_lock:
            self.req_id = (self.req_id % 65536) + 1
            req_id = self.req_id

        # Merge default_data
        if data is None and self.default_data:
            data = self.default_data
        elif data is not None:
            data = {**self.default_data, **data}  # `data` should overwrite

        req = Request(OP_TO_CODE[operation], data, req_id)

        # Prepare response queue
        response_queue = queue.Queue()
        with self.pending_lock:
            self.pending[req_id] = response_queue

        # Push request to server
        total, sent = req.push(self.sock)
        if sent != total:
            logging.error("Unable to send full request. Sent %d/%d bytes.", sent, total)

        return response_queue

    def close(self):
        """Clean-up of threads and socket."""
        try:
            if self.sock:
                self.sock.close()

        except Exception as e:
            logging.error("%s: %s", e.__class__.__name__, str(e))

        if self.lthread is not None:
            self.lthread.join(timeout=1)

        if self.pthread is not None:
            self.pthread.join(timeout=1)
