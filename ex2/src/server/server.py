from concurrent import futures
import logging
import queue

import grpc

from src.common import protocol_pb2_grpc

from .utils import route, routing_registry
from . import db, actions  # noqa: F401

logger = logging.getLogger(__name__)


class Server(protocol_pb2_grpc.BVChatServicer):
    def __init__(self, host: str, port: int, db_url: str, verbose: bool = False):
        # Server information
        self.host = host
        self.port = port
        self.verbose = verbose
        self.db_url = db_url

        # Set up database
        db.session = db.create_session(self.db_url, self.verbose)

        # Set up notifications
        self.notifications = queue.Queue()

        self.load_actions()

    def load_actions(self):
        for name, (fn, tmp, df) in routing_registry.items():
            # Overwrite existing class functions
            setattr(self, name, route(self, fn, tmp, df))
            logger.info(f"Loaded action {name}")

    def start(self):
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=12))
        protocol_pb2_grpc.add_BVChatServicer_to_server(self, server)
        # TODO: add host
        server.add_insecure_port(f"[::]:{self.port}")
        server.start()
        logger.info("Server started, listening on %d", self.port)
        server.wait_for_termination()
