from concurrent import futures
import logging
import queue
from collections import defaultdict

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
        self.active_listeners = defaultdict(queue.Queue)

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

    def ListenForMessages(self, request, context):
        """
        Streams Message objects to the client whenever a new message
        arrives for them, as long as they remain connected.
        """
        try:
            # 1) Validate the login token from request.header
            token_value = request.header.login_token
            if not token_value:
                # Not authenticated
                context.set_details("Unauthorized: no token provided.")
                context.set_code(grpc.StatusCode.UNAUTHENTICATED)
                return  # ends the stream

            login_token = db.session.query(db.Token).filter_by(value=token_value).first()
            if not login_token:
                # No valid token found
                context.set_details("Invalid or expired token.")
                context.set_code(grpc.StatusCode.UNAUTHENTICATED)
                return

            current_user = login_token.user
            user_id = current_user.id

            # 2) Continuously yield new messages from self.active_listeners[user_id]
            while context.is_active():
                try:
                    # Block for up to 60s waiting for a new message
                    msg_obj = self.active_listeners[user_id].get(timeout=60)
                    # Convert your DB message object -> gRPC `Message`
                    yield actions.build_message_proto(msg_obj)
                except queue.Empty:
                    # If no messages arrive for a while, we just check
                    # whether the stream is still active; if so, continue
                    if not context.is_active():
                        break

        except Exception as e:
            logger.error(f"ListenForMessages error: {e}")
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            return
