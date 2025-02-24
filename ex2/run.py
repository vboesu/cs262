"""
Bright-Vincent Chat: Run as either a client or a server.

USAGE
-----
  python run.py client [--host HOST] [--port PORT]
    - Starts the chat client (GUI).
    - By default, HOST is 0.0.0.0 and PORT is 50262 (unless overridden by environment variables).

  python run.py server [--host HOST] [--port PORT] [--db-url DB_URL] [--verbose VERBOSE]
    - Starts the chat server.
    - By default, HOST is 0.0.0.0, PORT is 50262, and DB_URL is sqlite:///app.db
      (unless overridden by environment variables).

EXAMPLES
--------
  # Start the client with all defaults:
  python run.py client

  # Start the client on a custom host/port:
  python run.py client --host 127.0.0.1 --port 6000

  # Start the server with default host and port, using the default DB:
  python run.py server

  # Start the server on a custom host/port, with a Postgres DB:
  python run.py server --host 127.0.0.1 --port 6000 --db-url postgresql://user:pass@localhost/dbname

DESCRIPTION
-----------
This script uses command-line arguments (and optionally environment variables via .env)
to configure the chat client or server:

  - "client" connects to a running server at the specified host and port.
  - "server" listens on the specified host and port, and uses the provided database URL
    for storing or retrieving data.

Environment variables (via .env or system-wide) override defaults if not explicitly passed:
  - HOST       : Default host/IP
  - PORT       : Default port number
  - DB_URL     : Default database URL (used only by the server)
  - VERBOSE    : If set to "1" (or truthy), enables verbose logging (used only by the server)

"""

import argparse
import logging
import os

from dotenv import load_dotenv

from src.client import Client
from src.server import Server

logging.basicConfig(
    format="%(asctime)s %(module)s.%(funcName)s:%(lineno)d %(levelname)s %(message)s",
    level=logging.INFO,
)

logger = logging.getLogger(__name__)


def start_client(host: str, port: str):
    """
    Start a client instance.

    Parameters
    ----------
    host : str
        Host address to connect to.
    port : str
        Port to connect to.
    """
    logger.info("Starting client, connecting to %s:%d", host, port)

    client = Client(host, port)
    client.root.mainloop()


def start_server(host: str, port: str, db_url: str):
    """
    Start a server instance.

    Parameters
    ----------
    host : str
        Host address to bind to.
    port : str
        Port to bind to.
    db_url : str
        Database to use.
    """
    logger.info("Starting server, binding to %s:%d", host, port)
    logger.info("Using database at %s", db_url)

    server = Server(host, port, db_url, os.getenv("VERBOSE"))
    server.start()


if __name__ == "__main__":
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Run Bright-Vincent Chat Client/Server"
    )
    parser.add_argument(
        "action",
        choices=["client", "server"],
        help="Choose whether to start a server or a client.",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=os.getenv("HOST", "0.0.0.0"),
        help=f"Host/IP to bind or connect to (default: {os.getenv('HOST', '0.0.0.0')})",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=int(os.getenv("PORT", 50262)),
        help=f"Port to bind or connect to (default: {os.getenv('PORT', 50262)})",
    )
    parser.add_argument(
        "-db",
        "--db-url",
        type=str,
        default=os.getenv("DB_URL", "sqlite:///app.db"),
        help=f"(for server) Database URL (default: {os.getenv('PORT', 50262)})",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        type=bool,
        default=bool(os.getenv("VERBOSE", "0")),
        help=f"Verbosity of loggin (default: {bool(os.getenv('VERBOSE', '0'))})",
    )
    args = parser.parse_args()

    if args.action == "client":
        start_client(args.host, args.port)
    elif args.action == "server":
        start_server(args.host, args.port, args.db_url)
