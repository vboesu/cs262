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
import sys
import json
from pathlib import Path

from dotenv import load_dotenv

from src.client import Client
from src.server import Server

logging.basicConfig(
    format="%(asctime)s %(module)s.%(funcName)s:%(lineno)d %(levelname)s %(message)s",
    level=logging.DEBUG,
)

logger = logging.getLogger(__name__)


def get_config(config: str) -> dict | list:
    path = Path(config)
    if not path.exists() and path.is_file():
        raise ValueError("Invalid configuration file provided.")

    logger.info(f"Loading configuration file from {path}.")
    with open(path, "r") as f:
        return json.load(f)


def start_client(config: str):
    """
    Start a client instance.

    Parameters
    ----------
    config : str
        Path to configuration file.
    """
    conf = get_config(config)
    remote_hosts = [(machine["host"], machine["port"]) for machine in conf["machines"]]
    local_host = conf["local_host"]

    client = Client(local_host, remote_hosts)
    client.root.mainloop()


def start_server(id: int, config: str, verbose: int):
    """
    Start a server instance.

    Parameters
    ----------
    id : int
        ID of the server to start, as defined in config file.
    config : str
        Path to configuration file.
    verbose : int
        Verbosity of logging.
    """
    conf = get_config(config)
    replicas = {int(m["id"]): m for m in conf["machines"]}

    if id not in replicas:
        raise ValueError(f"Unable to find configuration for machine with ID {id}.")

    machine = replicas[id]

    server = Server(
        id,
        machine["host"],
        machine["port"],
        machine["internal_port"],
        machine["db_url"],
        replicas,
        conf["heartbeat_interval"],
        verbose,
    )
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
        "-i",
        "--instance",
        type=int,
        help="ID of server instance to start",
        required="server" in sys.argv,
    )
    parser.add_argument(
        "--config",
        type=str,
        default=os.getenv("SERVER_CONFIG", "config.json"),
        help=f"Path to configuration file (default: {os.getenv('SERVER_CONFIG', 'config.json')})",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        type=int,
        default=int(os.getenv("VERBOSE", "0")),
        help=f"Verbosity of logging (default: {int(os.getenv('VERBOSE', '0'))})",
    )
    args = parser.parse_args()

    if args.action == "client":
        start_client(args.config)
    elif args.action == "server":
        start_server(args.instance, args.config, args.verbose)
