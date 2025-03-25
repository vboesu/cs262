"""
Bright-Vincent Chat: Run as either a client or a server.
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
        "0.0.0.0",
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
        required="server" in sys.argv,  # require only for running server
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
