import config
import argparse
import logging.config

from proxy import Proxy

logging.config.dictConfig(config.LOGGING_CONFIG)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--id", type=int, default=1)

    args = parser.parse_args()

    api_config = config.API_CONFIG.copy()
    api_config.update(
        {
            "SERVER_NAME": f"127.0.0.1:{args.port}",
        }
    )

    replica_config = config.REPLICA_CONFIG.copy()
    replica_config.update(
        {
            "SERVER_ID": args.id,
            "INSTANCE_PATH": f"instance_{args.id}",
            "STRONG_CONSISTENCY": [
                "users.username",
                "users.password_hash",
                "accounts.*",
            ],
            "SETUP_SCRIPT": "setup.sql",
        }
    )

    logging.info("API CONFIG: %s", api_config)
    logging.info("REPLICA CONFIG: %s", replica_config)

    proxy = Proxy(replica_config, api_config)
    proxy.start()
