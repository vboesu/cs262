import os
import time
import config
import logging.config
import dns.resolver

from proxy import Proxy

logging.config.dictConfig(config.LOGGING_CONFIG)

SERVER_ID = int(os.getenv("SERVER_ID"))


if __name__ == "__main__":
    api_config = config.API_CONFIG.copy()

    replica_config = config.REPLICA_CONFIG.copy()
    replica_config.update(
        {
            "SERVER_ID": SERVER_ID,
            "STRONG_CONSISTENCY": [
                "users.username",
                "users.password_hash",
                "accounts.*",
            ],
        }
    )

    logging.info("API CONFIG: %s", api_config)
    logging.info("REPLICA CONFIG: %s", replica_config)

    proxy = Proxy(replica_config, api_config)
    proxy.start()
