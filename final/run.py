import config
import logging.config

from src.proxy import Proxy

logging.config.dictConfig(config.LOGGING_CONFIG)


if __name__ == "__main__":
    api_config = config.API_CONFIG.copy()

    replica_config = config.REPLICA_CONFIG.copy()
    replica_config.update(
        {
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
