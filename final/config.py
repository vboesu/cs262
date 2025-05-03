API_CONFIG = {
    "DEBUG": True,
}

REPLICA_CONFIG = {
    "SERVER_ID": 1,
    "INSTANCE_PATH": "instance",
    "HEARTBEAT_INTERVAL_MS": 100,
    "ELECTION_TIMEOUT_MS": 1_000,
    "STRONG_CONSISTENCY": [
        "users.username",
        "users.password_hash",
        "accounts.*",
    ],
    "SETUP_SCRIPT": "setup.sql",
}

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "detailed": {
            "format": "%(asctime)s.%(msecs)06d [%(levelname)s] %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "detailed",
            "stream": "ext://sys.stdout",
        },
        "file": {
            "class": "logging.FileHandler",
            "level": "DEBUG",
            "formatter": "detailed",
            "filename": "main.log",
            "mode": "a",
            "encoding": "utf-8",
        },
    },
    "root": {"level": "INFO", "handlers": ["console", "file"]},
}
