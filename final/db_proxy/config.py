API_CONFIG = {
    "DEBUG": True,
    "SERVER_NAME": "127.0.0.1:9999",
}

REPLICA_CONFIG = {
    "SERVER_ID": 1,
    "REPLICAS": {
        1: "127.0.0.1:10001",
        2: "127.0.0.1:20002",
        3: "127.0.0.1:30003",
        4: "127.0.0.1:40004",
    },
    "INSTANCE_PATH": "instance_1",
    "HEARTBEAT_INTERVAL_MS": 1_000,
    "ELECTION_TIMEOUT_MS": 6_000,
    "STRONG_CONSISTENCY": [],
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
    "root": {"level": "DEBUG", "handlers": ["console", "file"]},
}
