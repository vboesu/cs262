from proxy import Proxy

if __name__ == "__main__":
    api_config = {
        "DEBUG": True,
        "SERVER_NAME": "127.0.0.1:9999",
    }

    replica_config = {
        "PORT": 40004,
    }

    proxy = Proxy(replica_config, api_config)
    proxy.start()
