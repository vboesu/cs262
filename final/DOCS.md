### Usage
To start the docker cluster, build the docker container using
```
docker build -t bvdb:latest .
```

Next, we initialize a docker swarm which will take care of spinning the desired number of replicas and the load balancing between the replicas.
```
docker swarm init
```

To start the replicas, we then run
```
docker stack deploy -c docker-compose.yml bvdb
```

Done! You can now access the database under `http://localhost:8888` (or change the port under `ports:published` in the `docker-compose.yml`).