# Hybrid-Consistency Replicated Database
Our final project implements a replicated database system, where data in specified tables and columns is kept strongly consistent with other data defaulting to eventual consistency. This setup is particularly interesting for use cases with mostly reads or with frequent reads and writes which do not require strong consistency.

For a more detailed documentation, see our [Report](report.pdf).

### Interface
Interactions with the database happen through a REST-style HTTP API. The HTTP request methods map to database operations according to the following table.

| **HTTP method** | **Database operation** |
| --------------- | ---------------------- |
| `GET`           | `SELECT`               |
| `POST`          | `INSERT`               |
| `PATCH`         | `UPDATE`               |
| `DELETE`        | `DELETE`               |

To interact with a specific table, call `/<table>` with the desired request method. If you want to interact with a specific row in a table, call `/<table>/<id>`, where `id` corresponds to the primary key column `id` of the table.

### Examples: Requests
Using the Python `requests` library, you can select the columns `username` and `name` from the table `users` as
```python
import requests

users = requests.get(
    "http://localhost:8888/users", 
    json={"columns": ["id", "name"]}
).json()
```
Similarly, if you want to select all columns from the `users` table for the row with `id` 123, you would run
```python
user = requests.get(
    "http://localhost:8888/users/123"
).json()
```
To create a new row in the `users` table, we call
```python
res = requests.post(
    "http://localhost:8888/users",
    json={"id": 123, "name": "My Name"}
)

if res.status_code == 200:
    print("Success!")
else:
    print(f"Error: {res.json()['error']}")
```
Notice that this operation is on the *table* as opposed to an individual row.

To update the value of a field such as `name`, we need to speficy the expected old value and the desired new value as a two-element list, i.e.
```python
res = requests.patch(
    "http://localhost:8888/users/123",
    json={"name": ["My Name", "My New Name"]}
)

if res.status_code == 200:
    print("Success!")
else:
    print(f"Error: {res.json()['error']}")
```
This operation is for a specific row, as identified by its primary key.

Finally, to delete a row, we call
```python
res = requests.delete(
    "http://localhost:8888/users/123"
)
```

### Configuration
To create the tables that will be available in your database instances, modify the setup script `setup.sql`. All tables should have a primary key column `id` which may be integers, UUIDs or strings. In `config.py` you can specify which columns should be kept strongly consistent by adding terms of the form `{table}.{column}` to the list. If you want to mark the entire table as strongly consistent, you can put `{table}.*`.

**Remark:** If you have an eventually consistent table, we recommend using UUIDs as primary keys, since autoincremented integers are vulnerable to race conditions.

You can control the number of replicas by setting the environment variable `N_REPLICAS` and `deploy:replicas` in the `docker-compose.yml`.

### Usage
To start the docker cluster, build the docker container using
```
docker build -t bvdb:latest .
```

Next, we initialize a docker swarm which will take care of spinning the desired number of replicas and the load balancing between the replicas.
```
docker swarm init
```
You only need to do this once. To start the replicas, we then run
```
docker stack deploy -c docker-compose.yml bvdb
```

Done! You can now access the database under `http://localhost:8888` (or change the port under `ports:published` in the `docker-compose.yml`).

If you want to inspect the combined logs from all replicas, you can do so using the command
```
docker service logs -f bvdb_bvdb
```

To shut down the cluster, run
```
docker service rm bvdb_bvdb
```