from datetime import datetime
from uuid import uuid4

from bvdb.bvdb.db import Database, Table
from bvdb.bvdb.schema import Column, Schema
from bvdb.bvdb.types import Integer, String, Timestamp, UUID

if __name__ == "__main__":
    path = "/Users/vincent/Desktop/_harvard/__YEAR 4/SR SPRING/cs 262/code/final/example.bv"

    columns = [
        Column(
            UUID,
            "id",
            index=True,
            nullable=False,
            immutable=True,
            unique=True,
        ),
        Column(
            String,
            "name",
            index=False,
            nullable=False,
            immutable=False,
            unique=False,
        ),
        Column(
            Integer,
            "age",
            index=False,
            nullable=False,
            immutable=False,
            unique=False,
        ),
        Column(
            Timestamp,
            "created",
            index=False,
            nullable=False,
            immutable=False,
            unique=False,
        ),
    ]

    schema = Schema("users", columns=columns)

    database = Database(path)
    database.create_table(schema)

    users: Table = database.users

    users.insert({"id": uuid4(), "name": "alice", "age": 23, "created": datetime.now()})
    users.insert({"id": uuid4(), "name": "bob", "age": 21, "created": datetime.now()})

    print(users.rows)

    for row in users.select(lambda row: row["age"] > 22):
        print("found row", row)

    database.save()

    database_2 = Database(path)
    database_2.load()

    users_table_2 = database_2.users
    print(users_table_2.rows)
