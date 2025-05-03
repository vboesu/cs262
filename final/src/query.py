from collections.abc import Hashable
from datetime import datetime
from typing import Any, Literal

from codec import default_encoder

Command = Literal[b"I", b"U", b"D"]


class Operation(object):
    cmd: Command
    schema: str
    column: str | None
    row: Hashable | None
    old_value: Any
    new_value: Any
    data: dict[str, Any]
    timestamp: datetime | None  # timestamp at which operation was performed
    logical_timestamp: int  # logical timestamp at which operation was performed
    transaction_id: bytes | None  # transaction ID when operation was performed

    def __init__(
        self,
        cmd: Command,
        schema: str,
        column: str | None = None,
        row: Hashable | None = None,
        old_value: Any = None,
        new_value: Any = None,
        data: dict[str, Any] = {},
        logical_timestamp: int = -1,
        timestamp: datetime | None = None,
        transaction_id: bytes | None = None,
    ):
        self.cmd = cmd
        self.schema = schema
        self.column = column
        self.row = row
        self.old_value = old_value
        self.new_value = new_value
        self.data = data
        self.logical_timestamp = logical_timestamp
        self.timestamp = timestamp
        self.transaction_id = transaction_id

        self.validate()

    def __repr__(self) -> str:
        return "Operation(" + ", ".join(f"{k}={v}" for k, v in vars(self).items()) + ")"

    def validate(self):
        assert self.cmd in {b"I", b"U", b"D"}
        assert self.schema
        assert self.schema.isascii()

        if self.column is not None:
            assert self.column.isascii()

        if self.cmd in {b"U", b"D"}:
            assert self.row is not None

        if self.cmd == b"U":
            assert self.column is not None
            # assert self.old_value != self.new_value

        if self.cmd == b"I":
            assert self.data

    ### BINARY
    def encode(self) -> bytes:
        return default_encoder.encode(
            [
                self.cmd,
                self.schema,
                self.column,
                self.row,
                self.old_value,
                self.new_value,
                self.data,
                self.logical_timestamp,
                self.timestamp,
                self.transaction_id,
            ]
        )

    @classmethod
    def decode(cls, b: bytes) -> "Operation":
        return cls(*default_encoder.decode(b)[0])

    ### SQL
    def _update_as_sql(self) -> tuple[str, list]:
        query = f"UPDATE {self.schema} SET {self.column} = ? WHERE id = ? AND {self.column} = ?"
        params = [self.new_value, self.row, self.old_value]

        return query, params

    def _insert_as_sql(self) -> tuple[str, list]:
        query = f"INSERT INTO {self.schema} ({', '.join(self.data.keys())}) VALUES ({', '.join('?' for _ in self.data)})"
        params = list(self.data.values())

        return query, params

    def _delete_as_sql(self) -> tuple[str, list]:
        query = f"DELETE FROM {self.schema} WHERE id = ?"
        params = [self.row]

        return query, params

    def as_sql(self) -> tuple[str, list]:
        """
        Construct the SQL query corresponding to the Operation object.

        Returns
        -------
        query : str
            SQL query string with placeholders.
        params : list
            SQL parameters.
        """
        _cmd_to_fn = {
            b"U": self._update_as_sql,
            b"I": self._insert_as_sql,
            b"D": self._delete_as_sql,
        }

        self.validate()
        return _cmd_to_fn[self.cmd]()

    def to_sql(
        self, schema: str, operation_id: int, strong: bool = False
    ) -> tuple[str, list]:
        """
        Construct the query to store the Operation object in a log.

        Parameters
        ----------
        schema : str
            Name of the table storing the log.
        operation_id : int
            ID of this operation within the query.
        strong : bool
            Flag for strong query, i.e. to include logical timestamp.

        Returns
        -------
        query : str
            SQL query string with placeholders.
        params : list
            SQL parameters.
        """
        self.validate()

        data = {
            "transaction_id": self.transaction_id,
            "operation_id": operation_id + 1,
            "command": ord(self.cmd),
            "schema": self.schema,
            "column": self.column,
            "row": self.row,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "data": default_encoder.encode(self.data),
            "timestamp": self.timestamp,
        }

        if strong:
            data["logical_timestamp"] = self.logical_timestamp

        return (
            f"""INSERT INTO {schema} ({", ".join(data.keys())}) 
                    VALUES ({", ".join("?" for _ in data.keys())})""",
            list(data.values()),
        )

    @classmethod
    def from_sql(cls, row: dict) -> "Operation":
        row["cmd"] = chr(row["command"]).encode("ascii")
        row["data"] = default_encoder.decode(row["data"])[0]

        # Remove unused arguments
        row.pop("command", None)
        row.pop("operation_id", None)

        return cls(**row)


class Query(object):
    ops: list[Operation]

    def __init__(self, ops: list[Operation]):
        self.ops = ops

    def __repr__(self) -> str:
        return f"Query(transaction_id={self.transaction_id}, logical_timestamp={self.logical_timestamp}, timestamp={self.timestamp})"

    def __getattr__(self, name: str) -> Any:
        if name in {"timestamp", "logical_timestamp", "transaction_id"}:
            if len(self.ops) == 0:
                return

            p = getattr(self.ops[0], name)
            if all(getattr(op, name) == p for op in self.ops):
                return p

            return None

        return super().__getattr__(name)

    def __setattr__(self, name: str, value: Any) -> Any:
        if name == "timestamp":
            value = value or datetime.now()

        if name in {"timestamp", "logical_timestamp", "transaction_id"}:
            for op in self.ops:
                setattr(op, name, value)

        super().__setattr__(name, value)

    def encode(self) -> bytes:
        return default_encoder.encode([op.encode() for op in self.ops])

    @classmethod
    def decode(cls, b: bytes) -> "Query":
        ops = [
            Operation(*default_encoder.decode(op_)[0])
            for op_ in default_encoder.decode(b)[0]
        ]
        return cls(ops)
