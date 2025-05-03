from pathlib import Path
from typing import IO, Any

from .base import Serializable
from .io import exact_read, write_file_header, validate_file_header
from .types import DataType, key_to_type_def


class Column(Serializable):
    name: str
    type_def: type[DataType]
    index: bool
    nullable: bool
    immutable: bool
    unique: bool
    flags: int

    def __init__(
        self,
        type_def: type[DataType],
        name: str = None,
        index: bool = False,
        nullable: bool = False,
        immutable: bool = False,
        unique: bool = False,
        flags: int = 0,
    ):
        self.type_def = type_def
        self.name = name
        self.index = index
        self.nullable = nullable
        self.immutable = immutable
        self.unique = unique
        self.flags = flags

    def to_binary(self) -> bytes:
        header = len(self.name).to_bytes(4, "big", signed=False)
        header += self.name.encode("ascii")
        col_flags = (
            (self.index << 0)
            | (self.nullable << 1)
            | (self.immutable << 2)
            | (self.unique << 3)
        )

        header += self.type_def.key.to_bytes(4, "big", signed=False)
        header += col_flags.to_bytes(1, "big", signed=False)
        header += self.flags.to_bytes(4, "big", signed=False)
        return header

    @classmethod
    def from_binary(cls, b: bytes) -> "Column":
        len_name = int.from_bytes(b[:4], "big", signed=False)
        b = b[4:]

        name = b[:len_name].decode("ascii")
        b = b[len_name:]

        type_def_key = int.from_bytes(b[:4], "big", signed=False)
        b = b[4:]

        col_flags = int.from_bytes(b[:1], "big", signed=False)
        b = b[1:]

        flags = int.from_bytes(b[:4], "big", signed=False)
        b = b[4:]

        index = (col_flags & (1 << 0)) != 0
        nullable = (col_flags & (1 << 1)) != 0
        immutable = (col_flags & (1 << 2)) != 0
        unique = (col_flags & (1 << 3)) != 0

        return Column(
            key_to_type_def.get(type_def_key),
            name,
            index,
            nullable,
            immutable,
            unique,
            flags,
        )

    @classmethod
    def read(cls, file: IO) -> "Column":
        len_name = int.from_bytes(exact_read(file, 4), "big", signed=False)
        name = exact_read(file, len_name).decode("ascii")
        type_def_key = int.from_bytes(exact_read(file, 4), "big", signed=False)
        col_flags = int.from_bytes(exact_read(file, 1), "big", signed=False)
        flags = int.from_bytes(exact_read(file, 4), "big", signed=False)

        index = (col_flags & (1 << 0)) != 0
        nullable = (col_flags & (1 << 1)) != 0
        immutable = (col_flags & (1 << 2)) != 0
        unique = (col_flags & (1 << 3)) != 0

        return Column(
            key_to_type_def.get(type_def_key),
            name,
            index,
            nullable,
            immutable,
            unique,
            flags,
        )


class Schema(Serializable):
    name: str
    flags: int
    columns: list[Column]

    def __init__(self, name: str = None, flags: int = 0, columns: list[Column] = []):
        self.name = name
        self.flags = flags
        self.columns = columns

    def to_binary(self) -> bytes:
        header = len(self.name).to_bytes(4, "big", signed=False)
        header += self.name.encode("ascii")
        header += self.flags.to_bytes(4, "big", signed=False)
        header += len(self.columns).to_bytes(4, "big", signed=False)
        return header + b"".join([col.to_binary() for col in self.columns])

    @classmethod
    def from_binary(cls, b: bytes) -> "Schema":
        schema = Schema()
        len_name = int.from_bytes(b[:4], "big", signed=False)
        b = b[4:]

        schema.name = b[:len_name].decode("ascii")
        b = b[len_name:]

        schema.flags = int.from_bytes(b[:4], "big", signed=False)
        b = b[4:]

        num_columns = int.from_bytes(b[:4], "big", signed=False)
        b = b[4:]

        for i in range(num_columns):
            col = Column.from_binary(b)
            b = b[col.length() :]

            schema.columns.append(col)

        return schema

    def write(self, file: IO):
        write_file_header(file)
        file.write(self.to_binary())

    @classmethod
    def read(self, file: IO) -> "Schema":
        validate_file_header(file)
        schema = Schema()
        len_name = int.from_bytes(exact_read(file, 4), "big", signed=False)
        schema.name = exact_read(file, len_name).decode("ascii")
        schema.flags = int.from_bytes(exact_read(file, 4), "big", signed=False)
        num_columns = int.from_bytes(exact_read(file, 4), "big", signed=False)

        schema.columns = [Column.read(file) for _ in range(num_columns)]

        return schema

    def save(self, path: str | Path):
        """Wrapper function for `write`."""
        with open(path, "wb") as file:
            self.write(file)

    @classmethod
    def load(cls, path: str | Path) -> "Schema":
        """Wrapper function for `read`."""
        with open(path, "rb") as file:
            return cls.read(file)

    def validate_row(self, row: dict[str, Any]) -> dict[str, DataType]:
        validated = {}

        for col in self.columns:
            if col.name not in row:
                raise ValueError(f"Missing value for column {col.name}.")

            if not isinstance(row[col.name], col.type_def):
                # convert to `DataType` for storage
                validated[col.name] = col.type_def(row[col.name])
            else:
                validated[col.name] = row[col.name]

        return validated
