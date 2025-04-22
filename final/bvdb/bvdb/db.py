from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any

from .io import write_file_header, validate_file_header
from .types import DataType
from .schema import Schema


class Table:
    """
    Stores rows (i.e. data) following a specified schema.
    """

    schema: Schema
    rows: list[dict[str, DataType]]
    num_rows: int

    def __init__(self, schema: Schema):
        self.schema = schema
        self.num_rows = 0
        self.rows = []

    ### FILE
    def load(self, path: str | Path):
        with open(path, "rb") as file:
            validate_file_header(file)
            num_rows = int.from_bytes(file.read(4), "big", signed=False)

            for _ in range(num_rows):
                row = {}
                for c in self.schema.columns:
                    row[c.name] = c.type_def.read(file)

                self._insert(row)

            assert self.num_rows == num_rows

    def save(self, path: str | Path):
        with open(path, "wb") as file:
            write_file_header(file)
            file.write(self.num_rows.to_bytes(4, "big", signed=False))

            for row in self.rows:
                for c in self.schema.columns:
                    row[c.name].write(file)

    ### PRIVATE INTERFACE
    def _insert(self, row: dict[str, DataType]):
        self.rows.append(row)
        self.num_rows += 1

    ### PUBLIC INTERFACE
    def select(self, condition_fn: Callable = lambda row: True) -> Generator:
        for i, row in enumerate(self.rows):
            if condition_fn(row):
                yield row

    def insert(self, row: dict[str, Any]):
        row = self.schema.validate_row(row)
        self._insert(row)

    def update(self, condition_fn: Callable, update_fn: Callable):
        for i, row in enumerate(self.rows):
            if condition_fn(row):
                update_fn(row)  # modify inplace
                self.rows[i] = self.schema.validate_row(row)

    def delete(self, condition_fn: Callable):
        for i, row in enumerate(self.rows):
            if condition_fn(row):
                self.rows.pop(i)


class Database:
    """
    Wrapper class for schemas and tables at a specified location.
    """

    schemas: dict[str, Schema]
    tables: dict[str, Table]
    path: str | Path

    def __init__(self, path: str | Path):
        self.path = Path(path)

        if self.path.suffix != ".bvdb":
            print(f"Expected path ending in `.bvdb`, got suffix `{self.path.suffix}`")

        self.schema_path = self.path / "schemas"
        self.table_path = self.path / "tables"

        self.schema_path.mkdir(0o755, parents=True, exist_ok=True)
        self.table_path.mkdir(0o755, parents=True, exist_ok=True)

        self.schemas = {}
        self.tables = {}

    ### TABLE MANAGEMENT
    def __getattr__(self, name: str) -> Any:
        if name in self.tables:
            return self.tables[name]

        raise AttributeError

    def create_table(self, schema: Schema):
        self.schemas[schema.name] = schema
        self.tables[schema.name] = Table(schema)

    def drop_table(self, name: str):
        self.schemas.pop(name)
        self.tables.pop(name)

        # Remove associated files
        (self.schema_path / f"{name}.schema").unlink(missing_ok=True)
        (self.table_path / f"{name}.table").unlink(missing_ok=True)

    ### FILE: LOAD
    def load_schemas(self, clear: bool = False):
        if clear:
            self.schemas = {}

        for sp in self.schema_path.glob("*.schema"):
            schema = Schema.load(sp)
            self.schemas[schema.name] = schema

    def load_tables(self, clear: bool = False):
        if clear:
            self.tables = {}

        for tp in self.table_path.glob("*.table"):
            if (name := tp.name[:-6]) not in self.schemas:
                raise ValueError(f"Please load schema for {name} before table.")

            table = Table(self.schemas[name])
            table.load(tp)
            self.tables[table.schema.name] = table

    ### FILE: SAVE
    def load(self, clear: bool = True):
        self.load_schemas(clear=clear)
        self.load_tables(clear=clear)

    def save_schemas(self):
        for name, schema in self.schemas.items():
            schema.save(self.schema_path / f"{name}.schema")

    def save_tables(self):
        for name, table in self.tables.items():
            table.save(self.table_path / f"{name}.table")

    def save(self):
        self.save_schemas()
        self.save_tables()
