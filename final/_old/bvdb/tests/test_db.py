import pytest

from bvdb.db import Table, Database
from bvdb.schema import Column, Schema
from bvdb.types import Integer


@pytest.fixture(autouse=True)
def disable_file_headers(monkeypatch):
    monkeypatch.setattr("bvdb.src.io.write_file_header", lambda f: None)
    monkeypatch.setattr("bvdb.src.io.validate_file_header", lambda f: None)


@pytest.fixture
def simple_schema():
    col = Column(Integer, name="id")
    return Schema(name="TestSchema", flags=0, columns=[col])


@pytest.fixture
def table(simple_schema):
    return Table(simple_schema)


def test_table_insert_and_select(table):
    table.insert({"id": "10"})
    rows = list(table.select(lambda row: row["id"].value == 10))
    assert len(rows) == 1
    assert rows[0]["id"].value == 10


def test_table_update(table):
    table.insert({"id": "5"})
    table.insert({"id": "15"})

    def condition(row):
        return row["id"].value < 10

    def updater(row):
        row["id"] = Integer(row["id"].value + 10)

    table.update(condition, updater)
    updated = list(table.select(lambda row: row["id"].value == 15))
    assert len(updated) == 2


def test_table_delete(table):
    table.insert({"id": "20"})
    table.insert({"id": "30"})
    table.delete(lambda row: row["id"].value == 20)
    remaining = list(table.select())
    assert len(remaining) == 1
    assert remaining[0]["id"].value == 30


def test_table_save_and_load(tmp_path, table):
    table.insert({"id": "100"})
    table.insert({"id": "200"})
    file_path = tmp_path / "table.bin"
    table.save(file_path)
    new_table = Table(table.schema)
    new_table.load(file_path)
    assert new_table.num_rows == 2
    loaded = [row["id"].value for row in new_table.rows]
    assert sorted(loaded) == [100, 200]


@pytest.fixture
def temp_database(tmp_path, simple_schema):
    db_path = tmp_path / "test.bvdb"
    db_path.mkdir()
    db = Database(db_path)
    db.create_table(simple_schema)
    return db


def test_database_getattr(temp_database):
    db = temp_database
    table_attr = getattr(db, db.schemas["TestSchema"].name)
    assert isinstance(table_attr, Table)


def test_database_create_and_drop_table(tmp_path, simple_schema):
    db_path = tmp_path / "drop_test.bvdb"
    db_path.mkdir()
    db = Database(db_path)
    db.create_table(simple_schema)
    name = simple_schema.name
    assert name in db.schemas
    assert name in db.tables
    schema_file = db.schema_path / f"{name}.schema"
    table_file = db.table_path / f"{name}.table"
    schema_file.write_bytes(b"dummy")
    table_file.write_bytes(b"dummy")
    db.drop_table(name)
    assert name not in db.schemas
    assert name not in db.tables
    assert not schema_file.exists()
    assert not table_file.exists()


def test_database_save_and_load(tmp_path, simple_schema):
    db_path = tmp_path / "db_test.bvdb"
    db_path.mkdir()
    db = Database(db_path)
    db.create_table(simple_schema)
    tbl = db.tables[simple_schema.name]
    tbl.insert({"id": "1"})
    tbl.insert({"id": "2"})
    db.save()

    db_2 = Database(db_path)
    db_2.load(clear=True)
    assert simple_schema.name in db_2.schemas
    assert simple_schema.name in db_2.tables
    loaded_table = db_2.tables[simple_schema.name]
    assert loaded_table.num_rows == 2
    loaded_ids = [row["id"].value for row in loaded_table.rows]
    assert sorted(loaded_ids) == [1, 2]
