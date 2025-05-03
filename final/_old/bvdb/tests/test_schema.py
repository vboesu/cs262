import io
import pytest

from bvdb.schema import Column, Schema
from bvdb.types import DataType, Integer


# Disable file header functions during tests for Schema.write/read.
@pytest.fixture(autouse=True)
def disable_file_header(monkeypatch):
    monkeypatch.setattr("bvdb.src.io.write_file_header", lambda f: None)
    monkeypatch.setattr("bvdb.src.io.validate_file_header", lambda f: None)


def test_column_to_binary_length():
    name = "col1"
    col = Column(
        Integer,
        name=name,
        index=True,
        nullable=False,
        immutable=True,
        unique=False,
        flags=42,
    )
    binary = col.to_binary()
    expected_length = 4 + len(name) + 4 + 1 + 4
    assert len(binary) == expected_length


def test_column_from_binary_roundtrip():
    name = "mycol"
    original = Column(
        Integer,
        name=name,
        index=True,
        nullable=True,
        immutable=False,
        unique=True,
        flags=7,
    )
    binary = original.to_binary()
    new_col = Column.from_binary(binary)
    assert new_col.name == original.name
    assert new_col.type_def == original.type_def
    assert new_col.index == original.index
    assert new_col.nullable == original.nullable
    assert new_col.immutable == original.immutable
    assert new_col.unique == original.unique
    assert new_col.flags == original.flags


def test_column_read_roundtrip():
    name = "col_read"
    original = Column(
        Integer,
        name=name,
        index=False,
        nullable=True,
        immutable=True,
        unique=False,
        flags=99,
    )
    binary = original.to_binary()
    stream = io.BytesIO(binary)
    new_col = Column.read(stream)
    assert new_col.name == original.name
    assert new_col.type_def == original.type_def
    assert new_col.index == original.index
    assert new_col.nullable == original.nullable
    assert new_col.immutable == original.immutable
    assert new_col.unique == original.unique
    assert new_col.flags == original.flags


def test_schema_to_binary_empty():
    schema = Schema(name="test_schema", flags=0, columns=[])
    binary = schema.to_binary()
    expected = (
        len(schema.name).to_bytes(4, "big", signed=False)
        + schema.name.encode("ascii")
        + schema.flags.to_bytes(4, "big", signed=False)
        + (0).to_bytes(4, "big", signed=False)
    )
    assert binary == expected


def test_schema_from_binary_empty():
    schema = Schema(name="test_schema", flags=123, columns=[])
    binary = schema.to_binary()
    new_schema = Schema.from_binary(binary)
    assert new_schema.name == schema.name
    assert new_schema.flags == schema.flags
    assert new_schema.columns == []


def test_schema_non_ascii_name_raises():
    non_ascii_name = "schéma"  # non-ASCII character
    schema = Schema(name=non_ascii_name, flags=0, columns=[])
    with pytest.raises(UnicodeEncodeError):
        schema.to_binary()


def test_schema_to_from_binary_with_columns():
    col = Column(
        Integer,
        name="age",
        index=True,
        nullable=False,
        immutable=False,
        unique=False,
        flags=0,
    )
    schema = Schema(name="Person", flags=1, columns=[col])
    binary = schema.to_binary()
    new_schema = Schema.from_binary(binary)
    assert new_schema.name == schema.name
    assert new_schema.flags == schema.flags
    assert len(new_schema.columns) == 1
    new_col = new_schema.columns[0]
    assert new_col.name == col.name
    assert new_col.type_def == col.type_def
    assert new_col.index == col.index
    assert new_col.nullable == col.nullable
    assert new_col.immutable == col.immutable
    assert new_col.unique == col.unique
    assert new_col.flags == col.flags


def test_schema_write_read_empty():
    schema = Schema(name="SchemaEmpty", flags=5, columns=[])
    stream = io.BytesIO()
    schema.write(stream)
    stream.seek(0)
    new_schema = Schema.read(stream)
    assert new_schema.name == schema.name
    assert new_schema.flags == schema.flags
    assert new_schema.columns == []


def test_schema_save_load(tmp_path):
    schema = Schema(name="FileSchema", flags=77, columns=[])
    file_path = tmp_path / "schema.bin"
    schema.save(file_path)
    new_schema = Schema.load(file_path)
    assert new_schema.name == schema.name
    assert new_schema.flags == schema.flags
    assert new_schema.columns == []


def test_schema_validate_row_success():
    col = Column(Integer, name="age")
    schema = Schema(name="Test", columns=[col])
    row = {"age": "42"}
    validated = schema.validate_row(row)
    assert "age" in validated
    # Assuming Integer converts "42" to an instance with integer value 42.
    assert isinstance(validated["age"], DataType)
    assert validated["age"].value == 42


def test_schema_validate_row_missing():
    col = Column(Integer, name="age")
    schema = Schema(name="Test", columns=[col])
    with pytest.raises(ValueError):
        schema.validate_row({})
