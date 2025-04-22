import io
import pytest

from bvdb.io import exact_read, write_file_header, validate_file_header


def test_file_header(monkeypatch):
    monkeypatch.setattr("bvdb.src.__magic__", b"TEST")
    monkeypatch.setattr("bvdb.src.__version__", 123)
    file_obj = io.BytesIO()
    write_file_header(file_obj)
    file_obj.seek(0)
    validate_file_header(file_obj)


def test_exact_read_success():
    file_obj = io.BytesIO(b"12345")
    data = exact_read(file_obj, 3)
    assert data == b"123"
    data = exact_read(file_obj, 2)
    assert data == b"45"


def test_exact_read_insufficient():
    file_obj = io.BytesIO(b"12")
    with pytest.raises(ValueError):
        exact_read(file_obj, 3)
