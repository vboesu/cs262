from typing import IO
from . import __magic__, __version__


def write_file_header(file: IO):
    """
    Write file header for database (schema, table) file.
    """
    file.write(__magic__)
    file.write(int(__version__).to_bytes(2, "big", signed=False))


def validate_file_header(file: IO):
    """
    Validate file header for database (schema, table) file. Consumes
    the relevant bytes of the file.
    """
    assert file.read(len(__magic__)) == __magic__
    assert int.from_bytes(file.read(2), "big", signed=False) == __version__


def exact_read(file: IO, n: int) -> bytes:
    """
    Read exactly `n` bytes, throw an error if unable to.
    """
    data = file.read(n)
    if len(data) != n:
        raise ValueError(f"Unable to read {n} bytes from file.")

    return data
