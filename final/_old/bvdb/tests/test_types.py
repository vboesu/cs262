import io
import struct
import pytest

from datetime import datetime, timezone
from uuid import uuid4

from bvdb.types import Integer, Double, Timestamp, UUID, String, Binary, key_to_type_def


def test_integer_to_from_binary():
    val = 12345678
    int_obj = Integer(val)
    binary = int_obj.to_binary()
    assert len(binary) == 8
    int_obj2 = Integer.from_binary(binary)
    assert int_obj.value == int_obj2.value


def test_integer_read():
    val = 987654321
    binary = val.to_bytes(8, "big", signed=True)
    file_obj = io.BytesIO(binary)
    int_obj = Integer.read(file_obj)
    assert int_obj.value == val


def test_double_to_from_binary():
    val = 3.14159
    double_obj = Double(val)
    binary = double_obj.to_binary()
    assert len(binary) == 8
    double_obj2 = Double.from_binary(binary)
    assert abs(double_obj2.value - val) < 1e-6


def test_double_read():
    val = 2.71828
    binary = struct.pack("!d", val)
    file_obj = io.BytesIO(binary)
    double_obj = Double.read(file_obj)
    assert abs(double_obj.value - val) < 1e-6


def test_string_to_from_binary():
    s = "Hello, world!"
    str_obj = String(s)
    binary = str_obj.to_binary()
    str_obj2 = String.from_binary(binary)
    assert str_obj.value == str_obj2.value


def test_string_read():
    s = "Hello, world!"
    encoded = s.encode("utf-8")
    pre = len(encoded).to_bytes(4, "big", signed=False)
    file_obj = io.BytesIO(pre + encoded)
    str_obj = String.read(file_obj)
    assert str_obj.value == s


def test_binary_to_from_binary():
    data = b"\x01\x02\x03\x04"
    bin_obj = Binary(data)
    binary = bin_obj.to_binary()
    bin_obj2 = Binary.from_binary(binary)
    assert bin_obj.value == bin_obj2.value


def test_binary_read():
    data = b"abc"
    pre = len(data).to_bytes(4, "big", signed=True)
    file_obj = io.BytesIO(pre + data)
    bin_obj = Binary.read(file_obj)
    assert bin_obj.value == data


def test_timestamp_to_from_binary():
    now = datetime.now(timezone.utc)
    ts_obj = Timestamp(now)
    binary = ts_obj.to_binary()
    ts_obj2 = Timestamp.from_binary(binary)
    # Allow a small difference due to rounding.
    assert abs(ts_obj.value.timestamp() - ts_obj2.value.timestamp()) < 1e-6


def test_timestamp_read():
    now = datetime.now(timezone.utc)
    ts = int(round(now.timestamp() * 1_000_000))
    binary = ts.to_bytes(8, "big", signed=True)
    file_obj = io.BytesIO(binary)
    ts_obj = Timestamp.read(file_obj)
    assert abs(ts_obj.value.timestamp() - now.timestamp()) < 1e-6


def test_uuid_to_from_binary():
    uuid_obj = UUID(uuid4())
    binary = uuid_obj.to_binary()
    uuid_obj2 = UUID.from_binary(binary)
    assert uuid_obj.value == uuid_obj2.value


def test_uuid_read():
    u = uuid4()
    file_obj = io.BytesIO(u.bytes)
    uuid_obj = UUID.read(file_obj)
    assert uuid_obj.value == u


def test_key_to_type_def_contains_all_types():
    types = {Integer, Double, String, Binary, Timestamp, UUID}
    mapped_types = set(key_to_type_def.values())
    assert types.issubset(mapped_types)


def test_data_type_comparisons():
    int_obj1 = Integer(100)
    int_obj2 = Integer(200)

    # comparison with other `DataType` objects
    assert int_obj1 < int_obj2
    assert int_obj2 > int_obj1
    assert int_obj1 != int_obj2
    assert int_obj1 == Integer(100)

    # comparison with values
    assert int_obj1 < 200
    assert int_obj2 > 100
    assert int_obj1 != 200
    assert int_obj1 == 100

    double_obj1 = Double(3.14159)
    double_obj2 = Double(2.71828)

    assert double_obj1 > 3
    assert double_obj1 < 4
    assert double_obj2 < double_obj1
    assert double_obj1 > double_obj2
    assert double_obj1 != double_obj2


def test_integer_setter_conversion():
    int_obj = Integer(3.7)
    assert isinstance(int_obj.value, int)


def test_double_setter_conversion():
    double_obj = Double("3.14")
    assert abs(double_obj.value - 3.14) < 1e-6


def test_string_setter_conversion():
    str_obj = String(123)
    assert str_obj.value == "123"


def test_uuid_setter_invalid_type():
    with pytest.raises(TypeError):
        UUID(123.4)


def test_timestamp_setter_with_int():
    ts_obj = Timestamp(1609459200)  # Jan 1, 2021
    assert isinstance(ts_obj.value, datetime)
