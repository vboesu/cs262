from datetime import datetime, timezone
from typing import IO, Any
from uuid import UUID as _UUID

import struct

from .base import Serializable
from .io import exact_read


class DataType(Serializable):
    key: int
    name: str
    _value: Any
    _type: type

    def __init__(self, value: Any):
        self.value = value

    def __repr__(self):
        return f"{self.__class__.__name__}({self.value})"

    ### OVERLOAD COMPARISONS
    def __eq__(self, other):
        if isinstance(other, DataType):
            return self.value.__eq__(other.value)
        return self.value.__eq__(other)

    def __ne__(self, other):
        if isinstance(other, DataType):
            return self.value.__ne__(other.value)
        return self.value.__ne__(other)

    def __gt__(self, other):
        if isinstance(other, DataType):
            return self.value.__gt__(other.value)
        return self.value.__gt__(other)

    def __lt__(self, other):
        if isinstance(other, DataType):
            return self.value.__lt__(other.value)
        return self.value.__lt__(other)

    def __ge__(self, other):
        if isinstance(other, DataType):
            return self.value.__ge__(other.value)
        return self.value.__ge__(other)

    def __le__(self, other):
        if isinstance(other, DataType):
            return self.value.__le__(other.value)
        return self.value.__le__(other)

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, v: Any):
        if isinstance(v, self._type):
            self._value = v
        else:
            self._value = self._type(v)  # attempt to convert


class Integer(DataType):
    """
    Integer (64-bit, unsigned, big-endian).
    """

    key: int = 0x01
    name: str = "integer"
    _value: int
    _type: type = int

    def to_binary(self) -> bytes:
        return self.value.to_bytes(8, "big", signed=True)

    @classmethod
    def from_binary(cls, b: bytes) -> "Integer":
        return Integer(int.from_bytes(b[:8], "big", signed=True))

    @classmethod
    def read(cls, file: IO) -> "Integer":
        return Integer(int.from_bytes(exact_read(file, 8), "big", signed=True))

    def length(self) -> int:
        return 8


class Double(DataType):
    """
    Double (64-bit, big-endian).
    """

    key: int = 0x02
    name: str = "double"
    _value: float
    _type: type = float

    def to_binary(self) -> bytes:
        return struct.pack("!d", self.value)

    @classmethod
    def from_binary(cls, b: bytes) -> "Double":
        return Double(struct.unpack("!d", b[:8])[0])

    @classmethod
    def read(cls, file: IO) -> "Double":
        return Double(struct.unpack("!d", exact_read(file, 8))[0])

    def length(self) -> int:
        return 8


class String(DataType):
    """
    String (UTF-8).
    """

    key: int = 0x03
    name: str = "string"
    _value: str
    _type: type = str

    def to_binary(self) -> bytes:
        encoded = self.value.encode("utf-8")
        pre = len(encoded).to_bytes(4, "big", signed=False)
        return pre + encoded

    @classmethod
    def from_binary(cls, b: bytes) -> "String":
        pre = int.from_bytes(b[:4], "big", signed=False)
        return String(b[4 : 4 + pre].decode("utf-8", errors="replace"))

    @classmethod
    def read(cls, file: IO) -> "String":
        pre = int.from_bytes(exact_read(file, 4), "big", signed=False)
        return String(exact_read(file, pre).decode("utf-8", errors="replace"))

    def length(self) -> int:
        return 4 + len(self.value.encode("utf-8"))


class Binary(DataType):
    """
    Binary data.
    """

    key: int = 0x04
    name: str = "binary"
    _value: bytes
    _type: type = bytes

    def to_binary(self) -> bytes:
        pre = len(self.value).to_bytes(4, "big", signed=True)
        return pre + self.value

    @classmethod
    def from_binary(cls, b: bytes) -> "Binary":
        pre = int.from_bytes(b[:4], "big", signed=True)
        return Binary(b[4 : 4 + pre])

    @classmethod
    def read(cls, file: IO) -> "Binary":
        pre = int.from_bytes(exact_read(file, 4), "big", signed=False)
        return Binary(exact_read(file, pre))

    def length(self) -> int:
        return 4 + len(self.value)


class Timestamp(DataType):
    """
    Timestamp (UTC) in microseconds.
    """

    key: int = 0x05
    name: str = "timezone"
    _value: datetime
    _type: type = datetime

    def __init__(self, value: int | datetime):
        self.value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, v: int | float | datetime):
        if isinstance(v, (int, float)):
            self._value = datetime.fromtimestamp(v, timezone.utc)
        elif isinstance(v, datetime):
            self._value = v

    def to_binary(self) -> bytes:
        ts = int(round(self.value.timestamp() * 1_000_000))
        return ts.to_bytes(8, "big", signed=True)

    @classmethod
    def from_binary(cls, b: bytes) -> "Timestamp":
        ts = int.from_bytes(b[:8], "big", signed=True)
        return Timestamp(ts / 1_000_000)

    @classmethod
    def read(cls, file: IO) -> "Timestamp":
        ts = int.from_bytes(exact_read(file, 8), "big", signed=True)
        return Timestamp(ts / 1_000_000)

    def length(self) -> int:
        return 8


class UUID(DataType):
    """
    Universally Unique Identifier (UUID), stored as 128-bit integer.
    """

    key: int = 0x06
    name: str = "uuid"
    _value: _UUID
    _type: type = _UUID

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, v: int | bytes | _UUID):
        if isinstance(v, int):
            self._value = _UUID(int=v)
        elif isinstance(v, bytes):
            self._value = _UUID(bytes=v)
        elif isinstance(v, _UUID):
            self._value = v
        else:
            raise TypeError(f"Unable to set UUID with object of type {type(v)}.")

    def to_binary(self) -> bytes:
        return self.value.bytes

    @classmethod
    def from_binary(cls, b: bytes) -> "UUID":
        return UUID(b[:16])

    @classmethod
    def read(cls, file: IO) -> "Binary":
        return UUID(exact_read(file, 16))

    def length(self) -> int:
        return 16


key_to_type_def: dict[int, type[DataType]] = {
    cls.key: cls for cls in DataType.__subclasses__()
}
