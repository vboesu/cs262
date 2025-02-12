import json
import struct
from typing import Any, Literal


class Codec:
    def encode(self, obj: Any) -> bytes:
        pass

    def decode(self, data: bytes) -> tuple[Any, bytes]:
        pass


class BVCodec(Codec):
    """
    Encoder/decoder class for Bright-Vincent-Codec.
    Uses a type-length-value encoding. Currently supports
    int, float, str, list, dict, bool, and None types.
    """

    # Define type codes as class constants
    TYPE_INT = 0x01
    TYPE_FLOAT = 0x02
    TYPE_STRING = 0x03
    TYPE_BYTES = 0x04
    TYPE_LIST = 0x05
    TYPE_DICT = 0x06
    TYPE_BOOL = 0x07
    TYPE_NONE = 0x08

    def __init__(self, byteorder: Literal["little", "big"] = "little"):
        self.byteorder = byteorder
        self.bo = "<" if byteorder == "little" else ">"

    ### PRIVATE + HELPER FUNCTIONS
    def _encode_int(self, obj: int) -> bytes:
        type_code = self.TYPE_INT.to_bytes(1, self.byteorder)
        byte_length = (obj.bit_length() // 8) + 1  # +1 because signed
        value = obj.to_bytes(byte_length, self.byteorder, signed=True)
        length = len(value).to_bytes(2, self.byteorder)
        return type_code + length + value

    def _encode_float(self, obj: float) -> bytes:
        type_code = self.TYPE_FLOAT.to_bytes(1, self.byteorder)
        value = struct.pack(f"{self.bo}d", obj)
        length = len(value).to_bytes(2, self.byteorder)
        return type_code + length + value

    def _encode_string(self, obj: str) -> bytes:
        type_code = self.TYPE_STRING.to_bytes(1, self.byteorder)
        value = obj.encode("utf-8")
        length = len(value).to_bytes(2, self.byteorder)
        return type_code + length + value

    def _encode_list(self, obj: list) -> bytes:
        type_code = self.TYPE_LIST.to_bytes(1, self.byteorder)
        length = len(obj).to_bytes(2, self.byteorder)  # Use number of elements
        elements = b"".join([self.encode(element) for element in obj])
        return type_code + length + elements

    def _encode_dict(self, obj: dict) -> bytes:
        type_code = self.TYPE_DICT.to_bytes(1, self.byteorder)
        length = len(obj).to_bytes(2, self.byteorder)  # Use number of items
        items = b""
        for key, value in obj.items():
            items += self.encode(key)
            items += self.encode(value)
        return type_code + length + items

    def _encode_bool(self, obj: bool) -> bytes:
        type_code = self.TYPE_BOOL.to_bytes(1, self.byteorder)
        value = b"\x01" if obj else b"\x00"
        length = int(1).to_bytes(2, self.byteorder)
        return type_code + length + value

    def _encode_none(self) -> bytes:
        return self.TYPE_NONE.to_bytes(1, self.byteorder) + b"\x00\x00"

    def _encode_bytes(self, obj: bytes) -> bytes:
        type_code = self.TYPE_BYTES.to_bytes(1, self.byteorder)
        length = len(obj).to_bytes(2, self.byteorder)
        return type_code + length + obj

    ### PUBLIC INTERFACE FUNCTIONS
    def encode(self, obj: Any) -> bytes:
        """
        Recursively encodes an object into BVCodec.
        """
        if isinstance(obj, bool):  # bool has to come first bc it's a subclass of int
            return self._encode_bool(obj)
        elif isinstance(obj, int):
            return self._encode_int(obj)
        elif isinstance(obj, float):
            return self._encode_float(obj)
        elif isinstance(obj, str):
            return self._encode_string(obj)
        elif isinstance(obj, bytes):
            return self._encode_bytes(obj)
        elif isinstance(obj, list):
            return self._encode_list(obj)
        elif isinstance(obj, dict):
            return self._encode_dict(obj)
        elif obj is None:
            return self._encode_none()

        raise TypeError(f"Unsupported type for encoding: {type(obj)}")

    def decode(self, data: bytes) -> tuple[Any, bytes]:
        """
        Decodes bytes into Python object(s) using BVCodec format.
        Returns tuple of decoded object and remaining bytes.
        """
        type_code, length = struct.unpack(f"{self.bo}BH", data[:3])
        remaining = data[3:]

        # Non-recursive data types
        if type_code == self.TYPE_INT:
            assert len(remaining) >= length
            return (
                int.from_bytes(remaining[:length], self.byteorder, signed=True),
                remaining[length:],
            )

        elif type_code == self.TYPE_FLOAT:
            assert len(remaining) >= length
            return (
                struct.unpack(f"{self.bo}d", remaining[:length])[0],
                remaining[length:],
            )

        elif type_code == self.TYPE_STRING:
            assert len(remaining) >= length
            return (
                remaining[:length].decode("utf-8"),
                remaining[length:],
            )

        elif type_code == self.TYPE_BYTES:
            assert len(remaining) >= length
            return remaining[:length], remaining[length:]

        elif type_code == self.TYPE_BOOL:
            assert len(remaining) >= length and length == 1
            if remaining[0] & 0b11111110:
                raise ValueError(f"Invalid bool option: received {remaining[0]}")
            return remaining[0] == 0x01, remaining[1:]

        elif type_code == self.TYPE_NONE:
            assert length == 0
            return None, remaining

        # Recursive data types
        elif type_code == self.TYPE_LIST:
            lst = list()
            for _ in range(length):
                obj, remaining = self.decode(remaining)
                lst.append(obj)
            return lst, remaining

        elif type_code == self.TYPE_DICT:
            dct = dict()
            for _ in range(length):
                key, remaining = self.decode(remaining)
                val, remaining = self.decode(remaining)
                dct[key] = val
            return dct, remaining

        raise ValueError(f"Unknown type code: {type_code}")


class JSONCodec(Codec):
    def __init__(self, *args, **kwargs):
        pass

    def encode(self, obj: Any) -> bytes:
        return json.dumps(obj).encode("utf-8")

    def decode(self, data: bytes) -> tuple[Any, bytes]:
        return json.loads(data), b""
