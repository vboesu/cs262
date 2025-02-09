import math
import pytest
from src.codec import BVCodec


@pytest.fixture
def codec():
    return BVCodec()


@pytest.mark.parametrize(
    "value",
    [
        0,
        1,
        -1,
        123456,
        -654321,
        2**64,
        -(2**64),
    ],
)
def test_encode_decode_int(codec, value):
    decoded, remaining = codec.decode(codec.encode(value))
    assert decoded == value, f"Failed for integer value: {value}"
    assert len(remaining) == 0


@pytest.mark.parametrize(
    "value",
    [
        0.0,
        -0.0,
        1.2345,
        -6.789,
        math.pi,
        math.e,
        float("inf"),
        float("-inf"),
        float("nan"),
    ],
)
def test_encode_decode_float(codec, value):
    decoded, remaining = codec.decode(codec.encode(value))
    if math.isnan(value):
        assert math.isnan(decoded), "Decoded value is not NaN as expected."
    else:
        assert decoded == value, f"Failed for float value: {value}"

    assert len(remaining) == 0


@pytest.mark.parametrize(
    "value",
    [
        "",
        "Hello, World!",
        "こんにちは世界",  # "Hello, World!" in Japanese
        "😊🚀🔥",
        "A" * 1000,  # Long string
    ],
)
def test_encode_decode_string(codec, value):
    decoded, remaining = codec.decode(codec.encode(value))
    assert decoded == value, f"Failed for string value: {value}"
    assert len(remaining) == 0


@pytest.mark.parametrize(
    "value",
    [
        b"",  # empty byte string
        b"\x01",
        "Hello, World!".encode("utf-8"),
        b"".join([i.to_bytes(2) for i in range(1000)]),
    ],
)
def test_encode_decode_bytes(codec, value):
    decoded, remaining = codec.decode(codec.encode(value))
    assert decoded == value, f"Failed for bytes value: {value}"
    assert len(remaining) == 0


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
    ],
)
def test_encode_decode_bool(codec, value):
    decoded, remaining = codec.decode(codec.encode(value))
    assert decoded == value, f"Failed for boolean value: {value}"
    assert len(remaining) == 0


def test_encode_decode_none(codec):
    decoded, remaining = codec.decode(codec.encode(None))
    assert decoded is None, "Failed for None value."
    assert len(remaining) == 0


def test_encode_decode_empty_list(codec):
    decoded, remaining = codec.decode(codec.encode(list()))
    assert decoded == list(), "Failed for empty list."
    assert len(remaining) == 0


def test_encode_decode_empty_dict(codec):
    decoded, remaining = codec.decode(codec.encode(dict()))
    assert decoded == dict(), "Failed for empty dictionary."
    assert len(remaining) == 0


@pytest.mark.parametrize(
    "value",
    [
        [1, 2, 3, 4, 5],
        ["a", "b", "c"],
        [True, False, True],
        [None, None],
    ],
)
def test_encode_decode_simple_list(codec, value):
    decoded, remaining = codec.decode(codec.encode(value))
    assert decoded == value, f"Failed for simple list: {value}"
    assert len(remaining) == 0


@pytest.mark.parametrize(
    "value",
    [
        [1, "two", 3.0, True, None],
        ["string", 42, False, 3.14, {"key": "value"}],
        [None, {"a": [1, 2, 3]}, [True, False], "end"],
    ],
)
def test_encode_decode_mixed_list(codec, value):
    decoded, remaining = codec.decode(codec.encode(value))
    assert decoded == value, f"Failed for mixed list: {value}"
    assert len(remaining) == 0


@pytest.mark.parametrize(
    "value",
    [
        {"a": 1, "b": 2},
        {"key": "value", "number": 42},
        {"bool_true": True, "bool_false": False},
        {"none": None},
    ],
)
def test_encode_decode_simple_dict(codec, value):
    decoded, remaining = codec.decode(codec.encode(value))
    assert decoded == value, f"Failed for simple dictionary: {value}"
    assert len(remaining) == 0


@pytest.mark.parametrize(
    "value",
    [
        {"int": 1, "str": "two", "float": 3.0},
        {"list": [1, 2, 3], "dict": {"nested_key": "nested_value"}},
        {"bool": True, "none": None, "number": 42},
    ],
)
def test_encode_decode_mixed_dict(codec, value):
    decoded, remaining = codec.decode(codec.encode(value))
    assert decoded == value, f"Failed for mixed dictionary: {value}"
    assert len(remaining) == 0


def test_encode_decode_nested_structures(codec):
    value = {
        "level1": {
            "level2": {
                "level3_int": 123,
                "level3_list": [1, {"level4": "deep"}, 3.14],
            },
            "level2_list": [True, False, None, {"key": "value"}],
        },
        "another_key": [{"a": 1}, {"b": 2}, [3, 4, 5]],
    }
    decoded, remaining = codec.decode(codec.encode(value))
    assert decoded == value, "Failed for nested structures."
    assert len(remaining) == 0


def test_encode_decode_large_structure(codec):
    value = {
        "numbers": list(range(1000)),
        "strings": ["str" + str(i) for i in range(1000)],
        "nested": {"key" + str(i): {"subkey": i} for i in range(100)},
        "mixed_list": [i if i % 2 == 0 else "odd" for i in range(1000)],
    }
    decoded, remaining = codec.decode(codec.encode(value))
    assert decoded == value, "Failed for large data structure."
    assert len(remaining) == 0


def test_decode_with_extra_data(codec):
    value = 42
    extra = b"\x00\x01\x02"
    encoded = codec.encode(value)
    decoded, remaining = codec.decode(encoded + extra)
    assert decoded == value, "Failed with extra data."
    assert remaining == extra
