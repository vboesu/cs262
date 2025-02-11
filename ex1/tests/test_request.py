import pytest
import socket
from unittest.mock import Mock

from src.request import Request, Header, HeaderV1, RequestCode, checksum


@pytest.fixture
def sample_payload():
    return b"\x10\x20\x30\x40"  # simple binary data


@pytest.fixture
def sample_data():
    return {"message": "hello", "value": 42}  # data to be encoded/decoded


class TestHeaderBase:
    """
    Tests for the base Header class. Since Header is intended to be
    subclassed, we'll test decode/encode with the default spec.
    """

    def test_header_format(self):
        # The base class spec has just one byte for version, little-endian
        fmt = Header.format()
        assert fmt == "<B"

    def test_header_size(self):
        # Base class is just 1 byte from the spec
        size = Header.size()
        assert size == 1

    def test_header_encode_decode_correct_version(self):
        header = Header(version=0)
        encoded = header.encode()
        # decode will raise ValueError if the version doesn't match
        decoded = Header.decode(encoded)
        assert decoded.version == 0

    def test_header_decode_wrong_version(self):
        """
        If we encode with a certain version, but the class has a different
        expected version, we should get a ValueError. We'll trick the class
        by changing the class-level version after creation.
        """
        header = Header(version=0)
        encoded = header.encode()

        # Temporarily change the class-level version to something else
        original_version = Header.version
        Header.version = 1  # mismatch
        with pytest.raises(ValueError):
            Header.decode(encoded)

        # Restore the original version
        Header.version = original_version


class TestHeaderV1:
    """
    Tests specific to HeaderV1, which is an actual usable subclass.
    """

    def test_header_v1_format(self):
        fmt = HeaderV1.format()
        # B = version, B = request_code, H = request_id, H = payload_checksum, H = payload_length
        # little-endian
        assert fmt == "<BBHHH"

    def test_header_v1_size(self):
        size = HeaderV1.size()
        # B(1) + B(1) + H(2) + H(2) + H(2) = 8 bytes
        assert size == 8

    def test_header_v1_encode_decode(self):
        header = HeaderV1(request_code=42, request_id=1234)
        encoded = header.encode()
        decoded = HeaderV1.decode(encoded)
        assert decoded.version == 1
        assert decoded.request_code == 42
        assert decoded.request_id == 1234
        assert decoded.payload_checksum == 0
        assert decoded.payload_length == 0

    def test_header_v1_update_with_payload(self, sample_payload):
        header = HeaderV1(request_code=42, request_id=9999)
        header.update_with_payload(sample_payload)
        assert header.payload_length == len(sample_payload)
        assert header.payload_checksum == checksum(sample_payload, size=2)

    def test_header_v1_verify_payload_good(self, sample_payload):
        header = HeaderV1(request_code=42)
        header.update_with_payload(sample_payload)
        # Should not raise an exception
        header.verify_payload(sample_payload)

    def test_header_v1_verify_payload_bad_checksum(self, sample_payload):
        header = HeaderV1(request_code=42)
        header.update_with_payload(sample_payload)
        bad_payload = sample_payload + b"\x00"
        with pytest.raises(AssertionError):
            header.verify_payload(bad_payload)

    def test_header_v1_verify_payload_bad_length(self, sample_payload):
        header = HeaderV1(request_code=42)
        header.update_with_payload(sample_payload)
        # short payload
        with pytest.raises(AssertionError):
            header.verify_payload(sample_payload[:-1])

    def test_header_v1_decode_wrong_version(self):
        # If the first byte isn't 1, we should get a ValueError
        wrong_version_data = b"\x02\x2a\x00\x00\x00\x00\x00\x00"
        with pytest.raises(ValueError) as excinfo:
            HeaderV1.decode(wrong_version_data)
        assert "Unable to process request version" in str(excinfo.value)


class TestRequest:
    """
    Tests for the Request class, focusing on:
    - Serialization / Deserialization
    - push / receive with mocked sockets
    """

    def test_request_init(self):
        req = Request(request_code=RequestCode.push, data={"abc": 123}, request_id=1)
        assert req.request_code == RequestCode.push
        assert req.data == {"abc": 123}
        assert req.request_id == 1

    def test_request_serialize(self, sample_data):
        req = Request(request_code=RequestCode.push, data=sample_data, request_id=99)
        serialized = req.serialize()

        # The first part of `serialized` is the header, then payload
        assert len(serialized) >= req.header_cls.size()  # at least the header size

        # Check correctness by parsing back
        parsed = Request.parse(serialized)
        assert parsed.request_code == RequestCode.push
        assert parsed.request_id == 99
        assert parsed.data == sample_data

    def test_request_parse_with_extra_data(self):
        # Make a normal request
        req = Request(request_code=RequestCode.push, data={"k": "v"})
        serialized = req.serialize()

        # Append extra data to the end
        serialized += b"\xff\xff\xff"

        parsed = Request.parse(serialized)
        assert parsed.data == {"k": "v"}

    def test_request_push(self, sample_data):
        """
        We mock the socket to verify that `request.push()` sends
        all the data in chunks.
        """
        req = Request(request_code=RequestCode.push, data=sample_data)

        # The data we expect to send (serialized)
        expected_data = req.serialize()

        mock_sock = Mock(spec=socket.socket)

        # We'll simulate sending data in two chunks
        # For example, the first call to send() sends half of the data,
        # the second call sends the rest.
        def side_effect_send(data_chunk):
            return len(data_chunk)

        mock_sock.send.side_effect = side_effect_send

        total_size, total_sent = req.push(mock_sock)
        assert total_size == len(expected_data)
        assert total_sent == len(expected_data)

        # Ensure `send` was called
        assert mock_sock.send.call_count >= 1

    def test_request_push_socket_error(self):
        """If socket.send() returns 0, it raises RuntimeError"""
        req = Request(request_code=RequestCode.push, data={})

        mock_sock = Mock(spec=socket.socket)
        # Simulate a broken socket on the first send
        mock_sock.send.return_value = 0

        with pytest.raises(RuntimeError):
            req.push(mock_sock)

    def test_request_receive(self, sample_data):
        """
        Test that receive() properly handles partial reads of header and payload.
        We'll mock out `socket.recv()` to feed partial data in small chunks.
        """
        req = Request(request_code=RequestCode.push, data=sample_data, request_id=202)
        serialized = req.serialize()

        # We'll break the serialized data into two parts:
        # 1) The header portion
        # 2) The payload portion
        header_size = req.header_cls.size()
        header_part = serialized[:header_size]
        payload_part = serialized[header_size:]

        # We'll define a side_effect that simulates reading from the socket:
        # 1. Return the first half of the header
        # 2. Return the rest of the header
        # 3. Return the first half of the payload
        # 4. Return the rest of the payload
        # This helps confirm that receive() loops until all required bytes are read.

        chunk1 = header_part[:2]
        chunk2 = header_part[2:]
        chunk3 = payload_part[:2]
        chunk4 = payload_part[2:]

        side_effect_sequence = [chunk1, chunk2, chunk3, chunk4]

        mock_sock = Mock(spec=socket.socket)
        mock_sock.recv.side_effect = side_effect_sequence

        received_req = Request.receive(mock_sock)
        assert received_req.request_code == RequestCode.push
        assert received_req.request_id == 202
        assert received_req.data == sample_data

        # Confirm recv was called multiple times
        assert mock_sock.recv.call_count == 4

    def test_request_receive_header_failure(self):
        """
        If we cannot read enough bytes for the header, we should raise ValueError.
        """
        mock_sock = Mock(spec=socket.socket)
        # Return an empty bytes object to simulate closed connection
        mock_sock.recv.return_value = b""

        with pytest.raises(ValueError):
            Request.receive(mock_sock)

    def test_request_receive_payload_failure(self):
        """
        If we fail to read enough bytes for the payload, we should raise ValueError.
        """
        req = Request(request_code=RequestCode.push, data={"test": "data"})
        serialized = req.serialize()

        # We'll provide the correct header but no payload
        header_size = req.header_cls.size()
        header_part = serialized[:header_size]
        payload_part = b""  # incomplete payload

        mock_sock = Mock(spec=socket.socket)
        # We'll give the header first, but no payload after
        mock_sock.recv.side_effect = [header_part, payload_part]

        with pytest.raises(ValueError):
            Request.receive(mock_sock)
