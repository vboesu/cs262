import struct
import socket

from .codec import BVCodec, JSONCodec


def checksum(data: bytes, size: int = 2) -> int:
    """Compute simple checksum by summing data modulo 2^(`size` * 8)
    to give an unsigned integer which can be stored in `size` bytes.

    Parameters
    ----------
    data : bytes
        Data for checksum
    size : int, optional
        Number of bytes required to represent checksum, by default 2

    Returns
    -------
    int
        Checksum
    """
    return sum(data) % 2 ** (size * 8)


class RequestCode:
    success = 100  # response code, think HTTP 200
    push = 42  # request code, think HTTP POST
    error = 40  # response code, think HTTP 400


class Header:
    version: int = 0
    spec: list[str] = [("B", "version", -1)]  # [(short_type, name, default), ...]
    byteorder: str = "<"  # "<" or ">" for little or big-endian, respectively

    def __init__(self, *args, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    @classmethod
    def format(cls) -> str:
        """Compute format (for ``struct``) of header for en-/decoding."""
        return cls.byteorder + "".join([s[0] for s in cls.spec])

    @classmethod
    def size(cls) -> int:
        """Compute size (in bytes) of header."""
        return struct.calcsize(cls.format())

    @classmethod
    def decode(cls, b: bytes) -> "Header":
        """Decode header from bytestring."""
        # Start by checking header version
        ver = int.from_bytes(
            b[:1], "little" if cls.byteorder == "<" else "big", signed=False
        )
        if ver != cls.version:
            raise ValueError(f"Unable to process request version: {ver}")

        items = struct.unpack(cls.format(), b[: cls.size()])
        return cls(**{name: i for (_, name, _), i in zip(cls.spec, items)})

    def encode(self) -> bytes:
        """Encode header information into bytes."""
        header_data = [getattr(self, name, default) for (_, name, default) in self.spec]
        return struct.pack(self.format(), *header_data)

    def update_with_payload(self, payload: bytes):
        """
        Update header information based on payload,
        mainly used for things like checksums and packet length.
        """
        raise NotImplementedError()

    def verify_payload(self, payload: bytes):
        """
        Verify received payload, e.g. by checking length
        and checksum.
        """
        raise NotImplementedError()


class HeaderV1(Header):
    version: int = 1
    spec: list[str] = [
        ("B", "version", 1),
        ("B", "request_code", 0),
        ("H", "request_id", 0),
        ("H", "payload_checksum", 0),
        ("H", "payload_length", 0),
    ]
    byteorder: str = "<"

    def update_with_payload(self, payload: bytes):
        self.payload_checksum = checksum(payload, size=2)
        self.payload_length = len(payload)

    def verify_payload(self, payload: bytes):
        assert self.payload_checksum == checksum(payload, size=2)
        assert self.payload_length == len(payload)


class Request:
    header_cls: type = HeaderV1
    codec_cls: type = BVCodec

    def __init__(
        self, request_code: int, data: dict | None = None, request_id: int = 0
    ):
        self.request_code = request_code
        self.data = data
        self.request_id = request_id

    def serialize(self) -> bytes:
        """
        Encode request metadata and payload into bytes using
        the ``Codec`` specified by ``codec_cls``.

        Returns
        -------
        bytes
            Encoded request.
        """
        codec = self.codec_cls()
        payload = codec.encode(self.data)

        # Create header with request arguments
        header = self.header_cls(
            request_code=self.request_code, request_id=self.request_id
        )
        header.update_with_payload(payload)

        return header.encode() + payload

    @classmethod
    def parse(cls, raw: bytes) -> "Request":
        """
        Parse bytes into Request. Requires the full
        byte string to have been read.

        Parameters
        ----------
        raw : bytes
            Bytes to process.

        Returns
        -------
        Request
            Parsed request.
        """
        header = cls.header_cls.decode(raw)
        payload = raw[header.size() : header.size() + header.payload_length]

        # Perform checks
        header.verify_payload(payload)

        # Decode data
        codec = cls.codec_cls()
        decoded, remaining = codec.decode(payload)

        if len(remaining) > 0:
            print("WARNING: unparsed bytes at the end of payload")

        return Request(header.request_code, decoded, header.request_id)

    def push(self, sock: socket.socket) -> tuple[int, int]:
        """
        Send data to socket without waiting for a response.

        Parameters
        ----------
        sock : socket.socket
            Destination socket

        Returns
        -------
        tuple[int, int]
            Total number of bytes of request, total number of bytes sent.

        Raises
        ------
        RuntimeError
            Invalid socket
        """
        encoded = self.serialize()

        # Send data
        total_sent = 0
        while total_sent < len(encoded):
            sent = sock.send(encoded[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken.")
            total_sent += sent

        return len(encoded), total_sent

    @classmethod
    def receive(cls, sock: socket.socket) -> "Request":
        """
        Receive data from socket. Blocks until full Request object
        has been received.

        Parameters
        ----------
        sock : socket.socket
            Socket to receive data on

        Returns
        -------
        Request
            Parsed request.
        """
        # Receive header
        header_size = cls.header_cls.size()
        header_data = b""

        while len(header_data) < header_size:
            data = sock.recv(header_size - len(header_data))
            if len(data) == 0:
                raise ValueError("Unable to receive header.")

            header_data += data

        header = cls.header_cls.decode(header_data)

        # Receive payload
        payload_data = b""

        while len(payload_data) < header.payload_length:
            data = sock.recv(header.payload_length - len(payload_data))
            if len(data) == 0:
                raise ValueError("Unable to receive payload.")

            payload_data += data

        # Decode payload
        codec = cls.codec_cls()
        decoded, remaining = codec.decode(payload_data)

        if len(remaining) > 0:
            print("WARNING: unparsed bytes at the end of payload")

        return Request(header.request_code, decoded, header.request_id)
