import json
import secrets


class Query:
    _method_to_cmd = {
        "SELECT": b"S",
        "INSERT": b"I",
        "UPDATE": b"U",
        "DELETE": b"D",
    }
    _cmd_to_method = {
        b"S": "SELECT",
        b"I": "INSERT",
        b"U": "UPDATE",
        b"D": "DELETE",
    }

    def __init__(
        self,
        id: bytes | None = None,
        method: str = "",
        cmd: bytes = b"",
        schema: str = "",
        query: str = "",
        params: list = [],
    ):
        self.id = id or secrets.token_bytes(16)
        self._method = method
        self._cmd = cmd
        self.schema = schema
        self.query = query
        self.params = params

    def __repr__(self) -> str:
        return f"Query(id={self.id.hex()} method={self.method} schema={self.schema} query='{self.query}' params={self.params})"

    @property
    def cmd(self) -> bytes:
        return self._cmd if self._cmd else self._method_to_cmd[self._method]

    @property
    def method(self) -> bytes:
        return self._method if self._method else self._cmd_to_method[self._cmd]

    def encode(self) -> bytes:
        """
        Encode query to a binary format which we can store.

        Byte structure:
        [0-15]: Query ID as bytes
        [16]: Command code as byte
        [17-first space]: Schema name as ASCII bytes
        [space]
        [next 4 bytes]: Length of query (UInt32, big-endian)
        [query]: Query as UTF-8
        [next 4 bytes]: Length of params (UInt32, big-endian)
        [params]: Params as JSON encoded as UTF-8
        """
        query_enc = self.query.encode("utf-8")
        params_enc = json.dumps(self.params).encode("utf-8")

        return (
            self.id
            + self.cmd
            + self.schema.encode("ascii")
            + b" "
            + len(query_enc).to_bytes(4, "big", signed=False)
            + query_enc
            + len(params_enc).to_bytes(4, "big", signed=False)
            + params_enc
        )

    @classmethod
    def decode(cls, b: bytes) -> "Query":
        """
        Decode bytes into Query object based on encoding
        specified in `encode`.
        """
        try:
            query_id = b[:16]
            assert len(query_id) == 16

            cmd = b[16:17]
            assert len(cmd) == 1

            schema_b, _, remainder = b[17:].partition(b" ")
            schema = schema_b.decode("ascii")
            assert schema != b""

            query_enc_len = int.from_bytes(remainder[:4], "big", signed=False)
            query_enc = remainder[4 : 4 + query_enc_len]
            assert len(query_enc) == query_enc_len
            query = query_enc.decode("utf-8")

            remainder = remainder[4 + query_enc_len :]
            params_enc_len = int.from_bytes(remainder[:4], "big", signed=False)
            params_enc = remainder[4 : 4 + params_enc_len]
            assert len(params_enc) == params_enc_len
            params = json.loads(params_enc.decode("utf-8"))

            return Query(
                id=query_id,
                cmd=cmd,
                schema=schema,
                query=query,
                params=params,
            )

        except Exception as e:
            raise ValueError(f"Unable to parse query. {str(e)}")
