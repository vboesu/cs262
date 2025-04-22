from abc import ABC, abstractmethod
from typing import IO


class Serializable(ABC):
    @abstractmethod
    def to_binary(self) -> bytes:
        """Write object to byte string."""
        pass

    @classmethod
    @abstractmethod
    def from_binary(cls, b: bytes) -> "Serializable":
        """Read object from byte string."""
        pass

    def write(self, file: IO):
        """Write self to file."""
        file.write(self.to_binary())

    @classmethod
    @abstractmethod
    def read(cls, file: IO) -> "Serializable":
        """Read object from file."""
        pass

    def length(self) -> int:
        """Encoded length (in bytes)."""
        return len(self.to_binary())
