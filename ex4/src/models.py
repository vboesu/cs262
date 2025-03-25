from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime,
    BLOB,
    Text,
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func

from src.common import TIMESTAMP_FORMAT

Base = declarative_base()


class User(Base):
    """
    User model representing a user in the system.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(64), nullable=False)

    # Relationship to Messages
    sent = relationship(
        "Message",
        back_populates="from_user",
        foreign_keys="Message.from_id",
        cascade="all, delete-orphan",
    )
    received = relationship(
        "Message",
        back_populates="to_user",
        foreign_keys="Message.to_id",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<User id={self.id} username='{self.username}'>"

    def to_dict(self):
        return {"id": self.id, "username": self.username}


class Message(Base):
    """
    Message model representing a message sent by a user.
    """

    __tablename__ = "messages"

    id = Column(Integer, primary_key=True)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False)
    read_at = Column(DateTime, nullable=True)

    from_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    to_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships to User
    from_user = relationship("User", back_populates="sent", foreign_keys=[from_id])
    to_user = relationship("User", back_populates="received", foreign_keys=[to_id])

    def __repr__(self):
        return f"<Message id={self.id} from_id={self.from_id} to_id={self.to_id}, timestamp='{self.timestamp}'>"

    def to_dict(self):
        return {
            "id": self.id,
            "from": self.from_user.username,
            "to": self.to_user.username,
            "content": self.content,
            "timestamp": self.timestamp.strftime(TIMESTAMP_FORMAT),
        }


class Log(Base):
    """
    Log model representing a log entry for a server replica.
    """

    __tablename__ = "logs"

    id = Column(Integer, primary_key=True)
    clock = Column(Integer, nullable=False)
    request = Column(BLOB, nullable=False)

    def __repr__(self) -> str:
        return f"<Log id={self.id} clock={self.clock} request='{self.request[:128]}'>"
