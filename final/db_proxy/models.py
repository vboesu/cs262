from collections.abc import Callable
from datetime import datetime
from typing import Annotated

import uuid
import sqlalchemy as sa
import sqlalchemy.orm as so


def generate_uuid() -> str:
    """Generate UUID v4 as hex string."""
    return uuid.uuid4().hex


# def current_timestamp() -> Callable:
#     """Ensure that the same timestamp is used throughout the transaction."""
#     transactions = {}

#     def fn(session: so.Session = None) -> datetime:
#         if session is not None and hasattr(session, "get_transaction"):
#             trans = session.get_transaction()
#             if trans not in transactions:
#                 transactions[trans] = datetime.now()

#             return transactions[trans]

#         return datetime.now()

#     return fn


# UUID primary key
uuid_t = Annotated[str, so.mapped_column(default=generate_uuid)]
uuidpk = Annotated[str, so.mapped_column(default=generate_uuid, primary_key=True)]

# Timestamp per transaction
timestamp_t = Annotated[
    datetime,
    so.mapped_column(nullable=False, default=datetime.now),
]

Base = so.declarative_base()


class User(Base):
    __tablename__ = "users"
    __consistency__ = "weak"

    id: so.Mapped[uuidpk]
    username: so.Mapped[str] = so.mapped_column(
        unique=True,
        info={"consistency": "strong"},
    )
    name: so.Mapped[str]
    password_hash: so.Mapped[str] = so.mapped_column(info={"consistency": "strong"})
    created: so.Mapped[timestamp_t]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "name": self.name,
            "password_hash": self.password_hash,
            "created": self.created.timestamp(),
        }


class Account(Base):
    __tablename__ = "accounts"
    __consistency__ = "strong"

    id: so.Mapped[uuidpk]
    user_id: so.Mapped[uuid_t] = so.mapped_column(sa.ForeignKey(User.id))
    balance: so.Mapped[int]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "balance": self.balance,
        }


class Post(Base):
    __tablename__ = "posts"
    __consistency__ = "weak"

    id: so.Mapped[uuidpk]
    user_id: so.Mapped[uuid_t] = so.mapped_column(sa.ForeignKey(User.id))
    content: so.Mapped[str]
    created: so.Mapped[timestamp_t]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "content": self.content,
            "created": self.created.timestamp(),
        }


class Comment(Base):
    __tablename__ = "comments"
    __consistency__ = "weak"

    id: so.Mapped[uuidpk]
    post_id: so.Mapped[uuid_t] = so.mapped_column(sa.ForeignKey(Post.id))
    user_id: so.Mapped[uuid_t] = so.mapped_column(sa.ForeignKey(User.id))
    content: so.Mapped[str]
    created: so.Mapped[timestamp_t]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "post_id": self.post_id,
            "content": self.content,
            "created": self.created.timestamp(),
        }
