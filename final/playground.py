from collections.abc import Callable
from datetime import datetime
import itertools
from typing import Annotated

import uuid
import sqlalchemy as sa
import sqlalchemy.orm as so


def generate_uuid() -> bytes:
    """Generate UUID v4."""
    return uuid.uuid4().bytes


def current_timestamp() -> Callable:
    """Ensure that the same timestamp is used throughout the transaction."""
    transactions = {}

    def fn(session: so.Session = None) -> datetime:
        if session is not None and hasattr(session, "get_transaction"):
            trans = session.get_transaction()
            if trans not in transactions:
                transactions[trans] = datetime.now()

            return transactions[trans]

        return datetime.now()

    return fn


# UUID primary key
uuidpk = Annotated[bytes, so.mapped_column(primary_key=True, default=generate_uuid)]

# Timestamp per transaction
timestamp_t = Annotated[
    datetime,
    so.mapped_column(nullable=False, default=current_timestamp()),
]

Base = so.declarative_base()


class ImportantModel(Base):
    __tablename__ = "important_model"
    __consistency__ = "strong"

    id: so.Mapped[uuidpk]
    value: so.Mapped[str]


class NotImportantModel(Base):
    __tablename__ = "not_important_model"
    __consistency__ = "weak"

    id: so.Mapped[uuidpk]
    value: so.Mapped[str]


class MyModel(Base):
    __tablename__ = "my_model"

    id: so.Mapped[uuidpk]
    name: so.Mapped[str]
    important: so.Mapped[int] = so.mapped_column(
        default=1, info={"consistency": "strong"}
    )
    created: so.Mapped[timestamp_t]
    updated: so.Mapped[timestamp_t] = so.mapped_column(onupdate=current_timestamp())

    @property
    def uuid(self) -> str:
        if self.id:
            return str(uuid.UUID(bytes=self.id))

        return str(uuid.UUID(int=0))

    def __repr__(self):
        return f"MyModel(id={self.uuid}, name={self.name}, created={self.created}, updated={self.updated})"


@sa.event.listens_for(so.Session, "before_commit")
def before_commit_handler(session: so.Session):
    """
    Before a potential commit, we need to:
       1. Set default/onupdate values and keys so that they can be propagated
          to other replicas in case we need to do a strong transaction.
       2. Determine whether we need to do a strong transaction by inspecting
          the columns and tables of all objects involved in the transaction.
       3. If necessary, perform a strongly consistent transaction.

    Parameters
    ----------
    session : sqlalchemy.orm.Session
        Current session engaged in transaction.
    """
    print("BEFORE COMMIT", session)
    ### DEFAULTS
    for obj in session.new:
        for key, column in sa.inspect(obj.__class__).columns.items():
            # Check if column has default and has not had a value set
            # TODO: this makes it impossible to force a value to be "null" if
            # a default value is set
            if (
                hasattr(column, "default")
                and column.default is not None
                and getattr(obj, key) is None
            ):
                if isinstance(column.default, sa.sql.schema.CallableColumnDefault):
                    setattr(obj, key, column.default.arg(session))
                else:
                    setattr(obj, key, column.default.arg)

    ### ONUPDATES
    for obj in session.dirty:
        for key, column in sa.inspect(obj.__class__).columns.items():
            if hasattr(column, "onupdate") and column.onupdate is not None:
                if isinstance(column.onupdate, sa.sql.schema.CallableColumnDefault):
                    setattr(obj, key, column.onupdate.arg(session))
                else:
                    setattr(obj, key, column.onupdate.arg)

    ### DETERMINE CONSISTENCY REQUIREMENT
    strong_transaction = False
    while not strong_transaction:
        # 1. Check if any of the tables are marked as strongly consistent
        for obj in itertools.chain(session.new, session.dirty, session.deleted):
            strong_transaction |= (
                getattr(obj.__class__, "__consistency__", "weak") == "strong"
            )

        # 2. Check if specific (modified) columns are marked as strongly consistent
        for obj in session.dirty:
            for key, column in sa.inspect(obj.__class__).columns.items():
                if column.info.get("consistency", "weak") == "strong":
                    strong_transaction |= bool(
                        getattr(sa.inspect(obj).attrs, key).history.added
                    )

        # 3. Check if any entries were added/deleted which have strongly consistent columns
        for obj in itertools.chain(session.new, session.deleted):
            for key, column in sa.inspect(obj.__class__).columns.items():
                strong_transaction |= column.info.get("consistency", "weak") == "strong"

        break

    print("strong transaction", strong_transaction)

    ### DEBUG
    for obj in session.new:
        print(f"Replication: New object prepared for commit: {obj}")
    for obj in session.dirty:
        print(f"Replication: Updated object prepared for commit: {obj}")
    for obj in session.deleted:
        print(
            f"Replication: Object scheduled for deletion: {obj.__table__}:{sa.inspect(obj).identity}"
        )


if __name__ == "__main__":
    engine = sa.create_engine("sqlite:///example.db")
    Base.metadata.create_all(engine)

    # Create a new session.
    with so.Session(engine) as session:
        # Create a few objects.
        obj1 = MyModel(name="First Object")
        obj2 = MyModel(name="Second Object")
        obj3 = MyModel(name="Third Object")

        # Add them to the session.
        session.add_all([obj1, obj2, obj3])

        # Commit changes: this will trigger the event listener.
        session.commit()

        # Make some changes (this transaction should be weakly consistent)
        obj1.name = "New First Object"

        # Commit again
        session.commit()

        obj1.important = 2

        # Delete and commit
        session.delete(obj1)
        session.commit()

        # Strong consistency
        obj4 = ImportantModel()
        obj4.value = "abc"

        session.add(obj4)
        session.commit()

        # Weak consistency
        obj5 = NotImportantModel()
        obj5.value = "def"

        session.add(obj5)
        session.commit()

        obj5.value = "efg"
        session.commit()

        # Read objects
        objects = session.execute(sa.select(MyModel)).scalars()
        for obj in objects:
            print("got", obj)
