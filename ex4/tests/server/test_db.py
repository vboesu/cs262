from sqlalchemy.orm.session import Session

from src.models import Base
from src.server.db import create_session


def test_create_session_returns_session():
    """
    Test that create_session returns a SQLAlchemy Session with a bound engine.
    """
    sess = create_session("sqlite:///:memory:", echo=False)
    assert isinstance(sess, Session)
    assert sess.bind is not None


def test_engine_configuration():
    """
    Test that the engine created is for an SQLite database.
    """
    sess = create_session("sqlite:///:memory:", echo=False)
    # For an in-memory SQLite database, the engine name should be 'sqlite'.
    assert sess.bind.name == "sqlite"


def test_create_session_calls_create_all(monkeypatch):
    """
    Test that Base.metadata.create_all is called during session creation.
    """
    called = False

    def dummy_create_all(engine):
        nonlocal called
        called = True

    # Patch the create_all method on the Base metadata.
    monkeypatch.setattr(Base.metadata, "create_all", dummy_create_all)
    _ = create_session("sqlite:///:memory:", echo=False)
    assert called
