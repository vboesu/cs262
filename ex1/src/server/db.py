from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session

from src.models import Base

# Global session object
session: Session = None


def create_session(db_url: str, echo: bool = False) -> Session:
    """
    Create a session for the database and make it globally available
    through the variable ``session``. Creates all necessary table
    if they do not yet exist.

    Parameters
    ----------
    db_url : str
        Path to database.
    echo : bool, optional
        Flag for verbose SQL logging, by default False

    Returns
    -------
    Session
        Session object for database.
    """
    engine = create_engine(db_url, echo=echo)
    Base.metadata.create_all(engine)  # create tables if necessary
    return sessionmaker(bind=engine)()
