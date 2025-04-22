from pathlib import Path

import sqlalchemy as sa

from models import Base


class SQLiteDatabase:
    def __init__(self, path: str | Path):
        self.path = path
        self.engine = sa.create_engine(f"sqlite:///{self.path}")
        self.base = Base

        self.db_setup()

    def db_setup(self):
        self.base.metadata.create_all(self.engine)

        # map from table -> model class
        self.tables = {}

        for mapper in self.base.registry.mappers:
            cls = mapper.class_
            if not cls.__name__.startswith("_"):
                tblname = cls.__tablename__
                self.tables[tblname] = cls
