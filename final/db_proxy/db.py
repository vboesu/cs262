from functools import cached_property
from pathlib import Path

import json
import logging
import sqlite3
from typing import Literal

# import sqlalchemy as sa
# import sqlalchemy.orm as so

# from models import Base
from query import Query

logger = logging.getLogger(__name__)

ERRORS_TO_STATUS_CODE = {
    "l7de": 10,  # UnsupportedCompilationError
    "xd1r": 11,  # AwaitRequired
    "xd2s": 12,  # MissingGreenlet
    "dbapi": 90,  # DBAPIError
    "rvf5": 91,  # InterfaceError
    "4xp6": 92,  # DatabaseError
    "e3q8": 93,  # OperationalError
    "gkpj": 94,  # IntegrityError
    "2j85": 95,  # InternalError
    "f405": 96,  # ProgrammingError
    "tw8g": 97,  # NotSupportedError
}

STATUS_CODE_TO_ERROR_DESCRIPTION = {
    10: "UnsupportedCompilationError",
    11: "AwaitRequired",
    12: "MissingGreenlet",
    90: "DBAPIError",
    91: "InterfaceError",
    92: "DatabaseError",
    93: "OperationalError",
    94: "IntegrityError",
    95: "InternalError",
    96: "ProgrammingError",
    97: "NotSupportedError",
    99: "UnknownError",
}


class SQLiteDatabase:
    def __init__(self, path: str | Path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = SQLiteDatabase._dict_factory
        self._ensure_meta()

        self.tables = self._public_tables()
        print("available tables", self.tables)

    @staticmethod
    def _dict_factory(cursor: sqlite3.Cursor, row: tuple):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def _ensure_meta(self):
        cursor = self.conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS internal_strong_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid BLOB UNIQUE,
            query BLOB,
            timestamp DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))
        )""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS internal_eventual_log (
            uuid BLOB PRIMARY KEY,
            query BLOB,
            timestamp DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))
        )""")
        self.conn.commit()

    def _public_tables(self):
        _query = Query(
            query="""
            SELECT name 
                FROM sqlite_master 
            WHERE type='table' 
                AND name NOT LIKE 'sqlite_%'
                AND name NOT LIKE 'internal_%'
            """,
        )
        _tables = self.execute(_query)
        return [row["name"] for row in _tables]

    def execute(self, query: Query, log: Literal["strong", "eventual"] | None = None):
        cursor = self.conn.cursor()
        cursor.execute(query.query, query.params or [])
        if log is not None:
            cursor.execute(
                f"INSERT INTO internal_{log}_log (uuid, query) VALUES (?, ?)",
                [query.id, query.encode()],
            )
        self.conn.commit()
        return cursor.fetchall()

    # def db_setup(self):
    #     self.base.metadata.create_all(self.engine)

    #     # map from table -> model class
    #     self.tables = {}

    #     for mapper in self.base.registry.mappers:
    #         cls = mapper.class_
    #         if not cls.__name__.startswith("_"):
    #             tblname = cls.__tablename__
    #             self.tables[tblname] = cls

    def try_query(
        self,
        query: Query,
        log: Literal["strong", "eventual"] | None = None,
    ) -> tuple[int, list]:
        try:
            logger.debug(f"TRY QUERY {query}")
            result = self.execute(query, log)
            status = 0
            logger.debug(f"EXECUTED QUERY {query} TO LOG {log} WITH RESULT {result}")

        except sqlite3.Error as e:
            result = []
            status = getattr(e, "sqlite_errorcode", 99)

        return status, result

    # def try_query(self, query: bytes) -> int:
    #     """
    #     Attempt to execute a query on the current database.

    #     Parameters
    #     ----------
    #     query : bytes
    #         Query to be attempted.

    #     Returns
    #     -------
    #     int
    #         Status (0 = success, >0 = failure)
    #     """
    #     query_id = query[:16]
    #     query_type = query[16:17]  # e.g. insert, update, etc.
    #     query_schema, _, query_raw_data = query[17:].partition(b" ")
    #     query_schema = query_schema.decode("ascii")
    #     logger.debug(f"RAW QUERY DATA {query_raw_data}")
    #     query_data = json.loads(query_raw_data) if query_raw_data else {}

    #     logger.debug(
    #         f"Attempting query {query_id} ({query_type} on {query_schema}): {query_data}"
    #     )

    #     if (model := self.tables.get(query_schema)) is None:
    #         return 99

    #     with so.Session(self.engine) as session:
    #         try:
    #             if query_type == b"I":
    #                 # INSERT
    #                 obj = model(**query_data)
    #                 session.add(obj)
    #                 session.commit()

    #             elif query_type == b"U":
    #                 # UPDATE
    #                 where = sa.true()
    #                 for key in list(query_data.keys()):
    #                     if key.startswith("where__"):
    #                         col = key[7:]
    #                         value = query_data.pop(key)
    #                         where &= getattr(model, col) == value

    #                 u_query = sa.update(model.__table__).where(where).values(query_data)
    #                 session.execute(u_query)
    #                 session.commit()

    #             else:
    #                 raise ValueError()  # TMP

    #         except sa.exc.SQLAlchemyError as e:
    #             logger.info(f"Unable to complete query {query}. {str(e)}")
    #             if hasattr(e, "code"):
    #                 return ERRORS_TO_STATUS_CODE.get(e.code, 99)

    #     logger.debug("Success!")
    #     return 0
