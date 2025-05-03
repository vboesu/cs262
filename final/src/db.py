import logging
import sqlite3

from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

from .query import Query

logger = logging.getLogger(__name__)


class SQLiteDatabase:
    def __init__(self, path: str | Path, setup_script: str | Path | None = None):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = SQLiteDatabase._dict_factory
        self.transaction_lock = Lock()
        self._ensure_meta()

        if setup_script:
            with open(setup_script, "r") as f:
                sql = f.read()
                cursor = self.conn.cursor()
                cursor.executescript(sql)
                self.conn.commit()

        self.tables = self._public_tables()
        logger.info("Available tables: %s", self.tables)

    @staticmethod
    def _dict_factory(cursor: sqlite3.Cursor, row: tuple) -> dict[str, Any]:
        d = {}

        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]

        return d

    def _ensure_meta(self):
        with self.transaction_lock:
            cursor = self.conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS internal_strong_log (
                transaction_id BLOB,
                operation_id INTEGER,
                command INTEGER,
                schema TEXT,
                column TEXT NULL,
                row BLOB NULL,
                old_value BLOB NULL,
                new_value BLOB NULL,
                data BLOB NULL,
                logical_timestamp INTEGER,
                timestamp DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))
            )""")
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS internal_eventual_log (
                transaction_id BLOB,
                operation_id INTEGER,
                command INTEGER,
                schema TEXT,
                column TEXT NULL,
                row BLOB NULL,
                old_value BLOB NULL,
                new_value BLOB NULL,
                data BLOB NULL,
                timestamp DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))
            )""")
            self.conn.commit()

    def _public_tables(self):
        with self.transaction_lock:
            cursor = self.conn.cursor()
            cursor.execute("""
            SELECT name 
                FROM sqlite_master 
            WHERE type='table' 
                AND name NOT LIKE 'sqlite_%'
                AND name NOT LIKE 'internal_%'
            """)
            return [row["name"] for row in cursor.fetchall()]

    def _log_entry(
        self,
        cursor: sqlite3.Cursor,
        query: Query,
        log: Literal["strong", "eventual"],
        transaction_id: bytes,
        logical_timestamp: int = -1,
        timestamp: datetime | None = None,
    ) -> Query:
        query.transaction_id = transaction_id
        query.timestamp = timestamp
        query.logical_timestamp = logical_timestamp

        for op_id, op in enumerate(query.ops):
            cursor.execute(
                *op.to_sql(f"internal_{log}_log", op_id + 1, log == "strong")
            )

        return query

    def write_query(
        self,
        query: Query,
        log: Literal["strong", "eventual"] = "eventual",
        transaction_id: bytes | None = None,
        logical_timestamp: int = -1,
        timestamp: datetime | None = None,
    ) -> tuple[int, Query]:
        with self.transaction_lock:
            cursor = self.conn.cursor()
            self.conn.execute("BEGIN")
            transaction_id = transaction_id or uuid4().bytes

            # Try each of the steps in the query, checking at each step that at least
            # one row was affected to make sure that the update, insert, and deletes
            # are consistent and not out of order.

            try:
                for op in query.ops:
                    cursor.execute(*op.as_sql())

                    if cursor.rowcount == 0:
                        # If no row was affected, the operation failed. This is
                        # usually because of some type of race condition or inconsistency
                        # problem, so now we need to go and fix it. TODO
                        raise sqlite3.DatabaseError(f"Operation {op} failed.")

                query = self._log_entry(
                    cursor,
                    query,
                    log,
                    transaction_id,
                    logical_timestamp,
                    timestamp,
                )
                self.conn.commit()
                return 0, query

            except sqlite3.Error as e:
                logger.error("Failed to complete query, rolling back.")
                logger.error(e, exc_info=True)
                self.conn.rollback()

                return getattr(e, "sqlite_errorcode", 99), query

    def try_execute(self, query: str, params: list = []) -> tuple[int, list]:
        with self.transaction_lock:
            cursor = self.conn.cursor()
            status, result = 0, []
            try:
                cursor.execute(query, params)
                result = cursor.fetchall()

            except sqlite3.Error as e:
                logger.error(e, exc_info=True)
                status = getattr(e, "sqlite_errorcode", 99)

            return status, result
