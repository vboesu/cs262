from collections.abc import Hashable
import json
from typing import Any

from flask import Request


# def get_query_columns(request: Request) -> list[str]:
#     columns = []
#     if "columns" in request.args:
#         if request.args["columns"].startswith("["):
#             try:
#                 columns = json.loads(request.args["columns"])
#             except json.JSONDecodeError:
#                 pass

#         else:
#             columns = [request.args["columns"]]

#     return columns


# def is_strong_query(model: Any, columns: list[str] = []) -> bool:
#     if getattr(model, "__consistency__", "weak") == "strong":
#         # If the entire table is strongly consistent, return True
#         return True

#     if not columns:
#         # Use all columns of the model
#         columns = [getattr(col, "key") for col in model.__table__.columns]

#     for col in columns:
#         if getattr(model, col).info.get("consistency", "weak") == "strong":
#             # If any of the columns is strongly consistent, return True
#             return True


# def is_strong_query(query_columns: list[str], strong_columns: list[str]):
#     query_tables = set(col.split(".")[0] for col in query_columns)
#     strong_tables = set(
#         col.split(".")[0] for col in strong_columns if col.split(".")[1] == "*"
#     )

#     # A query is strong if there is any column in it which is strong or if there is
#     # any column in a table marked as strong
#     return bool(query_tables & strong_tables) | bool(
#         set(query_columns) & set(strong_columns)
#     )


# def validate_query_columns(model: Any, columns: list[str]) -> bool:
#     model_cols = set(getattr(col, "key") for col in model.__table__.columns)
#     return set(columns).issubset(model_cols)


def build_sql_filters(data: dict, row_id: str = None) -> tuple[str, list]:
    # filters are chained and currently only support equality
    # if `row_id` is set, no other filters should be applied but we're
    # not going to stop you from doing it
    filters = data.get("filters", {})
    if row_id is not None:
        filters["id"] = row_id

    if filters:
        return (
            " WHERE " + " AND ".join(f"{k} = ?" for k in filters),
            list(filters.values()),
        )

    return "", []


def build_select_query(
    schema: str, data: dict = {}, row_id: Hashable = None
) -> tuple[str, list]:
    _columns = (
        [f"{schema}.{col}" for col in data["columns"]]
        if "columns" in data
        else [f"{schema}.*"]
    )
    _query = f"SELECT {', '.join(_columns)} FROM {schema}"

    f_query, _params = build_sql_filters(data, row_id)

    return _query + f_query, _params
