import json
from typing import Any

from flask import Request


def get_query_columns(request: Request) -> list[str]:
    columns = []
    if "columns" in request.args:
        if request.args["columns"].startswith("["):
            try:
                columns = json.loads(request.args["columns"])
            except json.JSONDecodeError:
                pass

        else:
            columns = [request.args["columns"]]

    return columns


def is_strong_query(model: Any, columns: list[str] = []) -> bool:
    if getattr(model, "__consistency__", "weak") == "strong":
        # If the entire table is strongly consistent, return True
        return True

    if not columns:
        # Use all columns of the model
        columns = [getattr(col, "key") for col in model.__table__.columns]

    for col in columns:
        if getattr(model, col).info.get("consistency", "weak") == "strong":
            # If any of the columns is strongly consistent, return True
            return True


def validate_query_columns(model: Any, columns: list[str]) -> bool:
    model_cols = set(getattr(col, "key") for col in model.__table__.columns)
    return set(columns).issubset(model_cols)
