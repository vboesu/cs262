from flask import Blueprint, request, g

import logging
import sqlalchemy as sa
import sqlalchemy.orm as so

from utils import get_query_columns, is_strong_query, validate_query_columns

logging.basicConfig(level=logging.DEBUG)


api = Blueprint("api", __name__)
logger = logging.getLogger(__name__)


@api.route("/<schema>", methods=["GET"])
def select(schema: str):
    if (model := g.db.tables.get(schema)) is None:
        return {"error": f"Schema {schema} not found."}, 404

    columns = get_query_columns(request)
    if not validate_query_columns(model, columns):
        return {"error": "Invalid columns."}, 400

    logger.debug("SELECT %s FROM %s", columns, schema)

    if is_strong_query(model, columns):
        # TODO: forward to leader
        logger.info("STRONG SELECT QUERY")
        return [], 200  # TODO

    # WEAK SELECT QUERY
    with so.Session(g.db.engine) as session:
        if columns:
            query = sa.select(*[getattr(model, c) for c in columns])
            return [
                {c: row[i] for i, c in enumerate(columns)}
                for row in session.execute(query).all()
            ]

        else:
            query = sa.select(model)
            return [row.to_dict() for row in session.execute(query).scalars()]


@api.route("/<schema>/<id>", methods=["GET"])
def select_id(schema: str, id: str):
    if (model := g.db.tables.get(schema)) is None:
        return {"error": f"Schema {schema} not found."}, 404

    columns = get_query_columns(request)
    if not validate_query_columns(model, columns):
        return {"error": "Invalid columns."}, 400

    logger.debug("SELECT %s FROM %s WHERE id = %s", columns, schema, id)

    if is_strong_query(model, columns):
        # TODO: forward to leader
        logger.info("STRONG SELECT QUERY")
        return [], 200  # TODO

    # WEAK SELECT QUERY
    with so.Session(g.db.engine) as session:
        if columns:
            query = sa.select(*[getattr(model, c) for c in columns])
            query = query.where(model.id == id)
            rows = session.execute(query).all()
            if len(rows) >= 1:
                return {c: rows[0][i] for i, c in enumerate(columns)}, 200
            return {}, 404

        else:
            query = sa.select(model).where(model.id == id)
            (obj,) = session.execute(query).one_or_none()
            return (obj.to_dict(), 200) if obj is not None else ({}, 404)


@api.route("/<schema>", methods=["POST"])
def insert(schema: str):
    if (model := g.db.tables.get(schema)) is None:
        return {"error": f"Schema {schema} not found."}, 404

    data = request.get_json()
    if not validate_query_columns(model, list(data.keys())):
        return {"error": "Invalid columns."}, 400

    logger.debug("INSERT INTO %s, DATA %s", schema, data)

    if is_strong_query(model, []):
        # TODO: forward to leader
        logger.info("STRONG INSERT QUERY")
        return [], 200  # TODO

    # WEAK INSERT QUERY
    with so.Session(g.db.engine) as session:
        try:
            obj = model(**data)
            session.add(obj)
            session.commit()
        except Exception as e:
            return {"error": str(e)}, 400

    # TODO: write insert query with unique ID to sync long
    return {}, 201


@api.route("/<schema>", methods=["PATCH"])
def update(schema: str):
    if (model := g.db.tables.get(schema)) is None:
        return {"error": f"Schema {schema} not found."}, 404

    data = request.get_json()
    columns = list(data.keys())
    if not validate_query_columns(model, columns):
        return {"error": "Invalid columns."}, 400

    logger.debug("UPDATE %s SET %s", schema, data)

    if is_strong_query(model, columns):
        # TODO: forward to leader
        logger.info("STRONG UPDATE QUERY")
        return [], 200  # TODO

    # WEAK UPDATE QUERY
    with so.Session(g.db.engine) as session:
        try:
            query = sa.update(model.__table__).values(data)
            session.execute(query)
            session.commit()
        except Exception as e:
            return {"error": str(e)}, 400

    # TODO: write update query with unique ID to sync long
    return {}, 200


@api.route("/<schema>/<id>", methods=["PATCH"])
def update_id(schema: str, id: str):
    if (model := g.db.tables.get(schema)) is None:
        return {"error": f"Schema {schema} not found."}, 404

    data = request.get_json()
    columns = list(data.keys())
    if not validate_query_columns(model, columns):
        return {"error": "Invalid columns."}, 400

    logger.debug("UPDATE %s SET %s WHERE id = %s", schema, data, id)

    if is_strong_query(model, columns):
        # TODO: forward to leader
        logger.info("STRONG UPDATE QUERY")
        return [], 200  # TODO

    # WEAK UPDATE QUERY
    with so.Session(g.db.engine) as session:
        try:
            query = sa.update(model.__table__).where(model.id == id).values(data)
            session.execute(query)
            session.commit()
        except Exception as e:
            return {"error": str(e)}, 400

    # TODO: write update query with unique ID to sync long
    return {}, 200


if __name__ == "__main__":
    api.run(host="0.0.0.0", port=9000, threaded=True)
