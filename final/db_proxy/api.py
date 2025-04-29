from flask import Blueprint, request, g

import logging

from utils import build_sql

logging.basicConfig(level=logging.DEBUG)


api = Blueprint("api", __name__)
logger = logging.getLogger(__name__)


@api.route("/<schema>", methods=["GET", "POST", "PATCH", "DELETE"])
def schema_ops(schema: str):
    if schema not in g.db.tables:
        return {"error": f"Schema {schema} not found."}, 404

    data = request.args.to_dict()
    if request.content_type == "application/json":
        data.update(request.get_json() or {})

    method, query, params, columns = build_sql(schema, request.method, data)
    result = g.proxy.dispatch(method, schema, query, params, columns)

    return result


@api.route("/<schema>/<row_id>", methods=["GET", "PATCH", "DELETE"])
def row_ops(schema: str, row_id: str):
    if schema not in g.db.tables:
        return {"error": f"Schema {schema} not found."}, 404

    data = request.args.to_dict()
    if request.content_type == "application/json":
        data.update(request.get_json() or {})

    method, query, params, columns = build_sql(schema, request.method, data, row_id)
    result = g.proxy.dispatch(method, schema, query, params, columns)

    return result


# @api.route("/<schema>", methods=["GET"])
# def select(schema: str):
#     if (model := g.db.tables.get(schema)) is None:
#         return {"error": f"Schema {schema} not found."}, 404

#     columns = get_query_columns(request)
#     if not validate_query_columns(model, columns):
#         return {"error": "Invalid columns."}, 400

#     logger.debug("SELECT %s FROM %s", columns, schema)

#     with so.Session(g.db.engine) as session:
#         if columns:
#             query = sa.select(*[getattr(model, c) for c in columns])
#             return [
#                 {c: row[i] for i, c in enumerate(columns)}
#                 for row in session.execute(query).all()
#             ]

#         else:
#             query = sa.select(model)
#             return [row.to_dict() for row in session.execute(query).scalars()]


# @api.route("/<schema>/<id>", methods=["GET"])
# def select_id(schema: str, id: str):
#     if (model := g.db.tables.get(schema)) is None:
#         return {"error": f"Schema {schema} not found."}, 404

#     columns = get_query_columns(request)
#     if not validate_query_columns(model, columns):
#         return {"error": "Invalid columns."}, 400

#     logger.debug("SELECT %s FROM %s WHERE id = %s", columns, schema, id)

#     with so.Session(g.db.engine) as session:
#         if columns:
#             query = sa.select(*[getattr(model, c) for c in columns])
#             query = query.where(model.id == id)
#             rows = session.execute(query).all()
#             if len(rows) >= 1:
#                 return {c: rows[0][i] for i, c in enumerate(columns)}, 200
#             return {}, 404

#         else:
#             query = sa.select(model).where(model.id == id)
#             (obj,) = session.execute(query).one_or_none()
#             return (obj.to_dict(), 200) if obj is not None else ({}, 404)


# @api.route("/<schema>", methods=["POST"])
# def insert(schema: str):
#     if (model := g.db.tables.get(schema)) is None:
#         return {"error": f"Schema {schema} not found."}, 404

#     data = request.get_json()
#     if not validate_query_columns(model, list(data.keys())):
#         return {"error": "Invalid columns."}, 400

#     logger.debug("INSERT INTO %s, DATA %s", schema, data)

#     # Store query in binary format, with query_id in front
#     query = binary_query(b"I", schema, request.data)

#     if is_strong_query(model, []):
#         status = g.proxy.send_query_to_leader(query)
#     else:
#         status = g.db.try_query(query)
#         # TODO: write query with unique ID to sync long

#     if status == 0:
#         return {}, 201

#     error = STATUS_CODE_TO_ERROR_DESCRIPTION.get(status)
#     return {"error": f"Database error ({error})."}, 400


# @api.route("/<schema>", methods=["PATCH"])
# def update(schema: str):
#     if (model := g.db.tables.get(schema)) is None:
#         return {"error": f"Schema {schema} not found."}, 404

#     data = request.get_json()
#     columns = list(data.keys())
#     if not validate_query_columns(model, columns):
#         return {"error": "Invalid columns."}, 400

#     logger.debug("UPDATE %s SET %s", schema, data)

#     # Store query in binary format, with query_id in front
#     query = binary_query(b"U", schema, request.data)

#     if is_strong_query(model, columns):
#         status = g.proxy.send_query_to_leader(query)
#     else:
#         status = g.db.try_query(query)
#         # TODO: write query with unique ID to sync long

#     if status == 0:
#         return {}, 200

#     error = STATUS_CODE_TO_ERROR_DESCRIPTION.get(status)
#     return {"error": f"Database error ({error})."}, 400


# @api.route("/<schema>/<id>", methods=["PATCH"])
# def update_id(schema: str, id: str):
#     if (model := g.db.tables.get(schema)) is None:
#         return {"error": f"Schema {schema} not found."}, 404

#     data = request.get_json()
#     columns = list(data.keys())
#     if not validate_query_columns(model, columns):
#         return {"error": "Invalid columns."}, 400

#     logger.debug("UPDATE %s SET %s WHERE id = %s", schema, data, id)

#     req_data = {**data, "where__id": id}

#     # Store query in binary format, with query_id in front
#     query = binary_query(b"U", schema, json.dumps(req_data).encode())

#     if is_strong_query(model, columns):
#         status = g.proxy.send_query_to_leader(query)
#     else:
#         status = g.db.try_query(query)
#         # TODO: write query with unique ID to sync long

#     if status == 0:
#         return {}, 200

#     error = STATUS_CODE_TO_ERROR_DESCRIPTION.get(status)
#     return {"error": f"Database error ({error})."}, 400


if __name__ == "__main__":
    api.run(host="0.0.0.0", port=9000, threaded=True)
