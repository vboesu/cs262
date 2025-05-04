import logging

from flask import Blueprint, request, g

api = Blueprint("api", __name__)
logger = logging.getLogger(__name__)


@api.route("/<schema>", methods=["GET", "POST"])
def schema_ops(schema: str):
    if schema not in g.proxy.db.tables:
        return {"error": f"Schema {schema} not found."}, 404

    data = request.args.to_dict()
    if request.content_type == "application/json":
        data.update(request.get_json() or {})

    result, code = g.proxy.dispatch(request.method, schema, data)

    return result, code


@api.route("/<schema>/<row_id>", methods=["GET", "PATCH", "DELETE"])
def row_ops(schema: str, row_id: str):
    if schema not in g.proxy.db.tables:
        return {"error": f"Schema {schema} not found."}, 404

    data = request.args.to_dict()
    if request.content_type == "application/json":
        data.update(request.get_json() or {})

    result, code = g.proxy.dispatch(request.method, schema, data, row_id)

    return (result[0], code) if len(result) else ({}, code)


if __name__ == "__main__":
    api.run(host="0.0.0.0", port=9000, threaded=True)
