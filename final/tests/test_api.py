import pytest
from flask import Flask, g, json

from src.api import api


class FakeDB:
    def __init__(self, tables):
        self.tables = tables


class FakeProxy:
    def __init__(self, tables=None):
        self.db = FakeDB(tables or [])
        self.calls = []

    def dispatch(self, method, schema, data, row_id=None):
        record = {"method": method, "schema": schema, "data": data, "row_id": row_id}
        self.calls.append(record)
        return record


@pytest.fixture
def app():
    app = Flask(__name__)
    app.register_blueprint(api, url_prefix="/api")
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def proxy(app):
    proxy = FakeProxy(tables=["table1", "table2"])
    with app.app_context():
        g.proxy = proxy
        yield proxy


def test_schema_not_found(client):
    resp = client.get("/api/unknown")
    assert resp.status_code == 404
    assert resp.get_json() == {"error": "Schema unknown not found."}


def test_get_schema_with_query_params(client, proxy):
    resp = client.get("/api/table1?foo=bar&baz=qux")
    assert resp.status_code == 200
    result = resp.get_json()
    assert result["method"] == "GET"
    assert result["schema"] == "table1"
    assert result["data"] == {"foo": "bar", "baz": "qux"}
    assert result["row_id"] is None


@pytest.mark.parametrize(
    "payload,content_type,expected_data",
    [
        ({"a": "1", "b": "2"}, "application/json", {"a": "1", "b": "2"}),
        ({}, "application/json", {}),
    ],
)
def test_post_schema_json(client, proxy, payload, content_type, expected_data):
    resp = client.post(
        "/api/table2?x=9", data=json.dumps(payload), content_type=content_type
    )
    assert resp.status_code == 200
    result = resp.get_json()
    # JSON body overrides or adds to query params
    merged = {"x": "9", **payload}
    assert result["data"] == merged
    assert result["method"] == "POST"
    assert result["schema"] == "table2"


def test_post_schema_no_json(client, proxy):
    resp = client.post("/api/table1?only=param")
    assert resp.status_code == 200
    result = resp.get_json()
    assert result["data"] == {"only": "param"}
    assert result["method"] == "POST"


@pytest.mark.parametrize(
    "method,endpoint,data,content_type,row_id",
    [
        ("GET", "/api/table1/10?foo=bar", None, None, "10"),
        ("PATCH", "/api/table2/20", {"p": "v"}, "application/json", "20"),
        ("DELETE", "/api/table1/30", None, None, "30"),
    ],
)
def test_row_operations(client, proxy, method, endpoint, data, content_type, row_id):
    kwargs = {}
    if data is not None:
        kwargs["data"] = json.dumps(data)
        kwargs["content_type"] = content_type
    resp = client.open(endpoint, method=method, **kwargs)
    assert resp.status_code == 200
    result = resp.get_json()
    assert result["method"] == method
    assert result["schema"] in ("table1", "table2")
    assert result["row_id"] == row_id
    # Data should merge query params and JSON
    args = endpoint.split("?")[1] if "?" in endpoint else ""
    params = dict(arg.split("=") for arg in args.split("&") if arg)
    expected = params.copy()
    if data:
        expected.update(data)
    assert result["data"] == expected


def test_row_schema_not_found(client):
    resp = client.get("/api/invalid/1")
    assert resp.status_code == 404
    assert resp.get_json() == {"error": "Schema invalid not found."}
