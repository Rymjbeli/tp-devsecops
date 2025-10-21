# tests/test_main.py
import base64
import pickle
from fastapi.testclient import TestClient
from app.main import app  # juste app

client = TestClient(app)


def test_read_root():
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"message": "Hello, Secure World!"}


def test_get_users():
    r = client.get("/users")
    assert r.status_code == 200
    users = r.json()
    assert isinstance(users, list)
    names = [u["name"] for u in users]
    assert "Rim" in names
    assert "Ramy" in names


def test_get_user_by_id_found():
    r = client.get("/users/1")
    assert r.status_code == 200
    assert r.json()["name"] == "Rim"


def test_get_user_by_id_not_found():
    r = client.get("/users/9999")
    assert r.status_code == 404


def test_secret_route():
    r = client.get("/secret")
    assert r.status_code == 200
    assert "secret" in r.json()
    assert r.json()["secret"] == "12345"


def test_debug_all_users():
    r = client.get("/debug/all_users")
    assert r.status_code == 200
    data = r.json()
    assert "users" in data
    assert isinstance(data["users"], list)
    assert any(u["name"] == "Rim" for u in data["users"])


def test_find_by_name_sql_pattern():
    name = "Rim"
    r = client.get("/find_by_name", params={"name": name})
    assert r.status_code == 200
    q = r.json().get("query", "")
    assert "SELECT * FROM users WHERE name" in q
    assert name in q


def test_run_cmd_echo():
    r = client.get("/run", params={"cmd": "echo test"})
    assert r.status_code == 200
    body = r.json()
    output = body.get("output", "") or body.get("error", "")
    assert "test" in output.lower()


def test_deserialize_unsafe():
    sample = {"evil": True, "n": 123}
    pickled = pickle.dumps(sample)
    b64 = base64.b64encode(pickled).decode()
    r = client.post("/deserialize", json={"data": b64})
    assert r.status_code == 200
    json_body = r.json()
    assert json_body.get("ok") is True
    assert "type" in json_body
