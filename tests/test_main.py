from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_read_root():
    r = client.get("/")
    assert r.status_code == 200
    # fallback for HTML page (DAST demo)
    assert "<html" in r.text.lower()
    assert "demo dast" in r.text.lower()


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
    assert r.json() == {"message": "Accès refusé - aucune donnée sensible exposée."}


def test_debug_all_users():
    r = client.get("/debug/all_users")
    assert r.status_code == 200
    data = r.json()
    assert "users" in data
    assert isinstance(data["users"], list)
    assert any(u["name"] == "Rim" for u in data["users"])


def test_find_by_name_found():
    r = client.get("/find_by_name", params={"name": "Rim"})
    assert r.status_code == 200
    body = r.json()
    assert body.get("found") is True
    assert body.get("user")["name"] == "Rim"


def test_find_by_name_not_found():
    r = client.get("/find_by_name", params={"name": "Unknown"})
    assert r.status_code == 200
    body = r.json()
    assert body.get("found") is False
    assert body.get("user") is None


def test_run_cmd_whitelist():
    r = client.get("/run", params={"cmd": "echo hello"})
    assert r.status_code == 200
    output = r.json().get("output", "")
    assert "hello" in output.lower()


def test_run_cmd_non_whitelist():
    r = client.get("/run", params={"cmd": "echo test"})
    assert r.status_code == 200
    output = r.json().get("output", "")
    assert "non autorisée" in output.lower()


def test_deserialize_valid_json():
    payload = {"data": '{"hello":"world"}'}
    r = client.post("/deserialize", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body.get("ok") is True
    assert "Contenu JSON valide" in body.get("message", "")
