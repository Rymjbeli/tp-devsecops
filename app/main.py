from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import List, Dict, Any
import subprocess
import pickle
from base64 import b64decode
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
from fastapi.responses import Response, HTMLResponse
import os

app = FastAPI()

# 1) CORS trop permissif
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Modèle pour les utilisateurs
class User(BaseModel):
    id: int
    name: str
    email: str


# Base de données en mémoire
users_db: List[User] = [
    User(id=1, name="Rim", email="rim@example.com"),
    User(id=2, name="Ramy", email="ramy@example.com"),
]

# -------------------------
# Secret en clair
# -------------------------
API_KEY: str = "super-secret-api-key-123456"


# -------- Routes publiques --------
@app.get("/", response_class=HTMLResponse)
def read_root_html():
    html = """
    <html><head><title>Demo DAST</title></head><body>
      <h1>Demo DAST - endpoints vulnérables</h1>

      <h2>Command Injection Test</h2>
      <form action="/run" method="get">
        <input name="cmd" placeholder="Enter command"/>
        <button>Run</button>
      </form>

      <h2>Direct Links</h2>
      <ul>
        <li><a href="/debug/all_users">/debug/all_users</a></li>
        <li><a href="/secret">/secret</a></li>
        <li><a href="/find_by_name?name=Rim">/find_by_name?name=Rim</a></li>
        <li><a href="/run?cmd=echo hello">/run?cmd=echo hello</a></li>
      </ul>
      <p>This page exists to help DAST scanners find the vulnerable endpoints.</p>
    </body></html>
    """
    return HTMLResponse(content=html)


@app.get("/users", response_model=List[User])
def get_users() -> List[User]:
    return users_db


@app.get("/users/{user_id}", response_model=User)
def get_user(user_id: int) -> User:
    for user in users_db:
        if user.id == user_id:
            return user
    raise HTTPException(status_code=404, detail="User not found")


# -------- Routes vulnérables --------
@app.get("/secret")
def read_secret() -> Dict[str, str]:
    return {"secret": "12345"}


@app.get("/debug/all_users")
def debug_all_users() -> Dict[str, List[Dict[str, Any]]]:
    return {"users": [u.model_dump() for u in users_db]}


@app.get("/find_by_name")
def find_by_name(name: str) -> Dict[str, str]:
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    return {"query": sql}


@app.get("/run")
def run_cmd(cmd: str) -> Dict[str, str]:
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return {"output": output.decode(errors="ignore")}
    except Exception as e:
        return {"error": str(e)}


@app.post("/deserialize")
def deserialize(payload: Dict[str, str]) -> Dict[str, Any]:
    data_b64 = payload.get("data", "")
    try:
        raw = b64decode(data_b64)
        obj = pickle.loads(raw)
        return {"ok": True, "type": str(type(obj))}
    except Exception as e:
        return {"error": str(e)}

