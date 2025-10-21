from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import List, Dict, Any
import subprocess
import pickle
from base64 import b64decode
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
import html

app = FastAPI()

# 1) CORS trop permissif
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Origine permissive
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
API_KEY: str = "super-secret-api-key-123456"  # Hardcoded secret


# -------- Routes publiques --------
@app.get("/")
def read_root() -> Dict[str, str]:
    return {"message": "Hello, Secure World!"}


@app.get("/users", response_model=List[User])
def get_users() -> List[User]:
    return users_db


@app.get("/users/{user_id}", response_model=User)
def get_user(user_id: int) -> User:
    for user in users_db:
        if user.id == user_id:
            return user
    raise HTTPException(status_code=404, detail="User not found")


# -------- Routes vulnérables conservées --------

# 1) Endpoint exposant un secret (DAST)
@app.get("/secret")
def read_secret() -> Dict[str, str]:
    return {"secret": "12345"}


# 2) Endpoint qui retourne toute la DB (exposition d'info) (DAST)
@app.get("/debug/all_users")
def debug_all_users() -> Dict[str, List[Dict[str, Any]]]:
    return {"users": [u.model_dump() for u in users_db]}


# 3) Injection SQL simulée (SAST)
@app.get("/find_by_name")
def find_by_name(name: str) -> Dict[str, str]:
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    return {"query": sql}


# 4) Command injection via subprocess (SAST)
@app.get("/run")
def run_cmd(cmd: str) -> Dict[str, str]:
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return {"output": output.decode(errors="ignore")}
    except Exception as e:
        return {"error": str(e)}


# 5) Désérialisation non sécurisée avec pickle (SAST)
@app.post("/deserialize")
def deserialize(payload: Dict[str, str]) -> Dict[str, Any]:
    data_b64 = payload.get("data", "")
    try:
        raw = b64decode(data_b64)
        obj = pickle.loads(raw)
        return {"ok": True, "type": str(type(obj))}
    except Exception as e:
        return {"error": str(e)}


# ----- XSS réfléchi (POUR DÉMONSTRATION UNIQUEMENT) -----
@app.get("/vuln/xss", response_class=HTMLResponse)
def vuln_xss(input: str = "") -> HTMLResponse:
    """
    VULN: XSS réfléchi - retourne du HTML contenant l'entrée utilisateur sans échappement.
    Ceci est intentionnellement vulnérable pour la démo TP.
    """
    # vulnérabilité intentionnelle : NE PAS assainir dans cette branche de démonstration
    vulnerable_html = f"""
    <html>
      <head><title>Démo XSS Réfléchi</title></head>
      <body>
        <h1>Démo XSS Réfléchi</h1>
        <p>Entrée (réfléchie) : {input}</p>
        <form action="/vuln/xss" method="get">
          <input name="input" value="{html.escape(input)}"/>
          <button type="submit">Envoyer</button>
        </form>
      </body>
    </html>
    """
    return HTMLResponse(content=vulnerable_html)


# ----- Redirection ouverte (POUR DÉMONSTRATION UNIQUEMENT) -----
@app.get("/vuln/redirect")
def vuln_redirect(url: str = ""):
    """
    VULN: redirection ouverte - redirige vers l'URL fournie par l'utilisateur sans validation.
    Intentionnel pour la démo uniquement.
    """
    # redirection simple vers l'URL fournie
    return RedirectResponse(url=url or "/")
