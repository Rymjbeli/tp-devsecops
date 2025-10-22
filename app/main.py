from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel
from typing import List, Dict, Any
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import json
import html

app = FastAPI()

# -------------------------------------------------
# Sécurité CORS : on autorise uniquement localhost
# -------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# -------------------------------------------------
# Middleware pour ajouter des headers de sécurité
# -------------------------------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Ajoute des headers HTTP de sécurité pour réduire la surface XSS / injection:
    - Content-Security-Policy : empêche le chargement de ressources externes non autorisées
    - X-Content-Type-Options : évite le sniffing du type MIME
    - X-Frame-Options : empêche le framing (clickjacking)
    - Referrer-Policy : limite les informations d'origine envoyées
    - Permissions-Policy : désactive quelques API puissantes côté client
    """
    response = await call_next(request)

    # Politique CSP recommandée pour une app simple : n'autorise que 'self' pour tout.
    # Si tu utilises des scripts/styles inline, il faudra adapter (nonces ou 'unsafe-inline' - à éviter).
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

    return response


# -------------------------------------------------
# Modèle de données utilisateur (inchangé)
# -------------------------------------------------
class User(BaseModel):
    id: int
    name: str
    email: str


# -------------------------------------------------
# Base de données fictive (en mémoire)
# -------------------------------------------------
users_db: List[User] = [
    User(id=1, name="Rim", email="rim@example.com"),
    User(id=2, name="Ramy", email="ramy@example.com"),
]


# -------------------------------------------------
# Clé d’API non exposée publiquement (supprimée)
# -------------------------------------------------
# (On n’expose plus de clé secrète dans le code)


# -------------------------------------------------
# Page HTML d’accueil (inchangée)
# -------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def read_root_html():
    html_content = """
    <html><head><title>Demo DAST</title></head><body>
      <h1>Demo DAST - endpoints sécurisés</h1>

      <h2>Commande simulée</h2>
      <form action="/run" method="get">
        <input name="cmd" placeholder="Enter command"/>
        <button>Run</button>
      </form>

      <h2>Liens utiles</h2>
      <ul>
        <li><a href="/debug/all_users">/debug/all_users</a></li>
        <li><a href="/find_by_name?name=Rim">/find_by_name?name=Rim</a></li>
        <li><a href="/run?cmd=echo hello">/run?cmd=echo hello</a></li>
      </ul>
      <p>Cette page permet de tester les endpoints sécurisés.</p>
    </body></html>
    """
    return HTMLResponse(content=html_content)


# -------------------------------------------------
# Lecture des utilisateurs
# -------------------------------------------------
@app.get("/users", response_model=List[User])
def get_users() -> List[User]:
    return users_db


@app.get("/users/{user_id}", response_model=User)
def get_user(user_id: int) -> User:
    for user in users_db:
        if user.id == user_id:
            return user
    raise HTTPException(status_code=404, detail="Utilisateur introuvable")


# -------------------------------------------------
# Endpoint supprimé : plus d’exposition de secrets
# -------------------------------------------------
@app.get("/secret")
def read_secret() -> Dict[str, str]:
    return {"message": "Accès refusé - aucune donnée sensible exposée."}


# -------------------------------------------------
# Debug : toujours sans données sensibles
# -------------------------------------------------
@app.get("/debug/all_users")
def debug_all_users() -> Dict[str, List[Dict[str, Any]]]:
    # On ne renvoie que des données publiques
    return {"users": [u.model_dump() for u in users_db]}


# -------------------------------------------------
# Recherche d'utilisateur (prévention injection)
# -------------------------------------------------
@app.get("/find_by_name")
def find_by_name(name: str = Query(..., min_length=1, max_length=50)) -> Dict[str, Any]:
    """
    Recherche un utilisateur par nom, sans exposer de texte SQL ni de logique interne.
    Retourne uniquement le résultat public (ou None) et un message non technique.
    """
    # Normalisation simple du nom pour la recherche
    name_norm = name.strip().lower()

    # Recherche côté application (pas de concaténation ni d'affichage de requête)
    user = next((u for u in users_db if u.name.lower() == name_norm), None)

    # Réponse épurée : pas de "query" ni d'information technique
    if user:
        return {"found": True, "user": user.model_dump()}
    else:
        return {"found": False, "user": None}


# -------------------------------------------------
# Exécution de commande simulée (pas réelle)
# -------------------------------------------------
@app.get("/run")
def run_cmd(cmd: str = Query(..., max_length=100)) -> Dict[str, str]:
    """
    Endpoint /run sécurisé :
    - N'exécute aucune commande système.
    - Ne reflète jamais la commande brute envoyée par l'utilisateur.
    - Supporte un petit ensemble autorisé (whitelist) de "commandes" simulées,
      chaque commande ayant un résultat prédéfini.
    - Si la commande n'est pas autorisée, renvoie un message générique.
    """

    # Liste blanche : mapping commande -> résultat simulé
    WHITELIST = {
        "echo hello": "hello",
        "version": "app v1.0.0",
        "status": "OK",
    }

    cmd_norm = cmd.strip().lower()

    if cmd_norm in WHITELIST:
        # on renvoie un résultat prédéfini, sans jamais renvoyer la chaîne saisie telle quelle
        result = WHITELIST[cmd_norm]
        return {"output": f"Résultat simulé pour la commande autorisée: {result}"}
    else:
        # pour les commandes non autorisées, on renvoie un message générique
        # *ne pas* inclure cmd dans la réponse (évite la réflexion / fuite)
        return {"output": "Commande non autorisée ou inconnue. Aucune exécution n'a été faite."}


# -------------------------------------------------
# Désérialisation sécurisée (sans pickle)
# -------------------------------------------------
@app.post("/deserialize")
def deserialize(payload: Dict[str, str]) -> Dict[str, Any]:
    data_b64 = payload.get("data", "")
    try:
        # On ne désérialise pas directement, on vérifie simplement si c’est du JSON
        decoded = data_b64.encode("utf-8").decode("utf-8", errors="ignore")
        json.loads(decoded)  # Validation JSON simple
        return {"ok": True, "message": "Contenu JSON valide"}
    except Exception as e:
        return {"error": str(e)}
