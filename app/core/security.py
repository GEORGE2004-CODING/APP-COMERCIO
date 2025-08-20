from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from app.core.config import settings
from schemas.user import TokenError, UserNotFoundError

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Passwords ---
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return hash_password(password)

# --- Tokens ---
def create_access_token(data: dict, expires_delta: timedelta = None, scopes: list[str] = None) -> str:
    to_encode = data.copy()
    if scopes:
        to_encode["scopes"] = scopes
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        raise TokenError("Token inválido o expirado")


def get_current_user(token: str) -> dict:
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise UserNotFoundError("Usuario no encontrado en el token")
    return {"user_id": user_id, "role": payload.get("role", "USER"), "scopes": payload.get("scopes", [])}


def create_refresh_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(days=30))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_refresh_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        raise TokenError("Token de refresco inválido o expirado")


def get_current_refresh_user(token: str) -> dict:
    payload = decode_refresh_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise UserNotFoundError("Usuario no encontrado en el token")
    return {"user_id": user_id, "role": payload.get("role", "USER"), "scopes": payload.get("scopes", [])}


# --- Roles / Scopes helpers ---
def is_admin(user: dict) -> bool:
    return user.get("role") == "ADMIN"


def has_scope(user: dict, scope: str) -> bool:
    return scope in user.get("scopes", [])
