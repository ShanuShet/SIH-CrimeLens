import base64
import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from .models import User

SESSION_COOKIE = "crimelens_session"
SESSION_TTL = int(os.getenv("SESSION_TTL_SECONDS", "28800"))
SESSION_SECRET = os.getenv("SESSION_SECRET", "CHANGE-ME-CRIMELENS-DEMO-SECRET")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = 2**14, 8, 1
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = _unb64(salt_b64)
        expected = _unb64(digest_b64)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def make_session(user: User) -> tuple[str, str]:
    expires = int(time.time()) + SESSION_TTL
    csrf = secrets.token_urlsafe(24)
    payload = f"{user.id}.{expires}.{csrf}"
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{_b64(sig)}", csrf


def decode_session(value: str | None):
    if not value:
        return None
    try:
        user_id, expires, csrf, sig = value.split(".", 3)
        payload = f"{user_id}.{expires}.{csrf}"
        expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_unb64(sig), expected):
            return None
        if int(expires) < int(time.time()):
            return None
        return {"user_id": int(user_id), "csrf": csrf, "expires": int(expires)}
    except Exception:
        return None


def current_user(request: Request, db: Session) -> User | None:
    session = decode_session(request.cookies.get(SESSION_COOKIE))
    if not session:
        return None
    user = db.query(User).filter(User.id == session["user_id"], User.active == True).first()  # noqa: E712
    return user


def require_user(request: Request, db: Session) -> User:
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_csrf(request: Request):
    session = decode_session(request.cookies.get(SESSION_COOKIE))
    if not session:
        raise HTTPException(status_code=401, detail="Authentication required")
    token = request.headers.get("X-CSRF-Token", "")
    if not token or not hmac.compare_digest(token, session["csrf"]):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"
