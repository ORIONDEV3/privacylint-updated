from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import HTTPException, Request


COOKIE_NAME = "pl_session"
REQUIRE_AUTH = os.getenv("REQUIRE_AUTH", "false").lower() == "true"
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
CSRF_SECRET = os.getenv("CSRF_SECRET", "")


def _session_token(cookie_value: str | None) -> str | None:
    if not cookie_value or not SESSION_SECRET:
        return None
    dot = cookie_value.rfind(".")
    if dot < 1:
        return None
    token, supplied = cookie_value[:dot], cookie_value[dot + 1:]
    expected = hmac.new(SESSION_SECRET.encode(), token.encode(), hashlib.sha256).digest()
    try:
        import base64

        encoded = base64.urlsafe_b64encode(expected).decode().rstrip("=")
    except Exception:
        return None
    return token if hmac.compare_digest(supplied, encoded) else None


def _check_csrf(request: Request, token: str) -> None:
    if not CSRF_SECRET:
        raise HTTPException(503, "Analysis service security is not configured.")
    origin = request.headers.get("origin", "")
    allowed = {origin.strip() for origin in os.getenv("WEB_ORIGIN", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()}
    if origin not in allowed and not (os.getenv("NODE_ENV") != "production" and __import__("re").fullmatch(r"https?://(localhost|127\.0\.0\.1):517[3-9]", origin)):
        raise HTTPException(403, "Request origin is not allowed.")
    expected = hmac.new(CSRF_SECRET.encode(), f"csrf:{token}".encode(), hashlib.sha256).digest()
    import base64

    value = base64.urlsafe_b64encode(expected).decode().rstrip("=")
    supplied = request.headers.get("x-csrf-token", "")
    if not hmac.compare_digest(supplied, value):
        raise HTTPException(403, "Your session token expired. Refresh and try again.")


async def current_user(request: Request) -> dict:
    if not REQUIRE_AUTH:
        return {"id": None, "role": "Admin", "email": None}
    if len(SESSION_SECRET) < 32 or len(CSRF_SECRET) < 32:
        raise HTTPException(503, "Analysis service security is not configured.")
    token = _session_token(request.cookies.get(COOKIE_NAME))
    if not token:
        raise HTTPException(401, "Authentication required.")
    pool = request.app.state.scan_store.pool
    if not pool:
        raise HTTPException(503, "Analysis service database is unavailable.")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    async with pool.acquire() as connection:
        row = await connection.fetchrow(
            """SELECT u.id,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.token_hash=$1 AND s.expires_at>NOW() AND u.is_verified=TRUE""",
            token_hash,
        )
    if not row:
        raise HTTPException(401, "Authentication required.")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        _check_csrf(request, token)
    return {"id": str(row["id"]), "role": row["role"], "email": row["email"]}
