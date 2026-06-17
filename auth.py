from __future__ import annotations

import bcrypt
import jwt
from datetime import datetime, timezone
from functools import wraps
from typing import Optional
from flask import request, jsonify, session, redirect, url_for

from config import Config
from encryption import encrypt_data, decrypt_data


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(Config.BCRYPT_ROUNDS)).decode()


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_jwt(username: str) -> str:
    payload = {
        "sub": encrypt_data(username),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + Config.JWT_EXPIRATION,
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)


def decode_jwt(token: str) -> str | None:
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
        return decrypt_data(payload["sub"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, Exception):
        return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("access_token") or session.get("access_token")
        if not token:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Missing token"}), 401
            return redirect(url_for("login_page"))
        username = decode_jwt(token)
        if not username:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Invalid or expired token"}), 401
            return redirect(url_for("login_page"))
        request.user = username
        return f(*args, **kwargs)
    return decorated
