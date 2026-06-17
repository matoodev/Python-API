import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production-abc123")
    JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production-def456")
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION = timedelta(hours=1)
    ENCRYPTION_KEY = os.environ.get(
        "ENCRYPTION_KEY",
        "change-me-in-production-ghi789=",
    )
    RATE_LIMIT = 5
    RATE_LIMIT_WINDOW = 60
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "change-me"
    BCRYPT_ROUNDS = 12
