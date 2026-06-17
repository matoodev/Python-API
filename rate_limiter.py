import time
from collections import defaultdict
from functools import wraps
from flask import request, jsonify, make_response

from config import Config


class RateLimiter:
    def __init__(self):
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def _key(self) -> str:
        return request.remote_addr or "127.0.0.1"

    def _clean(self, key: str):
        now = time.time()
        window = Config.RATE_LIMIT_WINDOW
        self._attempts[key] = [t for t in self._attempts[key] if now - t < window]

    def is_allowed(self) -> bool:
        key = self._key()
        self._clean(key)
        return len(self._attempts[key]) < Config.RATE_LIMIT

    def register(self):
        key = self._key()
        self._attempts[key].append(time.time())

    def remaining(self) -> int:
        key = self._key()
        self._clean(key)
        return max(0, Config.RATE_LIMIT - len(self._attempts[key]))

    def reset_time(self) -> float:
        key = self._key()
        self._clean(key)
        if not self._attempts[key]:
            return 0.0
        return self._attempts[key][0] + Config.RATE_LIMIT_WINDOW


rate_limiter = RateLimiter()


def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not rate_limiter.is_allowed():
            resp = make_response(
                jsonify({
                    "error": "Too many requests. Please wait and try again.",
                    "retry_after": int(rate_limiter.reset_time() - time.time()),
                }),
                429,
            )
            resp.headers["X-RateLimit-Limit"] = str(Config.RATE_LIMIT)
            resp.headers["X-RateLimit-Remaining"] = "0"
            resp.headers["Retry-After"] = str(
                int(rate_limiter.reset_time() - time.time())
            )
            return resp
        rate_limiter.register()
        return f(*args, **kwargs)
    return decorated
