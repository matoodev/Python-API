import time
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, make_response
# from flask_cors import CORS

from config import Config
from auth import check_password, create_jwt, decode_jwt, login_required, hash_password
from rate_limiter import rate_limit, rate_limiter
from encryption import encrypt_data, decrypt_data

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

_hashed_admin = hash_password(Config.ADMIN_PASSWORD)
_logged_in_users: set[str] = set()


@app.route("/")
def index():
    return redirect(url_for("login_page"))


@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
@rate_limit
def api_login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username != Config.ADMIN_USERNAME:
        time.sleep(0.5)
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password(password, _hashed_admin):
        time.sleep(0.5)
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_jwt(username)

    _logged_in_users.add(username)

    response_data = {
        "message": "Authenticated successfully",
        "token": token,
        "user": encrypt_data(username),
    }

    resp = make_response(jsonify(response_data), 200)
    resp.set_cookie(
        "access_token",
        token,
        httponly=True,
        secure=False,
        samesite="Lax",
        max_age=int(Config.JWT_EXPIRATION.total_seconds()),
    )

    session["access_token"] = token
    session["user"] = username

    resp.headers["X-User-Encrypted"] = encrypt_data(username)

    return resp


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=request.user)


@app.route("/api/me", methods=["GET"])
@login_required
def api_me():
    return jsonify({
        "user": encrypt_data(request.user),
        "active_sessions": len(_logged_in_users),
    })


@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():
    token = request.cookies.get("access_token") or session.get("access_token")
    username = decode_jwt(token)
    if username:
        _logged_in_users.discard(username)

    session.clear()
    session.modified = True

    resp = jsonify({"message": "Disconnected successfully"})
    resp.set_cookie("access_token", "", expires=0)
    return resp


@app.route("/api/validate", methods=["GET"])
@login_required
def api_validate():
    return jsonify({
        "valid": True,
        "user": encrypt_data(request.user),
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5777, debug=False)
