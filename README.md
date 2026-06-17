# python api

aight, here's a flask-based auth api with jwt, bcrypt, rate limiting, and encryption.

came in handy for small projects where you need a quick auth layer without setting up a whole backend framework. login, dashboard, token validation — all there.

## what's inside

- **login** — username + password, returns jwt token
- **dashboard** — shows user info, active sessions, api status
- **rate limiting** — 5 requests per 60s window per ip, configurable
- **encryption** — fernet (symmetric) for user data in tokens and headers
- **jwt auth** — required for all `/api/*` routes, `login_required` decorator

## before you go live

swap the example keys in `config.py`:

| key | what it is |
|-----|------------|
| `SECRET_KEY` | flask session secret |
| `JWT_SECRET` | jwt signing secret |
| `ENCRYPTION_KEY` | fernet key for data encryption |
| `ADMIN_PASSWORD` | the admin login password |

## run

```bash
pip install -r requirements.txt
python app.py
```

then hit `http://localhost:5777` in your browser.

default admin login: `admin` / `change-me`

## stack

flask, pyjwt, bcrypt, cryptography. nothing fancy.
