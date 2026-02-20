# World's Greatest Cafe Management System ☕

A full-stack FastAPI app with:

- Real-time auth event stream over WebSockets.
- Secure registration/login/logout with signed access tokens.
- Menu management and order management APIs.
- Interactive front-end dashboard.

## Quick start

```bash
cd 050_Worlds_Greatest_Cafe_Management_System
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000`.

## API highlights

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/logout`
- `GET /auth/validate`
- `GET /menu` and `POST /menu`
- `POST /orders`, `GET /orders`, `PATCH /orders/{order_id}`
- `WS /ws/auth/{user_id}?token=<access_token>` for real-time auth notifications.

## Tests

```bash
pytest tests/test_app.py
```
