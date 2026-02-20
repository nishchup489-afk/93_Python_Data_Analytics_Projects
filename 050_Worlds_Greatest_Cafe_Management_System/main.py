from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cafe.db"
SECRET_KEY = os.getenv("CAFE_SECRET", "super-secret-cafe-key")
TOKEN_TTL_SECONDS = 60 * 60 * 8

app = FastAPI(title="World's Greatest Cafe Management System", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
auth_scheme = HTTPBearer(auto_error=False)


class RegisterIn(BaseModel):
    name: str = Field(min_length=2)
    email: EmailStr
    password: str = Field(min_length=8)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class MenuItemIn(BaseModel):
    name: str
    price: float = Field(gt=0)
    category: str
    in_stock: bool = True


class OrderItem(BaseModel):
    menu_item_id: int
    quantity: int = Field(gt=0)


class OrderIn(BaseModel):
    items: list[OrderItem]


class OrderStatusIn(BaseModel):
    status: str


class AuthRealtimeHub:
    def __init__(self) -> None:
        self.connections: dict[int, list[WebSocket]] = {}

    async def connect(self, user_id: int, socket: WebSocket) -> None:
        await socket.accept()
        self.connections.setdefault(user_id, []).append(socket)

    def disconnect(self, user_id: int, socket: WebSocket) -> None:
        user_sockets = self.connections.get(user_id, [])
        if socket in user_sockets:
            user_sockets.remove(socket)
        if not user_sockets and user_id in self.connections:
            self.connections.pop(user_id)

    async def publish(self, user_id: int, payload: dict[str, Any]) -> None:
        for socket in list(self.connections.get(user_id, [])):
            await socket.send_json(payload)


hub = AuthRealtimeHub()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS menu_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            in_stock INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total REAL NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            menu_item_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            FOREIGN KEY(order_id) REFERENCES orders(id),
            FOREIGN KEY(menu_item_id) REFERENCES menu_items(id)
        );
        """
    )
    conn.commit()
    conn.close()


@app.on_event("startup")
def startup() -> None:
    init_db()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    salt, digest = stored_hash.split("$", maxsplit=1)
    calculated = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return hmac.compare_digest(calculated, digest)


def sign(payload: dict[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    signature = hmac.new(SECRET_KEY.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def unsign(token: str) -> dict[str, Any]:
    try:
        encoded, signature = token.split(".", maxsplit=1)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Malformed token") from exc
    expected = hmac.new(SECRET_KEY.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="Invalid signature")
    return json.loads(base64.urlsafe_b64decode(encoded.encode()).decode())


def build_session_token(user_id: int) -> tuple[str, int]:
    now = int(time.time())
    expires_at = now + TOKEN_TTL_SECONDS
    payload = {"user_id": user_id, "exp": expires_at, "iat": now, "nonce": secrets.token_hex(8)}
    return sign(payload), expires_at


def resolve_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(auth_scheme),
) -> sqlite3.Row:
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = credentials.credentials
    payload = unsign(token)
    if payload["exp"] < int(time.time()):
        raise HTTPException(status_code=401, detail="Token expired")

    conn = get_conn()
    session = conn.execute(
        "SELECT user_id, is_active, expires_at FROM sessions WHERE token = ?", (token,)
    ).fetchone()
    if not session or not session["is_active"] or session["expires_at"] < int(time.time()):
        conn.close()
        raise HTTPException(status_code=401, detail="Session inactive")

    user = conn.execute("SELECT id, name, email FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.get("/", response_class=HTMLResponse)
def home() -> FileResponse:
    return FileResponse(BASE_DIR / "templates" / "index.html")


@app.post("/auth/register")
async def register(payload: RegisterIn) -> dict[str, Any]:
    conn = get_conn()
    try:
        cursor = conn.execute(
            "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (payload.name, payload.email.lower(), hash_password(payload.password), datetime.utcnow().isoformat()),
        )
        user_id = cursor.lastrowid
        token, expires_at = build_session_token(user_id)
        conn.execute(
            "INSERT INTO sessions (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (user_id, token, datetime.utcnow().isoformat(), expires_at),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.close()
        raise HTTPException(status_code=409, detail="Email already registered") from exc
    user = conn.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    await hub.publish(user_id, {"event": "auth.login", "user_id": user_id, "email": user["email"]})
    return {"token": token, "user": dict(user)}


@app.post("/auth/login")
async def login(payload: LoginIn) -> dict[str, Any]:
    conn = get_conn()
    user = conn.execute(
        "SELECT id, name, email, password_hash FROM users WHERE email = ?", (payload.email.lower(),)
    ).fetchone()
    if not user or not verify_password(payload.password, user["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token, expires_at = build_session_token(user["id"])
    conn.execute(
        "INSERT INTO sessions (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (user["id"], token, datetime.utcnow().isoformat(), expires_at),
    )
    conn.commit()
    conn.close()

    await hub.publish(user["id"], {"event": "auth.login", "user_id": user["id"], "email": user["email"]})
    return {"token": token, "user": {"id": user["id"], "name": user["name"], "email": user["email"]}}


@app.post("/auth/logout")
async def logout(
    user: sqlite3.Row = Depends(resolve_user),
    credentials: HTTPAuthorizationCredentials | None = Depends(auth_scheme),
) -> dict[str, str]:
    conn = get_conn()
    conn.execute("UPDATE sessions SET is_active = 0 WHERE token = ?", (credentials.credentials,))
    conn.commit()
    conn.close()
    await hub.publish(user["id"], {"event": "auth.logout", "user_id": user["id"]})
    return {"status": "logged_out"}


@app.get("/auth/validate")
def validate(user: sqlite3.Row = Depends(resolve_user)) -> dict[str, Any]:
    return {"valid": True, "user": dict(user)}


@app.websocket("/ws/auth/{user_id}")
async def auth_events(websocket: WebSocket, user_id: int, token: str = Query(...)) -> None:
    payload = unsign(token)
    if payload["user_id"] != user_id or payload["exp"] < int(time.time()):
        await websocket.close(code=1008)
        return

    await hub.connect(user_id, websocket)
    try:
        await websocket.send_json({"event": "auth.connected", "user_id": user_id})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(user_id, websocket)


@app.get("/menu")
def list_menu() -> dict[str, Any]:
    conn = get_conn()
    items = [dict(row) for row in conn.execute("SELECT * FROM menu_items ORDER BY id DESC").fetchall()]
    conn.close()
    return {"items": items}


@app.post("/menu")
def create_menu_item(payload: MenuItemIn, _: sqlite3.Row = Depends(resolve_user)) -> dict[str, Any]:
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO menu_items (name, category, price, in_stock) VALUES (?, ?, ?, ?)",
        (payload.name, payload.category, payload.price, int(payload.in_stock)),
    )
    conn.commit()
    item = conn.execute("SELECT * FROM menu_items WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return {"item": dict(item)}


@app.post("/orders")
def place_order(payload: OrderIn, user: sqlite3.Row = Depends(resolve_user)) -> dict[str, Any]:
    conn = get_conn()
    total = 0.0
    line_items: list[tuple[int, int, float]] = []
    for row in payload.items:
        item = conn.execute("SELECT id, price, in_stock FROM menu_items WHERE id = ?", (row.menu_item_id,)).fetchone()
        if not item:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Menu item {row.menu_item_id} not found")
        if not item["in_stock"]:
            conn.close()
            raise HTTPException(status_code=400, detail=f"Item {row.menu_item_id} is out of stock")
        total += item["price"] * row.quantity
        line_items.append((item["id"], row.quantity, item["price"]))

    order_cur = conn.execute(
        "INSERT INTO orders (user_id, total, status, created_at) VALUES (?, ?, ?, ?)",
        (user["id"], total, "pending", datetime.utcnow().isoformat()),
    )
    order_id = order_cur.lastrowid
    for item_id, quantity, unit_price in line_items:
        conn.execute(
            "INSERT INTO order_items (order_id, menu_item_id, quantity, unit_price) VALUES (?, ?, ?, ?)",
            (order_id, item_id, quantity, unit_price),
        )
    conn.commit()
    conn.close()
    return {"order_id": order_id, "total": round(total, 2), "status": "pending"}


@app.get("/orders")
def list_orders(_: sqlite3.Row = Depends(resolve_user)) -> dict[str, Any]:
    conn = get_conn()
    orders = [dict(row) for row in conn.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()]
    conn.close()
    return {"orders": orders}


@app.patch("/orders/{order_id}")
def update_order(order_id: int, payload: OrderStatusIn, _: sqlite3.Row = Depends(resolve_user)) -> dict[str, Any]:
    conn = get_conn()
    conn.execute("UPDATE orders SET status = ? WHERE id = ?", (payload.status, order_id))
    conn.commit()
    order = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    conn.close()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"order": dict(order)}
