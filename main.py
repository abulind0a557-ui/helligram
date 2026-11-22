import os
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI()

DB_PATH = "/data/helligram.db" if os.path.exists("/data") else "helligram.db"

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            owner_username TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS room_members (
            room_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            PRIMARY KEY (room_id, username)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS room_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            text TEXT NOT NULL,
            time TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def hash_password(password: str) -> str:
    salt = "helligram_secret_salt_v1"
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()

def get_user_by_token(token: str):
    if not token:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE token = ?", (token,))
    row = cur.fetchone()
    conn.close()
    return row["username"] if row else None

class AuthRequest(BaseModel):
    username: str
    password: str

class CreateRoomRequest(BaseModel):
    name: str
    type: str

class StartDMRequest(BaseModel):
    target_username: str

class ConnectionManager:
    def __init__(self):
        self.user_sockets: dict[str, set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.user_sockets.setdefault(username, set()).add(websocket)

    def disconnect(self, websocket: WebSocket, username: str):
        if username in self.user_sockets:
            self.user_sockets[username].discard(websocket)
            if not self.user_sockets[username]:
                del self.user_sockets[username]

    async def send_to_users(self, usernames: list[str], payload: dict):
        msg_str = json.dumps(payload)
        for u in usernames:
            for ws in list(self.user_sockets.get(u, [])):
                try:
                    await ws.send_text(msg_str)
                except Exception:
                    self.disconnect(ws, u)

manager = ConnectionManager()

@app.post("/api/signup")
async def signup(req: AuthRequest):
    username = req.username.strip()
    if len(username) < 3 or len(req.password) < 4:
        raise HTTPException(status_code=400, detail="Username kam az kam 3 aur password 4 characters ka ho.")
    conn = get_db()
    cur = conn.cursor()
    try:
        token = secrets.token_hex(32)
        cur.execute(
            "INSERT INTO users (username, password_hash, token, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(req.password), token, datetime.now().isoformat())
        )
        conn.commit()
        return {"username": username, "token": token}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Yeh username pehle se mojood hai.")
    finally:
        conn.close()

@app.post("/api/login")
async def login(req: AuthRequest):
    username = req.username.strip()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username, password_hash, token FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row or row["password_hash"] != hash_password(req.password):
        raise HTTPException(status_code=401, detail="Username ya password ghalat hai.")
    return {"username": row["username"], "token": row["token"]}

@app.get("/api/rooms")
async def get_my_rooms(x_auth_token: str = Header(None)):
    username = get_user_by_token(x_auth_token)
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT r.id, r.name, r.type, r.owner_username,
               (SELECT text FROM room_messages WHERE room_id = r.id ORDER BY id DESC LIMIT 1) as last_msg,
               (SELECT time FROM room_messages WHERE room_id = r.id ORDER BY id DESC LIMIT 1) as last_time,
               (SELECT COUNT(*) FROM room_members WHERE room_id = r.id) as member_count
        FROM rooms r
        JOIN room_members rm ON r.id = rm.room_id
        WHERE rm.username = ?
        ORDER BY (SELECT COALESCE(MAX(id), 0) FROM room_messages WHERE room_id = r.id) DESC, r.id DESC
    """, (username,))
    rows = cur.fetchall()

    rooms = []
    for r in rows:
        display_name = r["name"]
        if r["type"] == "dm":
            cur.execute("SELECT username FROM room_members WHERE room_id = ? AND username != ?", (r["id"], username))
            other = cur.fetchone()
            display_name = other["username"] if other else username
        rooms.append({
            "id": r["id"],
            "name": display_name,
            "type": r["type"],
            "owner": r["owner_username"],
            "last_msg": r["last_msg"] or "No messages yet",
            "last_time": r["last_time"] or "",
            "members": r["member_count"]
        })
    conn.close()
    return {"rooms": rooms}

@app.get("/api/search")
async def search_all(q: str = "", x_auth_token: str = Header(None)):
    username = get_user_by_token(x_auth_token)
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    q = q.strip()
    if not q:
        return {"users": [], "rooms": []}

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username LIKE ? AND username != ? LIMIT 10", (f"%{q}%", username))
    users = [r["username"] for r in cur.fetchall()]

    cur.execute("SELECT id, name, type FROM rooms WHERE type IN ('group', 'channel') AND name LIKE ? LIMIT 10", (f"%{q}%",))
    rooms = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"users": users, "rooms": rooms}

@app.post("/api/dm")
async def start_dm(req: StartDMRequest, x_auth_token: str = Header(None)):
    username = get_user_by_token(x_auth_token)
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    target = req.target_username.strip()
    if target == username:
        raise HTTPException(status_code=400, detail="Khud se DM nahi kar sakte.")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (target,))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User nahi mila.")

    cur.execute("""
        SELECT r.id FROM rooms r
        JOIN room_members m1 ON r.id = m1.room_id AND m1.username = ?
        JOIN room_members m2 ON r.id = m2.room_id AND m2.username = ?
        WHERE r.type = 'dm'
    """, (username, target))
    existing = cur.fetchone()
    if existing:
        conn.close()
        return {"room_id": existing["id"]}

    cur.execute(
        "INSERT INTO rooms (name, type, owner_username, created_at) VALUES (?, 'dm', ?, ?)",
        (f"DM:{username}:{target}", username, datetime.now().isoformat())
    )
    room_id = cur.lastrowid
    cur.execute("INSERT INTO room_members (room_id, username) VALUES (?, ?)", (room_id, username))
    cur.execute("INSERT INTO room_members (room_id, username) VALUES (?, ?)", (room_id, target))
    conn.commit()
    conn.close()

    await manager.send_to_users([target], {"type": "refresh_rooms"})
    return {"room_id": room_id}

@app.post("/api/rooms/create")
async def create_room(req: CreateRoomRequest, x_auth_token: str = Header(None)):
    username = get_user_by_token(x_auth_token)
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    name = req.name.strip()
    if len(name) < 2 or req.type not in ("group", "channel"):
        raise HTTPException(status_code=400, detail="Valid naam aur type dein.")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO rooms (name, type, owner_username, created_at) VALUES (?, ?, ?, ?)",
        (name, req.type, username, datetime.now().isoformat())
    )
    room_id = cur.lastrowid
    cur.execute("INSERT INTO room_members (room_id, username) VALUES (?, ?)", (room_id, username))
    conn.commit()
    conn.close()
    return {"room_id": room_id}

@app.post("/api/rooms/{room_id}/join")
async def join_room(room_id: int, x_auth_token: str = Header(None)):
    username = get_user_by_token(x_auth_token)
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, type FROM rooms WHERE id = ?", (room_id,))
    room = cur.fetchone()
    if not room or room["type"] == "dm":
        conn.close()
        raise HTTPException(status_code=404, detail="Room nahi mila.")

    cur.execute("INSERT OR IGNORE INTO room_members (room_id, username) VALUES (?, ?)", (room_id, username))
    conn.commit()
    conn.close()
    return {"ok": True, "room_id": room_id}

@app.get("/api/rooms/{room_id}/messages")
async def get_room_messages(room_id: int, x_auth_token: str = Header(None)):
    username = get_user_by_token(x_auth_token)
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM room_members WHERE room_id = ? AND username = ?", (room_id, username))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Aap is chat ke member nahi hain.")

    cur.execute("SELECT id, sender, text, time FROM room_messages WHERE room_id = ? ORDER BY id ASC LIMIT 100", (room_id,))
    msgs = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"messages": msgs}

@app.get("/")
async def get():
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    username = get_user_by_token(token)
    if not username:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, username)
    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)
            if data.get("action") == "send_message":
                room_id = data.get("room_id")
                text = (data.get("text") or "").strip()
                if not room_id or not text:
                    continue

                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT type, owner_username FROM rooms WHERE id = ?", (room_id,))
                room = cur.fetchone()
                if not room:
                    conn.close()
                    continue

                if room["type"] == "channel" and room["owner_username"] != username:
                    conn.close()
                    continue

                cur.execute("SELECT username FROM room_members WHERE room_id = ?", (room_id,))
                members = [r["username"] for r in cur.fetchall()]
                if username not in members:
                    conn.close()
                    continue

                time_now = datetime.now().strftime("%I:%M %p")
                cur.execute(
                    "INSERT INTO room_messages (room_id, sender, text, time) VALUES (?, ?, ?, ?)",
                    (room_id, username, text, time_now)
                )
                msg_id = cur.lastrowid
                conn.commit()
                conn.close()

                await manager.send_to_users(members, {
                    "type": "new_message",
                    "room_id": room_id,
                    "id": msg_id,
                    "sender": username,
                    "text": text,
                    "time": time_now
                })
    except WebSocketDisconnect:
        manager.disconnect(websocket, username)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
