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
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            time TEXT NOT NULL,
            is_bot INTEGER DEFAULT 0
        )
    """)
    # Purane DB mein agar is_bot column na ho toh safe tarike se add karein
    try:
        cur.execute("ALTER TABLE messages ADD COLUMN is_bot INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    cur.execute("""
        CREATE TABLE IF NOT EXISTS bots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_username TEXT NOT NULL,
            bot_name TEXT UNIQUE NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def hash_password(password: str) -> str:
    salt = "helligram_secret_salt_v1"
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()

class AuthRequest(BaseModel):
    username: str
    password: str

class CreateBotRequest(BaseModel):
    bot_name: str

class BotMessageRequest(BaseModel):
    text: str

def get_user_by_token(token: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE token = ?", (token,))
    row = cur.fetchone()
    conn.close()
    return row["username"] if row else None

def get_bot_by_token(bot_token: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, bot_name, owner_username FROM bots WHERE token = ?", (bot_token,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def save_message(username: str, text: str, time_str: str, is_bot: int = 0):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO messages (username, text, time, is_bot) VALUES (?, ?, ?, ?)",
        (username, text, time_str, is_bot)
    )
    msg_id = cur.lastrowid
    conn.commit()
    conn.close()
    return msg_id

def get_recent_messages(limit: int = 50):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, text, time, is_bot FROM messages ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [
        {"type": "chat", "id": r["id"], "user": r["username"], "text": r["text"], "time": r["time"], "is_bot": bool(r["is_bot"])}
        for r in reversed(rows)
    ]

# --- AUTH API ---
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

# --- BOTFATHER API (User ke liye) ---
@app.post("/api/bots/create")
async def create_bot(req: CreateBotRequest, x_auth_token: str = Header(None)):
    username = get_user_by_token(x_auth_token or "")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    bot_name = req.bot_name.strip()
    if len(bot_name) < 3:
        raise HTTPException(status_code=400, detail="Bot ka naam kam az kam 3 characters ka ho.")
    if not bot_name.lower().endswith("bot"):
        bot_name += "_bot"

    bot_token = f"{secrets.randbelow(899999) + 100000}:{secrets.token_urlsafe(24)}"
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO bots (owner_username, bot_name, token, created_at) VALUES (?, ?, ?, ?)",
            (username, bot_name, bot_token, datetime.now().isoformat())
        )
        conn.commit()
        return {"bot_name": bot_name, "token": bot_token}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Is naam ka bot pehle se mojood hai.")
    finally:
        conn.close()

@app.get("/api/bots/list")
async def list_bots(x_auth_token: str = Header(None)):
    username = get_user_by_token(x_auth_token or "")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, bot_name, token FROM bots WHERE owner_username = ? ORDER BY id DESC", (username,))
    rows = cur.fetchall()
    conn.close()
    return {"bots": [dict(r) for r in rows]}

@app.delete("/api/bots/{bot_id}")
async def delete_bot(bot_id: int, x_auth_token: str = Header(None)):
    username = get_user_by_token(x_auth_token or "")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM bots WHERE id = ? AND owner_username = ?", (bot_id, username))
    conn.commit()
    conn.close()
    return {"ok": True}

# --- WEBSOCKET MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[websocket] = username
        history = get_recent_messages(50)
        await websocket.send_text(json.dumps({
            "type": "history",
            "messages": history,
            "online": len(self.active_connections)
        }))
        await self.broadcast({
            "type": "system",
            "text": f"{username} joined Helligram",
            "online": len(self.active_connections)
        })

    async def disconnect(self, websocket: WebSocket):
        username = self.active_connections.pop(websocket, "Someone")
        await self.broadcast({
            "type": "system",
            "text": f"{username} left",
            "online": len(self.active_connections)
        })

    async def broadcast(self, message: dict):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                dead_connections.append(connection)
        for conn in dead_connections:
            self.active_connections.pop(conn, None)

manager = ConnectionManager()

# --- CUSTOM HELLIGRAM BOT API (Python Scripts ke liye) ---
@app.get("/bot{bot_token}/getMe")
async def bot_get_me(bot_token: str):
    bot = get_bot_by_token(bot_token)
    if not bot:
        raise HTTPException(status_code=401, detail="Invalid Bot Token")
    return {"ok": True, "result": bot}

@app.post("/bot{bot_token}/sendMessage")
async def bot_send_message(bot_token: str, req: BotMessageRequest):
    bot = get_bot_by_token(bot_token)
    if not bot:
        raise HTTPException(status_code=401, detail="Invalid Bot Token")
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Message khali nahi ho sakta")

    time_now = datetime.now().strftime("%I:%M %p")
    msg_id = save_message(bot["bot_name"], text, time_now, is_bot=1)
    await manager.broadcast({
        "type": "chat",
        "id": msg_id,
        "user": bot["bot_name"],
        "text": text,
        "time": time_now,
        "is_bot": True,
        "online": len(manager.active_connections)
    })
    return {"ok": True, "message_id": msg_id, "bot": bot["bot_name"]}

@app.get("/bot{bot_token}/getUpdates")
async def bot_get_updates(bot_token: str, offset: int = 0):
    bot = get_bot_by_token(bot_token)
    if not bot:
        raise HTTPException(status_code=401, detail="Invalid Bot Token")
    conn = get_db()
    cur = conn.cursor()
    # Sirf humans ke naye messages return karega taake bot khud ko reply na kare
    cur.execute(
        "SELECT id, username, text, time FROM messages WHERE id > ? AND is_bot = 0 ORDER BY id ASC LIMIT 20",
        (offset,)
    )
    rows = cur.fetchall()
    conn.close()
    return {
        "ok": True,
        "result": [{"update_id": r["id"], "from": r["username"], "text": r["text"], "time": r["time"]} for r in rows]
    }

# --- FRONTEND & WEBSOCKET ---
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
            data = await websocket.receive_text()
            text = data.strip()
            if not text:
                continue
            time_now = datetime.now().strftime("%I:%M %p")
            msg_id = save_message(username, text, time_now, is_bot=0)
            await manager.broadcast({
                "type": "chat",
                "id": msg_id,
                "user": username,
                "text": text,
                "time": time_now,
                "is_bot": False,
                "online": len(manager.active_connections)
            })
    except WebSocketDisconnect:
        await manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
