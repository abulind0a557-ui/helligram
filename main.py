import os
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI()

# Railway Persistent Volume agar mount ho toh /data use karega, warna local folder
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
            time TEXT NOT NULL
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

def get_user_by_token(token: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE token = ?", (token,))
    row = cur.fetchone()
    conn.close()
    return row["username"] if row else None

def save_message(username: str, text: str, time_str: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO messages (username, text, time) VALUES (?, ?, ?)", (username, text, time_str))
    conn.commit()
    conn.close()

def get_recent_messages(limit: int = 50):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username, text, time FROM messages ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [{"type": "chat", "user": r["username"], "text": r["text"], "time": r["time"]} for r in reversed(rows)]

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[websocket] = username
        
        # Purane messages sirf naye connect hone wale user ko bhejein
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
            save_message(username, text, time_now)
            await manager.broadcast({
                "type": "chat",
                "user": username,
                "text": text,
                "time": time_now,
                "online": len(manager.active_connections)
            })
    except WebSocketDisconnect:
        await manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
