import os
import json
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

app = FastAPI()

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[websocket] = username
        await self.broadcast({
            "type": "system",
            "text": f"{username} joined the chat",
            "online": len(self.active_connections)
        })

    async def disconnect(self, websocket: WebSocket):
        username = self.active_connections.pop(websocket, "Someone")
        await self.broadcast({
            "type": "system",
            "text": f"{username} left the chat",
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

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    await manager.connect(websocket, username)
    try:
        while True:
            data = await websocket.receive_text()
            time_now = datetime.now().strftime("%I:%M %p")
            await manager.broadcast({
                "type": "chat",
                "user": username,
                "text": data,
                "time": time_now,
                "online": len(manager.active_connections)
            })
    except WebSocketDisconnect:
        await manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
