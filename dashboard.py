import asyncio

from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/")
async def get():
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


clients = []


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.append(ws)

    try:
        while True:
            await ws.receive_text()
    except:
        clients.remove(ws)


async def broadcast(data):
    for ws in clients:
        try:
            await ws.send_json(data)
        except:
            continue
