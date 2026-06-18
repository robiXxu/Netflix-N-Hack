import ssl
import os
import asyncio
import argparse
import urllib.request
import json
from collections import deque
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("--tg-token",  default="", help="Telegram bot token")
parser.add_argument("--tg-chat",   default="", help="Telegram chat ID")
parser.add_argument("--raw-port",  type=int, default=0,
                    help="Listen on a raw TCP socket on this port instead of WebSocket")
args = parser.parse_args()

TELEGRAM_BOT_TOKEN = args.tg_token
TELEGRAM_CHAT_ID   = args.tg_chat

log_filename = datetime.now().strftime("ws_%Y%m%d-%H%M%S.log")
log_file = open(log_filename, "a", buffering=1)

try:
    os.unlink("ws_latest.log")
except FileNotFoundError:
    pass
os.symlink(log_filename, "ws_latest.log")

def log(msg):
    now = datetime.now()
    ts = now.strftime("%Y%m%d_%H%M%S.") + f"{now.microsecond // 1000:03d}"
    for line in (msg.splitlines() or [msg]):
        print(f"{ts} {line}")
        log_file.write(f"{ts} {line}\n")

def telegram_send(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        log(f"Telegram send failed: {e}")

# --- raw TCP handler ---

async def handle_raw_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    client_ip = writer.get_extra_info("peername")[0]
    log(f"raw TCP Client connected from {client_ip}")
    recent = deque(maxlen=10)
    buf = b""

    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                msg = line.decode("utf-8", errors="replace").rstrip("\r")
                if msg:
                    log(msg)
                    recent.extend(msg.splitlines())
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

    log("raw TCP Client disconnected")
    summary = "\n".join(recent) if recent else "(no messages)"
    telegram_send(f"raw TCP Client {client_ip} disconnected\n\nLast messages:\n{summary}")

# --- WebSocket handler ---

async def handle_ws_client(websocket):
    import websockets
    client_ip = websocket.remote_address[0]
    log(f"Client connected from {client_ip}")
    recent = deque(maxlen=10)

    try:
        async for message in websocket:
            log(message)
            recent.extend(message.splitlines())
    except websockets.ConnectionClosed:
        pass

    log("Client disconnected")
    summary = "\n".join(recent) if recent else "(no messages)"
    telegram_send(f"Client {client_ip} disconnected\n\nLast messages:\n{summary}")

# --- main ---

async def main():
    log(f"Logging to {log_filename}")

    if args.raw_port:
        server = await asyncio.start_server(handle_raw_client, "0.0.0.0", args.raw_port)
        log(f"Listening on 0.0.0.0:{args.raw_port} (raw TCP)...")
        async with server:
            await server.serve_forever()
    else:
        import websockets
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        async with websockets.serve(handle_ws_client, "0.0.0.0", 1337, ssl=ssl_context):
            log("Listening on 0.0.0.0:1337 (WebSocket/TLS)...")
            await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
