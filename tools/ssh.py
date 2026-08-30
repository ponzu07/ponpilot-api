#!/usr/bin/env python3
import json
import os
import sys
import threading

from websocket import create_connection

host = os.environ.get("PONPILOT_API", "https://openpilot.copirobo.com")
token = os.environ.get("PONPILOT_TOKEN") or json.load(
    open(os.path.expanduser("~/.comma/auth.json"))
)["access_token"]

ws = create_connection(
    f"{host.replace('http', 'ws', 1)}/v1/devices/{sys.argv[1]}/ssh",
    header=[f"Authorization: JWT {token}"],
    enable_multithread=True,
)


def send():
    while data := sys.stdin.buffer.read1(4096):
        ws.send_binary(data)
    ws.close()


threading.Thread(target=send, daemon=True).start()

try:
    while data := ws.recv():
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
except Exception:
    pass

os._exit(0)
