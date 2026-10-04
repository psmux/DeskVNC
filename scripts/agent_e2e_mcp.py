#!/usr/bin/env python3
"""Drive a machine through dvv exactly the way OpenCode would.

Reads OpenCode's own config, spawns the command DeskVNCViewer wrote into it,
and speaks MCP over stdio: initialize, list the saved machines, open one by
its saved name, wait for it, take a screenshot, close it. Exits non zero with
the reason on the first step that does not do what an agent needs.

Run with DeskVNCViewer closed, which is the case it exists for: dvv has to
start the app itself.

    python3 scripts/agent_e2e_mcp.py <machine name> <screenshot.png>
"""

import base64
import json
import os
import pathlib
import queue
import re
import subprocess
import sys
import threading

NAME = sys.argv[1]
OUT = pathlib.Path(sys.argv[2])


def fail(why):
    print(f"FAIL: {why}", flush=True)
    sys.exit(1)


def opencode_command():
    base = pathlib.Path(os.environ.get("XDG_CONFIG_HOME") or pathlib.Path.home() / ".config")
    for name in ("opencode.jsonc", "opencode.json"):
        path = base / "opencode" / name
        if path.exists():
            text = path.read_text()
            # JSONC: drop comments before parsing. Nothing in this config
            # puts // inside a string, so this is enough for the test.
            text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
            entry = json.loads(text)["mcp"]["deskvnc"]
            print(f"OpenCode config {path} runs: {entry['command']}", flush=True)
            return entry["command"]
    fail("OpenCode has no config with a deskvnc entry: the app did not wire it")


command = opencode_command()
if not pathlib.Path(command[0]).is_file():
    fail(f"the dvv OpenCode was pointed at does not exist: {command[0]}")

proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
lines = queue.Queue()
threading.Thread(target=lambda: [lines.put(l) for l in proc.stdout], daemon=True).start()
next_id = 0


def call(method, params, timeout=90):
    global next_id
    next_id += 1
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": next_id, "method": method, "params": params}) + "\n")
    proc.stdin.flush()
    while True:
        try:
            line = lines.get(timeout=timeout)
        except queue.Empty:
            fail(f"{method} got no answer in {timeout}s")
        message = json.loads(line)
        if message.get("id") == next_id:
            if "error" in message:
                fail(f"{method}: {message['error']}")
            return message["result"]


def tool(name, arguments, timeout=90):
    result = call("tools/call", {"name": name, "arguments": arguments}, timeout)
    text = " ".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
    print(f"{name}: {text[:300]}", flush=True)
    if result.get("isError"):
        fail(f"{name} refused: {text[:600]}")
    return result


call("initialize", {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "agent-e2e", "version": "1"},
})
proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
proc.stdin.flush()

tool("dvv_hosts", {})
opened = tool("dvv_open", {"hostId": NAME, "perceive": True})
blob = json.dumps(opened)
match = re.search(r"lmb_[a-z]+_[0-9a-f]+_\d+", blob)
if not match:
    fail("dvv_open answered without a limb id")
limb = match.group(0)
tool("dvv_wait", {"limbId": limb, "until": "connected", "timeoutMs": 30000})

image = None
for attempt in range(5):
    shot = tool("dvv_screen", {"limbId": limb, "scale": 0.5}, timeout=120)
    image = next((c for c in shot.get("content", []) if c.get("type") == "image"), None)
    if image:
        break
if not image:
    fail("dvv_screen never returned a picture")
OUT.write_bytes(base64.b64decode(image["data"]))
print(f"screenshot saved: {OUT} ({OUT.stat().st_size} bytes)", flush=True)

tool("dvv_close", {"limbId": limb})
proc.stdin.close()
proc.wait(timeout=30)
print("PASS: OpenCode's configured dvv started the app, opened the machine and read its screen", flush=True)
