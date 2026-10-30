"""The fast lane: drive a desktop through DeskVNC at the speed of the machine.

A large model is slow in the loop because every step is a turn of its own,
seconds each. Here it writes the plan once and leaves. Each step of the plan is
then carried out by a loop with no large model in it:

    deskvnc-sense table -> one jevos request -> one DeskVNC action -> settle

* The table is the desktop's controls as numbered rows, read by deskvnc-sense
  on the remote computer through UI Automation in tens of milliseconds.
* jevos (github.com/feder-cr/jev, MIT) is an open decision model in TypeSafe
  Jev's wire format. One request asks it for the operation and, speculatively,
  for the target of every operation, so a decision is one round trip.
* Text to type comes from a small open model behind llama.cpp, asked only when
  the operation is to type and the plan step does not already say the text.
* The wait is deskvnc-sense's settle: it reads the table until it has changed
  and then reads the same twice, so a step waits exactly as long as the screen
  keeps changing.

Run:  python3 fastlane.py --plan plan.json
plan.json: {"host_id": "<DeskVNC saved host>", "steps": ["Open the Run box", ...]}
Settings come from the environment: FASTLANE_KEY (the shared bearer token),
FASTLANE_JEV (http://host:8017), FASTLANE_LLM (http://host:8018),
FASTLANE_DVV (the dvv binary), FASTLANE_SENSE_PORT (5942).
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

KEY = os.environ.get("FASTLANE_KEY", "")
JEV = os.environ.get("FASTLANE_JEV", "http://127.0.0.1:8017")
LLM = os.environ.get("FASTLANE_LLM", "http://127.0.0.1:8018")
DVV = os.environ.get("FASTLANE_DVV", "dvv")
SENSE_PORT = int(os.environ.get("FASTLANE_SENSE_PORT", "5942"))

CLICKABLE = {"button", "checkbox", "radio", "combobox", "link", "listitem", "menuitem", "tab", "treeitem", "row", "header", "textbox", "document"}
EDITABLE = {"textbox", "combobox", "document"}
KEYS = {
    "Enter": "Enter, to confirm or run what was typed",
    "Escape": "Escape, to close a menu or dialog",
    "Tab": "Tab, to move to the next field",
    "super+r": "Windows+R, to open the Run box when a program must be started by name",
    "super": "the Windows key, to open the Start menu",
    "alt+F4": "Alt+F4, to close the window in front",
}


def post(url, body, timeout=10):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json", "Authorization": f"Bearer {KEY}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


class Sense:
    """The remote computer's deskvnc-sense, which dials in to us."""

    def __init__(self, port):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        print(f"waiting for deskvnc-sense on port {port}", file=sys.stderr)
        conn, addr = srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.io = conn.makefile("rw")
        hello = json.loads(self.io.readline())
        if hello.get("token") != KEY:
            raise SystemExit("deskvnc-sense sent the wrong token")
        print(f"deskvnc-sense connected from {addr[0]}", file=sys.stderr)

    def ask(self, **request):
        self.io.write(json.dumps(request) + "\n")
        self.io.flush()
        return json.loads(self.io.readline())

    def snapshot(self):
        return self.ask(op="snapshot")

    def settle(self, after, change_ms=1000, max_ms=5000):
        return self.ask(op="settle", after=after, change_ms=change_ms, max_ms=max_ms)


class Dvv:
    """DeskVNC's MCP server over stdio: the hands."""

    def __init__(self, binary, host_id):
        self.p = subprocess.Popen([binary, "mcp", "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "fastlane", "version": "1"}})
        card = self.call("dvv_open", hostId=host_id, perceive=True)
        self.limb = card["structuredContent"]["limb"]["limb_id"]
        self.call("dvv_screen", scale=0.1)

    def rpc(self, method, params):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n")
        self.p.stdin.flush()
        while True:
            m = json.loads(self.p.stdout.readline())
            if m.get("id") == self.n:
                return m.get("result", {})

    def call(self, name, **args):
        if name != "dvv_open":
            args.setdefault("limbId", getattr(self, "limb", None))
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        if r.get("isError"):
            raise RuntimeError(r["content"][0]["text"][:300])
        return r

    def click(self, x, y):
        self.call("dvv_click", action="click", x=x, y=y)

    def fence(self, row=None):
        # Typing is refused until the screen has been read since its last big
        # repaint. A tiny crop of the field is the cheapest read that counts.
        region = {"x": row["x"], "y": row["y"], "w": max(8, row["w"]), "h": max(8, row["h"])} if row else None
        if region:
            self.call("dvv_screen", form="region", region=region)
        else:
            self.call("dvv_screen", scale=0.1)

    def type(self, text):
        self.call("dvv_type", text=text, wpm=1200)

    def key(self, keys):
        self.call("dvv_key", keys=keys)

    def close(self):
        try:
            self.call("dvv_control", action="release")
            self.call("dvv_close")
        finally:
            self.p.stdin.close()


def rows_text(rows):
    lines = []
    for r in rows:
        extra = f" · {r['value']}" if r.get("value") else ""
        flags = "".join([" (focused)" if r.get("focus") else "", " (disabled)" if r.get("disabled") else "", " (checked)" if r.get("checked") else ""])
        lines.append(f"[{r['i']}] {r['area']} {r['role']} {r['name']}{extra}{flags}")
    return "\n".join(lines)


# jevos asks one yes/no pass per option and takes at most 26, so the controls
# are ranked against the step in code and the best few are offered.
OFFER = 12


def words(text):
    return {w for w in "".join(c.lower() if c.isalnum() else " " for c in text).split() if len(w) > 1}


def shortlist(rows, step, roles):
    want = words(step)
    def score(r):
        name = words(f"{r['name']} {r.get('value', '')}")
        overlap = len(want & name)
        return (overlap, r.get("focus", False), r["area"] == "window")
    picked = [r for r in rows if r["role"] in roles and not r.get("disabled") and (r["name"] or r["role"] in EDITABLE)]
    picked.sort(key=score, reverse=True)
    return {str(r["i"]): f"{r['role']} {r['name']}".strip() for r in picked[:OFFER]}


def decide(step, goal, table, history):
    rows = table["elements"]
    clickable = shortlist(rows, step, CLICKABLE)
    editable = shortlist(rows, step, EDITABLE)
    state = {
        "overall_goal": goal,
        "current_step": step,
        "window_in_front": table["window"]["title"] or table["window"]["class"],
        "done_so_far": history[-6:] or ["nothing yet"],
        "controls_on_screen": rows_text(rows),
    }
    ops = {
        "click": "click one of the controls on screen",
        "type": "type text into a text box",
        "key": "press a key or shortcut",
        "done": "the current step is already complete, as the screen shows",
    }
    questions = {"op": {"type": "choice", "instructions": "What should be done next to complete the current step? Choose done only if the screen already shows the step is complete.", "criteria": ops}}
    if len(clickable) >= 2:
        questions["click"] = {"type": "choice", "instructions": "If clicking, which control should be clicked to complete the current step?", "criteria": clickable}
    if len(editable) >= 2:
        questions["field"] = {"type": "choice", "instructions": "If typing, which text box should receive the text?", "criteria": editable}
    questions["key"] = {"type": "choice", "instructions": "If pressing a key, which one completes the current step?", "criteria": KEYS}
    started = time.time()
    answer = post(f"{JEV}/v1/systemone", {"model": "jev-latest", "state": state, "questions": questions})
    return answer["answers"], (time.time() - started) * 1000, {"click": clickable, "field": editable}


def chosen(answer):
    return answer.get("choice") or answer.get("answer") or max(answer.get("probs", {"": 0}), key=answer["probs"].get)


def text_for(step, goal, field):
    started = time.time()
    r = post(f"{LLM}/v1/chat/completions", {
        "messages": [
            {"role": "system", "content": "You fill in one field on a computer screen. Reply with only a JSON object {\"text\": \"...\"} holding the exact text to type."},
            {"role": "user", "content": f"Overall goal: {goal}\nCurrent step: {step}\nField: {field}"},
        ],
        "temperature": 0, "max_tokens": 64,
    })
    content = r["choices"][0]["message"]["content"]
    text = json.loads(content[content.index("{"): content.rindex("}") + 1])["text"]
    return text, (time.time() - started) * 1000


def run(plan, max_actions=40):
    sense = Sense(SENSE_PORT)
    dvv = Dvv(DVV, plan["host_id"])
    goal = plan.get("goal", " then ".join(plan["steps"]))
    history, log = [], []
    t0 = time.time()
    table = sense.snapshot()
    try:
        for step in plan["steps"]:
            say_text = None
            if isinstance(step, dict):
                say_text, step = step.get("text"), step["step"]
            for _ in range(max_actions):
                answers, jev_ms, offered = decide(step, goal, table, history)
                op = chosen(answers["op"])
                entry = {"t": round((time.time() - t0) * 1000), "step": step, "op": op, "jev_ms": round(jev_ms), "rows": len(table["elements"])}
                rows = {str(r["i"]): r for r in table["elements"]}
                if op == "done":
                    log.append(entry)
                    history.append(f"finished: {step}")
                    break
                only = lambda kind: next(iter(offered[kind]), None)
                if op == "click" and ("click" in answers or only("click")):
                    row = rows[chosen(answers["click"]) if "click" in answers else only("click")]
                    dvv.click(row["x"] + row["w"] // 2, row["y"] + row["h"] // 2)
                    did = f"clicked {row['role']} {row['name']}"
                elif op == "type" and ("field" in answers or only("field")):
                    row = rows[chosen(answers["field"]) if "field" in answers else only("field")]
                    if say_text is None:
                        text, entry["llm_ms"] = text_for(step, goal, f"{row['role']} {row['name']}")
                    else:
                        text = say_text
                    if not row.get("focus"):
                        dvv.click(row["x"] + row["w"] // 2, row["y"] + row["h"] // 2)
                    dvv.fence(row)
                    dvv.type(text)
                    did = f"typed {text!r} into {row['name']}"
                else:
                    keys = chosen(answers["key"])
                    dvv.fence()
                    dvv.key(keys)
                    did = f"pressed {keys}"
                entry["did"] = did
                history.append(did)
                settle_started = time.time()
                table = sense.settle(table["hash"])
                entry["settle_ms"] = round((time.time() - settle_started) * 1000)
                entry["settle"] = table.get("outcome")
                log.append(entry)
                print(json.dumps(entry), file=sys.stderr, flush=True)
            else:
                log.append({"step": step, "gave_up": True})
                break
    finally:
        dvv.close()
    total = time.time() - t0
    return {"seconds": round(total, 2), "actions": sum(1 for e in log if "did" in e), "log": log}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    plan = json.load(open(ap.parse_args().plan))
    print(json.dumps(run(plan), indent=1))
