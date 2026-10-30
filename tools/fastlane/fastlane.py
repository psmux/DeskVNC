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
plan.json: {"host_id": "<DeskVNC saved host>", "steps": [...]}, steps as run() describes.
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
        # DeskVNC stops typing when the screen repaints a lot, so an agent that
        # types blind cannot type into a dialog that just opened. Here the
        # table is the check, and a repaint while typing is usually the field's
        # own suggestion list, so read the screen and go on from the exact
        # character DeskVNC stopped at.
        for _ in range(20):
            r = self.rpc("tools/call", {"name": "dvv_type", "arguments": {"limbId": self.limb, "text": text, "wpm": 1200}})
            if not r.get("isError"):
                return
            message = r["content"][0]["text"]
            if not message.startswith("SCREEN_CHANGED"):
                raise RuntimeError(message[:300])
            sent = 0
            if message.startswith("SCREEN_CHANGED: typed "):
                sent = int(message.split("typed ", 1)[1].split(" ", 1)[0])
            text = text[sent:]
            self.fence()
        raise RuntimeError("the screen kept changing while typing")

    def key(self, keys):
        try:
            self.call("dvv_key", keys=keys)
        except RuntimeError as e:
            if not str(e).startswith("SCREEN_CHANGED"):
                raise
            for _ in range(5):
                self.fence()
                r = self.rpc("tools/call", {"name": "dvv_key", "arguments": {"limbId": self.limb, "keys": keys}})
                if not r.get("isError"):
                    return
                if not r["content"][0]["text"].startswith("SCREEN_CHANGED"):
                    break
            raise RuntimeError(r["content"][0]["text"][:300])

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


def find(rows, name, roles, step):
    """The row a plan step names, by its name in code when that is clear and
    by one jevos choice when it is not."""
    candidates = [r for r in rows if r["role"] in roles and not r.get("disabled")]
    want = name.lower()
    for test in (lambda n: n == want, lambda n: n.startswith(want), lambda n: want in n):
        hits = [r for r in candidates if test(r["name"].lower().rstrip(":"))]
        # A combo box and the edit inside it share a name; the one with the
        # keyboard focus is the one that takes text.
        focused = [r for r in hits if r.get("focus")]
        if len(hits) == 1 or len(focused) == 1:
            return (focused or hits)[0], 0.0
        if hits:
            candidates = hits
            break
    offered = shortlist(candidates, name, roles)
    if not offered:
        return None, 0.0
    if len(offered) == 1:
        return next(r for r in rows if str(r["i"]) in offered), 0.0
    started = time.time()
    answer = post(f"{JEV}/v1/systemone", {
        "model": "jev-latest",
        "state": {"step": step, "controls_on_screen": rows_text(rows)},
        "questions": {"target": {"type": "choice", "instructions": f"Which control is the one called {name!r} in the step?", "criteria": offered}},
    })["answers"]["target"]
    return next(r for r in rows if str(r["i"]) == chosen(answer)), (time.time() - started) * 1000


def met(expect, table):
    if not expect:
        return True
    title = (table["window"]["title"] or "").lower()
    if "window" in expect and expect["window"].lower() not in title:
        return False
    if "shows" in expect and not any(expect["shows"].lower() in r["name"].lower() for r in table["elements"]):
        return False
    return True


# Words on the buttons that make an unexpected screen go away without
# agreeing to anything: an extension that wants installing, a sign in offer, a
# "restore pages" bar, a survey.
DISMISS = ["not now", "no thanks", "no, thanks", "maybe later", "remind me later", "later", "skip", "dismiss",
           "got it", "close", "cancel", "don't allow", "block", "decline", "reject", "no"]


class Runner:
    """One connection to the remote computer, many steps.

    Each step says what to do, so most need no model:

        {"key": "super+r", "expect": {"window": "Run"}}
        {"type": "notepad", "into": "Open"}       into omitted: the focused field
        {"click": "Save", "expect": {"shows": "Saved"}}
        {"read": "price|$"}                       copy matching rows into the log
        {"goal": "free text", "text": "..."}      jevos picks the operation too

    when, with the same form as expect, skips the step unless the screen
    matches it first. expect is checked after the screen settles: window is a
    piece of the front window's title, shows a piece of any control's name.

    A step that cannot find its control or whose expectation is not met is
    not given up at once: something the plan did not cause may be in front,
    so the runner looks for a way to dismiss it, and tries the step again."""

    def __init__(self, host_id):
        self.sense = Sense(SENSE_PORT)
        self.dvv = Dvv(DVV, host_id)
        self.t0 = time.time()
        self.table = self.sense.snapshot()
        self.log, self.history = [], []

    def now(self):
        return round((time.time() - self.t0) * 1000)

    def note(self, entry):
        self.log.append(entry)
        print(json.dumps(entry), file=sys.stderr, flush=True)

    def settle(self, expect=None, limit=4000):
        started = time.time()
        self.table = self.sense.settle(self.table["hash"], change_ms=1000 if expect else 300)
        while not met(expect, self.table) and (time.time() - started) * 1000 < limit:
            self.table = self.sense.settle(self.table["hash"], change_ms=limit, max_ms=limit)
        return round((time.time() - started) * 1000)

    def step(self, step, retries=2):
        """Do one step; True when it did what it said."""
        for attempt in range(retries + 1):
            ok, entry = self.attempt(step)
            if ok:
                return True
            if attempt < retries and self.recover(step):
                continue
            entry["failed"] = True
            self.note(entry)
            return False
        return False

    def attempt(self, step):
        entry = {"t": self.now(), "step": step}
        if not met(step.get("when"), self.table):
            entry["skipped"] = True
            self.note(entry)
            return True, entry
        rows = self.table["elements"]
        if "read" in step:
            entry["read"] = read_rows(rows, step["read"])[: step.get("limit", 15)]
            self.note(entry)
            return True, entry
        dvv = self.dvv
        if "key" in step:
            dvv.fence()
            dvv.key(step["key"])
            entry["did"] = f"pressed {step['key']}"
        elif "type" in step:
            row = None
            if step.get("into"):
                row, entry["jev_ms"] = find(rows, step["into"], EDITABLE, f"type into {step['into']}")
                if row is None:
                    entry["missing"] = step["into"]
                    return False, entry
                if not row.get("focus"):
                    dvv.click(row["x"] + row["w"] // 2, row["y"] + row["h"] // 2)
            dvv.fence(row)
            # A named field is set, not added to: a field keeps what it had
            # (the Run box remembers the last command). Text typed where the
            # caret is, in a document, must never select all of it first.
            if step.get("replace", bool(step.get("into"))):
                dvv.key("ctrl+a")
            dvv.type(step["type"])
            entry["did"] = f"typed {step['type'][:40]!r}" + (f" into {row['name']}" if row else "")
        elif "click" in step:
            row, entry["jev_ms"] = find(rows, step["click"], CLICKABLE, f"click {step['click']}")
            if row is None:
                entry["missing"] = step["click"]
                return False, entry
            dvv.click(row["x"] + row["w"] // 2, row["y"] + row["h"] // 2)
            entry["did"] = f"clicked {row['role']} {row['name'][:40]}"
        self.history.append(entry["did"])
        entry["settle_ms"] = self.settle(step.get("expect"), step.get("expect_ms", 4000))
        ok = met(step.get("expect"), self.table)
        if ok:
            self.note(entry)
        return ok, entry

    def recover(self, step):
        """Something the plan did not expect may be in front. Find the button
        that sends it away and press it; True if anything was done."""
        rows = [r for r in self.table["elements"] if r["area"] == "window" and r["role"] in ("button", "link") and not r.get("disabled")]
        candidates = [r for r in rows if r["name"].lower().strip() in DISMISS]
        if not candidates:
            candidates = [r for r in rows if any(r["name"].lower().startswith(w) for w in DISMISS if len(w) > 3)]
        entry = {"t": self.now(), "recover": step, "window": self.table["window"]["title"]}
        if not candidates:
            # Nothing to dismiss by name: Escape closes most menus, flyouts
            # and dialogs, and does nothing harmful on a page.
            self.dvv.fence()
            self.dvv.key("Escape")
            entry["did"] = "pressed Escape"
        else:
            pick = candidates[0]
            if len(candidates) > 1:
                started = time.time()
                answer = post(f"{JEV}/v1/systemone", {
                    "model": "jev-latest",
                    "state": {"what_we_were_doing": json.dumps(step), "window_in_front": self.table["window"]["title"], "controls_on_screen": rows_text(self.table["elements"][:120])},
                    "questions": {"dismiss": {"type": "choice", "instructions": "Something unexpected is in the way of the step. Which button closes or declines it without agreeing to anything or losing work?",
                                              "criteria": {str(r["i"]): r["name"] for r in candidates[:12]}}},
                })["answers"]["dismiss"]
                entry["jev_ms"] = round((time.time() - started) * 1000)
                pick = next(r for r in candidates if str(r["i"]) == chosen(answer))
            self.dvv.click(pick["x"] + pick["w"] // 2, pick["y"] + pick["h"] // 2)
            entry["did"] = f"dismissed with {pick['name']}"
        entry["settle_ms"] = self.settle()
        self.note(entry)
        return True

    def close(self):
        self.dvv.close()


def read_rows(rows, filter_text):
    """Rows whose text holds any of the |-separated words, or all text when
    the filter is empty. In a browser only the page, not its toolbar."""
    want = [w.lower() for w in filter_text.split("|") if w]
    docs = [r for r in rows if r["role"] == "document" and r["area"] == "window"]
    page = max(docs, key=lambda r: r["w"] * r["h"]) if docs else None
    def inside(r):
        return page is None or (r is not page and page["x"] <= r["x"] < page["x"] + page["w"] and page["y"] <= r["y"] < page["y"] + page["h"])
    found, seen = [], set()
    for r in rows:
        text = r["name"] + (f" · {r['value']}" if r.get("value") and r["role"] != "link" else "")
        if r["area"] != "window" or not inside(r) or text in seen or not text:
            continue
        if not want or any(w in text.lower() for w in want):
            seen.add(text)
            found.append(text)
    return found


def run(plan, max_actions=40):
    """Carry out one plan and return its log and the screen it ended on."""
    runner = Runner(plan["host_id"])
    failed = None
    try:
        for step in plan["steps"]:
            if "goal" in step:
                runner.table, ok = goal_loop(step, plan.get("goal", ""), runner.sense, runner.dvv, runner.table, runner.history, runner.log, runner.t0, max_actions)
            else:
                ok = runner.step(step)
            if not ok:
                failed = step
                break
    except RuntimeError as e:
        failed = {"error": str(e)}
    finally:
        runner.close()
    log, table = runner.log, runner.table
    result = {"seconds": round(time.time() - runner.t0, 2), "actions": sum(1 for e in log if "did" in e), "log": log}
    # The screen as it ended, so the planner can check the outcome or plan
    # from there without looking at a picture.
    result["window"] = table["window"]
    result["controls"] = rows_text(table["elements"])
    if failed is not None:
        result["failed"] = failed
    return result


def goal_loop(step, goal, sense, dvv, table, history, log, t0, max_actions):
    """A step the planner could not spell out: jevos picks the operation too."""
    say_text, text = step.get("text"), step["goal"]
    for _ in range(max_actions):
        answers, jev_ms, offered = decide(text, goal, table, history)
        op = chosen(answers["op"])
        entry = {"t": round((time.time() - t0) * 1000), "step": text, "op": op, "jev_ms": round(jev_ms), "rows": len(table["elements"])}
        rows = {str(r["i"]): r for r in table["elements"]}
        if op == "done":
            log.append(entry)
            history.append(f"finished: {text}")
            return table, True
        only = lambda kind: next(iter(offered[kind]), None)
        if op == "click" and ("click" in answers or only("click")):
            row = rows[chosen(answers["click"]) if "click" in answers else only("click")]
            dvv.click(row["x"] + row["w"] // 2, row["y"] + row["h"] // 2)
            did = f"clicked {row['role']} {row['name']}"
        elif op == "type" and ("field" in answers or only("field")):
            row = rows[chosen(answers["field"]) if "field" in answers else only("field")]
            if say_text is None:
                typed, entry["llm_ms"] = text_for(text, goal, f"{row['role']} {row['name']}")
            else:
                typed = say_text
            if not row.get("focus"):
                dvv.click(row["x"] + row["w"] // 2, row["y"] + row["h"] // 2)
            dvv.fence(row)
            dvv.type(typed)
            did = f"typed {typed!r} into {row['name']}"
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
        log.append(entry)
        print(json.dumps(entry), file=sys.stderr, flush=True)
    return table, False


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    plan = json.load(open(ap.parse_args().plan))
    print(json.dumps(run(plan), indent=1))
