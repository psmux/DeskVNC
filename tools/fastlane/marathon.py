"""Ten minutes of nonstop desktop work through the fast lane, checked.

Cycles through varied tasks on one Windows computer, each written as a plan
here and carried out by fastlane.Runner with no large model in the loop:
flights on Google Flights, a Google News section, a Wikipedia lookup, sums
in Calculator, a formatted Word report built from what the earlier tasks
read, a Notepad log saved to disk, and a File Explorer check that the files
really are there. Every task is verified, not just run: a calculator answer
against the same sum done exactly here, a saved file by its name in Explorer.

    python3 marathon.py --host-id <saved host> --minutes 10 > result.json
"""

import argparse
import json
import random
import sys
import time

import fastlane

ROUTES = [("Chennai", "London", "2026-12-15"), ("Bengaluru", "Singapore", "2026-12-20"), ("Mumbai", "Dubai", "2027-01-05"),
          ("Delhi", "New York", "2027-01-12"), ("Chennai", "Tokyo", "2026-12-28"), ("Hyderabad", "Frankfurt", "2027-02-02")]
SECTIONS = ["Technology", "Business", "World", "India", "Entertainment"]
TOPICS = ["Raspberry Pi", "Alan Turing", "Ada Lovelace", "James Webb Space Telescope", "Chennai", "Linus Torvalds"]


def run_box(command, expect, ms=10000):
    return [{"key": "super+r", "expect": {"window": "Run"}},
            {"type": command, "into": "Open"},
            {"key": "Enter", "expect": expect, "expect_ms": ms}]


def open_url(url, expect, ms=15000):
    return run_box(f"msedge {url}", expect, ms)


def task_flights(n, memory):
    a, b, date = ROUTES[n % len(ROUTES)]
    q = f"one+way+flights+from+{a.replace(' ', '+')}+to+{b.replace(' ', '+')}+on+{date}"
    steps = open_url(f"https://www.google.com/travel/flights?q={q}&curr=INR", {"shows": "₹"}, 20000) + [
        {"read": "₹", "limit": 12},
        {"click": "Cheapest", "expect": {"shows": "Cheapest"}},
        {"read": "₹", "limit": 12},
    ]
    def check(reads):
        fares = [r for r in sum(reads, []) if "₹" in r and len(r) > 12]
        if fares:
            memory["flights"] = (a, b, date, fares[:3])
        return bool(fares), f"{len(fares)} fares for {a} to {b}"
    return f"flights {a} to {b}", steps, check


def task_news(n, memory):
    section = SECTIONS[n % len(SECTIONS)]
    steps = open_url("https://news.google.com/?hl=en-IN&gl=IN&ceid=IN:en", {"shows": "Top stories"}) + [
        {"click": section, "expect": {"window": section}, "expect_ms": 10000},
        {"read": "", "limit": 40},
    ]
    def check(reads):
        heads = [r for r in sum(reads, []) if len(r) > 45 and not r.startswith("More - ") and " - " not in r]
        if heads:
            memory["news"] = (section, heads[:3])
        return len(heads) >= 3, f"{len(heads)} {section} headlines"
    return f"news {section}", steps, check


def task_wiki(n, memory):
    topic = TOPICS[n % len(TOPICS)]
    steps = open_url("https://en.wikipedia.org/wiki/Main_Page", {"window": "Wikipedia"}) + [
        {"type": topic + "\n", "into": "Search Wikipedia", "expect": {"window": topic}, "expect_ms": 10000},
        {"read": topic.split()[0], "limit": 6},
    ]
    def check(reads):
        lines = [r for r in sum(reads, []) if len(r) > 60]
        if lines:
            memory["wiki"] = (topic, lines[0][:200])
        return bool(lines), f"{topic}: {len(lines)} sentences"
    return f"wikipedia {topic}", steps, check


def task_calc(n, memory):
    rng = random.Random(n)
    sums = []
    for _ in range(4):
        a, b, c = rng.randint(100, 99999), rng.randint(2, 999), rng.randint(10, 9999)
        sums.append(rng.choice([f"{a}*{b}", f"{a}/{b}", f"{a}+{b}*{c}", f"{a}-{c}"]))
    steps = run_box("calc", {"window": "Calculator"})
    for expr in sums:
        steps += [{"key": "Escape"}, {"type": expr + "=", "expect": {"shows": "Display is"}}, {"read": "Display is"}]
    def check(reads):
        got = [r for r in sum(reads, []) if r.startswith("Display is")]
        good = 0
        results = []
        for expr, line in zip(sums, got):
            shown = float(line.replace("Display is", "").replace(",", "").strip())
            # Calculator in Standard mode works left to right, the way a
            # pocket calculator does, not by operator precedence.
            want = left_to_right(expr)
            ok = abs(shown - want) <= 1e-9 * max(1, abs(want))
            good += ok
            results.append(f"{expr} = {line.replace('Display is ', '')}")
        memory["calc"] = results
        return good == len(sums), f"{good}/{len(sums)} right"
    return "calculator", steps, check


def left_to_right(expr):
    import re
    tokens = re.findall(r"\d+|[-+*/]", expr)
    total = float(tokens[0])
    for op, num in zip(tokens[1::2], tokens[2::2]):
        x = float(num)
        total = {"+": total + x, "-": total - x, "*": total * x, "/": total / x}[op]
    return total


def task_word(n, memory):
    name = f"Fast Lane Report {n}"
    a, b, date, fares = memory.get("flights", ("?", "?", "?", []))
    section, heads = memory.get("news", ("news", []))
    topic, line = memory.get("wiki", ("", ""))
    calcs = memory.get("calc", [])
    def bullets(items):
        items = [i.replace("₹", "INR ").replace("−", "-") for i in items if i]
        return "* " + "\n".join(items) + "\n\n" if items else "Nothing read this time.\n"
    steps = run_box("winword", {"shows": "Blank document"}, 20000) + [
        {"click": "Blank document", "expect": {"window": "Document"}, "expect_ms": 10000},
        {"key": "ctrl+e"}, {"key": "ctrl+alt+1"}, {"type": f"Fast Lane Report {n}\n"}, {"key": "ctrl+l"},
        {"key": "ctrl+i"}, {"type": "Written on the MSI by the DeskVNC fast lane from what it read a minute ago."}, {"key": "ctrl+i"}, {"type": "\n"},
        {"key": "ctrl+alt+2"}, {"type": f"Flights, {a} to {b}, {date}\n"}, {"type": bullets(fares)},
        {"key": "ctrl+alt+2"}, {"type": f"{section} headlines\n"}, {"type": bullets(heads)},
        {"key": "ctrl+alt+2"}, {"type": f"From Wikipedia: {topic}\n"}, {"type": (line.replace("₹", "INR ") or "Nothing read.") + "\n"},
        {"key": "ctrl+alt+2"}, {"type": "Calculations\n"}, {"type": bullets(calcs)},
        {"type": "Checked by "}, {"key": "ctrl+b"}, {"type": "marathon.py"}, {"key": "ctrl+b"}, {"type": ".\n"},
        {"key": "F12", "expect": {"window": "Save As"}, "expect_ms": 8000},
        {"type": name, "into": "File name"},
        {"key": "Enter", "expect": {"window": name}, "expect_ms": 10000},
        {"key": "alt+F4", "when": {"window": name}},
    ]
    def check(reads):
        memory.setdefault("files", []).append(name + ".docx")
        return True, name
    return "word report", steps, check


def task_notepad(n, memory):
    name = f"fastlane-log-{n}.txt"
    text = f"fast lane log {n}\n" + "\n".join(memory.get("calc", [])) + "\n"
    steps = run_box("notepad", {"window": "Notepad"}) + [
        {"key": "ctrl+n"},
        {"type": text},
        {"key": "ctrl+s", "expect": {"window": "Save as"}, "expect_ms": 8000},
        {"type": name, "into": "File name"},
        {"key": "Enter", "expect": {"window": name}, "expect_ms": 8000},
        {"key": "ctrl+w", "when": {"window": name}},
    ]
    def check(reads):
        memory.setdefault("files", []).append(name)
        return True, name
    return "notepad log", steps, check


def task_explorer(n, memory):
    files = memory.get("files", [])[-4:]
    steps = [{"key": "super+e", "expect": {"window": "File Explorer"}, "expect_ms": 8000},
             {"key": "ctrl+l"},
             {"type": "%USERPROFILE%\\Documents\n", "expect": {"window": "Documents"}, "expect_ms": 8000},
             {"read": "|".join(f.rsplit(".", 1)[0] for f in files) or "Fast Lane", "limit": 30},
             {"key": "alt+F4", "when": {"window": "Documents"}}]
    def check(reads):
        seen = " ".join(sum(reads, []))
        found = [f for f in files if f.rsplit(".", 1)[0] in seen]
        return len(found) == len(files), f"{len(found)}/{len(files)} saved files found in Documents"
    return "explorer check", steps, check


CYCLE = [task_flights, task_news, task_wiki, task_calc, task_word, task_notepad, task_explorer]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host-id", required=True)
    ap.add_argument("--minutes", type=float, default=10)
    args = ap.parse_args()
    runner = fastlane.Runner(args.host_id)
    memory, tasks = {}, []
    deadline = time.time() + args.minutes * 60
    n = 0
    try:
        while time.time() < deadline:
            make = CYCLE[n % len(CYCLE)]
            title, steps, check = make(n // len(CYCLE), memory)
            started, first = time.time(), len(runner.log)
            ok_steps = True
            try:
                for step in steps:
                    if not runner.step(step):
                        ok_steps = False
                        break
            except RuntimeError as e:
                runner.note({"t": runner.now(), "error": str(e)[:200]})
                ok_steps = False
            entries = runner.log[first:]
            reads = [e["read"] for e in entries if "read" in e]
            passed, detail = check(reads) if ok_steps else (False, f"stopped at {json.dumps(entries[-1].get('step') or entries[-1].get('recover') or entries[-1].get('error'))[:160]}" if entries else "stopped")
            record = {"task": title, "passed": passed, "detail": detail, "seconds": round(time.time() - started, 2),
                      "actions": sum(1 for e in entries if "did" in e), "recoveries": sum(1 for e in entries if "recover" in e)}
            tasks.append(record)
            print("TASK " + json.dumps(record), file=sys.stderr, flush=True)
            if not ok_steps:
                # Leave the screen as clean as a person would before the next
                # task: Escape out of whatever is open.
                runner.dvv.fence()
                runner.dvv.key("Escape")
                runner.settle()
            n += 1
    finally:
        runner.close()
    total = time.time() - runner.t0
    actions = sum(1 for e in runner.log if "did" in e)
    print(json.dumps({
        "minutes": round(total / 60, 2), "tasks": len(tasks), "passed": sum(t["passed"] for t in tasks),
        "actions": actions, "actions_per_minute": round(actions / (total / 60), 1),
        "recoveries": sum(t["recoveries"] for t in tasks), "task_log": tasks, "memory": memory,
    }, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
