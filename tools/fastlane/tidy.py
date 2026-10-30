"""Close what fast lane runs opened, and nothing else.

    python3 tidy.py --host-id <saved host>

A person leaves a computer the way they found it. This opens Task View
(Win+Tab), which lists every window with its own Close button, and closes the
windows the fast lane opens: Calculators, its Notepad logs, its Word reports.
A window that asks to save is answered "Don't save" only when the prompt
names a file of ours or an untitled one; any other name gets Cancel and the
window is left for its owner. In the browser it closes the tabs whose titles
match pages the fast lane loads and leaves every other tab.
"""

import argparse
import json
import re

import fastlane

WINDOWS = [r"^Calculator$", r"^Untitled - Notepad$", r"fast ?lane", r"^Document\d+ - Word$", r"^Fast Lane Report",
           r"^Book\d+ - Excel$", r"^Presentation\d+ - PowerPoint$", r"^Watchlist",
           r"^Trip ", r"^Market "]
TABS = ["google flights", "google news", "wikipedia", "new tab", "- search", "google search", "inr to", "weather",
        "fast lane", "trip budget", "market"]
MINE_IN_PROMPT = re.compile(r"untitled|fast ?lane|document\d|book\d|presentation\d|trip |market |watchlist", re.I)


def ours_window(title):
    return any(re.search(p, title, re.I) for p in WINDOWS)


def ours_tab(title):
    t = title.lower()
    return any(p in t for p in TABS)


def answer_save_prompt(runner, closed, kept, window):
    """A close that asks to save: Don't save for our files, Cancel otherwise.

    Notepad names the tab it asks about ("Do you want to save changes to
    notes.md?"); Word only asks "Save your changes to this file?", about the
    window that was just closed."""
    rows = runner.table["elements"]
    if not any(r["role"] == "button" and r["name"].lower() == "don't save" for r in rows):
        return False
    prompt = next((r["name"] for r in rows if "save" in r["name"].lower() and r["role"] == "text"), "")
    named = re.search(r"changes to (.+?)\?", prompt)
    subject = named.group(1) if named and named.group(1) != "this file" else window
    if MINE_IN_PROMPT.search(subject):
        runner.step({"click": "Don't save"})
        closed.append(f"discarded unsaved: {subject[:70]}")
        return True
    runner.step({"click": "Cancel"})
    kept.append(f"left open, not ours: {subject[:70]}")
    return False


def task_view(runner):
    runner.step({"key": "super+Tab", "expect": {"window": "Task View"}, "expect_ms": 3000})
    return [r for r in runner.table["elements"] if r["role"] == "listitem" and r["area"] == "window"]


def close_windows(runner, closed, kept, rounds=60, names=None):
    """Bring each window of ours to the front, alt+F4 it, answer its save
    prompt, and count again to be sure it is gone. With names, close just
    those windows (one each), whatever they are called."""
    skip = set()
    names = list(names) if names is not None else None
    for _ in range(rounds):
        items = task_view(runner)
        if names is not None:
            mine = [r for r in items if r["name"] in names and r["name"] not in skip]
        else:
            mine = [r for r in items if ours_window(r["name"]) and r["name"] not in skip]
        if not mine:
            runner.step({"key": "Escape"})
            return
        item = mine[0]
        count = sum(1 for r in items if r["name"] == item["name"])
        runner.dvv.click(item["x"] + item["w"] // 2, item["y"] + item["h"] // 2)
        runner.settle()
        # The window's own Close button, beside Minimize; alt+F4 if it has none.
        rows = runner.table["elements"]
        caption = {r["y"] for r in rows if r["area"] == "window" and r["name"].lower().startswith("minimize")}
        close = next((r for r in rows if r["area"] == "window" and r["role"] == "button" and r["name"] == "Close"
                      and any(abs(r["y"] - y) <= 6 for y in caption)), None)
        if close:
            runner.dvv.click(close["x"] + close["w"] // 2, close["y"] + close["h"] // 2)
            runner.settle()
        else:
            runner.step({"key": "alt+F4"})
        # A Notepad window with several tabs asks once per tab.
        for _ in range(10):
            if not answer_save_prompt(runner, closed, kept, item["name"]):
                break
        if kept and kept[-1].startswith("left open"):
            skip.add(item["name"])
        after = sum(1 for r in task_view(runner) if r["name"] == item["name"])
        runner.step({"key": "Escape"})
        if after < count:
            closed.append(item["name"])
            if names is not None:
                names.remove(item["name"])
        elif item["name"] not in skip:
            # It did not go and said nothing we could answer: leave it for a
            # person rather than try forever.
            skip.add(item["name"])
            kept.append(f"would not close: {item['name']}")


def close_tabs(runner, closed, rounds=80):
    # Bring the browser to the front through Task View.
    edge = next((r for r in task_view(runner) if "Edge" in r["name"]), None)
    if edge is None:
        runner.step({"key": "Escape"})
        return
    runner.step({"click": edge["name"], "expect": {"window": "Edge"}})
    for _ in range(rounds):
        title = runner.table["window"]["title"] or ""
        if "edge" not in title.lower():
            return
        if ours_tab(title.split(" and ")[0]):
            closed.append("tab: " + title.split(" and ")[0][:60])
            runner.step({"key": "ctrl+w"})
            continue
        tabs = [r for r in runner.table["elements"] if r["role"] == "tab" and r["area"] == "window" and ours_tab(r["name"])]
        if not tabs:
            return
        runner.dvv.click(tabs[0]["x"] + tabs[0]["w"] // 2, tabs[0]["y"] + tabs[0]["h"] // 2)
        runner.settle()


def tidy(runner):
    closed, kept = [], []
    close_windows(runner, closed, kept)
    close_tabs(runner, closed)
    return closed, kept


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host-id", required=True)
    args = ap.parse_args()
    runner = fastlane.Runner(args.host_id)
    try:
        closed, kept = tidy(runner)
    finally:
        runner.close()
    print(json.dumps({"seconds": round(fastlane.time.time() - runner.t0, 1), "closed": closed, "kept": kept,
                      "taskbar": [r["name"] for r in runner.table["elements"] if r["area"] == "taskbar" and "running" in r["name"]]}, indent=1))


if __name__ == "__main__":
    main()
