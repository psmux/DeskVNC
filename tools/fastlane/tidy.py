"""Close what fast lane runs opened, and nothing else.

    python3 tidy.py --host-id <saved host>

A person leaves a computer the way they found it. This lists the open
windows through deskvnc-sense, so nothing flashes on screen, brings each one
the fast lane opens forward and closes it: Calculators, its Notepad logs, its
Office files. A window that asks to save is answered "Don't save" only when
the prompt names a file of ours or an untitled one; any other name gets
Cancel and the window is left for its owner. With --tabs it also closes
browser tabs whose titles match pages the fast lane loads.
"""

import argparse
import json
import re

import fastlane

WINDOWS = [r"^Calculator$", r"^Untitled - Notepad$", r"fast ?lane", r"^Document\d+ - Word$", r"^Fast Lane Report",
           r"^Book\d+ - Excel$", r"^Presentation\d+ - PowerPoint$", r"^Watchlist",
           r"^Trip ", r"^Market "]
# Only with --tabs: pages the fast lane loads. A person may have the same
# pages open, so this is for clearing up after a run that crashed before it
# could close its own windows, on a computer nobody else is using.
TABS = ["google flights", "google news", "wikipedia, the free", "inr to", "weather "]
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
    if fastlane.office_prompt(runner.table):
        # Office's prompt in front of an app that is not answering UI
        # Automation: the window just closed is the subject, alt+N is Don't Save.
        if MINE_IN_PROMPT.search(window):
            runner.step({"key": "alt+n"})
            closed.append(f"discarded unsaved: {window[:70]}")
            return True
        runner.step({"key": "Escape"})
        kept.append(f"left open, not ours: {window[:70]}")
        return False
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


def open_windows(runner):
    """Every window a person could Alt+Tab to, from the sense. Nothing on
    screen moves to list them."""
    return runner.sense.ask(op="windows")["windows"]


def bring_forward(runner, hwnd):
    front = runner.sense.ask(op="activate", hwnd=hwnd).get("front")
    runner.table = runner.sense.settle(runner.table["hash"], change_ms=600)
    return front


def close_windows(runner, closed, kept, names=None):
    """Bring each window of ours to the front, close it, answer its save
    prompt, and check by its handle that it is gone. With names, close just
    those windows (one each), whatever they are called."""
    names = list(names) if names is not None else None
    tried = set()
    while True:
        items = [w for w in open_windows(runner) if w["hwnd"] not in tried]
        if names is not None:
            mine = [w for w in items if w["title"] in names]
        else:
            mine = [w for w in items if ours_window(w["title"])]
        if not mine:
            return
        item = mine[0]
        tried.add(item["hwnd"])
        if not bring_forward(runner, item["hwnd"]):
            kept.append(f"would not come forward: {item['title']}")
            continue
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
            if not answer_save_prompt(runner, closed, kept, item["title"]):
                break
        if any(w["hwnd"] == item["hwnd"] for w in open_windows(runner)):
            if not (kept and kept[-1].startswith("left open")):
                # It did not go and said nothing we could answer: leave it
                # for a person rather than try forever.
                kept.append(f"would not close: {item['title']}")
        else:
            closed.append(item["title"])
            if names is not None:
                names.remove(item["title"])


def close_tabs(runner, closed, rounds=80):
    edge = next((w for w in open_windows(runner) if "Edge" in w["title"]), None)
    if edge is None or not bring_forward(runner, edge["hwnd"]):
        return
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


def tidy(runner, tabs=False):
    closed, kept = [], []
    close_windows(runner, closed, kept)
    if tabs:
        close_tabs(runner, closed)
    return closed, kept


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host-id", required=True)
    ap.add_argument("--tabs", action="store_true", help="also close browser tabs that look like fast lane pages")
    args = ap.parse_args()
    runner = fastlane.Runner(args.host_id)
    try:
        closed, kept = tidy(runner, args.tabs)
    finally:
        runner.close()
    print(json.dumps({"seconds": round(fastlane.time.time() - runner.t0, 1), "closed": closed, "kept": kept,
                      "taskbar": [r["name"] for r in runner.table["elements"] if r["area"] == "taskbar" and "running" in r["name"]]}, indent=1))


if __name__ == "__main__":
    main()
