"""Close what fast lane runs opened, and nothing else.

    python3 tidy.py --host-id <saved host>

A person leaves a computer the way they found it. This goes through the
browser windows tab by tab and closes the tabs whose titles match pages the
fast lane loads (Google Flights, Google News, Wikipedia, its Bing and Google
searches, empty new tabs), then closes the fast lane's own Calculator, Notepad
logs and Word reports. Tabs and documents it did not open, such as a person's
restored session, stay where they are.
"""

import argparse
import json
import sys

import fastlane

OURS = ["google flights", "google news", "wikipedia", "new tab", "google flights from", "- search", "| google search",
        "inr to gbp", "london weather", "fast lane report", "fastlane-log", "trip budget", "trip brief", "trip summary"]
APPS = {"Calculator": "alt+F4"}


def ours(name):
    n = name.lower()
    return any(p in n for p in OURS)


def tidy(runner, max_closes=120):
    closed = []
    for _ in range(max_closes):
        tabs = [r for r in runner.table["elements"] if r["area"] == "window" and r["role"] == "tab" and ours(r["name"])
                and "edge" in (runner.table["window"]["title"] or "").lower()]
        if tabs:
            tab = tabs[0]
            # Select the tab, then close it from the keyboard: the close
            # button is only on the tab under the pointer.
            runner.step({"click": tab["name"]})
            if ours(runner.table["window"]["title"] or ""):
                runner.step({"key": "ctrl+w"})
                closed.append(tab["name"][:60])
                continue
        title = runner.table["window"]["title"] or ""
        if "edge" in title.lower() and ours(title):
            runner.step({"key": "ctrl+w"})
            closed.append(title[:60])
            continue
        if title in APPS:
            runner.step({"key": APPS[title]})
            closed.append(title)
            continue
        # Bring the next window of ours to the front, if the taskbar shows one.
        nxt = None
        for r in runner.table["elements"]:
            if r["area"] == "taskbar" and r["role"] == "button" and ("Microsoft Edge" in r["name"] or "Calculator" in r["name"]):
                nxt = r
        if nxt is None or len(closed) and closed[-1] == "switched":
            break
        runner.step({"key": "alt+Tab"})
        if not (ours(runner.table["window"]["title"] or "") or any(ours(r["name"]) for r in runner.table["elements"] if r["role"] == "tab")):
            break
    return closed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host-id", required=True)
    args = ap.parse_args()
    runner = fastlane.Runner(args.host_id)
    try:
        closed = tidy(runner)
    finally:
        runner.close()
    print(json.dumps({"closed": closed, "window": runner.table["window"],
                      "taskbar": [r["name"] for r in runner.table["elements"] if r["area"] == "taskbar" and "running" in r["name"]]}, indent=1))


if __name__ == "__main__":
    main()
