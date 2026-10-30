"""Run the spec's cases against the Python prototype in fastlane.py.

Run: python3 spec/check.py   (from tools/fastlane)
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
os.environ["FASTLANE_JEV"] = ""

import fastlane  # noqa: E402


def filled(table):
    rows = []
    for n, r in enumerate(table["elements"], 1):
        rows.append({"i": n, "area": "window", "x": 0, "y": 0, "w": 100, "h": 20, **r})
    return {**table, "elements": rows}


def outcome(case):
    table = filled(case["table"])
    rows = table["elements"]
    check = case["check"]
    if check == "find":
        name, roles = (case["click"], fastlane.CLICKABLE) if "click" in case else (case["into"], fastlane.EDITABLE)
        row, _ = fastlane.find(rows, name, roles, "")
        return row and row["i"]
    if check == "recover":
        picks = [] if case.get("typo") else fastlane.dismissers(table)
        return picks[0]["i"] if picks else "Escape"
    if check == "met":
        return fastlane.met(case["expect"], table)
    if check == "read":
        return fastlane.read_rows(rows, case["read"])[: case.get("limit", 15)]
    if check == "echo":
        return fastlane.echoed(case["type"], table)
    raise ValueError(f"unknown check {check}")


def main():
    cases = json.load(open(os.path.join(HERE, "cases.json")))["cases"]
    failed = 0
    for case in cases:
        got = outcome(case)
        if got != case["want"]:
            failed += 1
            print(f"FAIL {case['name']}: want {case['want']!r}, got {got!r}")
    print(f"{len(cases) - failed} of {len(cases)} cases pass")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
