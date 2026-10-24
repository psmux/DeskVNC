#!/usr/bin/env python3
"""Turn remote-bench JSON results into Markdown tables.

    python3 tools/bench/tables.py docs/benchmarks/raw/container-*.json

One table per measure, one row per run, so runs from different builds sit
side by side with their build named in the row.
"""
import json
import sys


def num(v, digits=0):
    if v is None:
        return "n/a"
    return f"{v:.{digits}f}"


def kbps(window):
    if not window:
        return "n/a"
    v = window.get("os_kbps") or window.get("driver_kbps")
    if v is None:
        return "n/a"
    return f"{v / 1000:.1f}" if v >= 1000 else f"{v / 1000:.2f}"


def cpu(window, key):
    return num(window.get(key)) if window else "n/a"


def main(paths):
    runs = []
    for p in paths:
        with open(p) as f:
            runs.append(json.load(f))
    runs.sort(key=lambda r: (r["label"].rsplit("-", 1)[0], r["protocol"]))

    print("### Input to screen (ms)\n")
    print("| Run | Build | Protocol | Pointer p50 | p90 | p99 | missed | Key p50 | p90 | p99 | missed |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in runs:
        p, t = r.get("pointer") or {}, r.get("typing") or {}
        pl, tl = p.get("lag_ms") or {}, t.get("lag_ms") or {}
        tcells = (
            ["skipped"] * 4
            if t.get("skipped")
            else [num(tl.get("p50"), 1), num(tl.get("p90"), 1), num(tl.get("p99"), 1), str(t.get("missed", "n/a"))]
        )
        print(
            f"| {r['label']} | {r['build']} | {r['protocol']} | {num(pl.get('p50'), 1)} | {num(pl.get('p90'), 1)} "
            f"| {num(pl.get('p99'), 1)} | {p.get('missed', 'n/a')} | " + " | ".join(tcells) + " |"
        )

    for scene in ("scroll", "motion"):
        print(f"\n### {scene.capitalize()}: frames delivered and frame latency\n")
        print("| Run | Protocol | fps seen | stage fps | dropped | latency p50 ms | p90 | p99 | Mbit/s | server CPU % | client CPU % |")
        print("|---|---|---|---|---|---|---|---|---|---|---|")
        for r in runs:
            s = r.get(scene)
            if not s:
                continue
            lat, w = s["latency_ms"], s.get("window") or {}
            dropped = f"{s['dropped']} of {s['span']}"
            print(
                f"| {r['label']} | {r['protocol']} | {num(s['fps'], 1)} | {num(s['stage_fps'], 1)} | {dropped} "
                f"| {num(lat['p50'])} | {num(lat['p90'])} | {num(lat['p99'])} | {kbps(w)} "
                f"| {cpu(w, 'server_cpu')} | {cpu(w, 'client_cpu')} |"
            )

    print("\n### After motion stops (ms)\n")
    print("| Run | Protocol | first still frame | sharp | detail at first | detail final |")
    print("|---|---|---|---|---|---|")
    for r in runs:
        s = r.get("still")
        if not s:
            continue
        print(
            f"| {r['label']} | {r['protocol']} | {num(s.get('first_ms'))} | {num(s.get('sharp_ms'))} "
            f"| {num(s.get('detail_first'))} | {num(s.get('detail_final'))} |"
        )

    print("\n### Idle and typing bandwidth (Mbit/s)\n")
    print("| Run | Protocol | pointer test | typing test | rects by kind |")
    print("|---|---|---|---|---|")
    for r in runs:
        kinds = ", ".join(f"{k} {v}" for k, v in sorted(r.get("rect_kinds", {}).items()))
        print(
            f"| {r['label']} | {r['protocol']} | {kbps((r.get('pointer') or {}).get('window'))} "
            f"| {kbps((r.get('typing') or {}).get('window'))} | {kinds} |"
        )


if __name__ == "__main__":
    main(sys.argv[1:])
