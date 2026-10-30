"""Missions: long goals done as a person would, phase by phase, each phase
working from what the earlier ones found.

    python3 missions.py --host-id <saved host> trip market

A mission is planned once (by a person or a large model) as a sequence of
skills from skills.py with the data flowing between them in code. The fast
lane carries it out. Before it starts the mission notes every window open on
the computer; when it ends it closes what its own ledger says it opened and
checks Task View against that first list, so anything it left behind, and
anything that appeared that nobody opened, is reported.
"""

import argparse
import json
import sys
import time

import fastlane
import skills
import tidy


def trip(ctx, origin="Chennai", destination="London", date="2026-12-15", travellers=3, discount_pct=10):
    """Plan and cost a trip, then write it up three ways and file it."""
    s = skills.REGISTRY
    # Research
    f = s["web.flights"](ctx, origin=origin, destination=destination, date=date) or {}
    fx = s["web.exchange_rate"](ctx, from_code="INR", to_code="GBP") or {}
    w = s["web.weather"](ctx, city=destination) or {}
    wiki = s["web.wikipedia"](ctx, topic=f"Tower of {destination}" if destination == "London" else destination) or {}
    cheapest = f.get("cheapest", {"airline": "unknown", "inr": 0, "stops": "", "duration": ""})
    rate = fx.get("rate", 0)
    # Compute: the fare in pounds, the group total, the discount, per person.
    fare = cheapest["inr"]
    c = s["calc.compute"](ctx, expressions=[f"{fare}*{rate}", f"{fare}*{travellers}", f"{fare}*{travellers}*{100 - discount_pct}/100",
                                           f"{fare}*{travellers}*{100 - discount_pct}/100/{travellers}"]) or {}
    values = [r["value"] for r in c.get("results", [])] or [None] * 4
    # Author: a budget with formulas, a brief, a deck.
    rows = [[fx_f["airline"], fx_f["inr"], f"=B{{r}}*{rate}"] for fx_f in f.get("fares", [])[:4]]
    sheet = s["office.spreadsheet"](ctx, name="Trip Budget", header=["Option", "INR", "GBP"], rows=rows or [["none", 0, 0]], totals="BC") or {}
    brief = s["office.document"](ctx, name="Trip Brief", title=f"Trip brief: {origin} to {destination}", blocks=[
        ["italic", f"Prepared by the DeskVNC fast lane on the MSI, run {ctx.run_id}."],
        ["h", "Flights"],
        ["bullets", [f"{x['airline']}, {x['stops']}, {x['duration']}: INR {x['inr']:,}" for x in f.get("fares", [])]],
        ["bold", "Cheapest: ", f"{cheapest['airline']} at INR {fare:,}"],
        ["h", "Costs"],
        ["bullets", [f"Exchange rate: 1 INR = {rate} GBP",
                     f"Cheapest fare in pounds: GBP {values[0]:,.2f}" if values[0] else "",
                     f"{travellers} travellers: INR {values[1]:,.0f}" if values[1] else "",
                     f"With {discount_pct}% off: INR {values[2]:,.0f}, or INR {values[3]:,.0f} each" if values[3] else "",
                     f"Budget sheet total for the options listed: INR {sheet.get('totals', {}).get('B', 0):,.0f}"]],
        ["h", f"Weather in {destination}"],
        ["bullets", w.get("lines", [])[:4]],
        ["h", "Worth seeing"],
        ["p", wiki.get("summary", "")],
    ]) or {}
    slides = s["office.deck"](ctx, name="Trip Summary", slides=[
        [f"{origin} to {destination}", [f"{date}, {travellers} travellers"]],
        ["Cheapest fare", [f"{cheapest['airline']}, {cheapest['stops']}", f"INR {fare:,} each"]],
        ["Group cost", [f"INR {values[2]:,.0f} after {discount_pct}% off" if values[2] else "not worked out"]],
    ]) or {}
    # Organise
    files = [x["file"] for x in (sheet, brief, slides) if x.get("file")]
    if files:
        s["files.organise"](ctx, folder="Trip", files=files)


def market(ctx):
    """A market brief: index levels and the day's business news, worked into a
    table with formulas and a memo."""
    s = skills.REGISTRY
    biz = s["web.news"](ctx, section="Business") or {}
    tech = s["web.news"](ctx, section="Technology") or {}
    # "Sensex 74,437.42 +0.39% +286.38": level, change in points.
    import re
    indices = []
    for line in biz.get("markets", []):
        m = re.match(r"^(.+?) ([\d,]+\.\d+) ([+\-−][\d.]+)% ([+\-−][\d,]+\.\d+)", line)
        if m:
            level = float(m.group(2).replace(",", ""))
            change = float(m.group(4).replace(",", "").replace("−", "-"))
            indices.append((m.group(1), level, change))
    if not indices:
        indices = [("Sensex", 0.0, 0.0)]
    c = s["calc.compute"](ctx, expressions=[f"{lvl}-{chg}" if chg >= 0 else f"{lvl}+{-chg}" for _, lvl, chg in indices[:3]]) or {}
    prev = [r["value"] for r in c.get("results", [])]
    rows = [[name, lvl, f"=B{{r}}-{chg}", "=(B{r}-C{r})/C{r}*100"] for name, lvl, chg in indices[:4]]
    sheet = s["office.spreadsheet"](ctx, name="Market Table", header=["Index", "Level", "Previous", "Change %"], rows=rows, totals="") or {}
    memo = s["office.document"](ctx, name="Market Brief", title="Market brief", blocks=[
        ["italic", f"From Google News, read by the fast lane, run {ctx.run_id}."],
        ["h", "Indices"],
        ["bullets", [f"{n}: {l:,.2f} ({'+' if ch >= 0 else ''}{ch:,.2f} points; previous close {p:,.2f})" for (n, l, ch), p in zip(indices, prev + [0] * 5)]],
        ["h", "Business headlines"], ["bullets", biz.get("headlines", [])[:5]],
        ["h", "Technology headlines"], ["bullets", tech.get("headlines", [])[:4]],
    ]) or {}
    s["office.note"](ctx, name="Watchlist", text="Watchlist\n" + "\n".join(f"{n} {l:,.2f}" for n, l, _ in indices))
    files = [x["file"] for x in (sheet, memo) if x.get("file")]
    if files:
        s["files.organise"](ctx, folder="Market", files=files)


MISSIONS = {"trip": trip, "market": market,
            "trip2": lambda ctx: trip(ctx, origin="Bengaluru", destination="Singapore", date="2026-12-20", travellers=2, discount_pct=5)}


def windows(runner):
    items = tidy.task_view(runner)
    runner.step({"key": "Escape"})
    return sorted(r["name"] for r in items if r["name"] != "Desktop 1")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host-id", required=True)
    ap.add_argument("missions", nargs="+")
    args = ap.parse_args()
    runner = fastlane.Runner(args.host_id)
    run_id = time.strftime("%H%M")
    ctx = skills.Ctx(runner, run_id)
    before = windows(runner)
    report = {"run": run_id, "missions": []}
    try:
        for name in args.missions:
            started, first = time.time(), len(ctx.results)
            MISSIONS[name](ctx)
            done = ctx.results[first:]
            report["missions"].append({"mission": name, "seconds": round(time.time() - started, 1),
                                       "skills": len(done), "passed": sum(r["passed"] for r in done)})
            print("MISSION " + json.dumps(report["missions"][-1]), file=sys.stderr, flush=True)
        # Leave the computer as it was found.
        after = windows(runner)
        extra = list(after)
        for w in before:
            if w in extra:
                extra.remove(w)
        if extra:
            # Exactly what appeared during the mission, one window per name
            # per copy, and the browser tabs of ours.
            closed, kept = [], []
            tidy.close_windows(runner, closed, kept, names=extra)
            tidy.close_tabs(runner, closed)
            report["tidied"] = closed
            report["left_for_person"] = kept
            after = windows(runner)
        report["unclosed_ledger"] = [i for i in ctx.ledger if not i["closed"]]
        left = list(after)
        for w in before:
            if w in left:
                left.remove(w)
        report["new_windows_at_end"] = left
        report["windows_gone_that_were_open"] = [w for w in before if w not in after]
    finally:
        runner.close()
    total = time.time() - runner.t0
    actions = sum(1 for e in runner.log if "did" in e)
    report.update({"minutes": round(total / 60, 2), "skills": len(ctx.results), "skills_passed": sum(r["passed"] for r in ctx.results),
                   "actions": actions, "actions_per_minute": round(actions / (total / 60), 1),
                   "recoveries": sum(1 for e in runner.log if "recover" in e),
                   "files": [i["name"] for i in ctx.ledger if i["kind"] == "file"], "results": ctx.results})
    print(json.dumps(report, indent=1, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
