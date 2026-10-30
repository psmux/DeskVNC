"""Reusable desktop skills for the fast lane, for missions to compose.

A skill is one capability a person has on a Windows computer: look up fares,
convert a currency, work out sums, build a spreadsheet with formulas, write a
formatted document, make a slide deck, file things in a folder. Each takes
plain arguments, returns what it found or made, checks its own work, and
records in the ledger every tab, window and file it opened or created, so a
mission can leave the computer as it found it.

A skill raises SkillFailed with the reason when it cannot finish; the mission
decides whether to go on without it.
"""

import json
import re
import time
import urllib.parse

import fastlane


class SkillFailed(Exception):
    pass


class Ctx:
    """What a mission carries from skill to skill."""

    def __init__(self, runner, run_id):
        self.runner = runner
        self.run_id = run_id
        self.memory = {}
        self.ledger = []
        self.results = []

    # ----------------------------------------------------------- doing steps
    def do(self, steps):
        """Run steps; return the rows each read step collected."""
        reads = []
        for step in steps:
            first = len(self.runner.log)
            if not self.runner.step(step):
                raise SkillFailed(f"step {json.dumps(step, ensure_ascii=False)[:140]} failed in {self.runner.table['window']['title']!r}")
            reads += [e["read"] for e in self.runner.log[first:] if "read" in e]
        return reads

    def opened(self, kind, name):
        self.ledger.append({"kind": kind, "name": name, "closed": False})

    def closed(self, kind, name):
        for item in self.ledger:
            if item["kind"] == kind and item["name"] == name and not item["closed"]:
                item["closed"] = True
                return

    def created(self, path):
        self.ledger.append({"kind": "file", "name": path, "closed": True})

    def name(self, base):
        """A file name no earlier run used: the run id is part of it."""
        return f"{base} {self.run_id}"

    # ------------------------------------------------------------- browsing
    def open_page(self, url, expect, ms=20000):
        self.do(run_box(f"msedge {url}", expect, ms))
        title = self.runner.table["window"]["title"].split(" and ")[0].split(" - Personal")[0]
        self.opened("tab", title)
        return title

    def close_page(self, title):
        self.do([{"key": "ctrl+w", "when": {"window": title[:40]}}])
        self.closed("tab", title)

    def page_text(self, words, limit=40):
        return fastlane.read_rows(self.runner.table["elements"], words)[:limit]


def run_box(command, expect, ms=10000):
    return [{"key": "super+r", "expect": {"window": "Run"}},
            {"type": command, "into": "Open"},
            {"key": "Enter", "expect": expect, "expect_ms": ms}]


REGISTRY = {}


def skill(category):
    def wrap(fn):
        def run(ctx, **args):
            started = time.time()
            first = len(ctx.runner.log)
            record = {"skill": f"{category}.{fn.__name__}", "args": args}
            try:
                record["output"] = fn(ctx, **args)
                record["passed"] = True
            except (SkillFailed, RuntimeError) as e:
                record["passed"] = False
                record["error"] = str(e)[:300]
                # Leave the screen as clean as a person would before going on.
                ctx.runner.dvv.fence()
                ctx.runner.dvv.key("Escape")
                ctx.runner.settle()
            log = ctx.runner.log[first:]
            record["seconds"] = round(time.time() - started, 2)
            record["actions"] = sum(1 for e in log if "did" in e)
            record["recoveries"] = sum(1 for e in log if "recover" in e)
            ctx.results.append(record)
            print("SKILL " + json.dumps({k: v for k, v in record.items() if k != "output"}, ensure_ascii=False), flush=True,
                  file=__import__("sys").stderr)
            return record.get("output")
        REGISTRY[f"{category}.{fn.__name__}"] = run
        run.__doc__ = fn.__doc__
        return run
    return wrap


def number(text):
    m = re.search(r"-?[\d,]+(?:\.\d+)?", text)
    return float(m.group(0).replace(",", "")) if m else None


# =================================================================== web
@skill("web")
def flights(ctx, origin, destination, date):
    """Fares on Google Flights, cheapest first: airline, duration, stops, INR."""
    q = urllib.parse.quote_plus(f"one way flights from {origin} to {destination} on {date}")
    title = ctx.open_page(f"https://www.google.com/travel/flights?q={q}&curr=INR", {"shows": "₹"})
    ctx.do([{"click": "Cheapest", "expect": {"shows": "Cheapest"}}])
    fares = []
    for line in ctx.page_text("₹"):
        m = re.search(r"(?:AM|PM)(?:\+\d)?\s*(?P<airline>[A-Za-z][A-Za-z ,&.\-]*?)\s*(?P<dur>\d+ hr(?: \d+ min)?)\s*(?P<stops>Nonstop|\d+ stops?).*?₹(?P<inr>[\d,]+)", line)
        if m:
            fares.append({"airline": m["airline"].strip(" ,"), "duration": m["dur"], "stops": m["stops"], "inr": int(m["inr"].replace(",", ""))})
    ctx.close_page(title)
    if not fares:
        raise SkillFailed("no fares read")
    fares.sort(key=lambda f: f["inr"])
    return {"route": f"{origin} to {destination}", "date": date, "fares": fares[:5], "cheapest": fares[0]}


@skill("web")
def search(ctx, query, words):
    """Google a question and read the lines of the answer holding any of the |-separated words."""
    title = ctx.open_page("https://www.google.com/search?q=" + urllib.parse.quote_plus(query), {"window": "Google Search"})
    lines = [l for l in ctx.page_text(words, 25) if len(l) < 300]
    ctx.close_page(title)
    if not lines:
        raise SkillFailed(f"nothing about {words!r}")
    return {"query": query, "lines": lines}


@skill("web")
def exchange_rate(ctx, from_code, to_code):
    """How many of to_code one from_code buys, from Google's converter."""
    title = ctx.open_page("https://www.google.com/search?q=" + urllib.parse.quote_plus(f"1 {from_code} to {to_code}"), {"window": "Google Search"})
    rate = None
    for line in ctx.page_text("equals|=|" + to_code, 30):
        m = re.search(r"1 [A-Za-z ]+? equals\s*([\d.]+)", line) or re.search(r"^([\d]+\.\d+)$", line.strip())
        if m:
            rate = float(m.group(1))
            break
    if rate is None:
        # The converter's own box holds the converted amount.
        for r in ctx.runner.table["elements"]:
            if r["role"] in ("textbox", "combobox", "text") and re.fullmatch(r"0\.\d+", (r.get("value") or r["name"]).strip()):
                rate = float((r.get("value") or r["name"]).strip())
                break
    ctx.close_page(title)
    if rate is None:
        raise SkillFailed("no rate on the page")
    return {"pair": f"{from_code}/{to_code}", "rate": rate}


@skill("web")
def weather(ctx, city):
    """Google's weather card for a city: temperature and conditions."""
    title = ctx.open_page("https://www.google.com/search?q=" + urllib.parse.quote_plus(f"weather {city}"), {"window": "Google Search"})
    lines = [l for l in ctx.page_text("°|precipitation|humidity|wind", 12)]
    ctx.close_page(title)
    if not lines:
        raise SkillFailed("no weather card")
    return {"city": city, "lines": lines[:6]}


@skill("web")
def wikipedia(ctx, topic):
    """The opening sentences of a Wikipedia article, found through its own search box."""
    title = ctx.open_page("https://en.wikipedia.org/wiki/Main_Page", {"window": "Wikipedia"})
    ctx.closed("tab", title)
    ctx.do([{"type": topic + "\n", "into": "Search Wikipedia", "expect": {"window": topic}, "expect_ms": 10000}])
    title = ctx.runner.table["window"]["title"].split(" and ")[0].split(" - Personal")[0]
    ctx.opened("tab", title)
    lines = [l for l in ctx.page_text(topic.split()[0], 12) if len(l) > 80]
    ctx.close_page(title)
    if not lines:
        raise SkillFailed("no article text")
    return {"topic": topic, "summary": lines[0][:400]}


@skill("web")
def news(ctx, section):
    """Headlines of one Google News section, and the market figures it shows."""
    title = ctx.open_page("https://news.google.com/?hl=en-IN&gl=IN&ceid=IN:en", {"shows": "Top stories"})
    ctx.closed("tab", title)
    ctx.do([{"click": section, "expect": {"window": section}, "expect_ms": 10000}])
    title = ctx.runner.table["window"]["title"].split(" and ")[0].split(" - Personal")[0]
    ctx.opened("tab", title)
    rows = ctx.page_text("", 80)
    heads = [r[len("More - "):] for r in rows if r.startswith("More - ")]
    markets = [r for r in rows if re.match(r"^(Sensex|NIFTY 50|Nikkei 225|SSE|Dow Jones|S&P 500|Nasdaq)\b", r)]
    ctx.close_page(title)
    if len(heads) < 3:
        raise SkillFailed(f"only {len(heads)} headlines")
    return {"section": section, "headlines": heads[:6], "markets": markets}


# ============================================================ calculator
@skill("calc")
def compute(ctx, expressions):
    """Work sums out in Calculator; checked against the same sums done here."""
    ctx.do(run_box("calc", {"window": "Calculator"}))
    ctx.opened("window", "Calculator")
    results, wrong = [], []
    for expr in expressions:
        reads = ctx.do([{"key": "Escape"}, {"type": expr + "=", "expect": {"shows": "Display is"}}, {"read": "Display is"}])
        shown = number(sum(reads, [""])[-1].replace("Display is", ""))
        want = left_to_right(expr)
        if shown is None or abs(shown - want) > 1e-6 * max(1, abs(want)):
            wrong.append(f"{expr}: showed {shown}, should be {want}")
        results.append({"expr": expr, "value": shown})
    ctx.do([{"key": "alt+F4", "when": {"window": "Calculator"}}])
    ctx.closed("window", "Calculator")
    if wrong:
        raise SkillFailed("; ".join(wrong))
    return {"results": results}


def left_to_right(expr):
    """Calculator's Standard mode works like a pocket calculator, left to right."""
    tokens = re.findall(r"\d+(?:\.\d+)?|[-+*/]", expr)
    total = float(tokens[0])
    for op, num in zip(tokens[1::2], tokens[2::2]):
        x = float(num)
        total = {"+": total + x, "-": total - x, "*": total * x, "/": total / x}[op]
    return total


# ================================================================= office
def save_as(ctx, name, dialog="Save As", app_suffix=""):
    ctx.do([{"key": "F12", "expect": {"window": dialog}, "expect_ms": 8000},
            {"type": name, "into": "File name"},
            {"key": "Enter", "expect": {"window": name}, "expect_ms": 10000}])


def answer_dont_save(ctx):
    ctx.do([{"click": "Don't Save", "when": {"shows": "Don't Save"}}])


@skill("office")
def spreadsheet(ctx, name, header, rows, totals, number_format_cols=""):
    """An Excel workbook: a bold header, rows (formulas allowed, {r} is the row
    number), a total row of SUMs over the given columns. Returns every
    computed cell of the total row, read back from Excel itself."""
    name = ctx.name(name)
    ctx.do(run_box("excel", {"shows": "Blank workbook"}, 25000))
    ctx.do([{"click": "Blank workbook", "expect": {"window": "Book"}, "expect_ms": 15000}])
    ctx.opened("window", "Excel")
    text = "\t".join(header) + "\n"
    for i, row in enumerate(rows, start=2):
        text += "\t".join(str(c).replace("{r}", str(i)) for c in row) + "\n"
    last = len(rows) + 1
    total_row = ["Total"] + [f"=SUM({c}2:{c}{last})" if c in totals else "" for c in "BCDEFG"[: len(header) - 1]]
    text += "\t".join(total_row) + "\n"
    ctx.do([{"type": text},
            # Bold header: from A1, select across the header and press ctrl+b.
            {"key": "ctrl+Home"}] + [{"key": "shift+ArrowRight"}] * (len(header) - 1) + [{"key": "ctrl+b"},
            {"key": "ctrl+Home"}])
    total_r = last + 1
    cells = {r["name"]: r.get("value", "") for r in ctx.runner.table["elements"] if r["role"] == "row"}
    total = {c: number(cells.get(f"{c}{total_r}", "")) for c in totals}
    save_as(ctx, name)
    ctx.created(f"{name}.xlsx")
    ctx.do([{"key": "alt+F4", "when": {"window": name}}])
    answer_dont_save(ctx)
    ctx.closed("window", "Excel")
    if any(v is None for v in total.values()):
        raise SkillFailed(f"total row not readable: {total}")
    return {"file": f"{name}.xlsx", "totals": total}


@skill("office")
def document(ctx, name, title, blocks):
    """A Word document. blocks: ["h", text], ["p", text], ["bullets", [..]],
    ["bold", label, value] (label, then value in bold), ["italic", text]."""
    name = ctx.name(name)
    ctx.do(run_box("winword", {"shows": "Blank document"}, 25000))
    ctx.do([{"click": "Blank document", "expect": {"window": "Document"}, "expect_ms": 15000}])
    ctx.opened("window", "Word")
    steps = [{"key": "ctrl+e"}, {"key": "ctrl+alt+1"}, {"type": title + "\n"}, {"key": "ctrl+l"}]
    for b in blocks:
        kind = b[0]
        if kind == "h":
            steps += [{"key": "ctrl+alt+2"}, {"type": b[1] + "\n"}]
        elif kind == "p":
            steps += [{"type": b[1] + "\n"}]
        elif kind == "italic":
            steps += [{"key": "ctrl+i"}, {"type": b[1]}, {"key": "ctrl+i"}, {"type": "\n"}]
        elif kind == "bullets":
            items = [str(i) for i in b[1] if i]
            if items:
                steps += [{"type": "* " + "\n".join(items) + "\n\n"}]
        elif kind == "bold":
            steps += [{"type": b[1]}, {"key": "ctrl+b"}, {"type": b[2]}, {"key": "ctrl+b"}, {"type": "\n"}]
    ctx.do(steps)
    save_as(ctx, name)
    ctx.created(f"{name}.docx")
    ctx.do([{"key": "alt+F4", "when": {"window": name}}])
    answer_dont_save(ctx)
    ctx.closed("window", "Word")
    return {"file": f"{name}.docx"}


@skill("office")
def deck(ctx, name, slides):
    """A PowerPoint deck typed in Outline View: slides = [[title, [bullets]], ...]."""
    name = ctx.name(name)
    ctx.do(run_box("powerpnt", {"shows": "Blank Presentation"}, 25000))
    ctx.do([{"click": "Blank Presentation", "expect": {"window": "Presentation"}, "expect_ms": 15000}])
    ctx.opened("window", "PowerPoint")
    ctx.do([{"click": "View", "expect": {"shows": "Outline View"}}, {"click": "Outline View"}])
    # The outline pane exposes no control; slide 1's line is at its top left.
    ctx.runner.dvv.click(80, 244)
    ctx.runner.settle()
    steps = []
    for k, (title, bullets) in enumerate(slides):
        if k:
            steps.append({"key": "shift+Tab"})
        steps.append({"type": title + "\n"})
        if bullets:
            steps.append({"key": "Tab"})
            steps.append({"type": "\n".join(bullets) + "\n"})
    steps.append({"key": "BackSpace"})
    ctx.do(steps)
    reads = ctx.do([{"read": "View Indicator"}])
    save_as(ctx, name)
    ctx.created(f"{name}.pptx")
    ctx.do([{"key": "alt+F4", "when": {"window": name}}])
    answer_dont_save(ctx)
    ctx.closed("window", "PowerPoint")
    count = sum(reads, [""])[-1]
    if f"of {len(slides)}" not in count:
        raise SkillFailed(f"deck has {count!r}, wanted {len(slides)} slides")
    return {"file": f"{name}.pptx", "slides": len(slides)}


@skill("office")
def note(ctx, name, text):
    """A Notepad file in Documents."""
    name = ctx.name(name) + ".txt"
    ctx.do(run_box("notepad", {"window": "Notepad"}))
    ctx.opened("window", "Notepad")
    ctx.do([{"key": "ctrl+n"}, {"type": text + "\n"},
            {"key": "ctrl+s", "expect": {"window": "Save as"}, "expect_ms": 8000},
            {"type": name, "into": "File name"},
            {"key": "Enter", "expect": {"window": name}, "expect_ms": 8000},
            {"key": "ctrl+w", "when": {"window": name}}])
    ctx.created(name)
    ctx.closed("window", "Notepad")
    return {"file": name}


# ================================================================= files
@skill("files")
def organise(ctx, folder, files):
    """Make a folder in Documents and move the files into it, in File Explorer."""
    folder = ctx.name(folder)
    ctx.do([{"key": "super+e", "expect": {"window": "File Explorer"}, "expect_ms": 8000},
            {"key": "ctrl+l"},
            {"type": "%USERPROFILE%\\Documents\n", "expect": {"window": "Documents"}, "expect_ms": 8000}])
    ctx.opened("window", "File Explorer")
    ctx.do([{"key": "ctrl+shift+n", "expect": {"shows": "New folder"}},
            {"type": folder + "\n", "replace": True, "expect": {"shows": folder}}])
    for f in files:
        base = f.rsplit(".", 1)[0]
        ctx.do([{"click": base, "expect": {"shows": base}}, {"key": "ctrl+x"}])
        ctx.do([{"click": folder}, {"key": "Enter", "expect": {"window": folder}},
                {"key": "ctrl+v", "expect": {"shows": base}},
                {"key": "alt+ArrowLeft", "expect": {"window": "Documents"}}])
    ctx.do([{"click": folder}, {"key": "Enter", "expect": {"window": folder}}])
    inside = " ".join(ctx.page_text("", 60))
    missing = [f for f in files if f.rsplit(".", 1)[0] not in inside]
    ctx.do([{"key": "alt+F4", "when": {"window": folder}}])
    ctx.closed("window", "File Explorer")
    if missing:
        raise SkillFailed(f"not in {folder}: {missing}")
    return {"folder": folder, "files": files}
