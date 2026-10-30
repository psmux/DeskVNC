"""Goals in plain words, done by the fast lane.

    python3 goal.py --host-id <saved host> "find flights from Pune to Paris on 2026-12-12 and put the cheapest in a Word report"

A small open model (Qwen2.5 3B behind llama.cpp on our own box) turns the goal
into calls to skills that are already tested, the same plans marathon.py
runs. Filling in a skill's arguments is a job a 3B model does well and
quickly; choosing raw clicks is not, which is what the first fast lane runs
showed. A goal that fits no skill is returned unanswered, for a larger model
or a person to plan.
"""

import argparse
import json
import sys
import time

import fastlane
import marathon

SKILLS = {
    "flights": "flights(origin, destination, date as YYYY-MM-DD): search Google Flights and read the fares",
    "news": "news(section): read headlines from Google News; section is one of India, World, Business, Technology, Entertainment",
    "wikipedia": "wikipedia(topic): look a topic up on Wikipedia and read its first lines",
    "calculate": "calculate(expressions): work out sums in Calculator, e.g. [\"1200*12\", \"500/7\"]; only + - * / and whole numbers",
    "word_report": "word_report(title): write a formatted Word report of everything read so far and save it",
    "note": "note(name, text): write text in Notepad and save it as name.txt",
    "check_files": "check_files(): confirm in File Explorer that the files saved so far are in Documents",
}


def plan_goal(goal):
    prompt = ("You turn a computer task into calls to these skills, in order, one call for every part of the task:\n" + "\n".join(f"* {v}" for v in SKILLS.values()) +
              "\nA note's text may say {results} where the calculator's answers go. Today is 2026-10-30."
              " Reply with only JSON: {\"calls\": [{\"skill\": name, \"args\": {...}}]}, or {\"calls\": []} if no skill fits.")
    examples = [
        ("look up Mumbai to Dubai flights on 5 January and write it up in Word",
         {"calls": [{"skill": "flights", "args": {"origin": "Mumbai", "destination": "Dubai", "date": "2027-01-05"}}, {"skill": "word_report", "args": {"title": "Mumbai to Dubai"}}]}),
        ("add 250 and 999, then save the answer in a note called sums",
         {"calls": [{"skill": "calculate", "args": {"expressions": ["250+999"]}}, {"skill": "note", "args": {"name": "sums", "text": "{results}"}}]}),
    ]
    messages = [{"role": "system", "content": prompt}]
    for ask, answer in examples:
        messages += [{"role": "user", "content": ask}, {"role": "assistant", "content": json.dumps(answer)}]
    started = time.time()
    r = fastlane.post(f"{fastlane.LLM}/v1/chat/completions", {
        "messages": messages + [{"role": "user", "content": goal}],
        "temperature": 0, "max_tokens": 300,
    }, timeout=60)
    content = r["choices"][0]["message"]["content"]
    body = content[content.index("{"): content.rindex("}") + 1]
    try:
        calls = json.loads(body)["calls"]
    except json.JSONDecodeError:
        # A bare {results} placeholder outside quotes is the usual slip.
        calls = json.loads(body.replace(": {results}", ": \"{results}\""))["calls"]
    return calls, round((time.time() - started) * 1000)


def task_for(call, n, memory):
    skill, args = call["skill"], call.get("args", {})
    if isinstance(args, list):
        # A small model sometimes passes the one argument bare.
        args = {"expressions": args[0] if args and isinstance(args[0], list) else args}
    if skill == "flights":
        marathon.ROUTES.insert(0, (args["origin"], args["destination"], args["date"]))
        return marathon.task_flights(0, memory)
    if skill == "news":
        marathon.SECTIONS.insert(0, args.get("section", "India"))
        return marathon.task_news(0, memory)
    if skill == "wikipedia":
        marathon.TOPICS.insert(0, args["topic"])
        return marathon.task_wiki(0, memory)
    if skill == "calculate":
        return calc_task(args["expressions"], memory)
    if skill == "word_report":
        return marathon.task_word(f"{n} {args.get('title', '')}".strip(), memory)
    if skill == "note":
        return note_task(args.get("name", f"note-{n}"), args.get("text", ""), memory)
    if skill == "check_files":
        return marathon.task_explorer(n, memory)
    raise ValueError(f"no skill {skill}")


def calc_task(expressions, memory):
    title, steps, check = marathon.task_calc(0, memory)
    # Rebuild the sums part of the plan with the goal's own expressions.
    steps = marathon.run_box("calc", {"window": "Calculator"})
    for expr in expressions:
        steps += [{"key": "Escape"}, {"type": f"{expr}=", "expect": {"shows": "Display is"}, "echo": True}, {"read": "Display is"}]
    def checked(reads):
        got = [r for r in sum(reads, []) if r.startswith("Display is")]
        results, good = [], 0
        for expr, line in zip(expressions, got):
            shown = float(line.replace("Display is", "").replace(",", "").strip())
            want = marathon.left_to_right(expr)
            good += abs(shown - want) <= 1e-9 * max(1, abs(want))
            results.append(f"{expr} = {line.replace('Display is ', '')}")
        memory["calc"] = results
        return good == len(expressions), f"{good}/{len(expressions)} right"
    return "calculator", steps, checked


def note_task(name, text, memory):
    name = name if name.endswith(".txt") else name + ".txt"
    if "{results}" in text or not text:
        text = text.replace("{results}", "") + "\n".join(memory.get("calc", []))
    steps = marathon.run_box("notepad", {"window": "Notepad"}) + [
        {"key": "ctrl+n"}, {"type": text + "\n"},
        {"key": "ctrl+s", "expect": {"window": "Save as"}, "expect_ms": 8000},
        {"type": name, "into": "File name"},
        {"key": "Enter", "expect": {"window": name}, "expect_ms": 8000},
        {"key": "ctrl+w", "when": {"window": name}},
    ]
    def check(reads):
        memory.setdefault("files", []).append(name)
        return True, name
    return f"note {name}", steps, check


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host-id", required=True)
    ap.add_argument("goals", nargs="+")
    args = ap.parse_args()
    runner = fastlane.Runner(args.host_id)
    memory, out = {}, []
    try:
        for g, goal in enumerate(args.goals):
            started = time.time()
            calls, plan_ms = plan_goal(goal)
            record = {"goal": goal, "plan_ms": plan_ms, "calls": calls, "tasks": []}
            if not calls:
                record["unanswered"] = "no skill fits; needs a larger planner"
            for n, call in enumerate(calls):
                title, steps, check = task_for(call, g * 10 + n, memory)
                first = len(runner.log)
                ok = True
                try:
                    for step in steps:
                        if not runner.step(step):
                            ok = False
                            break
                except RuntimeError as e:
                    ok = False
                    runner.note({"t": runner.now(), "error": str(e)[:200]})
                reads = [e["read"] for e in runner.log[first:] if "read" in e]
                passed, detail = check(reads) if ok else (False, "stopped")
                record["tasks"].append({"task": title, "passed": passed, "detail": detail})
                print("TASK " + json.dumps(record["tasks"][-1]), file=sys.stderr, flush=True)
                if not ok:
                    break
            record["seconds"] = round(time.time() - started, 2)
            out.append(record)
            print("GOAL " + json.dumps(record), file=sys.stderr, flush=True)
    finally:
        runner.close()
    print(json.dumps({"goals": out, "memory": memory}, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
