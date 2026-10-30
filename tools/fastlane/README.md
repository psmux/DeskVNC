# The fast lane

An experiment in driving a desktop through DeskVNC as fast as the desktop can
go, with open source models only and nothing sent to a third party.

## Why an agent was slow

An agent like Claude driving DeskVNC spends almost all of its time thinking
between steps, about 3 to 6 seconds a turn, and every step is a turn: act,
wait, look, decide. DeskVNC itself answers in tens of milliseconds on a LAN.

## What the fast lane does instead

The large model writes the plan once. A loop with no large model in it carries
the plan out:

1. `deskvnc-sense` on the remote computer reads the screen's controls through
   UI Automation and serves them as numbered rows, each with its role, name,
   value and rectangle. One read takes about 40 ms on an MSI laptop.
2. Each plan step names its operation and the control by name, for example
   `{"type": "notepad", "into": "Open"}`. Code finds the control in the
   table. When a name is ambiguous, jevos picks among the best dozen matches
   in one request.
3. The action goes through DeskVNC (`dvv` over MCP), at the control's own
   rectangle.
4. The wait is `deskvnc-sense`'s settle: it reads the table until it changes
   and then reads it until two reads match. No timers; a step waits exactly as
   long as the screen keeps changing.
5. Each step can say what the screen should show afterwards (`expect`) and when
   it applies at all (`when`). A step whose expectation is not met stops the
   run and returns the table, so the planner sees the real screen and plans
   again from there.

A step the planner cannot spell out can be a free text `goal`. jevos then
picks the operation too. On the first runs it chose badly at this, so treat it
as a fallback.

## Models, all open source and on our own machines

* **jevos-v5** ([feder-cr/jev](https://github.com/feder-cr/jev), MIT): a
  decision model in TypeSafe Jev's request format. On its authors' tests it is
  the closest open model to Jev. On the AM5 it answers a yes/no question in
  16 ms.
* **Qwen2.5 3B Instruct** behind llama.cpp, only for text a plan step does
  not give. About 440 ms for a short answer on the AM5's CPU.

Laya was considered. Untuned, it scored about half of jevos's accuracy on the
same tests, so it would need fine tuning on our own cases first.

## Measured on the MSI, 2026-10-30

Escape, open the Run box, type `notepad`, press Enter, type a line into
Notepad: 5 actions in **5.27 s**, of which Notepad's own start took 2.35 s.
Closing the windows and answering a save prompt took 0.4 to 0.7 s a step. The
same kind of job driven by Claude turn by turn took 15 to 160 s.

## Running it

On the remote Windows computer, as the signed in user:

```powershell
$env:DESKVNC_SENSE_TOKEN = '<shared secret>'
Start-Process deskvnc-sense.exe '--connect <controller ip>:5942'
```

It dials the controller, so Windows asks for no inbound firewall rule.

On the controller:

```sh
FASTLANE_KEY=<shared secret> \
FASTLANE_JEV=http://<am5>:8017 FASTLANE_LLM=http://<am5>:8018 \
FASTLANE_DVV=/Applications/DeskVNCViewer.app/Contents/MacOS/dvv \
python3 tools/fastlane/fastlane.py --plan plan.json
```

```json
{"host_id": "<DeskVNC saved host id>",
 "steps": [
  {"key": "super+r", "expect": {"window": "Run"}},
  {"type": "notepad", "into": "Open"},
  {"key": "Enter", "expect": {"window": "Notepad"}},
  {"type": "hello", "into": "Text editor"}
 ]}
```

## Limits

* Windows only so far. macOS has the same kind of tree (the accessibility
  API), and it is the next reader to write.
* Apps that draw their own controls (games, some Electron and canvas apps)
  expose few rows. Those still need pixels.
* A plan that closes windows must name what it closes. Windows Notepad
  restores earlier sessions when it starts, so "close every Notepad" would
  have reached documents the plan never opened. The `when` guard limits a step
  to the screen it was written for.
