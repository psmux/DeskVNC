# The fast lane

An experiment in driving a desktop through DeskVNC as fast as the desktop can
go, with open source models only and nothing sent to a third party.

## Why an agent was slow

An agent like Claude driving DeskVNC spends almost all of its time thinking
between steps, about 3 to 6 seconds a turn, and every step is a turn: act,
wait, look, decide. DeskVNC itself answers in tens of milliseconds on a LAN.

## What the fast lane does instead

The agent (any agent, with whatever model it already uses) writes the plan
once. A loop with no model in it carries the plan out:

1. `deskvnc-sense` on the remote computer reads the screen's controls through
   UI Automation and serves them as numbered rows, each with its role, name,
   value and rectangle. One read takes about 40 ms on an MSI laptop. Reads run
   on worker threads with a 1.8 s deadline, so an app that stops answering
   (Excel does, for seconds at a time) gives a table marked `partial` with the
   window's title and class, never a stalled step.
2. Each plan step names its operation and the control by name, for example
   `{"type": "notepad", "into": "Open"}`. Code finds the control in the
   table by its name. Ties go to the focused control, then one in the window
   over the taskbar, then the closest name. A control that is not there is
   reported missing; nothing is guessed.
3. The action goes through DeskVNC (`dvv` over MCP), at the control's own
   rectangle.
4. Steps that say what the screen should show afterwards (`expect`) wait for
   it with `deskvnc-sense`'s settle: it reads the table until it changes and
   then until two reads match. Steps that expect nothing do not wait at all;
   the next step that needs the screen reads it.
5. Something the plan did not expect in front (a sign in offer, an "install
   this app" bubble) is sent away with the safest button from a fixed list
   ("Not now" before "Close"). Tab close buttons never count.

## Models

None are needed. jevos-v5 ([feder-cr/jev](https://github.com/feder-cr/jev),
MIT) is optional: set `FASTLANE_JEV` to a running `jev serve` and it breaks
ties between controls with the same name, picks among several dismiss
buttons, and allows free text `goal` steps. Without it, `goal` steps are
refused and the rules above decide.

Measured with no model on the MSI, 2026-10-30: the trip and market missions
(16 skills: flights, exchange rate, weather, Wikipedia, news, Calculator,
Excel with totals checked, Word, PowerPoint, Notepad, filing into folders)
passed 16 of 16 in 6.3 minutes, 211 actions, no recoveries, every window they
opened closed and nothing of the person's touched.

## Skills and missions

`skills.py` holds the tested skills; each checks its own result (Calculator
answers against the same sum done exactly, Excel totals copied back out of
Excel, saved files confirmed in Documents) and records what it opened.
`missions.py` chains skills, passing what one found to the next, and closes
exactly the windows that appeared during the run. `tidy.py` clears up after
a run that crashed. Window lists come from the sense, so nothing flashes on
screen.

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
