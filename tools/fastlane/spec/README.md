# Fast lane spec, version 1

This is the contract between a reader, which turns a screen into a table, and a
runner, which carries out a plan of steps against that table with no model in
the loop. DeskVNC's reader is deskvnc-sense (Windows UI Automation). BrowserGlass
can map `pageMap()` into the same table. Each product keeps its own runner in
its own language, and every runner must pass the cases in `cases.json`.

The spec lives here until a second product uses it. Then it moves to a repo of
its own, and both products pin a version.

## The table

One read of the screen, as JSON.

```json
{
  "hash": "1234567890",
  "window": { "title": "Untitled - Notepad", "class": "Notepad" },
  "partial": true,
  "elements": [
    { "i": 1, "area": "window", "role": "button", "name": "Save",
      "x": 10, "y": 20, "w": 80, "h": 24,
      "value": "", "focus": true, "disabled": true, "checked": false }
  ]
}
```

* `hash` changes when anything in the table changes. It is a string, so a 64 bit number survives JavaScript.
* `window` is what is in front: a desktop window, or a browser page (title and URL host are a good pair).
* `partial` is present and true when the reader ran out of time and some controls are missing. A runner must not call a control missing on a partial table; it reads again first.
* `elements` are numbered from 1 in reading order.
* `area` is `window` for what is in front, anything else (`taskbar`, `toolbar`) for chrome around it.
* `role` is one of `button checkbox radio combobox textbox document link listitem menuitem tab treeitem row header slider text`.
* `x y w h` are screen pixels. A runner clicks the middle.
* `value`, `focus`, `disabled` and `checked` are left out when empty or false.

Readers may add fields. Runners ignore what they do not know.

## Steps

A plan is a list of steps. Each step does one of these:

```json
{"key": "super+r", "expect": {"window": "Run"}}
{"type": "notepad", "into": "Open"}
{"click": "Save", "expect": {"shows": "Saved"}}
{"read": "price|$", "limit": 15}
```

* `key` presses a key or chord, in DeskVNC's key names.
* `type` types text. With `into`, the runner finds that field, clicks it unless it has focus, and replaces what it held (`"replace": false` keeps it). Without `into`, the text goes where the caret is.
* `click` finds the named control and clicks its middle.
* `read` returns the text of rows holding any of the `|` separated words, or all rows when empty, at most `limit` (15).

Any step may also carry:

* `when`, a condition in the same form as `expect`. The step is skipped unless the screen meets it.
* `expect`, checked after the screen settles: `window` is a piece of the front window's title, `shows` a piece of any element's name or value. Both are case blind. `expect_ms` (4000) is how long to wait for it.
* `echo: true` on a `type` step: the typed letters and digits must then appear, in order, in some element's name and value. This catches a lost keystroke.

## Finding a control

`click` searches the roles `button checkbox radio combobox link listitem menuitem tab treeitem row header textbox document`. `into` searches `textbox combobox document`. Disabled rows are never picked.

1. Compare the wanted name with each row's name, case blind, with a trailing colon dropped from the row's name. Try equal, then starts with, then contains. The first test that matches anything decides the hits.
2. One hit is the answer. Several hits with exactly one focused: the focused one (a combo box and the edit inside it share a name).
3. Several hits otherwise: the closest, ordered by focused first, then `area` window over anything else, then the name nearest in length to the wanted name, then top, then left.
4. No hits: a near miss is allowed only when it shares a word with the wanted name. Words are runs of letters and digits, lower case, two characters or longer. A `document` is never a near miss. Pick among near misses as in 3.
5. Nothing: the control is missing. A runner never guesses.

## When a step fails

A step fails when its control is missing, or its expectation is not met in time, or its echo is not seen. Something the plan did not cause may be in front, so the runner recovers and tries the step again, twice at most.

Recovery looks for a button that sends the thing away:

1. Take `window` area rows with role `button` or `link`, not disabled.
2. Drop the window's caption buttons: any row within 6 pixels vertically of a row whose name starts with "minimize". Closing the app is never the way past a popup.
3. A row dismisses when its name, case blind and trimmed, equals a word in the list below, or starts with one of its phrases of two words or more. A name with the word "tab" in it never dismisses: closing something the person has open is never the way past a popup.
4. Click the row whose word comes earliest in the list. Ties go to the earlier row.
5. No such row: press Escape.

After a failed echo there is nothing to dismiss. Recovery presses Escape only.

The list, safest first:

```json
["not now", "no thanks", "no, thanks", "maybe later", "remind me later", "later", "skip", "dismiss",
 "got it", "close", "cancel", "don't allow", "block", "decline", "reject", "no"]
```

## Reading

`read` takes only `window` area rows. When the window holds `document` rows (a browser page), only rows inside the largest of them count, and the document row itself does not. A row's text is its name, followed by ` · ` and its value when it has one and is not a link. Empty text and repeats are skipped.

## Cases

`cases.json` holds the cases every runner must pass. Each case gives a table and one check. Rows in a case may leave out fields: `area` defaults to `window`, `x` and `y` to 0, `w` to 100, `h` to 20, `i` to the row's position counting from 1.

| check | input | want |
|---|---|---|
| `find` | `click` or `into` (the name) | the `i` of the row, or null |
| `recover` | `typo` (optional) | the `i` of the row to click, or `"Escape"` |
| `met` | `expect` | true or false |
| `read` | `read`, `limit` | the list of texts |
| `echo` | `type` | true or false |

Run them with `python3 spec/check.py` for the Python prototype and `cargo test -p fastlane-plan` for the Rust runner.
