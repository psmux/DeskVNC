# Session screen

The remote desktop viewer of the phone app. `SessionScreen.tsx` exports
`SessionScreen` with props `{ api, target, title, onExit }`.

## Files

| Path | What it does |
|---|---|
| `SessionScreen.tsx` | The screen: stage, gestures, toolbar, key bar, sheets |
| `useRemoteSession.ts` | Connect, frames to the renderer, events, background and return |
| `render/` | WebGL2 renderer and frame parser, copied from the desktop `ui/src/render/` |
| `input/packets.ts` | Input bodies in the `send_input` layout, `InputSender` with `x-input-seq` |
| `input/gestures.ts` | Touch gestures as a pure state machine |
| `input/viewport.ts` | Zoom and pan math |
| `input/keys.ts` | Key bar keys, sticky modifiers, the hidden text field differ |
| `input/keysyms.ts` | Copied from the desktop `ui/src/render/keysyms.ts` |
| `ui/` | Connecting scene, toolbar, key bar, coach, sheets, illustrations |
| `dev/` | A dev page with a pretend computer, see below |
| `preview/` | Screenshots from the dev page |

## Gestures

Trackpad: slide one finger to move the pointer, tap to click, tap then slide
to hold the button, two finger tap for a right click, two finger slide to
scroll, three finger tap for the keyboard.

Touch: tap where you want to click, press and hold for a right click (a ring
fills first), slide one finger to drag, two finger slide to scroll.

Both: pinch to zoom around the fingers, with a glide when let go. A double
tap zooms in on a spot while the whole desktop is showing; once zoomed in, a
double tap is a double click so the desktop still gets those. When zoomed,
the view follows the pointer near the edges, and a drag that reaches an edge
slides the picture along. "Show the whole screen" zooms back out.

## Typing

The phone keyboard types into a hidden text field. `TextDiffer` compares the
field with what was already sent: what disappeared becomes backspaces, what
is new goes to `api.sessionText`. Autocorrect and suggestions work that way.
While an IME composes (Japanese, Chinese, Korean) nothing is sent until the
composition ends; Latin keyboards that compose every word (Android) are sent
letter by letter. With a key bar modifier lit, characters go as key events
with the modifier held, so Ctrl and C is a real Ctrl+C. Special keys from a
hardware keyboard (iPad, Android tablets) go straight through as key events.

## H.264 and the fallback

H.264 rects (format 3) decode with WebCodecs `VideoDecoder`, as on the
desktop. WKWebView has it from iOS 16.4 and Android System WebView from
Chrome 94. Where it is missing, `wireQuality` sends the "quality" preset
instead of "auto", so the computer keeps to JPEG and raw tiles, and the
quality sheet says so. If an H.264 rect still arrives, the renderer reports
`no-h264` and the screen switches to that preset and tells the person.

## App lifecycle

Going to the background sends release all keys and stops drawing. Coming
back starts drawing again, or, when the session ended meanwhile (Rust keeps
it about 30 seconds), shows a card with one Reconnect button.

## Dev page

```
npx vite mobile/ui/src/session/dev
```

Query strings pick a scenario: `?cred=1`, `?cred=user`, `?trunc=1`,
`?cert=1`, `?cert=change`, `?fail=1`, `?drop=5`, `?slow=1`, `?hold=1`, and
`?demo=1` to run against the app's own mock Api and the demo computer.
