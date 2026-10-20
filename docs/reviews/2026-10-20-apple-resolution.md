# Why the requested picture size varied between sessions

> Historical hypothesis, not a confirmed root-cause analysis. Superseded by
> [the resolution stabilization audit and repair plan](../plans/2026-10-20-apple-resolution-stabilization-plan.md)
> at `6933f0d`. The old serializer already used `max(request, prior cap)`, so
> the claim below that a small advertised cap necessarily prevented growth
> is not established. The mode-table explanation and the claim that the
> encoder always follows points also remain unverified. The newer audit
> reproduces false one-pixel rollback, stale rollback state, and stale local
> presentation, and records the required implementation and validation steps.

## What was observed

Two sessions to the same Mac, minutes apart, asked for the same thing and got
different answers. From the session log:

```
01:20:09  the Mac's own geometry width=3600 height=2338 logical=1800x1169
01:21:03  display resize requested pixels=(3600,2338) points=(1800,1169)
01:21:05  layout received bw=1600 bh=1200 lw=800 lh=600      <- 800x600 points
01:23:26  display resize requested pixels=(1800,1170) points=(1800,1169)
01:23:27  layout received bw=3600 bh=2338 lw=1800 lh=1169     <- accepted
```

A request for the Retina backing size was answered with a smaller desktop
(800x600 points). That reads as the view zooming in: fewer points for the same
windows.

## Where the number came from

`0x1d` SetDisplayConfiguration asks for a display mode. Three parts of that
message decide the outcome.

1. `max_width`/`max_height` bound the display. The daemon caps the display at
   this size and answers a request outside it with a fallback, not a clamp.
   We were writing the current desktop here, so a session that started from a
   small desktop could never ask for a large one, and the answer depended on
   the state the previous session left behind.
2. The mode table has to look like a display's mode list: several different
   point sizes, each with its backing size. We wrote the same point size five
   times with shrinking pixel sizes, and two entries were identical. A table
   that does not look like a display's is answered with the daemon's own
   fallback, which is where 800x600 came from.
3. Points and pixels are separate. A mode entry carries the desktop size in
   points and the backing in pixels. A quality change should move the pixels
   and leave the points alone; changing points is a display mode change and
   rearranges every window.

The reference client (`iShareScreen`, which interoperates with the daemon)
advertises `max = 3840x2160` unconditionally and scales a native mode template
to the requested desktop. Its own notes record the same behaviour:

> the server caps the virtual display at this backing size regardless of the
> mode-table entries. Larger requests get a server-side fallback (typically to
> a safe minimum).

## The fix

`display_config` now takes a request (desktop points plus pixels per point) and
a cap, and writes:

* `max_width`/`max_height` as the largest of the request, the panel, and the
  reference cap of 3840x2160, so a request is never outside its own bound.
* a mode table scaled from the native template, with entries at different
  point sizes, each entry's backing being its points times the ratio.
* the first entry equal to the requested desktop at the requested ratio.

Quality presets therefore express sharpness rather than size: Low is one pixel
per point, High is the panel's own ratio, and the desktop keeps its point size
in both. A request that still comes back smaller than it was asked for puts
the previous geometry back, so a failed quality change cannot leave the
desktop shrunk.

## What is still unknown

* Whether the daemon accepts a cap larger than the panel, and what it does with
  the extra room. Advertising only the panel is the more conservative reading,
  but it is also what produced the fallback when a session started small.
* Whether the media encoder follows the layout's backing size. Observations so
  far show it following the point size: a layout of 3600x2338 arrived as
  1800x1168. That would mean a Retina backing buys no sharpness over the media
  path. One live session with the new descriptor would settle it.
