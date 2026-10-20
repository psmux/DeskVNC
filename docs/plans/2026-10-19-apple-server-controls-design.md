# Apple server-side quality and physical display controls

Approved scope: two independent controls, not local rendering substitutions.

## Stream quality

Wire the existing quality action to verified server-side Apple settings. Probe ScaleFactor (0x08) and media re-offers on the current physical-console session, keeping H.264 4:2:0 hardware decoding and curtain off. Do not assume a documented framebuffer knob also affects the high-performance UDP encoder. Report requested versus effective state; reject unsupported presets explicitly. Capture decoded dimensions, received media bytes and picture cadence before/after. Do not label local grayscale or fewer locally displayed frames as server quality reduction.

Changes must preserve the authenticated control connection and valid SRTP keys, handle fresh stream identifiers/configuration packets and keyframes, and refresh geometry and input transforms together. Do not drop reference pictures to make presentation faster.

## Physical Mac display resolution

Separate from stream quality, with explicit selection and restore. Enumerate actual display modes and save the original mode before changing it. Apply only supported modes and verify the effective mode. Restore explicitly and on orderly disconnect where possible; do not promise restoration after a crash or network loss.

Apple SetDisplayConfiguration's virtual/private display path is not proof of physical display mode control. Never substitute a curtained virtual display. If physical mode changes require authenticated SSH/CoreGraphics, expose this additional transport and host-key trust requirement rather than hiding it. No credentials in logs, source, command arguments or temporary files. No silent SSH host-key acceptance.

## Validation

- Unit tests for wire messages, bounds, unchanged quality, rejection, rollback and key reuse.
- Live comparison of effective resolution, received bytes and picture cadence.
- Input checks at center and edges in windowed fit, fullscreen, zoom and pan.
- Preserve the last working stream when a setting is rejected; unsupported controls must not appear successfully applied.

## Initial findings

The current Apple driver ignores SetQuality and RequestResize. The existing offer always advertises the same capabilities. Built-in Screen Sharing physical-mode support has not been demonstrated. A read-only SSH key-authentication probe to the target failed authentication; no password was retrieved and no Mac settings were changed.
