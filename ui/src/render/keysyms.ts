/**
 * KeyboardEvent -> X11 keysym + X11 (evdev+8) keycode mapping.
 *
 * keysym: for printable characters we derive from `event.key` (Unicode rule:
 * codepoint < 0x100 maps directly; otherwise 0x01000000 + codepoint). Special
 * keys come from the table below, keyed by `event.key` or `event.code`.
 */

const KEY_TO_KEYSYM: Record<string, number> = {
  Backspace: 0xff08,
  Tab: 0xff09,
  Clear: 0xff0b,
  Enter: 0xff0d,
  Pause: 0xff13,
  ScrollLock: 0xff14,
  Escape: 0xff1b,
  Delete: 0xffff,
  Home: 0xff50,
  ArrowLeft: 0xff51,
  ArrowUp: 0xff52,
  ArrowRight: 0xff53,
  ArrowDown: 0xff54,
  PageUp: 0xff55,
  PageDown: 0xff56,
  End: 0xff57,
  Insert: 0xff63,
  ContextMenu: 0xff67,
  PrintScreen: 0xff61,
  NumLock: 0xff7f,
  CapsLock: 0xffe5,
  F1: 0xffbe, F2: 0xffbf, F3: 0xffc0, F4: 0xffc1, F5: 0xffc2, F6: 0xffc3,
  F7: 0xffc4, F8: 0xffc5, F9: 0xffc6, F10: 0xffc7, F11: 0xffc8, F12: 0xffc9,
  F13: 0xffca, F14: 0xffcb, F15: 0xffcc, F16: 0xffcd, F17: 0xffce, F18: 0xffcf,
  F19: 0xffd0, F20: 0xffd1,
};

/** Modifier keysyms depend on left/right, so key off `event.code`. */
const CODE_TO_KEYSYM: Record<string, number> = {
  ShiftLeft: 0xffe1,
  ShiftRight: 0xffe2,
  ControlLeft: 0xffe3,
  ControlRight: 0xffe4,
  AltLeft: 0xffe9,
  AltRight: 0xffea,
  MetaLeft: 0xffeb, // Super_L
  MetaRight: 0xffec,
  OSLeft: 0xffeb,
  OSRight: 0xffec,
  NumpadEnter: 0xff8d,
  NumpadMultiply: 0xffaa,
  NumpadAdd: 0xffab,
  NumpadSubtract: 0xffad,
  NumpadDecimal: 0xffae,
  NumpadDivide: 0xffaf,
  Numpad0: 0xffb0, Numpad1: 0xffb1, Numpad2: 0xffb2, Numpad3: 0xffb3,
  Numpad4: 0xffb4, Numpad5: 0xffb5, Numpad6: 0xffb6, Numpad7: 0xffb7,
  Numpad8: 0xffb8, Numpad9: 0xffb9,
};

/**
 * `event.code` -> XT (PC set 1) scancode, what the QEMU Extended Key Event
 * actually carries.
 *
 * This used to be a table of X11 keycodes (evdev + 8) and they were sent
 * verbatim, which silently typed the WRONG KEY on every server that
 * negotiates the extension. The two numberings are offset by 8, so Backspace
 * (X11 22 = 0x16) arrived as XT 0x16, which is the U key: pressing backspace
 * typed "u". Everything in the main block was shifted the same way.
 *
 * evdev keycodes 1..88 were deliberately chosen to equal XT set-1 scancodes,
 * so the main block is just `x11 - 8`; it is written out in full anyway
 * because the extended keys are NOT (they carry an 0xE0 prefix), and a table
 * that is half arithmetic and half exceptions is how the next person
 * reintroduces this bug.
 */
const CODE_TO_XT_SCANCODE: Record<string, number> = {
  Escape: 0x01,
  Digit1: 0x02, Digit2: 0x03, Digit3: 0x04, Digit4: 0x05, Digit5: 0x06,
  Digit6: 0x07, Digit7: 0x08, Digit8: 0x09, Digit9: 0x0a, Digit0: 0x0b,
  Minus: 0x0c, Equal: 0x0d, Backspace: 0x0e, Tab: 0x0f,
  KeyQ: 0x10, KeyW: 0x11, KeyE: 0x12, KeyR: 0x13, KeyT: 0x14, KeyY: 0x15,
  KeyU: 0x16, KeyI: 0x17, KeyO: 0x18, KeyP: 0x19,
  BracketLeft: 0x1a, BracketRight: 0x1b, Enter: 0x1c, ControlLeft: 0x1d,
  KeyA: 0x1e, KeyS: 0x1f, KeyD: 0x20, KeyF: 0x21, KeyG: 0x22, KeyH: 0x23,
  KeyJ: 0x24, KeyK: 0x25, KeyL: 0x26, Semicolon: 0x27, Quote: 0x28,
  Backquote: 0x29, ShiftLeft: 0x2a, Backslash: 0x2b,
  KeyZ: 0x2c, KeyX: 0x2d, KeyC: 0x2e, KeyV: 0x2f, KeyB: 0x30, KeyN: 0x31,
  KeyM: 0x32, Comma: 0x33, Period: 0x34, Slash: 0x35, ShiftRight: 0x36,
  NumpadMultiply: 0x37, AltLeft: 0x38, Space: 0x39, CapsLock: 0x3a,
  F1: 0x3b, F2: 0x3c, F3: 0x3d, F4: 0x3e, F5: 0x3f,
  F6: 0x40, F7: 0x41, F8: 0x42, F9: 0x43, F10: 0x44,
  NumLock: 0x45, ScrollLock: 0x46,
  Numpad7: 0x47, Numpad8: 0x48, Numpad9: 0x49, NumpadSubtract: 0x4a,
  Numpad4: 0x4b, Numpad5: 0x4c, Numpad6: 0x4d, NumpadAdd: 0x4e,
  Numpad1: 0x4f, Numpad2: 0x50, Numpad3: 0x51, Numpad0: 0x52,
  NumpadDecimal: 0x53,
  IntlBackslash: 0x56, F11: 0x57, F12: 0x58,

  // Extended (grey) keys: XT prefixes these with 0xE0, and the QEMU extended
  // key event carries the prefix in the high byte. Sending the bare low byte
  // would hit the numpad twin of each one (Home would become Numpad7).
  NumpadEnter: 0xe01c, ControlRight: 0xe01d, NumpadDivide: 0xe035,
  AltRight: 0xe038, Home: 0xe047, ArrowUp: 0xe048, PageUp: 0xe049,
  ArrowLeft: 0xe04b, ArrowRight: 0xe04d, End: 0xe04f, ArrowDown: 0xe050,
  PageDown: 0xe051, Insert: 0xe052, Delete: 0xe053,
  MetaLeft: 0xe05b, MetaRight: 0xe05c, ContextMenu: 0xe05d,
  PrintScreen: 0xe037,
};

export interface KeyIds {
  keysym: number;
  /**
   * XT (PC set 1) scancode for the QEMU Extended Key Event; 0 when unknown,
   * which makes the session fall back to the plain keysym-only KeyEvent.
   */
  keycode: number;
}

export function keyEventToIds(e: Pick<KeyboardEvent, "key" | "code">): KeyIds | null {
  const keycode = CODE_TO_XT_SCANCODE[e.code] ?? 0;
  const fromCode = CODE_TO_KEYSYM[e.code];
  if (fromCode !== undefined) return { keysym: fromCode, keycode };
  const fromKey = KEY_TO_KEYSYM[e.key];
  if (fromKey !== undefined) return { keysym: fromKey, keycode };
  if (e.key.length === 1) {
    const cp = e.key.codePointAt(0);
    if (cp === undefined) return null;
    const keysym = cp < 0x100 ? cp : 0x01000000 + cp;
    return { keysym, keycode };
  }
  if (e.key === "Dead") return null; // dead keys: wait for the composed character
  return null;
}

/** Well-known keysyms for the "Send key" menu. */
export const KEYSYM = {
  Control_L: 0xffe3,
  Alt_L: 0xffe9,
  Delete: 0xffff,
  Super_L: 0xffeb,
  Tab: 0xff09,
  Escape: 0xff1b,
  F4: 0xffc1,
} as const;
