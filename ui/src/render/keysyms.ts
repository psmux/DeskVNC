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

/** `event.code` -> X11 keycode (evdev keycode + 8), for servers that prefer scancodes. */
const CODE_TO_X11_KEYCODE: Record<string, number> = {
  Escape: 9,
  Digit1: 10, Digit2: 11, Digit3: 12, Digit4: 13, Digit5: 14,
  Digit6: 15, Digit7: 16, Digit8: 17, Digit9: 18, Digit0: 19,
  Minus: 20, Equal: 21, Backspace: 22, Tab: 23,
  KeyQ: 24, KeyW: 25, KeyE: 26, KeyR: 27, KeyT: 28, KeyY: 29, KeyU: 30,
  KeyI: 31, KeyO: 32, KeyP: 33, BracketLeft: 34, BracketRight: 35, Enter: 36,
  ControlLeft: 37,
  KeyA: 38, KeyS: 39, KeyD: 40, KeyF: 41, KeyG: 42, KeyH: 43, KeyJ: 44,
  KeyK: 45, KeyL: 46, Semicolon: 47, Quote: 48, Backquote: 49, ShiftLeft: 50,
  Backslash: 51,
  KeyZ: 52, KeyX: 53, KeyC: 54, KeyV: 55, KeyB: 56, KeyN: 57, KeyM: 58,
  Comma: 59, Period: 60, Slash: 61, ShiftRight: 62,
  NumpadMultiply: 63, AltLeft: 64, Space: 65, CapsLock: 66,
  F1: 67, F2: 68, F3: 69, F4: 70, F5: 71, F6: 72, F7: 73, F8: 74, F9: 75, F10: 76,
  NumLock: 77, ScrollLock: 78,
  Numpad7: 79, Numpad8: 80, Numpad9: 81, NumpadSubtract: 82,
  Numpad4: 83, Numpad5: 84, Numpad6: 85, NumpadAdd: 86,
  Numpad1: 87, Numpad2: 88, Numpad3: 89, Numpad0: 90, NumpadDecimal: 91,
  IntlBackslash: 94, F11: 95, F12: 96,
  NumpadEnter: 104, ControlRight: 105, NumpadDivide: 106, PrintScreen: 107,
  AltRight: 108, Home: 110, ArrowUp: 111, PageUp: 112, ArrowLeft: 113,
  ArrowRight: 114, End: 115, ArrowDown: 116, PageDown: 117, Insert: 118,
  Delete: 119, Pause: 127, ContextMenu: 135, MetaLeft: 133, MetaRight: 134,
};

export interface KeyIds {
  keysym: number;
  /** X11 keycode (evdev + 8); 0 when unknown */
  keycode: number;
}

export function keyEventToIds(e: Pick<KeyboardEvent, "key" | "code">): KeyIds | null {
  const keycode = CODE_TO_X11_KEYCODE[e.code] ?? 0;
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
