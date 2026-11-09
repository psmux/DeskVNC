/**
 * Boundary help codes. A code is twelve digits, shown and read aloud as three
 * groups of four (`1234 5678 9012`). A full invitation starts `boundary1:`.
 */

export const CODE_DIGITS = 12;
export const GROUP_SIZE = 4;

/** Only the digits, at most twelve. */
export function codeDigits(text: string): string {
  return text.replace(/\D/g, "").slice(0, CODE_DIGITS);
}

/** `123456789012` becomes `1234 5678 9012`; a partial code is grouped as far as it goes. */
export function formatCode(text: string): string {
  const digits = codeDigits(text);
  const groups: string[] = [];
  for (let i = 0; i < digits.length; i += GROUP_SIZE) groups.push(digits.slice(i, i + GROUP_SIZE));
  return groups.join(" ");
}

/** The three groups as arrays of single characters, blanks where nothing is typed yet. */
export function codeBoxes(text: string): string[][] {
  const digits = codeDigits(text);
  const out: string[][] = [];
  for (let g = 0; g < CODE_DIGITS / GROUP_SIZE; g++) {
    const row: string[] = [];
    for (let i = 0; i < GROUP_SIZE; i++) row.push(digits[g * GROUP_SIZE + i] ?? "");
    out.push(row);
  }
  return out;
}

export function isCompleteCode(text: string): boolean {
  return codeDigits(text).length === CODE_DIGITS;
}

export function isInvitation(text: string): boolean {
  return /^boundary1:\S+$/.test(text.trim());
}

export type PastedHelp =
  | { kind: "code"; digits: string }
  | { kind: "invitation"; invitation: string }
  | { kind: "nothing" };

/**
 * Make sense of whatever was on the clipboard. A message like "my code is
 * 1234-5678-9012, thanks" still yields the code, because people paste whole
 * messages, not just the number.
 */
export function readPastedHelp(text: string): PastedHelp {
  const trimmed = text.trim();
  const invite = /boundary1:\S+/.exec(trimmed);
  if (invite) return { kind: "invitation", invitation: invite[0] };
  const run = /(\d[\d\s.-]{10,}\d)/.exec(trimmed);
  if (run) {
    const digits = run[1].replace(/\D/g, "");
    if (digits.length === CODE_DIGITS) return { kind: "code", digits };
  }
  return { kind: "nothing" };
}
