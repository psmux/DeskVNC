/**
 * The colours a person can give a computer. `Host.color` stores the key.
 * Each has a main tone and a soft tint for backgrounds; both read well on the
 * light and the dark theme.
 */
export interface Swatch {
  key: string;
  label: string;
  main: string;
  soft: string;
  deep: string;
}

export const SWATCHES: Swatch[] = [
  { key: "violet", label: "Violet", main: "#7c5cff", soft: "#e9e3ff", deep: "#4b2fd1" },
  { key: "blue", label: "Blue", main: "#3b82f6", soft: "#dceaff", deep: "#1d4fb8" },
  { key: "teal", label: "Teal", main: "#14b8a6", soft: "#d3f5ef", deep: "#0b7d70" },
  { key: "green", label: "Green", main: "#3fbf5f", soft: "#dcf5e2", deep: "#23823a" },
  { key: "sun", label: "Sunshine", main: "#f5b52e", soft: "#fff0cc", deep: "#b57c06" },
  { key: "orange", label: "Orange", main: "#f97a3c", soft: "#ffe3d4", deep: "#c2501a" },
  { key: "rose", label: "Rose", main: "#f0508c", soft: "#ffdbe8", deep: "#b6245c" },
  { key: "slate", label: "Slate", main: "#64748b", soft: "#e3e8ef", deep: "#3c4757" },
];

export function swatch(key: string | null | undefined): Swatch {
  return SWATCHES.find((s) => s.key === key) ?? SWATCHES[0];
}
