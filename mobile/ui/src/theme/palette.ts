/**
 * The colours a person can give a computer. `Host.color` stores the key.
 *
 * The colour is a marker, the way a tag dot is on the desktop app: a small
 * dot beside the name and a thin edge on the card. It never fills a card or a
 * button, so the set is muted and every tone holds up on the light and the
 * dark theme alike.
 *
 * The keys are the ones saved by earlier versions, so a computer saved as
 * "sun" or "rose" still finds its colour. Only the tones and two labels moved.
 */
export interface Swatch {
  key: string;
  label: string;
  /** The marker colour: the dot, the edge, the picker circle. */
  main: string;
  /** A faint tint of it, for a selected state behind ink. */
  soft: string;
  /** A darker step, for a tick or text drawn on `soft`. */
  deep: string;
}

export const SWATCHES: Swatch[] = [
  { key: "blue", label: "Blue", main: "#4a7fd9", soft: "rgba(74, 127, 217, 0.14)", deep: "#2f5fae" },
  { key: "slate", label: "Slate", main: "#7a8494", soft: "rgba(122, 132, 148, 0.16)", deep: "#4f5867" },
  { key: "teal", label: "Teal", main: "#3a9a96", soft: "rgba(58, 154, 150, 0.14)", deep: "#26716e" },
  { key: "green", label: "Green", main: "#4f9a62", soft: "rgba(79, 154, 98, 0.14)", deep: "#36714a" },
  { key: "sun", label: "Amber", main: "#c09233", soft: "rgba(192, 146, 51, 0.16)", deep: "#8a6519" },
  { key: "orange", label: "Copper", main: "#c27349", soft: "rgba(194, 115, 73, 0.14)", deep: "#8f4f2c" },
  { key: "rose", label: "Rose", main: "#b9677c", soft: "rgba(185, 103, 124, 0.14)", deep: "#8a4458" },
  { key: "violet", label: "Violet", main: "#7f72c2", soft: "rgba(127, 114, 194, 0.14)", deep: "#5a4e98" },
];

/** The swatch for a saved key. An unknown or missing key gets the blue. */
export function swatch(key: string | null | undefined): Swatch {
  return SWATCHES.find((s) => s.key === key) ?? SWATCHES[0];
}
