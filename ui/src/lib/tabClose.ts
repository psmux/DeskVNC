/**
 * Which tabs a "Close ..." command from the tab strip's menu takes, and which
 * tab ends up in front afterwards.
 *
 * Pure so the rules can be tested without mounting the strip. They follow what
 * Chrome, Edge and Firefox do, since that is the habit everyone brings.
 */

export type CloseScope = "this" | "others" | "left" | "right" | "all";

/**
 * Ids of the tabs `scope` closes, counted from `id`. An `id` that is not in
 * `ids` closes nothing, except for "all", which does not depend on one.
 */
export function tabsToClose(
  ids: readonly string[],
  id: string | null,
  scope: CloseScope,
): string[] {
  if (scope === "all") return [...ids];
  const index = id === null ? -1 : ids.indexOf(id);
  if (index < 0) return [];
  switch (scope) {
    case "this":
      return [id as string];
    case "others":
      return ids.filter((other) => other !== id);
    case "left":
      return ids.slice(0, index);
    case "right":
      return ids.slice(index + 1);
  }
}

/**
 * The tab in front once `closing` are gone.
 *
 * A tab that survives stays in front. When the front tab goes, the nearest
 * survivor to its right takes over, then the nearest to its left, the way a
 * browser lands on a neighbour. Nothing left means the library (null).
 */
export function frontAfterClose(
  ids: readonly string[],
  activeId: string | null,
  closing: ReadonlySet<string>,
): string | null {
  if (activeId === null || !closing.has(activeId)) return activeId;
  const index = ids.indexOf(activeId);
  if (index < 0) return null;
  for (let i = index + 1; i < ids.length; i++) if (!closing.has(ids[i])) return ids[i];
  for (let i = index - 1; i >= 0; i--) if (!closing.has(ids[i])) return ids[i];
  return null;
}
