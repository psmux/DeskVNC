/**
 * Saved pane arrangements, remembered against a group.
 *
 * A group is already the thing that means "these machines belong together", so
 * it is the natural place to hang "and this is how I like to see them". Opening
 * one as a grid connects every host in it at once and puts each where it was
 * left; a group that has never been saved opens as a plain grid in whatever
 * order the library lists it, which the user can then rearrange and save.
 *
 * What is stored is a tree of PROFILE ids, not session ids. A session lives
 * only as long as the connection does, so remembering one would remember
 * nothing by the time the group was opened again. The tree keeps its shape and
 * its divider positions, since the weights are what most of the arranging
 * actually was.
 *
 * This lives in `localStorage` next to `lib/viewPrefs` rather than in the Rust
 * store, for the same reason that one does: it is a decision the webview makes
 * about how to draw things, no part of the backend reads it, and a machine that
 * has never been arranged simply has nothing here.
 */
import {
  isLeaf,
  leaf,
  nextId,
  type LayoutNode,
} from "./layout";

const PREFIX = "deskvnc.grouplayout.";

/** The stored shape. Deliberately small, and versioned by the key prefix. */
type StoredNode =
  | { k: "l"; p: string | null }
  | { k: "s"; d: "row" | "column"; w: number[]; c: StoredNode[] };

function keyFor(groupId: string): string {
  return `${PREFIX}${groupId}`;
}

/**
 * Turn a live layout into something worth writing down.
 *
 * `resolve` maps a session id to the profile it was opened from. A session with
 * no profile behind it (an ad-hoc connect to a bare address) stores `null`: the
 * pane is remembered, the machine in it is not, because there is no saved host
 * to reconnect to and inventing one would put a surprise in the user's library.
 */
export function serializeLayout(
  root: LayoutNode,
  resolve: (sessionId: string) => string | null,
): string {
  const walk = (node: LayoutNode): StoredNode =>
    isLeaf(node)
      ? { k: "l", p: node.sessionId ? resolve(node.sessionId) : null }
      : { k: "s", d: node.dir, w: node.weights.slice(), c: node.children.map(walk) };
  return JSON.stringify(walk(root));
}

/**
 * Read a stored tree back, rejecting anything that is not one.
 *
 * Hand-edited or half-written storage has to be treated as absent rather than
 * trusted: a malformed weight would spread `NaN` through every rectangle in the
 * tab, and a split with one child would break the flattening invariant that the
 * rest of `lib/layout` maintains by construction.
 */
function parse(raw: string): StoredNode | null {
  const ok = (value: unknown): value is StoredNode => {
    if (typeof value !== "object" || value === null) return false;
    const node = value as Record<string, unknown>;
    if (node.k === "l") return node.p === null || typeof node.p === "string";
    if (node.k !== "s") return false;
    if (node.d !== "row" && node.d !== "column") return false;
    if (!Array.isArray(node.c) || node.c.length < 2) return false;
    if (!Array.isArray(node.w) || node.w.length !== node.c.length) return false;
    if (!node.w.every((n) => typeof n === "number" && Number.isFinite(n) && n > 0)) return false;
    return node.c.every(ok);
  };
  try {
    const value: unknown = JSON.parse(raw);
    return ok(value) ? value : null;
  } catch {
    return null;
  }
}

/** The profile ids a saved arrangement mentions, in reading order. */
export function savedProfiles(groupId: string): string[] {
  const stored = readStored(groupId);
  if (!stored) return [];
  const out: string[] = [];
  const walk = (node: StoredNode): void => {
    if (node.k === "l") {
      if (node.p) out.push(node.p);
      return;
    }
    node.c.forEach(walk);
  };
  walk(stored);
  return out;
}

function readStored(groupId: string): StoredNode | null {
  try {
    const raw = localStorage.getItem(keyFor(groupId));
    return raw ? parse(raw) : null;
  } catch {
    return null;
  }
}

/** Has this group been arranged before? */
export function hasSavedLayout(groupId: string): boolean {
  return readStored(groupId) !== null;
}

export function saveGroupLayout(groupId: string, serialized: string): void {
  try {
    localStorage.setItem(keyFor(groupId), serialized);
  } catch {
    /* storage unavailable: the arrangement is simply not remembered */
  }
}

export function forgetGroupLayout(groupId: string): void {
  try {
    localStorage.removeItem(keyFor(groupId));
  } catch {
    /* nothing to forget */
  }
}

/** A saved arrangement, rebuilt: the shape, and which pane wants which host. */
export interface RestoredLayout {
  /** Every pane empty. Connecting is the caller's job, and it is asynchronous. */
  root: LayoutNode;
  /** Where each remembered host goes, in reading order. */
  places: Array<{ paneId: string; profileId: string }>;
}

/**
 * Rebuild a saved arrangement, ready to be filled.
 *
 * The panes come back empty and paired with the host each one is waiting for,
 * rather than the caller matching hosts to panes by position: a pane whose host
 * was ad-hoc stored no profile at all, so the two lists are not the same length
 * and lining them up by index would put machines in the wrong places.
 *
 * Every pane is kept even if its host has since been deleted from the library.
 * An empty pane where a machine used to be shows a host picker pointing at the
 * hole, which is a better answer than quietly reflowing the arrangement the
 * user took the trouble to save.
 */
export function restoreLayout(groupId: string): RestoredLayout | null {
  const stored = readStored(groupId);
  if (!stored) return null;
  const places: RestoredLayout["places"] = [];
  const build = (node: StoredNode): LayoutNode => {
    if (node.k === "l") {
      const pane = leaf(null);
      if (node.p) places.push({ paneId: pane.id, profileId: node.p });
      return pane;
    }
    return {
      kind: "split",
      id: nextId("split"),
      dir: node.d,
      children: node.c.map(build),
      weights: node.w.slice(),
    };
  };
  const root = build(stored);
  return { root, places };
}
