/**
 * The pane layout tree: how one tab's area is carved up between sessions.
 *
 * A tab used to hold exactly one session filling the whole area. It now holds
 * a tree: leaves are panes, and a split node divides its area between two or
 * more children along one axis. Splitting, closing and dragging a divider are
 * all rewrites of this tree, and every one of them is a pure function here so
 * the shell can stay a thin renderer over the result.
 *
 * Two decisions are worth stating up front, because everything else follows
 * from them.
 *
 * The tree is n-ary, not binary. Splitting the left pane of a two pane row a
 * second time gives one row of three, not a row containing a nested row, so
 * dragging the middle divider moves exactly two neighbours and leaves the
 * third alone. A binary tree would have made that drag resize a subtree, which
 * is the behaviour people complain about in editors that use one. The rule
 * that keeps it n-ary is the flattening invariant: a split never directly
 * contains a split along the same axis.
 *
 * Panes carry an identity of their own, separate from the session shown in
 * them. `sessionId` is nullable, so an empty pane waiting for the user to pick
 * a host is representable, and moving a session from one pane to another is a
 * change of two fields rather than a change of shape. That matters more than
 * it looks: the shell keys mounted viewers by session id, so a session keeps
 * its connection across any rearrangement of the tree.
 *
 * Geometry is computed in pixels against a measured container rather than in
 * percentages, because dividers have a real thickness that has to come out of
 * the space before the weights are applied, and a percentage would leave a
 * fractional seam that drifts as the window resizes.
 */

/** Which way a split's children are laid out. */
export type Direction = "row" | "column";

/** Where a new pane goes relative to the one being split. */
export type Placement = "before" | "after";

/** A single pane: one rectangle showing at most one session. */
export interface LeafNode {
  kind: "leaf";
  /** Stable pane identity. Survives every rewrite in this module. */
  id: string;
  /** The session shown here, or null for a pane waiting for a connection. */
  sessionId: string | null;
}

/** An area divided between two or more children along one axis. */
export interface SplitNode {
  kind: "split";
  id: string;
  /** "row" lays children out left to right, "column" top to bottom. */
  dir: Direction;
  /** Always at least two, and never a split along `dir` (see flattening). */
  children: LayoutNode[];
  /**
   * One weight per child, in the same order. Only the ratios matter: the
   * absolute numbers are free to drift as long as they stay positive, which
   * lets a divider drag be a local edit of two entries.
   */
  weights: number[];
}

export type LayoutNode = LeafNode | SplitNode;

/** A pane's place on screen, in CSS pixels relative to the layout's origin. */
export interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** A pane, paired with the box it occupies. */
export interface PaneRect {
  pane: LeafNode;
  rect: Rect;
}

/** One draggable gap between two adjacent children of a split. */
export interface DividerRect {
  /** Unique within a layout, and stable while the tree keeps its shape. */
  id: string;
  /** The split whose weights this divider edits. */
  splitId: string;
  /** The gap after child `index`, so it moves children `index` and `index+1`. */
  index: number;
  /** The axis of the parent split. A "row" split has vertical dividers. */
  dir: Direction;
  rect: Rect;
}

export interface LayoutGeometry {
  panes: PaneRect[];
  dividers: DividerRect[];
}

/** How thin a pane may get when a divider is dragged, in CSS pixels. */
export const MIN_PANE_PX = 80;

let counter = 0;

/**
 * Ids are generated rather than derived from what a pane holds, because a pane
 * with no session in it still has to be addressable, and because a pane's
 * identity has to survive the session inside it being moved out.
 *
 * Note that a session may be in at most one pane across the whole window: the
 * shell keys its mounted viewers by session id, so two panes naming one
 * session would mean two viewers on one connection. `TabsContext` is where that
 * is enforced; nothing in this module depends on it.
 */
export function nextId(prefix: string): string {
  counter += 1;
  return `${prefix}-${counter}`;
}

export function leaf(sessionId: string | null, id: string = nextId("pane")): LeafNode {
  return { kind: "leaf", id, sessionId };
}

export function isLeaf(node: LayoutNode): node is LeafNode {
  return node.kind === "leaf";
}

/**
 * Every pane in the tree, in reading order: left to right within a row, top to
 * bottom within a column. Tab order and "next pane" both follow this, which is
 * why it is the tree's own order rather than a sort on the computed rects.
 */
export function panes(root: LayoutNode): LeafNode[] {
  if (isLeaf(root)) return [root];
  return root.children.flatMap(panes);
}

export function findPane(root: LayoutNode, paneId: string): LeafNode | null {
  return panes(root).find((p) => p.id === paneId) ?? null;
}

/** Every session currently placed somewhere in the tree, without duplicates. */
export function placedSessions(root: LayoutNode): string[] {
  const seen = new Set<string>();
  for (const p of panes(root)) if (p.sessionId) seen.add(p.sessionId);
  return [...seen];
}

/** The first pane holding this session, or null. */
export function paneForSession(root: LayoutNode, sessionId: string): LeafNode | null {
  return panes(root).find((p) => p.sessionId === sessionId) ?? null;
}

/**
 * Rebuild a split, collapsing it away if it no longer earns its place.
 *
 * A split with one child is not a split, and a split holding a split along the
 * same axis is the nested shape this module exists to avoid, so both are
 * dissolved here. Every rewrite below funnels through this, which is what
 * keeps the flattening invariant true by construction rather than by a pass
 * over the tree afterwards.
 */
function rebuild(split: SplitNode, children: LayoutNode[], weights: number[]): LayoutNode {
  if (children.length === 0) throw new Error("a split cannot be emptied");
  if (children.length === 1) return children[0];

  const flatChildren: LayoutNode[] = [];
  const flatWeights: number[] = [];
  children.forEach((child, i) => {
    if (child.kind === "split" && child.dir === split.dir) {
      // The inner split's weights are relative to each other; scale them so
      // they keep the same share of the outer split that the child had.
      // Never a division by zero unless a weight has gone wrong upstream, and
      // a NaN here would spread to every rectangle in the tab.
      const inner = total(child.weights) || child.children.length;
      child.children.forEach((grandchild, j) => {
        flatChildren.push(grandchild);
        flatWeights.push((weights[i] * child.weights[j]) / inner);
      });
    } else {
      flatChildren.push(child);
      flatWeights.push(weights[i]);
    }
  });

  return { kind: "split", id: split.id, dir: split.dir, children: flatChildren, weights: flatWeights };
}

function total(weights: readonly number[]): number {
  return weights.reduce((a, b) => a + b, 0);
}

/**
 * Put `added` beside the pane `paneId`, splitting along `dir`.
 *
 * The new pane takes half of the pane being split, never half of the whole
 * area, so splitting one pane of a busy layout disturbs only that pane. When
 * the pane already sits in a split along the same axis this inserts a sibling
 * rather than nesting, so a row of two becomes a row of three.
 *
 * Returns the tree unchanged if `paneId` is not in it.
 */
export function splitPane(
  root: LayoutNode,
  paneId: string,
  dir: Direction,
  added: LeafNode,
  place: Placement = "after",
): LayoutNode {
  if (isLeaf(root)) {
    if (root.id !== paneId) return root;
    const children = place === "after" ? [root, added] : [added, root];
    return { kind: "split", id: nextId("split"), dir, children, weights: [1, 1] };
  }

  const index = root.children.findIndex(
    (child) => isLeaf(child) && child.id === paneId,
  );

  if (index >= 0 && root.dir === dir) {
    // Same axis: insert as a sibling and halve the split pane's own share, so
    // the other children keep exactly the widths they had.
    const half = root.weights[index] / 2;
    const children = root.children.slice();
    const weights = root.weights.slice();
    weights[index] = half;
    children.splice(place === "after" ? index + 1 : index, 0, added);
    weights.splice(place === "after" ? index + 1 : index, 0, half);
    return rebuild(root, children, weights);
  }

  const children = root.children.map((child) => splitPane(child, paneId, dir, added, place));
  if (children.every((child, i) => child === root.children[i])) return root;
  return rebuild(root, children, root.weights.slice());
}

/**
 * Take a pane out of the tree.
 *
 * Its space goes back to its siblings in proportion to what they already had,
 * which is what makes closing the middle of three panes look like the divider
 * simply disappeared. Returns null when the last pane goes, which the caller
 * reads as "this tab is now empty".
 */
export function closePane(root: LayoutNode, paneId: string): LayoutNode | null {
  if (isLeaf(root)) return root.id === paneId ? null : root;

  const index = root.children.findIndex(
    (child) => isLeaf(child) && child.id === paneId,
  );
  if (index >= 0) {
    const children = root.children.filter((_, i) => i !== index);
    const weights = root.weights.filter((_, i) => i !== index);
    return rebuild(root, children, weights);
  }

  const children: LayoutNode[] = [];
  const weights: number[] = [];
  let changed = false;
  root.children.forEach((child, i) => {
    const next = closePane(child, paneId);
    if (next !== child) changed = true;
    if (next !== null) {
      children.push(next);
      weights.push(root.weights[i]);
    }
  });
  if (!changed) return root;
  if (children.length === 0) return null;
  return rebuild(root, children, weights);
}

/** Point a pane at a different session, or at none. */
export function setPaneSession(
  root: LayoutNode,
  paneId: string,
  sessionId: string | null,
): LayoutNode {
  if (isLeaf(root)) {
    if (root.id !== paneId || root.sessionId === sessionId) return root;
    return { ...root, sessionId };
  }
  const children = root.children.map((child) => setPaneSession(child, paneId, sessionId));
  if (children.every((child, i) => child === root.children[i])) return root;
  return { ...root, children };
}

/**
 * Exchange the sessions in two panes.
 *
 * Deliberately a swap of contents rather than a move of nodes: the panes keep
 * their boxes, so the two views trade places without the layout reflowing
 * around them, and dropping a session onto an occupied pane has an obvious
 * meaning instead of needing a rule about where the displaced one goes.
 */
export function swapPanes(root: LayoutNode, a: string, b: string): LayoutNode {
  if (a === b) return root;
  const first = findPane(root, a);
  const second = findPane(root, b);
  if (!first || !second) return root;
  const once = setPaneSession(root, a, second.sessionId);
  return setPaneSession(once, b, first.sessionId);
}

/**
 * Move the divider after child `index` of `splitId` by `deltaPx`.
 *
 * The drag is applied against the split's own extent in pixels rather than
 * against the whole layout, so a divider inside a nested split tracks the
 * pointer at the same speed as one at the top level. Only the two children
 * either side of the divider change, and neither is allowed below
 * {@link MIN_PANE_PX}, so a hard drag parks a pane at its minimum instead of
 * collapsing it to nothing and stranding whatever was connected inside it.
 */
export function resizeSplit(
  root: LayoutNode,
  splitId: string,
  index: number,
  deltaPx: number,
  splitExtentPx: number,
): LayoutNode {
  if (isLeaf(root)) return root;

  if (root.id === splitId) {
    if (index < 0 || index + 1 >= root.children.length) return root;
    const sum = total(root.weights);
    if (sum <= 0 || splitExtentPx <= 0) return root;
    const perPx = sum / splitExtentPx;
    const before = root.weights[index];
    const after = root.weights[index + 1];
    const min = MIN_PANE_PX * perPx;
    // Clamping the delta rather than the results keeps the pair's combined
    // weight exactly what it was, so the rest of the split never shifts.
    const lower = min - before;
    const upper = after - min;
    // Both panes are already at or under the minimum, which happens in a
    // window too narrow to honour it. Refusing the drag outright is the only
    // safe answer: clamping to a range whose lower bound is above its upper
    // bound returns the wrong end, and the wrong end here is a delta pointing
    // the opposite way to the pointer. That inverted drag then wrote a
    // negative weight, which `splitPane` halves and `rebuild` scales, so one
    // hard drag in a narrow window corrupted the tree for good.
    if (upper <= lower) return root;
    const wanted = deltaPx * perPx;
    const delta = Math.max(lower, Math.min(upper, wanted));
    if (delta === 0 || !Number.isFinite(delta)) return root;
    const weights = root.weights.slice();
    weights[index] = before + delta;
    weights[index + 1] = after - delta;
    return { ...root, weights };
  }

  const children = root.children.map((child) =>
    resizeSplit(child, splitId, index, deltaPx, splitExtentPx),
  );
  if (children.every((child, i) => child === root.children[i])) return root;
  return { ...root, children };
}

/** Give every child of a split the same share, the way tmux's even layouts do. */
export function evenSplit(root: LayoutNode, splitId: string): LayoutNode {
  if (isLeaf(root)) return root;
  if (root.id === splitId) return { ...root, weights: root.children.map(() => 1) };
  const children = root.children.map((child) => evenSplit(child, splitId));
  if (children.every((child, i) => child === root.children[i])) return root;
  return { ...root, children };
}

/** Give every split in the tree equal shares. */
export function evenAll(root: LayoutNode): LayoutNode {
  if (isLeaf(root)) return root;
  return {
    ...root,
    children: root.children.map(evenAll),
    weights: root.children.map(() => 1),
  };
}

/**
 * Turn the tree into boxes.
 *
 * Child boundaries are accumulated as floats and rounded once, at the edge, so
 * adjacent panes share an exact pixel boundary and the rounding error cannot
 * accumulate into a visible seam at the far end of a wide row.
 */
export function layoutGeometry(root: LayoutNode, area: Rect, gap: number): LayoutGeometry {
  const out: LayoutGeometry = { panes: [], dividers: [] };
  walk(root, area, gap, out);
  return out;
}

function walk(node: LayoutNode, area: Rect, gap: number, out: LayoutGeometry): void {
  if (isLeaf(node)) {
    out.panes.push({ pane: node, rect: area });
    return;
  }

  const horizontal = node.dir === "row";
  const extent = horizontal ? area.width : area.height;
  const gaps = gap * (node.children.length - 1);
  // A layout squeezed below the space its dividers need would produce negative
  // widths, and a negative width on an absolutely positioned canvas is a
  // console error per frame rather than a visible mistake. Floor it instead.
  const usable = Math.max(0, extent - gaps);
  // Guarded on the sum being unusable rather than merely falsy: weights are
  // positive by construction, and anything else is a bug whose blast radius
  // should be one badly proportioned split, not a tab full of NaN.
  const weights = total(node.weights) > 0 ? node.weights : node.children.map(() => 1);
  const sum = total(weights);

  let cursor = 0;
  node.children.forEach((child, i) => {
    const share = Math.max(0, (usable * weights[i]) / sum);
    const start = Math.round(cursor);
    const end = Math.round(cursor + share);
    const size = Math.max(0, end - start);
    const offset = start + gap * i;

    walk(
      child,
      horizontal
        ? { x: area.x + offset, y: area.y, width: size, height: area.height }
        : { x: area.x, y: area.y + offset, width: area.width, height: size },
      gap,
      out,
    );

    if (i < node.children.length - 1) {
      const at = area.x + offset;
      const down = area.y + offset;
      out.dividers.push({
        id: `${node.id}:${i}`,
        splitId: node.id,
        index: i,
        dir: node.dir,
        rect: horizontal
          ? { x: at + size, y: area.y, width: gap, height: area.height }
          : { x: area.x, y: down + size, width: area.width, height: gap },
      });
    }
    cursor += share;
  });
}

/** The pixel extent of a split along its own axis, needed to scale a drag. */
export function splitExtent(root: LayoutNode, splitId: string, area: Rect, gap: number): number {
  const found = findSplitArea(root, splitId, area, gap);
  if (!found) return 0;
  const node = found.node;
  const extent = node.dir === "row" ? found.area.width : found.area.height;
  return Math.max(0, extent - gap * (node.children.length - 1));
}

function findSplitArea(
  node: LayoutNode,
  splitId: string,
  area: Rect,
  gap: number,
): { node: SplitNode; area: Rect } | null {
  if (isLeaf(node)) return null;
  if (node.id === splitId) return { node, area };

  const horizontal = node.dir === "row";
  const extent = horizontal ? area.width : area.height;
  const usable = Math.max(0, extent - gap * (node.children.length - 1));
  // Same fallback as `walk`, and it has to be the same or this would measure a
  // split against proportions the renderer did not use.
  const weights = total(node.weights) > 0 ? node.weights : node.children.map(() => 1);
  const sum = total(weights);

  let cursor = 0;
  for (let i = 0; i < node.children.length; i += 1) {
    const share = Math.max(0, (usable * weights[i]) / sum);
    const start = Math.round(cursor);
    const size = Math.max(0, Math.round(cursor + share) - start);
    const offset = start + gap * i;
    const childArea = horizontal
      ? { x: area.x + offset, y: area.y, width: size, height: area.height }
      : { x: area.x, y: area.y + offset, width: area.width, height: size };
    const hit = findSplitArea(node.children[i], splitId, childArea, gap);
    if (hit) return hit;
    cursor += share;
  }
  return null;
}

/**
 * How many columns a grid of `count` panes should use.
 *
 * The obvious rule, `ceil(sqrt(n))`, gives 3 columns for 8 and leaves a ragged
 * row of two under a row of three. Screens are wider than they are tall, so the
 * counts people actually ask for read better slightly wide, and they are few
 * enough to simply name. Everything else falls back to the square rule, which
 * is never embarrassing even when it is not what a human would have drawn.
 */
function gridColumns(count: number): number {
  switch (count) {
    case 2:
    case 3:
      return count;
    case 4:
      return 2;
    case 6:
      return 3;
    case 8:
      return 4;
    case 10:
      return 5;
    case 12:
      return 4;
    default:
      return Math.ceil(Math.sqrt(count));
  }
}

/**
 * A ready made grid of `count` panes, filled from `sessionIds` in reading
 * order and left empty wherever that list runs out.
 *
 * Rows are built as a column split of row splits, which is the same shape
 * splitting by hand would have produced, so every later split, close and
 * divider drag behaves exactly as it does on a layout the user built up
 * themselves. A last row with fewer panes than the others stretches to fill
 * its width rather than leaving a gap, which falls out of the weights and is
 * what makes an awkward count like 7 still look deliberate.
 */
export function gridLayout(count: number, sessionIds: readonly (string | null)[] = []): LayoutNode {
  const total = Math.max(1, Math.floor(count));
  const next = (i: number): LeafNode => leaf(sessionIds[i] ?? null);
  if (total === 1) return next(0);

  const columns = Math.min(gridColumns(total), total);
  const rows: LayoutNode[] = [];
  for (let start = 0; start < total; start += columns) {
    const width = Math.min(columns, total - start);
    const cells = Array.from({ length: width }, (_, i) => next(start + i));
    rows.push(
      width === 1
        ? cells[0]
        : { kind: "split", id: nextId("split"), dir: "row", children: cells, weights: cells.map(() => 1) },
    );
  }

  if (rows.length === 1) return rows[0];
  return { kind: "split", id: nextId("split"), dir: "column", children: rows, weights: rows.map(() => 1) };
}

export type Side = "left" | "right" | "up" | "down";

/**
 * The pane to move the focus to, chosen by geometry rather than by tree shape.
 *
 * Walking the tree for this gives answers that surprise people, because "the
 * pane to my right" is a thing the user reads off the screen, not off the
 * nesting. So this does what tmux does: take the candidates that genuinely lie
 * on that side and overlap this pane across the perpendicular axis, and among
 * them prefer the nearest edge, breaking a tie on the pane whose centre is
 * closest to ours. Returns null at the edge of the layout.
 */
export function neighbour(geometry: LayoutGeometry, paneId: string, side: Side): string | null {
  const from = geometry.panes.find((p) => p.pane.id === paneId);
  if (!from) return null;
  const a = from.rect;
  const horizontal = side === "left" || side === "right";

  let best: { id: string; gap: number; offset: number } | null = null;
  for (const { pane, rect: b } of geometry.panes) {
    if (pane.id === paneId) continue;

    // Does it lie on the right side of us at all, and is it a neighbour rather
    // than something further along past another pane?
    const gap = side === "right" ? b.x - (a.x + a.width)
      : side === "left" ? a.x - (b.x + b.width)
      : side === "down" ? b.y - (a.y + a.height)
      : a.y - (b.y + b.height);
    if (gap < 0) continue;

    // Overlap across the other axis, or a pane in the next column that starts
    // below this one would count as being "to the right".
    const overlap = horizontal
      ? Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y)
      : Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x);
    if (overlap <= 0) continue;

    const offset = horizontal
      ? Math.abs(b.y + b.height / 2 - (a.y + a.height / 2))
      : Math.abs(b.x + b.width / 2 - (a.x + a.width / 2));

    if (!best || gap < best.gap || (gap === best.gap && offset < best.offset)) {
      best = { id: pane.id, gap, offset };
    }
  }
  return best?.id ?? null;
}

/** The next or previous pane in reading order, wrapping. Cmd+] and Cmd+[. */
export function cyclePane(root: LayoutNode, paneId: string, delta: number): string | null {
  const list = panes(root);
  if (list.length === 0) return null;
  const index = list.findIndex((p) => p.id === paneId);
  if (index < 0) return list[0].id;
  const size = list.length;
  return list[(((index + delta) % size) + size) % size].id;
}

/**
 * The divider a pointer is over, with a little slack either side.
 *
 * A divider is only a few pixels wide, which is a smaller target than a mouse
 * comfortably hits, so the hit box is grown without growing the drawn gap.
 */
export function dividerAt(
  geometry: LayoutGeometry,
  x: number,
  y: number,
  slack = 3,
): DividerRect | null {
  for (const divider of geometry.dividers) {
    const r = divider.rect;
    if (
      x >= r.x - slack &&
      x <= r.x + r.width + slack &&
      y >= r.y - slack &&
      y <= r.y + r.height + slack
    ) {
      return divider;
    }
  }
  return null;
}
