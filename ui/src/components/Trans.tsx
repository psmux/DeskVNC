/**
 * A translated sentence with React nodes in place of some of its words.
 *
 * `t()` returns a string, so it cannot carry a `<strong>` or a link. This
 * splits the translated text and interleaves nodes, so the catalog still holds
 * one whole sentence per language: a translator sees the order the words
 * appear in and can move a placeholder without touching the call site.
 *
 * Two placeholder forms, both named in the catalog:
 *
 *   {name}          a node, replaced whole
 *   <name>...</name> a node wrapped around a run of text
 *
 * The paired form is what keeps emphasis translatable: the text between the
 * tags is part of the sentence, so it belongs in the catalog, and the tags only
 * say how to draw it.
 *
 *   <Trans text="Use {scan} to find computers, or {host} to add one."
 *          nodes={{ scan: <strong>Scan network</strong>, host: <strong>New Host</strong> }} />
 *   <Trans text="Do not continue <strong>unless you know why.</strong>"
 *          nodes={{ strong: <strong /> }} />
 */
import { cloneElement, Fragment, isValidElement, type ReactNode } from "react";
import { useT } from "../lib/i18n";

export function Trans({
  text,
  nodes,
}: {
  text: string;
  nodes: Record<string, ReactNode>;
}): ReactNode {
  const tr = useT();
  const parts = tr(text).split(/(<\/?[a-zA-Z]\w*>|\{\w+\})/);

  const out: ReactNode[] = [];
  /** Open paired tags, innermost last, so a close returns to the right node. */
  const stack: { name: string; children: ReactNode[] }[] = [];

  const push = (node: ReactNode): void => {
    if (stack.length > 0) stack[stack.length - 1].children.push(node);
    else out.push(node);
  };

  for (const part of parts) {
    if (part === "") continue;

    const selfClosing = /^\{(\w+)\}$/.exec(part);
    if (selfClosing) {
      // An unknown name stays on screen as `{name}`, which names the parameter
      // that was not provided instead of leaving an invisible gap.
      push(nodes[selfClosing[1]] ?? part);
      continue;
    }

    const open = /^<([a-zA-Z]\w*)>$/.exec(part);
    if (open) {
      // A node that is not supplied still has to consume its children, or the
      // close tag would be treated as text. Using a Fragment keeps the layout
      // of the sentence intact and just drops the styling.
      stack.push({ name: open[1], children: [] });
      continue;
    }

    const close = /^<\/([a-zA-Z]\w*)>$/.exec(part);
    if (close) {
      const top = stack.pop();
      // Unbalanced markup in a catalog should not crash a dialog: the text
      // still renders, just without the wrapper.
      if (!top) {
        push(part);
        continue;
      }
      const wrapper = nodes[top.name];
      if (wrapper === undefined) {
        for (const c of top.children) push(c);
      } else {
        // The node came from a call site as a bare element (for example
        // `<strong />`), so its own children are the text this split out.
        push(rewrite(wrapper, top.children));
      }
      continue;
    }

    push(part);
  }

  // Anything still open (a catalog with a missing close tag) is emitted
  // unwrapped rather than lost.
  while (stack.length > 0) {
    const top = stack.pop();
    if (top) for (const c of top.children) push(c);
  }

  return <>{out.map((n, i) => <Fragment key={i}>{n}</Fragment>)}</>;
}

/**
 * Put `children` inside an element the call site supplied.
 *
 * `cloneElement` would keep any children the call site had already given it,
 * and those are exactly the ones being replaced here.
 */
function rewrite(node: ReactNode, children: ReactNode[]): ReactNode {
  if (isValidElement<{ children?: ReactNode }>(node)) {
    return cloneElement(node, undefined, ...children);
  }
  // A plain string or number: the wrapper is meaningful only with a type, so
  // the text is all there is to keep.
  return <>{children}</>;
}
