/**
 * The text the session's clipboard sync last moved, in either direction.
 *
 * Neither automatic half of the sync may repeat itself: without this, text
 * copied on the remote is written to the local clipboard and then pushed
 * straight back the next time the window is focused.
 *
 * What it remembers belongs to one connection. A reconnect is a new
 * connection, and over RDP a new connection is a new clipboard channel that
 * starts empty: the server asks for our formats again and is told there are
 * none. Remembering across it made the first push after the reconnect look
 * like a repeat, so it was skipped, and pasting on the remote gave nothing
 * until the user copied something new locally (issue #9).
 */
/**
 * One piece of text the remote put on its clipboard. Each arrival is a new
 * value even when the text repeats: copying the same thing again on the
 * remote, after copying something else locally, has to reach the local
 * clipboard again, and a plain string state would compare equal and never
 * re-run the effect that writes it.
 */
export interface RemoteClipboard {
  text: string;
  seq: number;
}

export function nextRemoteClipboard(prev: RemoteClipboard | null, text: string): RemoteClipboard {
  return { text, seq: (prev?.seq ?? 0) + 1 };
}

export class ClipboardEcho {
  private last: string | null = null;

  /** A connection (first or reconnect) came up: forget what was moved. */
  connected(): void {
    this.last = null;
  }

  /** Record text moved in either direction. */
  moved(text: string): void {
    this.last = text;
  }

  /**
   * Whether a push of `text` is worth sending. Empty text never is; an
   * explicit push (`force`) always is otherwise.
   */
  shouldPush(text: string, force: boolean): boolean {
    if (!text) return false;
    return force || text !== this.last;
  }
}

/**
 * Whether the window sends the local clipboard to the remote on its own when
 * the person arrives: on connecting, on a reconnect, on switching back to the
 * window, and (on Boundary) when the remote starts taking clipboard text
 * because the helper was given control.
 *
 * Never on Boundary. There the helper is a support tech at someone else's
 * computer, and whatever the tech last copied (a password, a note about
 * another customer) would land on that person's clipboard without the tech
 * pasting anything. A Boundary helper's clipboard goes over only on an
 * explicit paste into the remote view (Ctrl+V or Cmd+V) or the Send
 * clipboard button. VNC and RDP keep the sync the preferences describe: the
 * remote there is the person's own machine.
 */
export function syncsOnArrival(arrival: {
  protocol: string;
  connected: boolean;
  owns: boolean;
  remoteTakesText: boolean;
}): boolean {
  if (arrival.protocol === "boundary") return false;
  return arrival.connected && arrival.owns && arrival.remoteTakesText;
}
