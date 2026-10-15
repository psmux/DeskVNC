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
