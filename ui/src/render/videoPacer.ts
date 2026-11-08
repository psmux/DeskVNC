/**
 * When one H.264 decoder's pictures go on screen.
 *
 * WebCodecs promises one picture out per chunk in, but not when. Chromium's
 * decoder (WebView2) gives picture N back before chunk N+1 is needed, and the
 * apply loop used to count on that: it fed chunk N, waited for picture N, and
 * gave up after half a second. WebKitGTK's decoder does not work that way. It
 * runs a GStreamer hardware decoder (vah264dec on an AMD card, nvh264dec on an
 * NVIDIA one) that hands picture N back only once chunk N+2 or N+3 has gone
 * in, with `optimizeForLatency` set or not. Measured in the webview itself:
 * picture 1 came out after chunk 3 on the AMD card and after chunk 4 on the
 * NVIDIA one, every time. Waiting for picture N before feeding N+1 then never
 * succeeds: every chunk sits out the full timeout, the picture it waited for
 * arrives after its waiter has gone and is thrown away, and the window shows
 * no video at all while a backlog of half-second waits builds up behind it.
 * (Until `avc.ts`, WebKitGTK refused the stream outright, which hid this.)
 *
 * So the pacer learns how many chunks the decoder holds (its lag) from the
 * pictures themselves: a picture that comes back while newer chunks are
 * already in says how far behind the decoder runs. After feeding chunk N the
 * apply loop waits only for picture N minus the lag, which the decoder can
 * actually produce, and every picture is shown the moment it comes back. A
 * decoder that keeps nothing back has a lag of 0, so on WebView2 and on macOS
 * the loop waits for each chunk's own picture exactly as before.
 *
 * Showing a picture when it arrives rather than at its chunk's place in the
 * update stream is safe because of `overtaken`: once anything else has drawn
 * over the decoder's area, every picture from a chunk fed before that is
 * dropped instead of painted over newer pixels.
 *
 * Nothing in here touches WebCodecs or GL, so it is tested with plain
 * objects. Timestamps are the ones the renderer gives each chunk, `STEP`
 * apart and increasing.
 */

/** What the pacer needs of a decoded picture: a `VideoFrame` has both. */
export interface Picture {
  readonly timestamp: number;
  close(): void;
}

/** Microseconds between the timestamps of consecutive chunks. */
export const STEP = 1000;

/** The most chunks a decoder is believed to hold back. */
export const MAX_LAG = 16;

/**
 * The lag every decoder in one window shares. All of them are the same
 * webview's decoder, so what one teaches holds for the next: a Boundary
 * computer starts a new encoder, and with it a new decoder here, every time
 * its video restarts, and learning the lag again would cost a wait each time.
 */
export interface LearnedLag {
  chunks: number;
}

export class VideoPacer<P extends Picture> {
  /** Timestamp of the newest chunk fed to the decoder. */
  private fed = 0;
  /** Timestamp of the newest picture the decoder has given back. */
  private newest = 0;
  /** Timestamp of the newest picture put on screen, or caught up to. */
  private shown = 0;
  /** Pictures at or before this were overtaken by other pixels. */
  private floor = 0;
  /** Area painted by something else since the last chunk was fed. */
  private covered = 0;
  private waiter: { done: () => void } | null = null;
  private closed = false;

  constructor(
    private readonly learned: LearnedLag,
    /** Put a picture on screen. It is the callee's to close. */
    private readonly show: (picture: P) => void,
    /** Pixels in the decoder's area, to tell when other updates covered it all. */
    private readonly area: number,
  ) {}

  /** The timestamp for the next chunk, which the caller is about to decode. */
  feed(): number {
    this.fed += STEP;
    this.covered = 0;
    return this.fed;
  }

  /** The decoder gave a picture back. */
  output(picture: P): void {
    const ts = picture.timestamp;
    const behind = Math.round((this.fed - ts) / STEP);
    if (behind > this.learned.chunks) this.learned.chunks = Math.min(behind, MAX_LAG);
    if (ts > this.newest) this.newest = ts;
    if (this.closed || ts <= this.floor || ts <= this.shown) {
      picture.close();
    } else {
      this.shown = ts;
      this.show(picture);
    }
    this.release();
  }

  /**
   * Wait, after feeding a chunk, until the decoder has given back the
   * picture it can be expected to have produced by now, or `timeoutMs`
   * passes. A lag learned while waiting shortens the wait at once.
   */
  settle(timeoutMs: number): Promise<void> {
    this.waiter?.done();
    if (this.closed || this.ready()) return Promise.resolve();
    return new Promise((resolve) => {
      const timer = setTimeout(() => done(), timeoutMs);
      const done = (): void => {
        clearTimeout(timer);
        if (this.waiter === waiter) this.waiter = null;
        resolve();
      };
      const waiter = { done };
      this.waiter = waiter;
    });
  }

  /**
   * Something else was drawn over `painted` pixels of this decoder's area.
   * Pictures from chunks already fed are older than that, so none of them
   * may land on top of it now. Once other updates have covered the whole
   * area, the screen there is as new as it gets and nothing is owed.
   */
  overtaken(painted: number): void {
    this.floor = this.fed;
    this.covered += painted;
    if (this.covered >= this.area) this.shown = this.fed;
    this.release();
  }

  /**
   * Chunks have gone in whose pictures this decoder has not given back and
   * nothing else has painted over since. A decoder that holds pictures back
   * keeps the last few of a run until more chunks come, which at the end of
   * motion may be never.
   */
  behind(): boolean {
    return !this.closed && this.shown < this.fed;
  }

  /** The decoder is gone: nothing more will come back from it. */
  close(): void {
    this.closed = true;
    this.waiter?.done();
  }

  private ready(): boolean {
    return this.newest >= this.fed - this.learned.chunks * STEP;
  }

  private release(): void {
    if (this.waiter && (this.closed || this.ready())) this.waiter.done();
  }
}
