/** Backend control/assembly telemetry. None of these fields proves presentation. */
export interface AppleMediaState {
  requestedWidth: number;
  requestedHeight: number;
  layoutWidth: number;
  layoutHeight: number;
  desktopWidth: number;
  desktopHeight: number;
  canvasWidth: number;
  canvasHeight: number;
  tiles: number;
  pictures: number;
  /** Packets lost on the way. */
  lost: number;
  /** Pictures dropped because the client could not keep up. */
  dropped: number;
  /** Fresh pictures asked for. */
  recoveries: number;
  /** Feedback packets sent to the Mac. */
  requests: number;
  /** Video datagrams read from the Mac. */
  packets: number;
  /** Bytes of those datagrams: the stream's bandwidth. */
  bytes: number;
  /** Times the stream went quiet long enough to need recovery. */
  stalls: number;
  /** Variation in the spacing between pictures, in milliseconds. */
  jitterMs: number;
  /** Smoothed time from input to the picture that answers it. */
  inputLatencyMs: number;
  /** The slowest such answer, so one freeze stays visible. */
  inputWorstMs: number;
}
