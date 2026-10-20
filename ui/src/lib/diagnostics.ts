/**
 * Live connection health, in the terms a person can act on.
 *
 * The counters the drivers report are about a protocol: packets, access
 * units, sequence gaps. They are the right numbers to measure and the wrong
 * numbers to show, because "311 lost packets" says nothing about whether
 * the session is usable. This module turns them into a short list of
 * findings with a severity, a live history for a trend line, and a text
 * report that can be pasted into a bug report.
 *
 * Everything here is pure: it takes samples in and gives findings out, so
 * the thresholds can be tested without a session.
 */

import type { AppleMediaState } from "./appleMedia";

export type Severity = "good" | "notice" | "warning" | "bad";

export interface Finding {
  severity: Severity;
  /** Short title, the sentence a person reads first. */
  title: string;
  /** What it means and what to try, when there is something to try. */
  detail?: string;
}

/** One second of a session, as the panel keeps it. */
export interface Sample {
  /** Milliseconds since the session's first sample. */
  at: number;
  /** Bits per second, from the transport's own counters. */
  throughput: number;
  /** Pictures per second. */
  fps: number;
  /** Fraction of packets that went missing, 0 to 1. */
  loss: number;
  /** Packet spacing variation, in milliseconds. */
  jitter: number;
  /** Pictures waiting for the shell, when the protocol reports it. */
  queued: number;
  /** Submission-to-output decoder delay, in milliseconds. */
  decodeMs: number;
  /** Input to answering picture, in milliseconds. Zero until the person uses it. */
  inputLatencyMs: number;
  /** What the webview configured: hardware or software. */
  acceleration: "hardware" | "software" | "unknown";
  /** The decoder dropped its queue because it could not keep up. */
  behind: boolean;
}

/** How many seconds of history the trend line keeps. */
export const HISTORY_SECONDS = 600;

/** A bounded history of samples, newest last. */
export class History {
  private samples: Sample[] = [];

  constructor(private readonly capacity = HISTORY_SECONDS) {}

  push(sample: Sample): void {
    this.samples.push(sample);
    while (this.samples.length > this.capacity) this.samples.shift();
  }

  all(): readonly Sample[] {
    return this.samples;
  }

  get length(): number {
    return this.samples.length;
  }

  clear(): void {
    this.samples = [];
  }

  /**
   * The value to draw for one series, scaled to 0..1.
   *
   * A flat series is drawn flat at zero rather than amplified into a
   * dramatic-looking line: an idle connection that reports the same number
   * every second has no trend, and drawing one would invent a problem.
   */
  normalized(pick: (sample: Sample) => number): number[] {
    return normalize(this.samples.map(pick));
  }
}

/** The same scaling [`History::normalized`] does, for a plain array. */
export function normalize(values: number[]): number[] {
  if (values.length === 0) return [];
  const max = Math.max(...values);
  const min = Math.min(...values);
  if (max <= 0 || max - min < 1e-9) return values.map(() => 0);
  return values.map((value) => (value - min) / (max - min));
}

/** Fraction of packets lost, from a cumulative count. */
export function lossFraction(lost: number, received: number): number {
  const total = lost + received;
  return total > 0 ? Math.min(1, Math.max(0, lost / total)) : 0;
}

/**
 * What is wrong, worst first.
 *
 * The thresholds are deliberately generous: a local network drops the
 * occasional packet and nobody notices, so a single lost packet is not a
 * finding. They are ordered so that the cause is named before the symptom:
 * a growing decoder queue explains a low frame rate, and saying "low frame
 * rate" alone would send someone looking at the wrong machine.
 */
export function findings(sample: Sample, totals: { stalls?: number; dropped?: number } = {}): Finding[] {
  const out: Finding[] = [];

  if (sample.loss >= 0.05) {
    out.push({
      severity: "bad",
      title: `Losing ${(sample.loss * 100).toFixed(1)}% of packets`,
      detail:
        "Above 5% the picture breaks up and every loss costs a full key frame to repair. " +
        "On a VPN this is usually the tunnel's MTU: try a smaller MTU or a TCP tunnel.",
    });
  } else if (sample.loss >= 0.01) {
    out.push({
      severity: "warning",
      title: `Losing ${(sample.loss * 100).toFixed(1)}% of packets`,
      detail: "Occasional visible artefacts. Fine on a busy Wi-Fi link, worth watching on a wire.",
    });
  }

  // A session that answers input in a few tens of milliseconds is working.
  // An idle desktop sends few pictures, and its spacing is uneven because
  // each one is a small change rather than a frame; reporting that as jitter
  // and as a low frame rate is what made a healthy session look broken.
  const responsive = sample.inputLatencyMs > 0 && sample.inputLatencyMs < 250;

  if (sample.jitter >= 120 && !responsive) {
    out.push({
      severity: "warning",
      title: `Picture spacing varies by ${Math.round(sample.jitter)} ms`,
      detail: "The stream arrives in bursts, which reads as stutter even when the average rate is fine.",
    });
  }

  if (sample.queued >= 4) {
    out.push({
      severity: "warning",
      title: `${sample.queued} pictures waiting to be decoded`,
      detail: "This machine is behind, not the network. The delay grows until frames are dropped.",
    });
  }

  if (sample.behind) {
    out.push({
      severity: "warning",
      title: "The decoder could not keep up and dropped its queue",
      detail: "Pictures are shown fresh rather than late, and a new one is requested. A smaller stream size is the real fix.",
    });
  }

  // Reported only when the webview said so. A slow decode time is not
  // evidence of software decoding, and saying it was is how a guess turns
  // into a wrong diagnosis.
  if (sample.acceleration === "software") {
    out.push({
      severity: "notice",
      title: "Decoding on the CPU",
      detail: "The webview did not take a hardware decoder. A hardware path would leave far more headroom at this picture size.",
    });
  }

  // The decoder holds one picture until the next arrives, so at a low
  // picture rate the handover-to-output delay is mostly that wait. Judging
  // it against the spacing is what keeps a still desktop from being
  // reported as a fault.
  const spacing = sample.fps > 0 ? 1000 / sample.fps : 0;
  const lagIsBeyondSpacing = spacing === 0 || sample.decodeMs > spacing * 1.5;
  if (sample.decodeMs >= 250 && lagIsBeyondSpacing) {
    out.push({
      severity: "warning",
      title: `A picture arrives ${Math.round(sample.decodeMs)} ms after it was handed over`,
      detail: sample.queued === 0
        ? "Nothing is queued, so this is buffering in the decoder pipeline rather than slow arithmetic."
        : "Some of this is pictures waiting in the decoder queue, which grows when the decoder cannot keep up.",
    });
  } else if (sample.decodeMs >= 60 && lagIsBeyondSpacing) {
    out.push({
      severity: "notice",
      title: `A picture takes ${Math.round(sample.decodeMs)} ms to come back`,
    });
  }

  if (sample.fps > 0 && sample.fps < 5 && sample.throughput > 0 && !responsive) {
    out.push({
      severity: "warning",
      title: `Only ${sample.fps.toFixed(1)} pictures per second`,
      detail: "A mostly still desktop looks like this. A desktop being used does not.",
    });
  }

  if (sample.inputLatencyMs >= 250) {
    out.push({
      severity: "warning",
      title: `The picture answers input after ${Math.round(sample.inputLatencyMs)} ms`,
      detail: "This is what lag feels like: the time from a pointer move or a key to the picture that shows it.",
    });
  } else if (sample.inputLatencyMs > 0) {
    out.push({
      severity: "good",
      title: `Input is answered in ${Math.round(sample.inputLatencyMs)} ms`,
    });
  }

  if ((totals.stalls ?? 0) > 0) {
    out.push({
      severity: "notice",
      title: `The stream stalled ${totals.stalls} time${totals.stalls === 1 ? "" : "s"}`,
      detail: "Each stall was repaired by asking the Mac for a fresh picture.",
    });
  }

  if ((totals.dropped ?? 0) > 0) {
    out.push({
      severity: "notice",
      title: `${totals.dropped} picture${totals.dropped === 1 ? "" : "s"} dropped locally`,
      detail: "The viewer could not keep up, so it kept the newest picture instead.",
    });
  }

  if (out.length === 0) {
    const healthy: Finding = sample.throughput > 0
      ? {
          severity: "good",
          title: "No problems detected",
          detail: "Nothing is being lost, delayed or dropped right now.",
        }
      : { severity: "notice", title: "Waiting for the first picture" };
    return [healthy];
  }
  const order: Record<Severity, number> = { bad: 0, warning: 1, notice: 2, good: 3 };
  return out.sort((a, b) => order[a.severity] - order[b.severity]);
}

/** One sample from the counters a session reports. */
export function sampleFrom(
  media: AppleMediaState | null,
  stats: { throughput_bps?: number; fps?: number } | null,
  decoder: { queued?: number; latencyMs?: number; acceleration?: "hardware" | "software"; behind?: boolean } | null,
  at: number,
): Sample {
  return {
    at,
    throughput: stats?.throughput_bps ?? 0,
    fps: stats?.fps ?? 0,
    loss: media ? lossFraction(media.lost, media.packets) : 0,
    jitter: media?.jitterMs ?? 0,
    queued: decoder?.queued ?? 0,
    decodeMs: decoder?.latencyMs ?? 0,
    inputLatencyMs: media?.inputLatencyMs ?? 0,
    acceleration: decoder?.acceleration ?? "unknown",
    behind: decoder?.behind ?? false,
  };
}

export interface ReportInput {
  appVersion?: string;
  /** The log file this build writes, when it opened one. */
  logPath?: string | null;
  protocol: string;
  desktopName: string;
  host: string;
  connectedFor: number;
  requested?: { w: number; h: number } | null;
  layout?: { w: number; h: number } | null;
  /** The desktop size in points, which is what a person sees as "zoomed". */
  desktopPoints?: { w: number; h: number } | null;
  decoded?: { w: number; h: number } | null;
  media: AppleMediaState | null;
  stats: { throughput_bps?: number; fps?: number; rtt_ms?: number; rtt_source?: string } | null;
  decoder:
    | { queued?: number; submitted?: number; decoded?: number; latencyMs?: number; acceleration?: "hardware" | "software"; behind?: boolean }
    | null;
  queue: { depth?: number; bytes?: number; dropped?: number } | null;
  findings: Finding[];
  history: readonly Sample[];
  /** What changed during the session, oldest first. */
  events?: readonly { at: number; text: string }[];
}

function mbps(bits: number): string {
  return `${(bits / 1e6).toFixed(2)} Mbit/s`;
}

/**
 * A block of text that describes the session without describing the user.
 *
 * No credentials, no clipboard, no window titles from the remote machine:
 * this is meant to be pasted somewhere public.
 */
export function report(input: ReportInput): string {
  const lines: string[] = [];
  const push = (line = ""): void => {
    lines.push(line);
  };
  push(`DeskVNC connection report${input.appVersion ? ` (${input.appVersion})` : ""}`);
  push(`Generated: ${new Date().toISOString()}`);
  push(`Protocol: ${input.protocol}`);
  push(`Host: ${input.host}`);
  push(`Desktop: ${input.desktopName}`);
  push(`Connected for: ${Math.round(input.connectedFor)}s`);
  if (input.logPath) push(`Log: ${input.logPath}`);
  push();
  push("Geometry");
  push(`  requested: ${input.requested ? `${input.requested.w}x${input.requested.h}` : "none"}`);
  push(`  layout:    ${input.layout ? `${input.layout.w}x${input.layout.h}` : "none"}`);
  push(`  desktop:   ${input.desktopPoints ? `${input.desktopPoints.w}x${input.desktopPoints.h} points` : "unknown"}`);
  push(`  decoded:   ${input.decoded ? `${input.decoded.w}x${input.decoded.h}` : "none"}`);
  push();
  push("Stream");
  if (input.stats) {
    push(`  throughput: ${mbps(input.stats.throughput_bps ?? 0)}`);
    push(`  pictures/s: ${(input.stats.fps ?? 0).toFixed(1)}`);
    push(
      `  latency:    ${input.stats.rtt_ms ? `${Math.round(input.stats.rtt_ms)} ms (${input.stats.rtt_source})` : "not measured"}`,
    );
  } else {
    push("  no transport statistics yet");
  }
  if (input.media) {
    const m = input.media;
    push(`  packets:    ${m.packets} (${mbps((m.bytes * 8) / Math.max(1, input.connectedFor))} average)`);
    push(`  pictures:   ${m.pictures}`);
    push(`  lost:       ${m.lost} (${(lossFraction(m.lost, m.packets) * 100).toFixed(2)}%)`);
    push(`  jitter:     ${m.jitterMs} ms`);
    push(
      `  input lag:  ${m.inputLatencyMs} ms typical, ${m.inputWorstMs} ms worst` +
        (m.inputLatencyMs === 0 ? " (not used yet in this session)" : ""),
    );
    push(`  stalls:     ${m.stalls}`);
    push(`  dropped:    ${m.dropped} locally`);
    push(`  recovers:   ${m.recoveries} (${m.requests} feedback packets sent)`);
    if (m.canvasWidth) push(`  canvas:     ${m.canvasWidth}x${m.canvasHeight}, ${m.tiles} tile(s)`);
  }
  if (input.decoder) {
    const d = input.decoder;
    push(`  picture lag: ${Math.round(d.latencyMs ?? 0)} ms from handover to output`);
    push(`  decoder:    ${d.queued ?? 0} queued, ${d.decoded ?? 0} of ${d.submitted ?? 0} decoded`);
    push(`  decoding:   ${d.acceleration ?? "unknown"}${d.behind ? ", dropped its queue" : ""}`);
  }
  if (input.queue) {
    const q = input.queue;
    push(`  renderer:   ${q.depth ?? 0} updates queued, ${q.dropped ?? 0} dropped`);
  }
  push();
  push("Findings");
  for (const finding of input.findings) push(`  [${finding.severity}] ${finding.title}`);
  if (input.events && input.events.length > 0) {
    push();
    push("Timeline (seconds into the session)");
    for (const event of input.events.slice(-60)) {
      push(`  ${Math.round(event.at / 1000)}s  ${event.text}`);
    }
  }
  if (input.history.length > 0) {
    push();
    push("Samples (seconds into the session, Mbit/s, pictures/s, loss %, jitter ms, queued)");
    // Every second that was recorded, not a sample of a sample: a freeze is
    // a run of identical rows, and hiding most of them hides the freeze.
    const recent = input.history.slice(-120);
    for (const sample of recent) {
      push(
        `  ${Math.round(sample.at / 1000).toString().padStart(5)} ` +
          `${(sample.throughput / 1e6).toFixed(2).padStart(6)} ` +
          `${sample.fps.toFixed(1).padStart(5)} ` +
          `${(sample.loss * 100).toFixed(2).padStart(6)} ` +
          `${Math.round(sample.jitter).toString().padStart(5)} ` +
          `${sample.queued}`,
      );
    }
  }
  return lines.join("\n");
}
