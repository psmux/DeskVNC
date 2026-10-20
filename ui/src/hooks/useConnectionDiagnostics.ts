/**
 * The live health of a session, sampled once a second.
 *
 * The drivers report on their own clocks: the transport reports throughput
 * and picture rate, the media path reports loss and stalls, and the decoder
 * reports how far behind it is. None of them is a diagnosis on its own, and
 * a person reporting "it feels unstable" cannot say which of them went
 * wrong. Sampling all of them together, on one clock, is what makes a
 * timeline out of them.
 *
 * Sampling happens here rather than in the panel so the history exists even
 * while the panel is closed: the interesting minute is usually the one
 * before somebody opened the dialog.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import type { AppleMediaState } from "../lib/appleMedia";
import { History, findings, sampleFrom, type Finding, type Sample, lossFraction } from "../lib/diagnostics";

export interface DiagnosticsInput {
  media: AppleMediaState | null;
  stats: { throughput_bps?: number; fps?: number; rtt_ms?: number; rtt_source?: string } | null;
  decoder:
    | { queued?: number; submitted?: number; decoded?: number; latencyMs?: number; acceleration?: "hardware" | "software"; behind?: boolean }
    | null;
  queue: { depth?: number; bytes?: number; dropped?: number } | null;
}

export interface DiagnosticEvent {
  /** Seconds into the session, on the same clock as the samples. */
  at: number;
  text: string;
}

export interface DiagnosticsState {
  sample: Sample;
  findings: Finding[];
  history: readonly Sample[];
  /** What changed, in order: stalls, drops, loss rising. */
  events: readonly DiagnosticEvent[];
  /** Seconds the session has been sampling. */
  seconds: number;
}

/** One second of healthy stream, before the first real sample arrives. */
const IDLE: Sample = { at: 0, throughput: 0, fps: 0, loss: 0, jitter: 0, queued: 0, decodeMs: 0, inputLatencyMs: 0, acceleration: "unknown", behind: false };

export function useConnectionDiagnostics(
  input: DiagnosticsInput,
  enabled: boolean,
  /**
   * When the session connected, in epoch milliseconds. The panel can be
   * opened long after the session started, and "connected for 8s" would
   * then describe the dialog rather than the connection.
   */
  connectedAt: number | null = null,
): DiagnosticsState {
  const history = useMemo(() => new History(), []);
  // The latest reading, kept in a ref so the interval is created once and
  // never re-created by a statistics tick.
  const latest = useRef(input);
  latest.current = input;
  // The clock the samples are on. `connectedAt` arrives a moment after the
  // first render, and mixing the two bases is what produced sample times of
  // "12027 seconds ago" for a session that had run for sixteen.
  const basis = useRef<number | null>(connectedAt);
  const events = useRef<DiagnosticEvent[]>([]);
  const previous = useRef<{ stalls?: number; dropped?: number; titles: string[] }>({ titles: [] });
  const startedAt = useRef<number>(performance.now());
  const [sample, setSample] = useState<Sample>(IDLE);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    if (!enabled) return;
    if (basis.current !== connectedAt) {
      // A new connection, or the clock finally arrived: the old samples
      // describe a different session and are not comparable.
      basis.current = connectedAt;
      history.clear();
      events.current = [];
      previous.current = { titles: [] };
      startedAt.current = performance.now();
    }
    const tick = (): void => {
      const value = latest.current;
      const at = connectedAt !== null
        ? Math.max(0, Date.now() - connectedAt)
        : Math.max(0, performance.now() - startedAt.current);
      const next = sampleFrom(value.media, value.stats, value.decoder, at);
      // What changed since the last second, recorded rather than averaged
      // away: a five second freeze disappears from a mean and is obvious in
      // a list.
      const last = previous.current;
      const note = (text: string): void => {
        events.current.push({ at, text });
        if (events.current.length > 120) events.current.shift();
      };
      if (value.media) {
        if (last.stalls !== undefined && value.media.stalls > last.stalls) {
          note(`the stream stalled (${value.media.stalls})`);
        }
        if (last.dropped !== undefined && value.media.dropped > last.dropped) {
          note(`${value.media.dropped - last.dropped} picture(s) dropped locally`);
        }
        last.stalls = value.media.stalls;
        last.dropped = value.media.dropped;
      }
      history.push(next);
      setSample(next);
      // The panel reads `history`, which is a mutable object: the version
      // counter is what tells React that its contents changed.
      setVersion((n) => n + 1);
    };
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [enabled, history, connectedAt]);

  const result = useMemo(() => {
    void version;
    const totals = {
      stalls: input.media?.stalls,
      dropped: input.media?.dropped,
    };
    const current = findings(sample, totals);
    // A finding that appears is worth recording; one that stays is not.
    const titles = current.map((f) => f.title);
    const fresh = titles.filter((title) => !previous.current.titles.includes(title));
    if (fresh.length > 0 && sample.at > 0) {
      for (const title of fresh) events.current.push({ at: sample.at, text: title });
      if (events.current.length > 120) events.current.splice(0, events.current.length - 120);
    }
    previous.current.titles = titles;

    return {
      sample,
      findings: current,
      history: history.all(),
      events: events.current.slice(),
      seconds: Math.round(sample.at / 1000),
    };
  }, [sample, input.media?.stalls, input.media?.dropped, history, version]);

  return result;
}

/** Loss as a percentage, for a label. */
export function lossPercent(media: AppleMediaState | null): number {
  if (!media) return 0;
  return lossFraction(media.lost, media.packets) * 100;
}
