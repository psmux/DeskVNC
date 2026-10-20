/**
 * Live connection health, in the dialog someone opens when it feels wrong.
 *
 * The numbers are only half of it. A person reporting a problem cannot tell
 * loss from jitter from a decoder that is behind, and all three look like
 * "it stutters". So the findings come first, in plain language, and the
 * counters are below them for whoever needs to check the reasoning.
 *
 * "Copy report" is the other half: it puts the same thing in the clipboard
 * as text that can be pasted into a bug report, including a short history,
 * so a problem that has already passed can still be described.
 */

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { safeInvoke, writeClipboard } from "../lib/tauri";
import type { AppleMediaState } from "../lib/appleMedia";
import { normalize, report, type Finding, type Sample } from "../lib/diagnostics";
import { useConnectionDiagnostics, lossPercent } from "../hooks/useConnectionDiagnostics";

const SEVERITY_STYLE: Record<Finding["severity"], { dot: string; text: string }> = {
  good: { dot: "bg-emerald-500", text: "text-primary" },
  notice: { dot: "bg-sky-500", text: "text-secondary" },
  warning: { dot: "bg-amber-500", text: "text-primary" },
  bad: { dot: "bg-red-500", text: "text-primary" },
};

function formatBps(bits: number): string {
  if (!Number.isFinite(bits) || bits <= 0) return "-";
  return bits >= 1e6 ? `${(bits / 1e6).toFixed(1)} Mbit/s` : `${Math.round(bits / 1e3)} kbit/s`;
}

/**
 * A trend line for one series.
 *
 * Drawn as a polyline rather than a chart library: this panel has to work in
 * a webview with no network, and a 60 point line needs no more than this.
 */
function Spark({ values, className }: { values: number[]; className?: string }): ReactNode {
  if (values.length < 2) return <div className={`h-6 ${className ?? ""}`} />;
  const points = values
    .map((value, i) => `${(i / (values.length - 1)) * 100},${28 - value * 26}`)
    .join(" ");
  return (
    <svg viewBox="0 0 100 28" preserveAspectRatio="none" className={`h-6 w-full ${className ?? ""}`}>
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

function Row({ label, value }: { label: string; value: string }): ReactNode {
  return (
    <>
      <dt className="text-tertiary">{label}</dt>
      <dd className="tabular-nums text-primary">{value}</dd>
    </>
  );
}

export interface ConnectionDiagnosticsProps {
  protocol: string;
  desktopName: string;
  host: string;
  media: AppleMediaState | null;
  stats: { throughput_bps?: number; fps?: number; rtt_ms?: number; rtt_source?: string } | null;
  decoder:
    | { queued?: number; submitted?: number; decoded?: number; latencyMs?: number; acceleration?: "hardware" | "software"; behind?: boolean }
    | null;
  queue: { depth?: number; bytes?: number; dropped?: number } | null;
  requested?: { w: number; h: number } | null;
  layout?: { w: number; h: number } | null;
  desktopPoints?: { w: number; h: number } | null;
  decoded?: { w: number; h: number } | null;
  /**
   * Where the log file is and which build wrote it. Fetched here rather than
   * passed in, because the answer is about the running binary and not about
   * the session, and a stale copy in a prop would be worse than none.
   */
  live: boolean;
  /** When the session connected, in epoch milliseconds. */
  connectedAt?: number | null;
}

interface AboutInfo {
  appVersion: string;
  logPath: string | null;
}

export function ConnectionDiagnostics(props: ConnectionDiagnosticsProps): ReactNode {
  const diagnostics = useConnectionDiagnostics(
    { media: props.media, stats: props.stats, decoder: props.decoder, queue: props.queue },
    props.live,
    props.connectedAt ?? null,
  );
  const [copied, setCopied] = useState<string | null>(null);
  const [about, setAbout] = useState<AboutInfo | null>(null);
  useEffect(() => {
    let cancelled = false;
    void safeInvoke<AboutInfo | null>("about_info", undefined, null).then((info) => {
      if (!cancelled) setAbout(info);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const copy = useCallback((): void => {
    const text = report({
      appVersion: about?.appVersion,
      logPath: about?.logPath ?? null,
      protocol: props.protocol,
      desktopName: props.desktopName,
      host: props.host,
      connectedFor: diagnostics.seconds,
      requested: props.requested,
      layout: props.layout,
      desktopPoints: props.desktopPoints,
      decoded: props.decoded,
      media: props.media,
      stats: props.stats ?? null,
      decoder: props.decoder ?? null,
      queue: props.queue ?? null,
      findings: diagnostics.findings,
      history: diagnostics.history,
      events: diagnostics.events,
    });
    // Through the shell, not `navigator.clipboard`: WebKit only honours the
    // DOM API while a user gesture is still active, and the copy is the last
    // step of building a report.
    void writeClipboard(text).then((ok) => setCopied(ok ? "Copied" : "Could not copy"));
    window.setTimeout(() => setCopied(null), 2000);
  }, [about, diagnostics, props]);

  const { sample, history } = diagnostics;
  return (
    <div className="space-y-3 text-xs">
      <ul className="space-y-2">
        {diagnostics.findings.map((finding) => (
          <li key={finding.title} className="flex gap-2">
            <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${SEVERITY_STYLE[finding.severity].dot}`} />
            <span>
              <span className={`block font-medium ${SEVERITY_STYLE[finding.severity].text}`}>{finding.title}</span>
              {finding.detail ? <span className="block text-tertiary">{finding.detail}</span> : null}
            </span>
          </li>
        ))}
      </ul>

      <div className="grid grid-cols-2 gap-x-3 gap-y-2 border-t border-subtle pt-2">
        <div>
          <p className="text-tertiary">Throughput</p>
          <Spark values={normalize(history.map((s: Sample) => s.throughput))} className="text-sky-500" />
        </div>
        <div>
          <p className="text-tertiary">Loss</p>
          <Spark values={normalize(history.map((s: Sample) => s.loss))} className="text-amber-500" />
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-y-1 border-t border-subtle pt-2">
        <Row label="Rate" value={formatBps(sample.throughput)} />
        <Row label="Pictures" value={`${sample.fps.toFixed(1)}/s`} />
        <Row label="Lost" value={`${lossPercent(props.media).toFixed(2)}%`} />
        <Row label="Jitter" value={`${Math.round(sample.jitter)} ms`} />
        <Row
          label="Input lag"
          value={sample.inputLatencyMs > 0 ? `${Math.round(sample.inputLatencyMs)} ms` : "-"}
        />
        <Row label="Decoder queue" value={`${sample.queued}`} />
        <Row label="Picture delay" value={`${Math.round(sample.decodeMs)} ms`} />
        {props.decoder?.acceleration
          ? <Row label="Decoder" value={props.decoder.acceleration} />
          : null}
        {props.media ? <Row label="Stalls" value={`${props.media.stalls}`} /> : null}
        {props.media ? <Row label="Dropped" value={`${props.media.dropped}`} /> : null}
        {props.media ? <Row label="Recoveries" value={`${props.media.recoveries}`} /> : null}
        <Row label="Sampling" value={`${diagnostics.seconds}s`} />
      </dl>

      {props.media && props.media.layoutWidth > 0 ? (
        <p className="border-t border-subtle pt-2 text-tertiary">
          Layout {props.media.layoutWidth}×{props.media.layoutHeight} px
          {props.media.desktopWidth > 0 && ` / ${props.media.desktopWidth}×${props.media.desktopHeight} pt`}
          {props.decoded ? `, decoded ${props.decoded.w}×${props.decoded.h}` : ""}
        </p>
      ) : null}

      <div className="flex items-center justify-between gap-2 border-t border-subtle pt-2">
        <span className="truncate text-tertiary" title={about?.logPath ?? undefined}>
          {about?.logPath ? "Log: deskvnc.log" : "No log file"}
        </span>
        <span className="flex items-center gap-2">
        {copied ? <span className="text-tertiary">{copied}</span> : null}
        <button
          className="rounded border border-subtle px-2 py-1 text-primary hover:bg-raised"
          onClick={copy}
        >
          Copy report
        </button>
        </span>
      </div>
    </div>
  );
}
