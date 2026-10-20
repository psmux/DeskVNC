import { useState } from "react";
import type { AppleMediaState } from "../lib/appleMedia";

export interface MacDisplayInfo {
  displayId: number;
  originalModeId: number;
  currentModeId: number;
  width: number;
  height: number;
  pixelWidth: number;
  pixelHeight: number;
  canRestore: boolean;
  modes: { id: number; width: number; height: number; pixelWidth: number; pixelHeight: number }[];
}
export type MacDisplayAction = { action: "list" | "restore" } | { action: "set"; width: number; height: number };

/** A size at half the native one, keeping its shape. */
function half(native: { w: number; h: number }): { w: number; h: number } {
  return { w: Math.max(2, Math.round(native.w / 2) & ~1), h: Math.max(2, Math.round(native.h / 2) & ~1) };
}

/** A size at a third of the native one, keeping its shape. */
function third(native: { w: number; h: number }): { w: number; h: number } {
  return { w: Math.max(2, Math.round(native.w / 3) & ~1), h: Math.max(2, Math.round(native.h / 3) & ~1) };
}

/**
 * Two separate Mac-side levers, honestly labelled:
 * stream size (the Apple Remote Desktop approach, over the live Screen
 * Sharing session) and the physical panel mode (SSH + CoreGraphics, advanced).
 */
export function MacDisplayControls(props: {
  info: MacDisplayInfo | null;
  notice: string | null;
  busy: boolean;
  size: { w: number; h: number } | null;
  native: { w: number; h: number } | null;
  /** Control-plane reports; separate from actual decoder output. */
  media?: AppleMediaState | null;
  /** What the video path is doing: the decoder's queue and its delay. */
  stats?: {
    queued: number;
    submitted: number;
    decoded: number;
    latencyMs: number;
    pictureWidth: number;
    pictureHeight: number;
    frameWidth: number;
    frameHeight: number;
  } | null;
  onStreamResize: (w: number, h: number) => void;
  onPanelMode: (action: MacDisplayAction) => void;
}) {
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState("");
  const modes = props.info ? Array.from(new Set(props.info.modes.filter(m => m.pixelWidth <= 4096 && m.pixelHeight <= 4096).map(m => `${m.width}x${m.height}`))) : [];
  const native = props.native;
  return <div className="absolute bottom-3 right-3 z-20 text-xs">
    <button className="rounded-md border border-subtle bg-raised px-3 py-2" onClick={() => setOpen(!open)}>Mac</button>
    {open && <div className="absolute bottom-full right-0 mb-2 w-80 space-y-3 rounded-lg border border-subtle bg-raised p-4 shadow-lg">
      <p className="text-secondary">
        {props.stats && props.stats.pictureWidth > 0
          ? `Decoded picture: ${props.stats.pictureWidth}×${props.stats.pictureHeight} pixels`
          : "No decoded picture yet"}
      </p>
      {props.stats && props.stats.submitted > 0 && (
        <p className="text-tertiary">
          Decoder: {props.stats.queued} queued, {props.stats.decoded} of {props.stats.submitted}{" "}
          decoded, {props.stats.latencyMs} ms submission-to-output
          {props.stats.pictureWidth > 0 && (
            <>
              {" "}· picture {props.stats.pictureWidth}×{props.stats.pictureHeight} in a{" "}
              {props.stats.frameWidth}×{props.stats.frameHeight} frame
            </>
          )}
        </p>
      )}
      {props.media && <div className="space-y-1 text-tertiary">
        {props.media.requestedWidth > 0 && <p>
          Requested: {props.media.requestedWidth}×{props.media.requestedHeight} pixels (not confirmation)
        </p>}
        {props.media.layoutWidth > 0 && <p>
          Server layout: {props.media.layoutWidth}×{props.media.layoutHeight} pixels
          {props.media.desktopWidth > 0 &&
            ` / ${props.media.desktopWidth}×${props.media.desktopHeight} desktop points`}
        </p>}
        {props.media.canvasWidth > 0 && <p>
          Media answer: {props.media.canvasWidth}×{props.media.canvasHeight} pixels
          {props.media.tiles > 0 && ` / ${props.media.tiles} tile(s)`}
        </p>}
        <p>
          {props.media.pictures} assembled pictures, {props.media.lost} packets lost,{" "}
          {props.media.dropped} dropped locally, {props.media.recoveries} recovery
          attempts, {props.media.requests} feedback packets sent
        </p>
      </div>}
      <div>
        <strong>Remote desktop size (experimental)</strong>
        <p className="mt-1 text-secondary">These requests change how many pixels are streamed. They keep the Mac desktop&apos;s point size, so windows stay where they are. They are not physical-panel mode controls.</p>
        <div className="mt-2 flex flex-wrap gap-2">
          {native && <>
            <button className="rounded border border-subtle px-2 py-1" onClick={() => props.onStreamResize(native.w, native.h)}>Native ({native.w}×{native.h})</button>
            <button className="rounded border border-subtle px-2 py-1" onClick={() => props.onStreamResize(half(native).w, half(native).h)}>Half ({half(native).w}×{half(native).h})</button>
            <button className="rounded border border-subtle px-2 py-1" onClick={() => props.onStreamResize(third(native).w, third(native).h)}>Third ({third(native).w}×{third(native).h})</button>
          </>}
        </div>
        <p className="mt-1 text-tertiary">Quality presets instead request the original desktop-point size with fewer pixels. Compare requested, server-reported and decoded sizes above; a request alone does not prove it took effect.</p>
      </div>
      <div>
        <strong>Physical panel mode (advanced)</strong>
        <p className="mt-1 text-secondary">Sets the Mac panel's own display mode over SSH with this Mac account and the trusted host key. Slower and heavier than the stream resize; never creates a private display.</p>
        <button disabled={props.busy} onClick={() => props.onPanelMode({action:"list"})} className="mt-2 rounded border border-subtle px-2 py-1 disabled:opacity-50">{props.busy ? "Waiting for macOS…" : "Read available modes"}</button>
        {props.info && <>
          <p className="mt-2">Panel: {props.info.width} × {props.info.height} points ({props.info.pixelWidth} × {props.info.pixelHeight} pixels)</p>
          <label className="mt-1 block">Mode <select aria-label="Physical Mac panel mode" className="mt-1 w-full rounded border border-subtle bg-canvas p-1" value={selected} onChange={e => setSelected(e.target.value)}>
            <option value="">Choose an available mode</option>
            {modes.map(mode => <option key={mode} value={mode}>{mode.replace("x", " × ")}</option>)}
          </select></label>
          <div className="mt-2 flex gap-2">
            <button disabled={props.busy || !selected} className="rounded border border-subtle px-2 py-1 disabled:opacity-50" onClick={() => {const [width,height]=selected.split("x").map(Number); props.onPanelMode({action:"set",width,height});}}>Apply on Mac</button>
            <button disabled={props.busy || !props.info.canRestore} className="rounded border border-subtle px-2 py-1 disabled:opacity-50" onClick={() => props.onPanelMode({action:"restore"})}>Restore original</button>
          </div>
          <p className="mt-1 text-secondary">Restoration is attempted on disconnect, but cannot be guaranteed after a crash or network loss.</p>
        </>}
      </div>
      {props.notice && <p role="status" className="break-words text-secondary">{props.notice}</p>}
    </div>}
  </div>;
}