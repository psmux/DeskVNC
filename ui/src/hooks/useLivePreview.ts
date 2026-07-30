/**
 * Live tile previews, the session-window half (item 7 of the live-thumbs
 * contract). While the Library's "Live previews" toggle is on and this session
 * is connected, publish a small JPEG of the framebuffer every 500 ms on the
 * app-wide `library://preview` event; the Library's SessionsContext puts it on
 * the matching tile.
 *
 * Hard guards, all of them (PRD/03 §3.2, never leak a login screen):
 *   enabled  AND  state === connected  AND  renderer.hasFrame()  AND  no
 *   credential/certificate prompt is up. A tick with no new frame since the
 *   last publish is skipped entirely.
 */
import { useEffect, useRef, useState } from "react";
import { emit } from "@tauri-apps/api/event";
import { inTauri, safeInvoke, safeListen } from "../lib/tauri";
import {
  LIVE_PREVIEWS_EVENT,
  LIVE_PREVIEWS_KEY,
  PREVIEW_EVENT,
  type PreviewPayload,
} from "../state/SessionsContext";
import type { WebGLRenderer } from "../render/WebGLRenderer";
import type { SessionParams } from "./useSession";

/** Publish cadence (~2 fps). */
const PREVIEW_INTERVAL_MS = 500;
/** Longest edge constraint: previews are downscaled to at most this wide. */
const PREVIEW_MAX_WIDTH = 360;
const PREVIEW_JPEG_QUALITY = 0.6;

function blobToDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(reader.error ?? new Error("could not read preview blob"));
    reader.readAsDataURL(blob);
  });
}

export function useLivePreview({
  params,
  rendererRef,
  connected,
  promptUp,
  frameCountRef,
}: {
  params: SessionParams;
  rendererRef: { readonly current: WebGLRenderer | null };
  /** Session state is exactly "connected". */
  connected: boolean;
  /** A credential/certificate prompt is on top of the canvas. */
  promptUp: boolean;
  /** Bumped by the bridge on every applied frame, the "new frame?" check. */
  frameCountRef: { readonly current: number };
}): void {
  // The toggle lives in the Library; this window reads the stored setting once
  // at startup and follows `library://live-previews` broadcasts thereafter.
  const [enabled, setEnabled] = useState(false);
  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    void safeInvoke<string | null>("get_app_setting", { key: LIVE_PREVIEWS_KEY }, null).then(
      (raw) => {
        if (!cancelled && raw === "1") setEnabled(true);
      },
    );
    void safeListen<{ enabled: boolean }>(LIVE_PREVIEWS_EVENT, (payload) => {
      if (!cancelled) setEnabled(payload?.enabled === true);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  // Prompts can appear mid-interval; read through a ref so a change guards the
  // very next tick without restarting the publisher.
  const promptUpRef = useRef(promptUp);
  promptUpRef.current = promptUp;

  useEffect(() => {
    if (!enabled || !connected || !inTauri()) return;
    const { address, port } = params;
    // The shell always puts the endpoint in the window URL; without it there
    // is no tile key to publish under.
    if (!address) return;
    const sessionId = params.sessionId ?? "";
    const key = params.profileId ?? `discovered:${address}:${port}`;

    let disposed = false;
    /** One capture at a time, a slow encode must not stack up behind itself. */
    let busy = false;
    let lastPublishedFrame = -1;

    const tick = async (): Promise<void> => {
      if (disposed || busy) return;
      if (promptUpRef.current) return; // never publish a login/cert screen
      const renderer = rendererRef.current;
      if (!renderer?.hasFrame()) return;
      // Frame count is latched BEFORE the read: frames landing during the
      // encode simply mark the next tick as fresh.
      const frameCount = frameCountRef.current;
      if (frameCount === lastPublishedFrame) return; // nothing new, skip
      const frame = renderer.readFramebufferRGBA();
      if (!frame) return;
      busy = true;
      try {
        // ImageData wants a plain ArrayBuffer-backed view (same dance as
        // WebGLRenderer.screenshot()).
        const imageData = new ImageData(
          new Uint8ClampedArray(frame.pixels),
          frame.width,
          frame.height,
        );
        const bitmap = await createImageBitmap(imageData, {
          resizeWidth: Math.min(PREVIEW_MAX_WIDTH, frame.width),
          resizeQuality: "medium",
        });
        const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
        const ctx = canvas.getContext("2d");
        if (!ctx) {
          bitmap.close();
          return;
        }
        ctx.drawImage(bitmap, 0, 0);
        bitmap.close();
        const blob = await canvas.convertToBlob({
          type: "image/jpeg",
          quality: PREVIEW_JPEG_QUALITY,
        });
        const dataUrl = await blobToDataUrl(blob);
        // Re-check the guards after the async work: a prompt that appeared
        // mid-encode means these pixels may already be stale, and worse.
        if (disposed || promptUpRef.current) return;
        lastPublishedFrame = frameCount;
        const payload: PreviewPayload = {
          sessionId,
          key,
          address,
          port,
          dataUrl,
          width: canvas.width,
          height: canvas.height,
        };
        await emit(PREVIEW_EVENT, payload);
      } catch (err: unknown) {
        // A preview is decorative; it must never disturb the session.
        console.warn("live preview publish failed:", err);
      } finally {
        busy = false;
      }
    };

    const iv = window.setInterval(() => void tick(), PREVIEW_INTERVAL_MS);
    void tick(); // first frame promptly on enable/connect, not 500 ms later
    return () => {
      disposed = true;
      window.clearInterval(iv);
    };
  }, [enabled, connected, params, rendererRef, frameCountRef]);
}
