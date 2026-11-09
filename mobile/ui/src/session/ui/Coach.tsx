/**
 * First run gesture tips: a card of animated hands for the touch mode in use.
 * Shown once per mode (remembered on the phone) and again from the touch mode
 * sheet.
 */
import type { TouchMode } from "../input/gestures";
import { load, save } from "../storage";
import { GestureScene, type CoachGesture } from "./art";

const TIPS: Record<TouchMode, { g: CoachGesture; text: string }[]> = {
  trackpad: [
    { g: "tp-move", text: "Slide one finger to move the pointer" },
    { g: "tp-click", text: "Tap to click" },
    { g: "tp-right", text: "Tap with two fingers to right click" },
    { g: "tp-drag", text: "Tap, then slide to select or drag" },
    { g: "scroll", text: "Slide two fingers to scroll" },
    { g: "pinch", text: "Pinch to zoom in and out" },
  ],
  direct: [
    { g: "dt-click", text: "Tap where you want to click" },
    { g: "dt-right", text: "Press and hold to right click" },
    { g: "scroll", text: "Slide two fingers to scroll" },
    { g: "pinch", text: "Pinch to zoom in and out" },
    { g: "dt-zoom", text: "Double tap to zoom in on a spot" },
    { g: "keyboard", text: "Tap with three fingers for the keyboard" },
  ],
};

export function coachSeen(mode: TouchMode): boolean {
  return load(`coach.${mode}`) === "1";
}

export function markCoachSeen(mode: TouchMode): void {
  save(`coach.${mode}`, "1");
}

export function Coach({ mode, onDone }: { mode: TouchMode; onDone(): void }) {
  return (
    <div className="dv-s-coach" role="dialog" aria-modal="true" aria-label="How to use your fingers">
      <div className="dv-s-coach-card">
        <h2>{mode === "trackpad" ? "Using the trackpad" : "Using touch"}</h2>
        <p className="dv-s-lead">{mode === "trackpad" ? "Your screen works like a laptop trackpad." : "Touch the computer's screen as if it were your phone's."}</p>
        <ul className="dv-s-tips">
          {TIPS[mode].map((t) => (
            <li key={t.g}>
              <GestureScene kind={t.g} pad={mode === "trackpad"} />
              <span>{t.text}</span>
            </li>
          ))}
        </ul>
        <button
          type="button"
          className="dv-s-big"
          onClick={() => {
            markCoachSeen(mode);
            onDone();
          }}
        >
          Got it
        </button>
      </div>
    </div>
  );
}
