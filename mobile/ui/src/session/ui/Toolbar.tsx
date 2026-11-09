/**
 * The floating toolbar. Closed, it is a small pill at the top of the screen;
 * open, a card of big round buttons with a label under each.
 */
import type { ReactNode } from "react";
import type { TouchMode } from "../input/gestures";
import { IconCamera, IconChevronDown, IconChevronUp, IconClipboard, IconKeyboard, IconKeys, IconPower, IconQuality, IconTouch, IconTrackpad } from "./icons";

export type ToolbarAction = "keyboard" | "mode" | "keys" | "quality" | "clipboard" | "snapshot" | "disconnect";

function Btn({ icon, label, on, danger, onClick }: { icon: ReactNode; label: string; on?: boolean; danger?: boolean; onClick(): void }) {
  return (
    <button type="button" className={`dv-s-tool${on ? " is-on" : ""}${danger ? " is-danger" : ""}`} aria-pressed={on} onClick={onClick}>
      <span className="dv-s-tool-icon">{icon}</span>
      <span className="dv-s-tool-label">{label}</span>
    </button>
  );
}

export function Toolbar({
  open,
  title,
  mode,
  keyboardOn,
  keysOn,
  hasClipboard,
  onToggle,
  onAction,
}: {
  open: boolean;
  title: string;
  mode: TouchMode;
  keyboardOn: boolean;
  keysOn: boolean;
  hasClipboard: boolean;
  onToggle(): void;
  onAction(a: ToolbarAction): void;
}) {
  return (
    <div className={`dv-s-toolbar${open ? " is-open" : ""}`}>
      <button type="button" className="dv-s-handle" onClick={onToggle} aria-expanded={open} aria-label={open ? "Hide the toolbar" : "Show the toolbar"}>
        <span className="dv-s-handle-title">{title}</span>
        {open ? <IconChevronUp size={20} /> : <IconChevronDown size={20} />}
      </button>
      {open ? (
        <div className="dv-s-tools" role="toolbar" aria-label="Session tools">
          <Btn icon={<IconKeyboard />} label="Keyboard" on={keyboardOn} onClick={() => onAction("keyboard")} />
          <Btn icon={mode === "trackpad" ? <IconTrackpad /> : <IconTouch />} label={mode === "trackpad" ? "Trackpad" : "Touch"} onClick={() => onAction("mode")} />
          <Btn icon={<IconKeys />} label="Keys" on={keysOn} onClick={() => onAction("keys")} />
          <Btn icon={<IconQuality />} label="Quality" onClick={() => onAction("quality")} />
          <Btn
            icon={
              <span className="dv-s-badge-wrap">
                <IconClipboard />
                {hasClipboard ? <span className="dv-s-badge-dot" /> : null}
              </span>
            }
            label="Clipboard"
            onClick={() => onAction("clipboard")}
          />
          <Btn icon={<IconCamera />} label="Snapshot" onClick={() => onAction("snapshot")} />
          <Btn icon={<IconPower />} label="Leave" danger onClick={() => onAction("disconnect")} />
        </div>
      ) : null}
    </div>
  );
}
