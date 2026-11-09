/** The sheets the toolbar opens: touch mode, picture quality, clipboard and connection details. */
import { useState } from "react";
import type { Quality, SessionStats } from "../../api/contract";
import type { TouchMode } from "../input/gestures";
import { LEVEL_WORDS, formatSpeed, qualityLevel } from "../status";
import { ModePicture } from "./art";
import { Sheet } from "./Sheet";
import { IconClipboard, IconCopy, IconPaste, IconQuality, IconSend, IconTouch, IconWifi } from "./icons";

export function ModeSheet({ mode, onPick, onClose, onShowTips }: { mode: TouchMode; onPick(m: TouchMode): void; onClose(): void; onShowTips(): void }) {
  const cards: { m: TouchMode; title: string; text: string }[] = [
    { m: "trackpad", title: "Trackpad", text: "Slide a finger to move the pointer, tap to click. Best for small things." },
    { m: "direct", title: "Touch", text: "Tap right where you want to click, like on a phone." },
  ];
  return (
    <Sheet title="How touching works" icon={<IconTouch />} onClose={onClose}>
      <div className="dv-s-cards two">
        {cards.map((c) => (
          <button
            key={c.m}
            type="button"
            className={`dv-s-card${mode === c.m ? " is-on" : ""}`}
            aria-pressed={mode === c.m}
            onClick={() => onPick(c.m)}
          >
            <ModePicture mode={c.m} />
            <strong>{c.title}</strong>
            <span>{c.text}</span>
          </button>
        ))}
      </div>
      <button type="button" className="dv-s-link" onClick={onShowTips}>
        Show me the gestures
      </button>
    </Sheet>
  );
}

const QUALITY_CARDS: { q: Quality; title: string; text: string; bars: number }[] = [
  { q: "auto", title: "Automatic", text: "Adjusts to your connection", bars: 0 },
  { q: "speed", title: "Faster", text: "Smoother on a slow connection", bars: 1 },
  { q: "balanced", title: "Balanced", text: "A good middle ground", bars: 2 },
  { q: "quality", title: "Sharpest", text: "Crisp text, needs good Wi-Fi", bars: 3 },
];

function Bars({ n }: { n: number }) {
  return (
    <svg viewBox="0 0 36 28" className="dv-s-bars" aria-hidden="true">
      {n === 0 ? (
        <path d="M6 20a12 12 0 0 1 24 0M18 20l6-8" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
      ) : (
        [0, 1, 2].map((i) => (
          <rect key={i} x={5 + i * 10} y={18 - i * 6} width="7" height={8 + i * 6} rx="2" fill="currentColor" opacity={i < n ? 1 : 0.22} />
        ))
      )}
    </svg>
  );
}

export function QualitySheet({ quality, videoOk, onPick, onClose }: { quality: Quality; videoOk: boolean; onPick(q: Quality): void; onClose(): void }) {
  return (
    <Sheet title="Picture quality" icon={<IconQuality />} onClose={onClose}>
      <div className="dv-s-cards four">
        {QUALITY_CARDS.map((c) => (
          <button key={c.q} type="button" className={`dv-s-card small${quality === c.q ? " is-on" : ""}`} aria-pressed={quality === c.q} onClick={() => onPick(c.q)}>
            <Bars n={c.bars} />
            <strong>{c.title}</strong>
            <span>{c.text}</span>
          </button>
        ))}
      </div>
      {!videoOk ? <p className="dv-s-note">This phone shows still pictures rather than video, so Automatic uses Sharpest.</p> : null}
    </Sheet>
  );
}

export function ClipboardSheet({
  fromComputer,
  onSend,
  onClose,
}: {
  fromComputer: string | null;
  onSend(text: string): void;
  onClose(): void;
}) {
  const [text, setText] = useState("");
  const [copied, setCopied] = useState(false);
  const paste = async (): Promise<void> => {
    try {
      const t = await navigator.clipboard.readText();
      if (t) setText(t);
    } catch {
      // Clipboard reading is blocked; the person can paste into the box.
    }
  };
  const copy = async (): Promise<void> => {
    if (!fromComputer) return;
    try {
      await navigator.clipboard.writeText(fromComputer);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <Sheet title="Copy and paste" icon={<IconClipboard />} onClose={onClose}>
      <div className="dv-s-form">
        <div className="dv-s-clip-block">
          <h3>Send to the computer</h3>
          <textarea value={text} onChange={(e) => setText(e.target.value)} placeholder="Type or paste text here" rows={3} />
          <div className="dv-s-row">
            <button type="button" className="dv-s-pill" onClick={() => void paste()}>
              <IconPaste size={20} /> Paste from phone
            </button>
            <button type="button" className="dv-s-pill is-primary" disabled={!text} onClick={() => onSend(text)}>
              <IconSend size={20} /> Send
            </button>
          </div>
        </div>
        <div className="dv-s-clip-block">
          <h3>Copied on the computer</h3>
          {fromComputer ? (
            <>
              <p className="dv-s-clip-text">{fromComputer}</p>
              <button type="button" className="dv-s-pill" onClick={() => void copy()}>
                <IconCopy size={20} /> {copied ? "Copied to this phone" : "Copy to this phone"}
              </button>
            </>
          ) : (
            <p className="dv-s-note">Copy something on the computer and it shows up here.</p>
          )}
        </div>
      </div>
    </Sheet>
  );
}

export function StatsSheet({ stats, onClose, onQuality }: { stats: SessionStats | null; onClose(): void; onQuality(): void }) {
  const level = qualityLevel(stats);
  return (
    <Sheet title={LEVEL_WORDS[level]} icon={<IconWifi />} onClose={onClose}>
      <div className={`dv-s-meter level-${level}`}>
        {[0, 1, 2].map((i) => (
          <span key={i} className={i <= (level === "good" ? 2 : level === "fair" ? 1 : 0) ? "on" : ""} />
        ))}
      </div>
      <dl className="dv-s-stats">
        <div>
          <dt>Reply time</dt>
          <dd>{stats ? `${Math.round(stats.rtt_ms)} ms` : "Measuring"}</dd>
        </div>
        <div>
          <dt>Pictures a second</dt>
          <dd>{stats ? Math.round(stats.fps) : "Measuring"}</dd>
        </div>
        <div>
          <dt>Speed</dt>
          <dd>{stats ? formatSpeed(stats.throughput_bps) : "Measuring"}</dd>
        </div>
      </dl>
      {level !== "good" ? <p className="dv-s-note">If things feel slow, try the Faster picture quality.</p> : null}
      <button type="button" className="dv-s-big secondary" onClick={onQuality}>
        Change picture quality
      </button>
    </Sheet>
  );
}
