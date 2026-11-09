/**
 * Help someone with a Boundary code: they read it out, you tap it in on a
 * big number pad, the digits drop into three groups of four, and one press
 * connects. A pasted invitation works too.
 */
import { AnimatePresence, motion } from "motion/react";
import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { IconBackspace, IconClose, IconEdit, IconPaste, IconPlay } from "../art/Icons";
import { ProtocolScene } from "../art/ProtocolArt";
import { Button } from "../components/Button";
import { ConnectingSteps } from "../components/ConnectingSteps";
import { Field } from "../components/Field";
import { Sheet } from "../components/Sheet";
import { CODE_DIGITS, codeBoxes, codeDigits, formatCode, isCompleteCode, readPastedHelp } from "../lib/code";
import { haptic } from "../lib/haptics";
import { setPrefs, usePrefs } from "../lib/prefs";
import { useApp } from "../state/app";
import { ScreenHeader, ScreenScroll } from "./layout";

type Phase = { kind: "enter" } | { kind: "lookup" } | { kind: "error"; message: string };

export function Help() {
  const app = useApp();
  const prefs = usePrefs();
  const [digits, setDigits] = useState("");
  const [invitation, setInvitation] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>({ kind: "enter" });
  const [askName, setAskName] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const press = useCallback(
    (d: string) => {
      setNote(null);
      setDigits((cur) => {
        if (cur.length >= CODE_DIGITS) return cur;
        const next = cur + d;
        haptic(next.length === CODE_DIGITS ? "success" : "tap");
        return next;
      });
    },
    [],
  );
  const erase = useCallback(() => {
    haptic("tap");
    setDigits((cur) => cur.slice(0, -1));
  }, []);

  const paste = async () => {
    let text = "";
    try {
      text = await navigator.clipboard.readText();
    } catch {
      // Not allowed: say so below.
    }
    const found = readPastedHelp(text ?? "");
    if (found.kind === "code") {
      haptic("success");
      setDigits(found.digits);
      setInvitation(null);
      setNote(null);
    } else if (found.kind === "invitation") {
      haptic("success");
      setInvitation(found.invitation);
      setDigits("");
      setNote(null);
    } else {
      haptic("warning");
      setNote("There is no code on your clipboard. Copy their message first, or type the numbers.");
    }
  };

  // A hardware keyboard works too, for tablets.
  useEffect(() => {
    if (phase.kind !== "enter" || askName) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement) return;
      if (/^\d$/.test(e.key)) press(e.key);
      else if (e.key === "Backspace") erase();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [phase.kind, askName, press, erase]);

  const ready = invitation !== null || isCompleteCode(digits);

  const go = async (name = prefs.helperName) => {
    if (!name.trim()) {
      setAskName(true);
      return;
    }
    haptic("tap");
    try {
      let inv = invitation;
      if (!inv) {
        setPhase({ kind: "lookup" });
        inv = (await api.boundaryResolve(formatCode(digits))).invitation;
      }
      app.connect({ kind: "boundary", invitation: inv, helperName: name.trim() }, "Their computer");
      // Back to a clean pad for next time.
      setPhase({ kind: "enter" });
      setDigits("");
      setInvitation(null);
    } catch (e) {
      haptic("error");
      setPhase({ kind: "error", message: e instanceof Error ? e.message : String(e) });
    }
  };

  if (phase.kind === "lookup") {
    return (
      <ScreenScroll>
        <div className="flex min-h-full flex-col justify-center py-10">
          <ConnectingSteps steps={["lookup", "approve", "connected"]} current="lookup" title="Finding their computer" subtitle={`Code ${formatCode(digits)}`} />
        </div>
      </ScreenScroll>
    );
  }

  return (
    <ScreenScroll>
      <ScreenHeader title="Help someone" />
      <div className="mx-auto max-w-5xl px-4 pb-6 md:grid md:grid-cols-2 md:items-start md:gap-10 md:px-8">
        <section className="mb-4 flex items-center gap-2 rounded-[1.75rem] bg-surface p-2 pr-4 shadow-card md:flex-col md:p-6 md:text-center">
          <ProtocolScene protocol="boundary" className="h-20 w-24 shrink-0 md:h-auto md:w-64" />
          <div>
            <h2 className="text-lg font-bold leading-tight md:text-2xl">Ask them for their code</h2>
            <p className="mt-1 text-base leading-snug text-ink-dim md:text-lg">
              They open DeskVNC Support, press Get a code and read you 12 numbers.
            </p>
          </div>
        </section>

        <div>
          {phase.kind === "error" && (
            <div role="alert" className="mb-4 flex items-start gap-3 rounded-2xl bg-danger-soft p-4 text-danger">
              <p className="flex-1 font-medium">{phase.message}</p>
              <button type="button" aria-label="Dismiss" className="-m-2 flex h-11 w-11 items-center justify-center" onClick={() => setPhase({ kind: "enter" })}>
                <IconClose size={20} />
              </button>
            </div>
          )}

          {invitation ? (
            <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="flex items-center gap-3 rounded-[1.5rem] border-2 border-boundary bg-boundary-soft p-4">
              <span className="flex h-12 w-12 items-center justify-center rounded-full bg-boundary text-white">
                <IconPaste />
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-lg font-bold">Invitation pasted</p>
                <p className="truncate text-sm text-ink-dim">Ready to connect</p>
              </div>
              <button type="button" aria-label="Remove invitation" className="flex h-12 w-12 items-center justify-center rounded-full text-ink-dim" onClick={() => setInvitation(null)}>
                <IconClose />
              </button>
            </motion.div>
          ) : (
            <CodeBoxes digits={digits} />
          )}

          {note && <p className="mt-3 text-center text-base text-ink-dim">{note}</p>}

          <div className="mt-3 flex items-center justify-center gap-2 text-base">
            <span className="text-ink-dim">They will see</span>
            <button type="button" onClick={() => setAskName(true)} className="inline-flex min-h-11 items-center gap-1.5 rounded-full bg-surface-2 px-4 font-semibold">
              {prefs.helperName || "your name"}
              <IconEdit size={16} className="text-ink-dim" />
            </button>
          </div>

          <div className="mt-3">
            <Button size="xl" block disabled={!ready} icon={<IconPlay />} onClick={() => void go()}>
              Connect
            </Button>
          </div>

          <Keypad onDigit={press} onErase={erase} onPaste={() => void paste()} disabled={invitation !== null} />
        </div>
      </div>

      <NameSheet
        open={askName}
        initial={prefs.helperName}
        onClose={() => setAskName(false)}
        onSave={(name) => {
          setPrefs({ helperName: name });
          setAskName(false);
          if (ready) void go(name);
        }}
      />
    </ScreenScroll>
  );
}

function CodeBoxes({ digits }: { digits: string }) {
  const rows = codeBoxes(digits);
  const at = codeDigits(digits).length;
  return (
    <div className="mx-auto flex w-full max-w-md justify-center gap-2.5 sm:gap-4" aria-label={digits ? `Code ${formatCode(digits)}` : "No code yet"} role="status">
      {rows.map((row, g) => (
        <div key={g} className="flex flex-1 gap-1 sm:gap-1.5">
          {row.map((d, i) => {
            const index = g * 4 + i;
            const current = index === at;
            return (
              <div
                key={i}
                className={`relative flex h-14 min-w-0 flex-1 items-center justify-center overflow-hidden rounded-xl text-[1.6rem] font-extrabold tabular-nums transition-colors sm:h-16 sm:w-10 sm:text-3xl ${d ? "bg-boundary text-white shadow-card" : current ? "border-2 border-boundary bg-surface" : "bg-surface-2"}`}
              >
                <AnimatePresence>
                  {d && (
                    <motion.span key={d + index} initial={{ y: -24, scale: 0.4, opacity: 0 }} animate={{ y: 0, scale: 1, opacity: 1 }} exit={{ y: 20, opacity: 0 }} transition={{ type: "spring", stiffness: 600, damping: 22 }}>
                      {d}
                    </motion.span>
                  )}
                </AnimatePresence>
                {current && <span className="absolute bottom-2 h-1 w-3 rounded-full bg-boundary dv-blink" />}
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}

function Keypad({ onDigit, onErase, onPaste, disabled }: { onDigit: (d: string) => void; onErase: () => void; onPaste: () => void; disabled: boolean }) {
  const key = "flex min-h-14 [@media(min-height:860px)]:min-h-16 items-center justify-center rounded-[1.25rem] text-[1.75rem] font-bold transition-transform active:scale-90 active:bg-accent-soft disabled:opacity-40 sm:min-h-[4.5rem]";
  return (
    <div className="mt-4 grid grid-cols-3 gap-2" aria-label="Number pad">
      {["1", "2", "3", "4", "5", "6", "7", "8", "9"].map((d) => (
        <button key={d} type="button" disabled={disabled} className={`${key} bg-surface shadow-card`} onClick={() => onDigit(d)}>
          {d}
        </button>
      ))}
      <button type="button" className={`${key} flex-col gap-0.5 bg-surface-2 text-sm text-accent`} onClick={onPaste} aria-label="Paste their code or invitation">
        <IconPaste size={26} />
        <span className="text-sm font-semibold">Paste</span>
      </button>
      <button type="button" disabled={disabled} className={`${key} bg-surface shadow-card`} onClick={() => onDigit("0")}>
        0
      </button>
      <button type="button" disabled={disabled} className={`${key} bg-surface-2 text-ink-dim`} onClick={onErase} aria-label="Delete last number">
        <IconBackspace size={30} />
      </button>
    </div>
  );
}

export function NameSheet({ open, initial, onClose, onSave }: { open: boolean; initial: string; onClose: () => void; onSave: (name: string) => void }) {
  const [name, setName] = useState(initial);
  useEffect(() => {
    if (open) setName(initial);
  }, [open, initial]);
  return (
    <Sheet
      open={open}
      onClose={onClose}
      title="What is your name?"
      subtitle="They see it on their screen before they let you in, so use a name they know."
      art={
        <div className="mx-auto flex h-24 w-24 items-center justify-center rounded-full bg-boundary-soft text-5xl" aria-hidden>
          <svg viewBox="0 0 48 48" width="64" height="64">
            <circle cx="24" cy="18" r="9" fill="#ffd0b5" stroke="var(--dv-art-line)" strokeWidth={2.5} />
            <path d="M9 42a15 13 0 0 1 30 0Z" fill="var(--dv-boundary)" stroke="var(--dv-art-line)" strokeWidth={2.5} strokeLinejoin="round" />
            <path d="M16 15q8-9 16 0" fill="#6b4226" />
          </svg>
        </div>
      }
    >
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) onSave(name.trim());
        }}
      >
        <Field label="Your name" value={name} autoFocus maxLength={80} placeholder="Like Sam from IT" onChange={(e) => setName(e.target.value)} />
        <Button type="submit" size="xl" block disabled={!name.trim()}>
          Save
        </Button>
      </form>
    </Sheet>
  );
}
