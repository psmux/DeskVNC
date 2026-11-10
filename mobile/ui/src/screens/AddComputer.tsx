/**
 * Add or edit a computer, one question per screen:
 * how to reach it, where it is, how it looks, and an optional sign in.
 * The rules live in lib/wizard.ts; this file only draws them.
 */
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useMemo, useReducer, useState, type ReactNode } from "react";
import { api } from "../api";
import type { FoundComputer, HostOs, Protocol } from "../api/contract";
import { IconBack, IconCheck, IconChevron, IconClose, IconLink, IconLock, IconPaste, IconPlay } from "../art/Icons";
import { OsArt } from "../art/OsArt";
import { PROTOCOL_HINT, PROTOCOL_TITLE, ProtocolIcon, ProtocolScene } from "../art/ProtocolArt";
import { SceneKey, SceneSaved } from "../art/Scenes";
import { Button, IconButton } from "../components/Button";
import { Field, Toggle } from "../components/Field";
import { formatCode } from "../lib/code";
import { haptic } from "../lib/haptics";
import { boundaryKind, canContinue, newWizard, reduceWizard, STEPS, toDraft, type WizardState } from "../lib/wizard";
import { useApp } from "../state/app";
import { SWATCHES, swatch } from "../theme/palette";

const OS_CHOICES: { os: HostOs; label: string }[] = [
  { os: "windows", label: "Windows" },
  { os: "mac", label: "Mac" },
  { os: "linux", label: "Linux" },
  { os: "raspberry", label: "Pi" },
  { os: "unknown", label: "Other" },
];

async function readClipboard(): Promise<string> {
  try {
    return (await navigator.clipboard.readText()) ?? "";
  } catch {
    return "";
  }
}

export function AddComputer({ initial }: { initial: WizardState }) {
  const app = useApp();
  const [s, dispatch] = useReducer(reduceWizard, initial ?? newWizard());
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [savedId, setSavedId] = useState<string | null>(null);
  const [dir, setDir] = useState(1);

  const stepIndex = STEPS.indexOf(s.step);
  const next = () => {
    setDir(1);
    const check = canContinue(s);
    haptic(check.ok ? "tap" : "warning");
    dispatch({ type: "next" });
  };
  const back = () => {
    setDir(-1);
    if (s.step === "how" || (s.mode === "edit" && s.step === "where") || s.step === "done") app.closeWizard();
    else dispatch({ type: "back" });
  };

  const save = async (withSecret: boolean) => {
    setBusy(true);
    setSaveError(null);
    try {
      let invitation: string | undefined;
      if (s.protocol === "boundary" && boundaryKind(s.boundaryText) === "code") {
        invitation = (await api.boundaryResolve(formatCode(s.boundaryText))).invitation;
      }
      const host = await app.saveHost(toDraft(s, invitation));
      if (withSecret && s.remember && (s.password || s.username)) {
        await api.hostsSetSecret(host.id, s.username.trim() || null, s.password || null);
      }
      haptic("success");
      setSavedId(host.id);
      setDir(1);
      dispatch({ type: "saved", id: host.id });
      void app.refresh();
    } catch (e) {
      haptic("error");
      setSaveError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

  const title = s.mode === "edit" ? `Edit ${initial.name}` : "Add a computer";

  return (
    <motion.div
      className="fixed inset-0 z-40 flex flex-col bg-bg"
      initial={{ y: "100%" }}
      animate={{ y: 0 }}
      exit={{ y: "100%" }}
      transition={{ type: "spring", stiffness: 340, damping: 36 }}
      role="dialog"
      aria-label={title}
    >
      <div className="pt-safe pl-safe pr-safe">
        <div className="mx-auto flex max-w-2xl items-center gap-3 px-4 pb-2 pt-3">
          <IconButton label={s.step === "how" || s.step === "done" || (s.mode === "edit" && s.step === "where") ? "Close" : "Back"} onClick={back}>
            {s.step === "how" || s.step === "done" || (s.mode === "edit" && s.step === "where") ? <IconClose /> : <IconBack />}
          </IconButton>
          <div className="flex-1">
            <p className="text-center text-base font-semibold">{title}</p>
            {s.step !== "done" && (
              <div className="mx-auto mt-2 flex max-w-[12rem] gap-1.5" aria-label={`Step ${stepIndex + 1} of ${STEPS.length}`}>
                {STEPS.map((st, i) => (
                  <span key={st} className={`h-1.5 flex-1 rounded-full transition-colors duration-300 ${i <= stepIndex ? "bg-accent" : "bg-line"}`} />
                ))}
              </div>
            )}
          </div>
          <span className="w-12" />
        </div>
      </div>

      <div className="relative flex-1 overflow-y-auto overflow-x-hidden">
        <AnimatePresence mode="popLayout" custom={dir} initial={false}>
          <motion.div
            key={s.step}
            custom={dir}
            initial={{ x: dir * 60, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: dir * -60, opacity: 0 }}
            transition={{ duration: 0.22 }}
            className="mx-auto w-full max-w-2xl px-5 pb-10 pt-2"
          >
            {s.step === "how" && <StepHow s={s} pick={(p) => (setDir(1), dispatch({ type: "pick-protocol", protocol: p }))} paste={(t) => dispatch({ type: "address", text: t })} />}
            {s.step === "where" && <StepWhere s={s} dispatch={dispatch} onEnter={next} />}
            {s.step === "look" && <StepLook s={s} dispatch={dispatch} />}
            {s.step === "signin" && <StepSignIn s={s} dispatch={dispatch} />}
            {s.step === "done" && (
              <StepDone
                name={s.name}
                edit={s.mode === "edit"}
                onConnect={() => {
                  app.closeWizard();
                  if (savedId) app.connect({ kind: "saved", hostId: savedId }, s.name);
                }}
                onDone={app.closeWizard}
              />
            )}
          </motion.div>
        </AnimatePresence>
      </div>

      {s.step !== "how" && s.step !== "done" && (
        <div className="pb-safe pl-safe pr-safe border-t border-line bg-surface/90 backdrop-blur-xl">
          <div className="mx-auto max-w-2xl px-5 py-3">
            {(s.error || saveError) && (
              <p role="alert" className="mb-3 rounded-[10px] bg-danger-soft px-4 py-3 text-center font-medium text-danger">
                {saveError ?? s.error}
              </p>
            )}
            {s.step === "signin" ? (
              <div className="flex flex-col gap-2">
                <Button size="xl" block disabled={busy} onClick={() => void save(true)} icon={busy ? <Spinner /> : <IconCheck />}>
                  {busy ? (s.protocol === "boundary" && boundaryKind(s.boundaryText) === "code" ? "Checking the code" : "Saving") : "Save"}
                </Button>
                <Button variant="ghost" size="md" block disabled={busy} onClick={() => void save(false)}>
                  Skip, ask me when I connect
                </Button>
              </div>
            ) : (
              <Button size="xl" block onClick={next} icon={<IconChevron />} className="flex-row-reverse">
                Continue
              </Button>
            )}
          </div>
        </div>
      )}
    </motion.div>
  );
}

function Spinner() {
  return <span className="h-5 w-5 rounded-full border-[3px] border-white/40 border-t-white dv-spin" />;
}

function StepTitle({ title, subtitle, art }: { title: string; subtitle?: ReactNode; art?: ReactNode }) {
  return (
    <div className="mb-5 text-center">
      {art && <div className="mx-auto mb-1 w-40">{art}</div>}
      <h2 className="text-[1.75rem] font-semibold leading-tight">{title}</h2>
      {subtitle && <p className="mx-auto mt-2 max-w-md text-lg text-ink-dim">{subtitle}</p>}
    </div>
  );
}

// ---------------------------------------------------------------- step 1

function StepHow({ s, pick, paste }: { s: WizardState; pick: (p: Protocol) => void; paste: (text: string) => void }) {
  const [pasteNote, setPasteNote] = useState<string | null>(null);
  return (
    <div>
      <StepTitle title="How will you reach it?" subtitle="Pick the one that fits. Not sure? Windows PCs at work are usually the first." />
      <div className="flex flex-col gap-3">
        {(["rdp", "vnc", "boundary"] as Protocol[]).map((p, i) => (
          <motion.button
            key={p}
            type="button"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 * i }}
            onClick={() => {
              haptic("select");
              pick(p);
            }}
            aria-pressed={s.protocol === p}
            className={`flex items-center gap-3 rounded-[14px] border bg-surface p-3 pr-4 text-left shadow-card transition-transform active:scale-[0.98] ${s.protocol === p ? "border-accent ring-1 ring-accent" : "border-line"}`}
          >
            <ProtocolScene protocol={p} className="h-24 w-32 shrink-0" />
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-2 text-lg font-semibold leading-tight">{PROTOCOL_TITLE[p]}</span>
              <span className="mt-1 block text-base leading-snug text-ink-dim">{PROTOCOL_HINT[p]}</span>
            </span>
            <IconChevron className="shrink-0 text-ink-dim" />
          </motion.button>
        ))}
      </div>
      <button
        type="button"
        className="mx-auto mt-6 flex min-h-12 items-center gap-2 rounded-full border border-line bg-surface-2 px-5 font-medium text-accent"
        onClick={async () => {
          const text = (await readClipboard()).trim();
          if (!text) return setPasteNote("Copy a link like rdp://office-pc first, then tap here.");
          paste(text);
          setPasteNote(null);
        }}
      >
        <IconLink size={20} />
        Got a link? Paste it
      </button>
      {pasteNote && <p className="mt-2 text-center text-sm text-ink-dim">{pasteNote}</p>}
    </div>
  );
}

// ---------------------------------------------------------------- step 2

function StepWhere({ s, dispatch, onEnter }: { s: WizardState; dispatch: React.Dispatch<Parameters<typeof reduceWizard>[1]>; onEnter: () => void }) {
  const app = useApp();
  const [more, setMore] = useState(s.portTouched && s.mode === "add");
  useEffect(() => {
    if (s.protocol !== "boundary" && !app.scanning && app.found.length === 0) void app.scan();
    // Only on arrival.
  }, []);
  const suggestions = useMemo(() => {
    const same = app.found.filter((f) => f.protocol === s.protocol);
    return same.length ? same : app.found.filter((f) => f.protocol !== "boundary");
  }, [app.found, s.protocol]);

  if (s.protocol === "boundary") {
    return (
      <div>
        <StepTitle
          art={<ProtocolScene protocol="boundary" />}
          title="Their code or invitation"
          subtitle="Ask them to open DeskVNC Support and tell you the code. A computer ID from that screen works too."
        />
        <Field
          label="Code, invitation or computer ID"
          placeholder="1234 5678 9012"
          value={/^\d+$/.test(s.boundaryText) ? formatCode(s.boundaryText) : s.boundaryText}
          onChange={(e) => dispatch({ type: "boundary", text: e.target.value })}
          inputMode="text"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          onKeyDown={(e) => e.key === "Enter" && onEnter()}
          trailing={
            <button
              type="button"
              aria-label="Paste"
              className="-mr-2 flex h-12 items-center gap-1.5 rounded-xl px-3 font-semibold text-accent"
              onClick={async () => dispatch({ type: "boundary", text: (await readClipboard()).trim() })}
            >
              <IconPaste size={20} /> Paste
            </button>
          }
        />
      </div>
    );
  }

  const portLabel = s.protocol === "rdp" ? "Port (Remote Desktop uses 3389)" : "Port (screen sharing uses 5900)";
  return (
    <div>
      <StepTitle
        title="Where is it?"
        subtitle={s.protocol === "rdp" ? "Type the PC's name or address, or tap it below if it is nearby." : "Type the computer's name or address, or tap it below if it is nearby."}
      />
      <Field
        label="Name or address"
        placeholder={s.protocol === "rdp" ? "office-pc or 192.0.2.20" : "studio.local or 10.0.0.5"}
        value={s.address}
        onChange={(e) => dispatch({ type: "address", text: e.target.value })}
        inputMode="url"
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        enterKeyHint="next"
        onKeyDown={(e) => e.key === "Enter" && onEnter()}
        trailing={
          !s.address && (
            <button
              type="button"
              aria-label="Paste"
              className="-mr-2 flex h-12 items-center gap-1.5 rounded-xl px-3 font-semibold text-accent"
              onClick={async () => dispatch({ type: "address", text: (await readClipboard()).trim() })}
            >
              <IconPaste size={20} /> Paste
            </button>
          )
        }
      />

      <div className="mt-6">
        <div className="mb-3 flex items-center gap-2 px-1">
          <span className="text-sm font-semibold text-ink-dim">Found nearby</span>
          {app.scanning && <span className="h-2 w-2 rounded-full bg-accent dv-blink" />}
        </div>
        <div className="flex flex-col gap-2">
          {suggestions.map((f) => (
            <FoundRow key={`${f.address}:${f.port}`} item={f} picked={s.address === f.address && s.port === f.port} onPick={() => dispatch({ type: "found", item: f })} />
          ))}
          {suggestions.length === 0 && (
            <p className="rounded-[10px] bg-surface-2 px-4 py-4 text-center text-ink-dim">{app.scanning ? "Looking around your network…" : "Nothing found nearby. Typing the address works just as well."}</p>
          )}
        </div>
      </div>

      <button type="button" onClick={() => setMore((v) => !v)} className="mt-6 flex min-h-12 items-center gap-2 px-1 font-semibold text-accent" aria-expanded={more}>
        <IconChevron size={20} className={`transition-transform ${more ? "rotate-90" : ""}`} />
        More options
      </button>
      {more && (
        <div className="mt-2 flex flex-col gap-4">
          <Field
            label={portLabel}
            inputMode="numeric"
            value={String(s.port)}
            onChange={(e) => dispatch({ type: "port", port: Number(e.target.value.replace(/\D/g, "")) || 0 })}
          />
          {s.protocol === "rdp" && <Field label="Domain, if your work uses one" placeholder="Leave empty if unsure" value={s.domain} autoCapitalize="none" onChange={(e) => dispatch({ type: "domain", text: e.target.value })} />}
        </div>
      )}
    </div>
  );
}

function FoundRow({ item, picked, onPick }: { item: FoundComputer; picked: boolean; onPick: () => void }) {
  return (
    <button
      type="button"
      onClick={() => {
        haptic("select");
        onPick();
      }}
      className={`flex min-h-16 items-center gap-3 rounded-[10px] border bg-surface p-2 pr-4 text-left transition-transform active:scale-[0.98] ${picked ? "border-accent ring-1 ring-accent" : "border-line"}`}
    >
      <OsArt os={item.os} className="h-12 w-16 shrink-0" />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-lg font-semibold">{item.name ?? "A computer"}</span>
        <span className="block truncate text-sm text-ink-dim">{item.address}</span>
      </span>
      {picked ? (
        <span className="flex h-8 w-8 items-center justify-center rounded-full bg-accent text-accent-ink">
          <IconCheck size={18} />
        </span>
      ) : (
        <ProtocolIcon protocol={item.protocol} size={28} />
      )}
    </button>
  );
}

// ---------------------------------------------------------------- step 3

function StepLook({ s, dispatch }: { s: WizardState; dispatch: React.Dispatch<Parameters<typeof reduceWizard>[1]> }) {
  const sw = swatch(s.color);
  return (
    <div>
      <StepTitle title="Make it yours" subtitle="A name, a picture and a colour, so you spot it in a second." />
      <motion.div layout className="mx-auto mb-6 flex max-w-xs flex-col items-center rounded-[14px] border border-line bg-surface-2 p-4">
        <OsArt os={s.os} backdrop={false} className="h-28" />
        <p className="mt-1 flex max-w-full items-center gap-2 text-lg font-semibold">
          <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: sw.main }} aria-hidden />
          <span className="truncate">{s.name || "Your computer"}</span>
        </p>
      </motion.div>
      <Field label="Name" value={s.name} placeholder="Like Studio PC or Mum's laptop" maxLength={60} onChange={(e) => dispatch({ type: "name", text: e.target.value })} />
      <p className="mb-2 mt-6 px-1 text-sm font-semibold text-ink-dim">Picture</p>
      <div className="grid grid-cols-5 gap-2">
        {OS_CHOICES.map((o) => (
          <button
            key={o.os}
            type="button"
            aria-pressed={s.os === o.os}
            onClick={() => {
              haptic("select");
              dispatch({ type: "os", os: o.os });
            }}
            className={`flex min-h-20 flex-col items-center justify-center rounded-[10px] border bg-surface p-1 ${s.os === o.os ? "border-accent ring-1 ring-accent" : "border-line"}`}
          >
            <OsArt os={o.os} backdrop={false} className="h-11 w-full" />
            <span className="text-xs font-medium">{o.label}</span>
          </button>
        ))}
      </div>
      <p className="mb-2 mt-6 px-1 text-sm font-semibold text-ink-dim">Colour</p>
      <div className="flex flex-wrap gap-3">
        {SWATCHES.map((c) => (
          <button
            key={c.key}
            type="button"
            aria-label={c.label}
            aria-pressed={s.color === c.key}
            onClick={() => {
              haptic("select");
              dispatch({ type: "color", color: c.key });
            }}
            className={`flex h-12 w-12 items-center justify-center rounded-full border transition-transform active:scale-90 ${s.color === c.key ? "border-line-strong bg-surface" : "border-transparent"}`}
          >
            <span className="flex h-7 w-7 items-center justify-center rounded-full text-white" style={{ background: c.main }}>
              {s.color === c.key && <IconCheck size={16} strokeWidth={2.6} />}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- step 4

function StepSignIn({ s, dispatch }: { s: WizardState; dispatch: React.Dispatch<Parameters<typeof reduceWizard>[1]> }) {
  const [askUser, setAskUser] = useState(s.protocol === "rdp" || s.username !== "");
  const boundary = s.protocol === "boundary";
  return (
    <div>
      <StepTitle
        art={<SceneKey />}
        title="Sign in, if you like"
        subtitle={
          boundary
            ? "Only for a computer set up to let you in when nobody is there. Otherwise skip this."
            : "Save it now and you will not be asked each time. You can skip this too."
        }
      />
      <div className="flex flex-col gap-4">
        {askUser && !boundary && (
          <Field label="User name" autoComplete="username" autoCapitalize="none" autoCorrect="off" value={s.username} onChange={(e) => dispatch({ type: "username", text: e.target.value })} />
        )}
        <Field
          label={boundary ? "Unattended password" : "Password"}
          type="password"
          autoComplete="current-password"
          value={s.password}
          onChange={(e) => dispatch({ type: "password", text: e.target.value })}
        />
        {!askUser && !boundary && (
          <button type="button" className="min-h-12 self-start px-1 font-semibold text-accent" onClick={() => setAskUser(true)}>
            It asks for a user name too
          </button>
        )}
        <div className="flex items-center gap-3 rounded-[10px] border border-line bg-surface p-4">
          <span className="flex h-11 w-11 items-center justify-center rounded-full bg-ok-soft text-ok">
            <IconLock />
          </span>
          <div className="flex-1">
            <p className="font-semibold">Remember on this phone</p>
            <p className="text-sm text-ink-dim">Locked away in the phone's keychain, never in a plain file.</p>
          </div>
          <Toggle on={s.remember} onChange={(on) => dispatch({ type: "remember", on })} label="Remember on this phone" />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- done

function StepDone({ name, edit, onConnect, onDone }: { name: string; edit: boolean; onConnect: () => void; onDone: () => void }) {
  return (
    <div className="flex flex-col items-center pt-6 text-center">
      <motion.div initial={{ scale: 0.6, rotate: -8 }} animate={{ scale: 1, rotate: 0 }} transition={{ type: "spring", stiffness: 260, damping: 14 }} className="w-60">
        <SceneSaved />
      </motion.div>
      <h2 className="mt-2 text-[1.75rem] font-semibold">{edit ? "Changes saved" : `${name} is ready`}</h2>
      <p className="mt-2 text-lg text-ink-dim">{edit ? "Everything is up to date." : "It is on your list now. Connect whenever you like."}</p>
      <div className="mt-8 flex w-full max-w-sm flex-col gap-3">
        <Button size="xl" block icon={<IconPlay />} onClick={onConnect}>
          Connect now
        </Button>
        <Button variant="soft" size="lg" block onClick={onDone}>
          Done
        </Button>
      </div>
    </div>
  );
}
