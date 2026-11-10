/**
 * The friendly "getting there" view: a picture for where things are and a
 * list of steps with ticks. The Help screen shows it while a code is looked
 * up, and the session screen can show it from `state-changed` events until
 * the first frame, so the two look like one continuous flow.
 *
 * Map a SessionState with `stepFor` below.
 */
import { AnimatePresence, motion } from "motion/react";
import type { Protocol, SessionState } from "../api/contract";
import { IconCheck } from "../art/Icons";
import { OsArt } from "../art/OsArt";
import { SceneApprove, SceneConnected, SceneLookup } from "../art/Scenes";

export type StepKey = "lookup" | "reach" | "approve" | "signin" | "connected";

const LABELS: Record<StepKey, string> = {
  lookup: "Looking up the code",
  reach: "Reaching the computer",
  approve: "Waiting for them to say yes",
  signin: "Signing in",
  connected: "Connected",
};

/** The steps shown for each way of connecting. */
export function stepsFor(protocol: Protocol | "demo", withCode: boolean): StepKey[] {
  if (protocol === "boundary") return withCode ? ["lookup", "approve", "connected"] : ["reach", "approve", "connected"];
  return ["reach", "signin", "connected"];
}

/** Which step a session state belongs to. */
export function stepFor(state: SessionState, protocol: Protocol | "demo"): StepKey {
  switch (state.state) {
    case "idle":
    case "resolving":
    case "connecting":
    case "reconnecting":
    case "disconnected":
      return "reach";
    case "negotiating":
      return protocol === "boundary" ? "approve" : "signin";
    case "authenticating":
      return protocol === "boundary" ? "approve" : "signin";
    case "connected":
      return "connected";
  }
}

interface Props {
  steps: StepKey[];
  current: StepKey;
  title: string;
  /** For the reach and sign in picture. */
  os?: Parameters<typeof OsArt>[0]["os"];
  subtitle?: string;
}

export function ConnectingSteps({ steps, current, title, os = "unknown", subtitle }: Props) {
  const at = Math.max(0, steps.indexOf(current));
  const art =
    current === "lookup" ? (
      <SceneLookup />
    ) : current === "approve" ? (
      <SceneApprove />
    ) : current === "connected" ? (
      <SceneConnected />
    ) : (
      <OsArt os={os} />
    );
  return (
    <div className="mx-auto flex w-full max-w-md flex-col items-center px-6 text-center">
      <AnimatePresence mode="wait">
        <motion.div
          key={current}
          className="w-64 max-w-full"
          initial={{ opacity: 0, scale: 0.9, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: -10 }}
          transition={{ duration: 0.25 }}
        >
          {art}
        </motion.div>
      </AnimatePresence>
      <h2 className="mt-2 text-title2">{title}</h2>
      {subtitle && <p className="mt-2 text-subhead text-ink-dim">{subtitle}</p>}
      <ol className="mt-6 w-full space-y-2 text-left">
        {steps.map((s, i) => {
          const done = i < at || (s === "connected" && current === "connected");
          const now = i === at && !done;
          return (
            <li
              key={s}
              className={`flex min-h-14 items-center gap-4 rounded-[10px] px-4 transition-colors ${now ? "border border-line bg-surface" : ""}`}
              aria-current={now ? "step" : undefined}
            >
              <span
                className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-footnote font-semibold ${done ? "bg-ok text-white" : now ? "bg-accent-fill text-accent-ink" : "bg-surface-2 text-ink-dim"}`}
              >
                {done ? <IconCheck size={20} /> : now ? <span className="h-3 w-3 rounded-full bg-accent-ink dv-blink" /> : i + 1}
              </span>
              <span className={`text-body ${now ? "font-semibold" : done ? "font-medium text-ink" : "text-ink-dim"}`}>{LABELS[s]}</span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
