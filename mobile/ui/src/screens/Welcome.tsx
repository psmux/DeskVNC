/**
 * Welcome: three pictures that explain the app, shown once. Swipe or tap
 * Next; Skip is always there.
 */
import { AnimatePresence, motion, type PanInfo } from "motion/react";
import { useState } from "react";
import { SceneReach, SceneSafety, SceneThreeWays } from "../art/Scenes";
import { Button } from "../components/Button";
import { haptic } from "../lib/haptics";

const CARDS = [
  {
    art: <SceneReach />,
    title: "Your computer, in your pocket",
    text: "See its screen on your phone and use it with your fingers, from the sofa or the other side of town.",
  },
  {
    art: <SceneThreeWays />,
    title: "Three ways in",
    text: "Remote Desktop for Windows PCs, screen sharing for Macs and Linux, and a simple code when someone asks you for help.",
  },
  {
    art: <SceneSafety />,
    title: "They always say yes first",
    text: "When you help someone, they see your name and decide. Passwords stay locked in your phone's keychain.",
  },
];

export function Welcome({ onDone }: { onDone: () => void }) {
  const [i, setI] = useState(0);
  const [dir, setDir] = useState(1);
  const last = i === CARDS.length - 1;
  const go = (n: number) => {
    if (n < 0 || n >= CARDS.length) return;
    haptic("select");
    setDir(n > i ? 1 : -1);
    setI(n);
  };
  const swipe = (_: unknown, info: PanInfo) => {
    if (info.offset.x < -60) go(i + 1);
    else if (info.offset.x > 60) go(i - 1);
  };
  const card = CARDS[i];
  return (
    <motion.div className="pt-safe pb-safe pl-safe pr-safe fixed inset-0 z-50 flex flex-col bg-bg" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
      <div className="flex justify-end px-4 pt-3">
        {!last && (
          <button type="button" className="min-h-12 rounded-full px-5 text-lg font-semibold text-ink-dim" onClick={onDone}>
            Skip
          </button>
        )}
        {last && <span className="min-h-12" />}
      </div>
      <div className="flex flex-1 flex-col items-center justify-center overflow-hidden px-6">
        <AnimatePresence mode="wait" custom={dir}>
          <motion.div
            key={i}
            className="flex w-full max-w-md flex-col items-center text-center"
            initial={{ x: dir * 80, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: dir * -80, opacity: 0 }}
            transition={{ duration: 0.25 }}
            drag="x"
            dragConstraints={{ left: 0, right: 0 }}
            dragElastic={0.4}
            onDragEnd={swipe}
          >
            <div className="w-full max-w-[22rem]">{card.art}</div>
            <h1 className="mt-4 text-[1.75rem] font-semibold leading-tight tracking-tight">{card.title}</h1>
            <p className="mt-3 text-lg leading-relaxed text-ink-dim">{card.text}</p>
          </motion.div>
        </AnimatePresence>
      </div>
      <div className="mx-auto w-full max-w-md px-6 pb-6">
        <div className="mb-6 flex justify-center gap-2" role="tablist" aria-label="Welcome pages">
          {CARDS.map((_, n) => (
            <button
              key={n}
              type="button"
              role="tab"
              aria-selected={n === i}
              aria-label={`Page ${n + 1}`}
              onClick={() => go(n)}
              className="flex h-8 items-center justify-center px-1"
            >
              <span className={`block h-2.5 rounded-full transition-all duration-300 ${n === i ? "w-8 bg-accent" : "w-2.5 bg-line-strong"}`} />
            </button>
          ))}
        </div>
        <Button size="xl" block onClick={() => (last ? onDone() : go(i + 1))}>
          {last ? "Let's go" : "Next"}
        </Button>
      </div>
    </motion.div>
  );
}
