/**
 * "Scan network" as a split button.
 *
 * The main part does what the button always did: scan the local subnets the
 * shell deems safe. The arrow beside it opens a menu of every network this
 * computer can reach (the LAN, VPNs, Cloudflare WARP, ranges routed through a
 * gateway, and virtual bridges last), read from its interfaces and routes by
 * `scan_networks`, plus "Scan an address range..." for a range typed by hand.
 * Picking one scans just that.
 *
 * A range larger than a /22 asks first, with the address count; one larger
 * than a /16, or one that is not private, cannot be picked. The shell holds
 * the same limits, so this is the friendly half of the check.
 *
 * While a scan runs the main part becomes its Stop button, with how far it
 * has got, and Escape on it stops the scan too. The arrow is off until the
 * scan has ended, so a second one cannot be started on top of it.
 */
import { useCallback, useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import type { ScanNetwork, ScanProgress, ScanTarget } from "../lib/types";
import {
  KIND_LABEL,
  formatAddresses,
  formatCidr,
  hostCount,
  judgeCidrs,
  judgeRange,
  parseCidr,
  rangeProblem,
  readLastPick,
  roughDuration,
  samePick,
  writeLastPick,
  type LastPick,
} from "../lib/scanRange";
import { classNames } from "../lib/util";
import { IconCheck, IconChevronDown, IconStop, IconZap } from "./icons";
import { Dialog } from "./primitives";

export interface ScanButtonProps {
  scan: ScanProgress;
  /** No target: today's default scan. A target: just those ranges. */
  onScan: (target?: ScanTarget) => Promise<void>;
  /** Stop the running scan (`stop_scan`). */
  onStop: () => void;
  /** `scan_networks`. */
  listNetworks: () => Promise<ScanNetwork[]>;
}

/** The name a typed range is remembered under. */
const TYPED_RANGE = "Address range";

/** A pick waiting for the person to confirm its size. */
interface Pending {
  pick: LastPick;
  addresses: number;
}

export function ScanButton({ scan, onScan, onStop, listNetworks }: ScanButtonProps): ReactNode {
  const [open, setOpen] = useState(false);
  const [networks, setNetworks] = useState<ScanNetwork[] | null>(null);
  const [lastPick, setLastPick] = useState<LastPick | null>(() => readLastPick());
  const [typing, setTyping] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const arrowRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  /** Where focus goes once the menu is drawn: an index, or "last" for the remembered pick. */
  const focusOnOpen = useRef<number | "last">(0);

  const close = useCallback((refocus: boolean) => {
    setOpen(false);
    if (refocus) arrowRef.current?.focus();
  }, []);

  const openMenu = useCallback(
    (focus: number | "last") => {
      focusOnOpen.current = focus;
      setNetworks(null);
      setOpen(true);
      void listNetworks()
        .then((list) => setNetworks(list))
        .catch(() => setNetworks([]));
    },
    [listNetworks],
  );

  const items = (): HTMLButtonElement[] =>
    menuRef.current
      ? [...menuRef.current.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not([disabled])')]
      : [];

  // Put the focus in the menu once its rows exist, on the remembered pick
  // when there is one, so Enter repeats the last scan.
  useEffect(() => {
    if (!open || networks === null) return;
    const all = items();
    if (all.length === 0) return;
    const want = focusOnOpen.current;
    const last = all.findIndex((b) => b.dataset.last === "true");
    const i = want === "last" ? (last >= 0 ? last : 0) : want < 0 ? all.length - 1 : want;
    all[Math.min(i, all.length - 1)]?.focus();
  }, [open, networks]);

  // A press anywhere else, or the window losing focus, closes the menu.
  useEffect(() => {
    if (!open) return;
    const away = (): void => close(false);
    window.addEventListener("pointerdown", away);
    window.addEventListener("blur", away);
    return () => {
      window.removeEventListener("pointerdown", away);
      window.removeEventListener("blur", away);
    };
  }, [open, close]);

  const run = useCallback(
    (pick: LastPick, allowLarge: boolean) => {
      writeLastPick(pick);
      setLastPick(pick);
      void onScan({ cidrs: pick.cidrs, allowLarge });
    },
    [onScan],
  );

  const choose = (pick: LastPick, verdict: ScanNetwork["verdict"], addresses: number): void => {
    close(true);
    if (verdict === "confirm") {
      setPending({ pick, addresses });
    } else if (verdict === "scan") {
      run(pick, false);
    }
  };

  const onMenuKey = (e: KeyboardEvent<HTMLDivElement>): void => {
    const all = items();
    const at = all.indexOf(document.activeElement as HTMLButtonElement);
    const go = (i: number): void => {
      e.preventDefault();
      all[(i + all.length) % all.length]?.focus();
    };
    switch (e.key) {
      case "ArrowDown":
        go(at + 1);
        break;
      case "ArrowUp":
        go(at - 1);
        break;
      case "Home":
        go(0);
        break;
      case "End":
        go(all.length - 1);
        break;
      case "Escape":
        e.preventDefault();
        e.stopPropagation();
        close(true);
        break;
      case "Tab":
        close(false);
        break;
      default:
        break;
    }
  };

  const onArrowKey = (e: KeyboardEvent<HTMLButtonElement>): void => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      openMenu(e.key === "ArrowDown" ? "last" : -1);
    }
  };

  const typedLast =
    lastPick && networks && !networks.some((n) => samePick(lastPick, n)) ? lastPick : null;

  const stopping = scan.running && scan.stopping === true;
  const progress = scan.total > 0 ? `${scan.done.toLocaleString("en-US")} of ${scan.total.toLocaleString("en-US")}` : "";

  const onMainKey = (e: KeyboardEvent<HTMLButtonElement>): void => {
    if (e.key === "Escape" && scan.running) {
      e.preventDefault();
      e.stopPropagation();
      if (!stopping) onStop();
    }
  };

  return (
    <div className="relative inline-flex">
      <button
        type="button"
        className="btn-secondary relative overflow-hidden tabular-nums"
        style={{ borderTopRightRadius: 0, borderBottomRightRadius: 0 }}
        // No tooltip: WebKitGTK keeps showing one after the scan ends and the
        // button has gone back to "Scan network".
        aria-keyshortcuts={scan.running ? "Escape" : undefined}
        aria-busy={scan.running}
        disabled={stopping}
        onClick={() => {
          if (!scan.running) void onScan();
          else if (!stopping) onStop();
        }}
        onKeyDown={onMainKey}
      >
        {scan.running ? (
          <span className="absolute inset-x-0 bottom-0 h-0.5 bg-inset">
            <span
              className={classNames("block h-full bg-accent", scan.total === 0 && "indeterminate-bar w-1/3")}
              style={scan.total > 0 ? { width: `${(scan.done / scan.total) * 100}%` } : undefined}
            />
          </span>
        ) : null}
        {scan.running ? <IconStop size={14} /> : <IconZap size={14} />}
        {!scan.running
          ? "Scan network"
          : stopping
            ? "Stopping…"
            : progress
              ? `Stop scan ${progress}`
              : "Stop scan"}
      </button>
      <button
        ref={arrowRef}
        type="button"
        aria-label="Choose a network to scan"
        // The tooltip would sit on top of the menu it opens.
        title={open ? undefined : "Choose a network to scan"}
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={scan.running}
        className={classNames("btn-secondary", scan.running && "opacity-60")}
        style={{
          borderTopLeftRadius: 0,
          borderBottomLeftRadius: 0,
          borderLeftWidth: 0,
          paddingLeft: 6,
          paddingRight: 6,
        }}
        onPointerDown={(e) => e.stopPropagation()}
        onClick={() => (open ? close(false) : openMenu("last"))}
        onKeyDown={onArrowKey}
      >
        <IconChevronDown size={14} />
      </button>

      {open ? (
        <div
          ref={menuRef}
          role="menu"
          aria-label="Networks to scan"
          className="fade-in absolute right-0 top-full z-50 mt-1 max-h-[70vh] w-80 overflow-y-auto rounded-md border border-subtle bg-raised p-1 shadow-(--shadow-pop)"
          onPointerDown={(e) => e.stopPropagation()}
          onKeyDown={onMenuKey}
        >
          {networks === null ? (
            <div className="px-2.5 py-1.5 text-sm text-tertiary">Looking for networks…</div>
          ) : networks.length === 0 ? (
            <div className="px-2.5 py-1.5 text-sm text-tertiary">No other networks found</div>
          ) : (
            networks.map((n, i) => {
              const last = samePick(lastPick, n);
              const blocked = n.verdict === "too-large" || n.verdict === "public";
              const pick: LastPick = { name: n.name, range: n.range, cidrs: n.cidrs };
              return (
                <div key={n.id}>
                  {i > 0 && networks[i - 1].kind !== n.kind ? (
                    <div className="mx-2 my-1 border-t border-subtle" />
                  ) : null}
                  <button
                    type="button"
                    role="menuitem"
                    tabIndex={-1}
                    disabled={blocked}
                    data-last={last ? "true" : undefined}
                    title={n.cidrs.join(", ")}
                    className={classNames(
                      "block w-full rounded-sm px-2.5 py-1.5 text-left text-sm outline-none",
                      blocked ? "cursor-default text-tertiary" : "text-primary hover:bg-inset focus:bg-inset",
                    )}
                    onClick={() => choose(pick, n.verdict, n.addresses)}
                  >
                    <span className="flex items-center gap-2">
                      <span className="w-3.5 shrink-0 text-accent">
                        {last ? <IconCheck size={14} aria-label="Last scanned" /> : null}
                      </span>
                      <span className="min-w-0 flex-1 truncate">{n.name}</span>
                      <span
                        className={classNames(
                          "shrink-0 rounded-sm px-1.5 text-[11px] leading-4",
                          n.kind === "virtual" ? "border border-subtle text-tertiary" : "bg-inset text-secondary",
                        )}
                      >
                        {KIND_LABEL[n.kind]}
                      </span>
                    </span>
                    <span className="mt-0.5 flex gap-2 pl-5.5 text-xs text-secondary tabular-nums">
                      <span className="truncate">{n.range}</span>
                      <span className="ml-auto shrink-0">
                        {n.verdict === "too-large"
                          ? "too large to scan whole"
                          : formatAddresses(n.addresses)}
                      </span>
                    </span>
                  </button>
                </div>
              );
            })
          )}
          <div className="mx-2 my-1 border-t border-subtle" />
          {typedLast ? (
            <button
              type="button"
              role="menuitem"
              tabIndex={-1}
              data-last="true"
              className="flex w-full items-center gap-2 rounded-sm px-2.5 py-1.5 text-left text-sm text-primary outline-none hover:bg-inset focus:bg-inset"
              onClick={() => {
                const { verdict, addresses } = judgeCidrs(typedLast.cidrs);
                choose(typedLast, verdict, addresses);
              }}
            >
              <span className="w-3.5 shrink-0 text-accent">
                <IconCheck size={14} aria-label="Last scanned" />
              </span>
              <span className="flex-1 truncate">Scan {typedLast.range} again</span>
            </button>
          ) : null}
          <button
            type="button"
            role="menuitem"
            tabIndex={-1}
            className="flex w-full items-center gap-2 rounded-sm px-2.5 py-1.5 text-left text-sm text-primary outline-none hover:bg-inset focus:bg-inset"
            onClick={() => {
              close(false);
              setTyping(true);
            }}
          >
            <span className="w-3.5 shrink-0" />
            Scan an address range…
          </button>
        </div>
      ) : null}

      {typing ? (
        <RangeDialog
          initial={typedLast?.range ?? ""}
          onClose={() => {
            setTyping(false);
            arrowRef.current?.focus();
          }}
          onScan={(pick, allowLarge) => {
            setTyping(false);
            run(pick, allowLarge);
          }}
        />
      ) : null}

      {pending ? (
        <ConfirmDialog
          pending={pending}
          onClose={() => setPending(null)}
          onConfirm={() => {
            setPending(null);
            run(pending.pick, true);
          }}
        />
      ) : null}
    </div>
  );
}

function ConfirmDialog({
  pending,
  onClose,
  onConfirm,
}: {
  pending: Pending;
  onClose: () => void;
  onConfirm: () => void;
}): ReactNode {
  return (
    <Dialog title="Scan a large range?" onClose={onClose} width={420} initialFocusSelector="[data-confirm]">
      <div className="space-y-3">
        <p className="text-sm text-secondary">
          {pending.pick.range}
          {pending.pick.name === TYPED_RANGE ? "" : ` on ${pending.pick.name}`} has{" "}
          {formatAddresses(pending.addresses)}. The scan
          stays polite, so it takes {roughDuration(pending.addresses)}.
        </p>
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn-primary" data-confirm onClick={onConfirm}>
            Scan {formatAddresses(pending.addresses)}
          </button>
        </div>
      </div>
    </Dialog>
  );
}

function RangeDialog({
  initial,
  onClose,
  onScan,
}: {
  initial: string;
  onClose: () => void;
  onScan: (pick: LastPick, allowLarge: boolean) => void;
}): ReactNode {
  const [text, setText] = useState(initial);
  const [touched, setTouched] = useState(false);
  const parsed = parseCidr(text);
  const problem = rangeProblem(text);
  const addresses = parsed ? hostCount(parsed) : 0;
  const large = parsed !== null && problem === null && judgeRange(parsed) === "confirm";
  const shown = parsed ? formatCidr(parsed) : "";

  const submit = (): void => {
    setTouched(true);
    if (!parsed || problem) return;
    onScan({ name: TYPED_RANGE, range: shown, cidrs: [shown] }, large);
  };

  return (
    <Dialog title="Scan an address range" onClose={onClose} width={420} initialFocusSelector="input">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <label className="block space-y-1.5">
          <span className="text-sm text-secondary">Address or range</span>
          <input
            className="field font-mono"
            value={text}
            placeholder="192.168.1.0/24"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            aria-invalid={touched && problem !== null}
            aria-describedby="scan-range-note"
            onChange={(e) => setText(e.target.value)}
          />
        </label>
        <p
          id="scan-range-note"
          className={classNames("text-xs", touched && problem ? "text-danger" : "text-secondary")}
        >
          {touched && problem
            ? problem
            : parsed && !problem
              ? large
                ? `${shown} has ${formatAddresses(addresses)}, which takes ${roughDuration(addresses)}.`
                : `${shown}, ${formatAddresses(addresses)}.`
              : "Private ranges only, up to a /16."}
        </p>
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary">
            {large ? `Scan ${formatAddresses(addresses)}` : "Scan"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
