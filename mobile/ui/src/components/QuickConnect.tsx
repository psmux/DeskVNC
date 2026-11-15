/**
 * The quick connect field at the top of Your computers: type a name or an
 * address and press Connect. The phone works out what is there itself
 * (`identify`), connects when one thing answers, asks when several do, and
 * says so plainly when nothing does. The rules are in lib/quick.ts.
 */
import { useState } from "react";
import { api } from "../api";
import type { FoundComputer } from "../api/contract";
import { IconLink, IconPlay, IconPlus } from "../art/Icons";
import { OsArt } from "../art/OsArt";
import { ProtocolIcon } from "../art/ProtocolArt";
import { bareAddress, choiceKey, choiceValue, chooseService, readQuickInput } from "../lib/quick";
import { haptic } from "../lib/haptics";
import { setPrefs, usePrefs } from "../lib/prefs";
import { newWizard, reduceWizard } from "../lib/wizard";
import { useApp } from "../state/app";
import { Button } from "./Button";
import { ActionSheet } from "./sheets/ActionSheet";
import { Sheet } from "./Sheet";

const SERVICE_LABEL: Record<FoundComputer["protocol"], string> = {
  rdp: "Remote Desktop",
  vnc: "Screen sharing (VNC)",
  boundary: "Boundary",
};
const USUAL_PORT: Record<FoundComputer["protocol"], number[]> = { rdp: [3389], vnc: [5900], boundary: [5940, 0] };

function serviceLabel(f: FoundComputer): string {
  return USUAL_PORT[f.protocol].includes(f.port) ? SERVICE_LABEL[f.protocol] : `${SERVICE_LABEL[f.protocol]}, port ${f.port}`;
}

interface Typed {
  address: string;
  username: string | null;
}

export function QuickConnect() {
  const app = useApp();
  const prefs = usePrefs();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pick, setPick] = useState<{ items: FoundComputer[]; typed: Typed } | null>(null);
  const [nothing, setNothing] = useState<string | null>(null);

  /** Connect to one service that answered, through its saved entry if it has one. */
  const open = (item: FoundComputer, typed: Typed) => {
    const saved = app.hosts.find(
      (h) => h.protocol === item.protocol && bareAddress(h.address) === bareAddress(item.address) && h.port === item.port,
    );
    setText("");
    if (saved) {
      app.connect({ kind: "saved", hostId: saved.id }, saved.name);
      return;
    }
    // A typed name is kept, since it outlives the address the router hands
    // out. A Boundary computer keeps the ID it sent in front of the address.
    const address = item.protocol === "boundary" ? item.address : typed.address;
    app.connect(
      { kind: "adhoc", protocol: item.protocol, address, port: item.port, ...(typed.username ? { username: typed.username } : {}) },
      item.name ?? typed.address,
      { protocol: item.protocol, address, port: item.port, username: typed.username, foundName: null, identifiedName: item.name, os: item.os },
    );
  };

  const go = async () => {
    if (busy) return;
    setError(null);
    const input = readQuickInput(text, app.hosts);
    switch (input.kind) {
      case "empty":
        haptic("warning");
        setError("Type a name or address");
        return;
      case "error":
        haptic("warning");
        setError(input.error);
        return;
      case "help":
        setText("");
        app.openHelp(input.text);
        return;
      case "saved":
        setText("");
        app.connect({ kind: "saved", hostId: input.host.id }, input.host.name);
        return;
      case "direct":
        open(
          { address: input.address, port: input.port, protocol: input.protocol, name: null, os: "unknown" },
          { address: input.address, username: input.username },
        );
        return;
      case "identify": {
        haptic("tap");
        setBusy(true);
        let items: FoundComputer[] = [];
        try {
          items = await api.identify(input.address, input.port);
        } catch (e) {
          setBusy(false);
          haptic("error");
          setError(e instanceof Error ? e.message : String(e));
          return;
        }
        setBusy(false);
        const typed = { address: input.address, username: input.username };
        const choice = chooseService(items, prefs.quickChoices);
        if (choice.kind === "none") {
          haptic("warning");
          setNothing(text.trim());
        } else if (choice.kind === "pick") {
          haptic("select");
          setPick({ items: choice.items, typed });
        } else {
          open(choice.item, typed);
        }
        return;
      }
    }
  };

  const byHand = (address: string) => {
    setText("");
    app.openWizard(reduceWizard(newWizard(), { type: "address", text: address }));
  };

  return (
    <>
      <form
        className="flex flex-col gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void go();
        }}
      >
        <div className="flex gap-2">
          <label className="flex min-h-12 min-w-0 flex-1 items-center gap-2 rounded-[10px] border border-line bg-surface px-3 focus-within:ring-2 focus-within:ring-accent">
            <IconLink size={18} className="shrink-0 text-ink-faint" />
            <input
              type="text"
              inputMode="url"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              enterKeyHint="go"
              value={text}
              disabled={busy}
              onChange={(e) => {
                setText(e.target.value);
                setError(null);
              }}
              placeholder="Name or IP address"
              aria-label="Type a name or address"
              aria-invalid={!!error}
              className="min-w-0 flex-1 bg-transparent py-2 text-body outline-none placeholder:text-ink-faint"
            />
          </label>
          <Button type="submit" size="lg" disabled={busy || text.trim() === ""} icon={busy ? undefined : <IconPlay size={12} />}>
            {busy ? "Looking…" : "Connect"}
          </Button>
        </div>
        {error && (
          <p role="alert" className="px-1 text-footnote font-medium text-danger">
            {error}
          </p>
        )}
      </form>

      <ActionSheet
        open={!!pick}
        onClose={() => setPick(null)}
        art={pick ? <OsArt os={pick.items[0].os} /> : undefined}
        title={pick ? `${pick.items[0].name ?? pick.typed.address} has more than one way in` : undefined}
        actions={
          pick
            ? pick.items.map((item) => ({
                label: serviceLabel(item),
                icon: (
                  <span className="flex h-10 w-10 items-center justify-center rounded-full bg-accent-fill">
                    <ProtocolIcon protocol={item.protocol} size={22} />
                  </span>
                ),
                onPick: () => {
                  setPrefs({ quickChoices: { ...prefs.quickChoices, [choiceKey(item.address)]: choiceValue(item) } });
                  open(item, pick.typed);
                },
              }))
            : []
        }
      />

      <Sheet
        open={nothing !== null}
        onClose={() => setNothing(null)}
        title={`Nothing answered at ${nothing ?? ""}`}
        subtitle="Check the address, that the computer is on, and that screen sharing or Remote Desktop is turned on there."
      >
        <div className="flex flex-col gap-2">
          <Button
            size="lg"
            block
            icon={<IconPlus size={18} />}
            onClick={() => {
              const address = nothing ?? "";
              setNothing(null);
              byHand(address);
            }}
          >
            Set it up by hand
          </Button>
          <Button variant="plain" size="lg" block onClick={() => setNothing(null)}>
            Close
          </Button>
        </div>
      </Sheet>
    </>
  );
}
