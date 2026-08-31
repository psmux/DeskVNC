/**
 * Dual-pane file manager + transfer queue (PRD/08 §3.2).
 *
 * Local pane left, remote pane right, the established convention (TightVNC,
 * UltraVNC, RealVNC, RustDesk all do this); we deliberately don't innovate on
 * the layout. Below the panes sits the transfer queue with per-item progress,
 * speed, ETA and cancel, plus the session's completed-transfer log.
 *
 * Everything the remote sends (file names, error text) is rendered as text
 * only. Paths are never assembled here from remote data, they go straight
 * back to Rust, which normalises them and rejects `..` traversal.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  breadcrumbs,
  isHidden,
  sortEntries,
  type FilesApi,
  type Pane,
  type PaneEntry,
  type PaneState,
  type Transfer,
} from "../hooks/useFiles";
import { usePaneVisible } from "./Pane";
import { pickLocalDirectory, pickLocalFiles } from "../lib/tauri";
import { classNames, fingerprintMnemonic } from "../lib/util";
import {
  IconAlert,
  IconChevronRight,
  IconFile,
  IconFolder,
  IconEye,
  IconLock,
  IconPlus,
  IconRefresh,
  IconTrash,
  IconX,
} from "./icons";

export interface FilePanelProps {
  files: FilesApi;
  /** Display name of the remote computer, for headings and the drop overlay. */
  hostName: string;
  onClose: () => void;
}

// --------------------------------------------------------------- formatting

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "-";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
}

export function formatRate(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) return "-";
  return `${formatBytes(bytesPerSec)}/s`;
}

export function formatEta(transferred: number, total: number, bytesPerSec: number): string {
  if (bytesPerSec <= 0 || total <= transferred) return "-";
  const secs = Math.round((total - transferred) / bytesPerSec);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

function formatWhen(ts: number | null): string {
  if (!ts) return "-";
  const d = new Date(ts * 1000);
  if (Number.isNaN(d.getTime())) return "-";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ------------------------------------------------------------------- panel

export function FilePanel({ files, hostName, onClose }: FilePanelProps): ReactNode {
  const [focused, setFocused] = useState<Pane>("local");
  const [renaming, setRenaming] = useState<{ pane: Pane; path: string; name: string } | null>(null);
  const [creating, setCreating] = useState<{ pane: Pane; name: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{ pane: Pane; paths: string[] } | null>(null);

  const conn = files.conn;
  const busy = conn.state === "connecting";
  const owns = usePaneVisible();

  // Esc closes the panel unless a nested prompt owns it. Only in the focused
  // pane: the listener is on `window`, so neither hiding the pane nor sitting
  // beside the pane in use reaches it, and it would otherwise answer an Escape
  // meant for whichever session the user is actually working in.
  useEffect(() => {
    if (!owns) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key !== "Escape") return;
      if (renaming || creating || confirmDelete) {
        setRenaming(null);
        setCreating(null);
        setConfirmDelete(null);
        e.stopPropagation();
        return;
      }
      onClose();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose, owns, renaming, creating, confirmDelete]);

  const activePane = focused === "local" ? files.local : files.remote;
  const canTransfer = conn.state === "connected";

  const doUpload = useCallback(async (): Promise<void> => {
    const chosen =
      files.local.selected.length > 0 ? files.local.selected : await pickLocalFiles();
    await files.upload(chosen);
  }, [files]);

  const doDownload = useCallback(async (): Promise<void> => {
    if (files.remote.selected.length === 0) return;
    const dir = files.local.path || (await pickLocalDirectory());
    if (!dir) return;
    await files.download(files.remote.selected, dir);
  }, [files]);

  return (
    <div
      className="fade-in absolute inset-0 z-30 flex flex-col bg-scrim"
      role="dialog"
      aria-modal="true"
      aria-label={`Files, ${hostName}`}
      onPointerDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="m-auto flex h-[min(88vh,760px)] w-[min(96vw,1180px)] flex-col overflow-hidden rounded-lg border border-subtle bg-surface shadow-(--shadow-pop)">
        {/* ------------------------------------------------------- header */}
        <div className="flex items-center justify-between border-b border-subtle px-4 py-2.5">
          <h2 className="truncate text-sm font-semibold text-primary">Files, {hostName}</h2>
          <div className="flex items-center gap-2">
            {conn.state === "connected" ? (
              <span className="text-2xs text-tertiary">
                {conn.username}@{conn.host} · SFTP
              </span>
            ) : null}
            <button
              type="button"
              aria-label="Close files"
              className="rounded-sm p-1 text-tertiary hover:text-primary"
              onClick={onClose}
            >
              <IconX size={16} />
            </button>
          </div>
        </div>

        {/* --------------------------------------------------- connection */}
        {conn.state === "host-key-prompt" ? (
          <HostKeyPrompt
            host={conn.host}
            port={conn.port}
            keyType={conn.keyType}
            fingerprint={conn.fingerprint}
            onAccept={() => files.acceptHostKey(conn.fingerprint)}
            onCancel={onClose}
          />
        ) : null}

        {conn.state === "host-key-changed" ? (
          <HostKeyChanged
            host={conn.host}
            port={conn.port}
            expected={conn.expected}
            actual={conn.actual}
            onClose={onClose}
          />
        ) : null}

        {conn.state === "error" ? (
          <div className="border-b border-subtle bg-danger-subtle px-4 py-2.5 text-sm text-danger">
            {conn.message}
          </div>
        ) : null}

        {/* -------------------------------------------------------- panes */}
        <div className="flex min-h-0 flex-1">
          <FilePane
            pane="local"
            title="Local"
            state={files.local}
            files={files}
            focused={focused === "local"}
            onFocus={() => setFocused("local")}
            renaming={renaming?.pane === "local" ? renaming : null}
            setRenaming={setRenaming}
            onRequestDelete={(paths) => setConfirmDelete({ pane: "local", paths })}
            disabled={false}
          />

          {/* transfer buttons live between the panes, arrows pointing the
              way the bytes go */}
          <div className="flex w-24 shrink-0 flex-col items-center justify-center gap-2 border-x border-subtle bg-inset/40 px-2">
            <button
              type="button"
              className="btn-primary w-full px-2 py-1.5 text-xs"
              disabled={!canTransfer || busy}
              title={
                canTransfer
                  ? "Upload the selected local files (or choose files) to the remote folder"
                  : "Connect the file-transfer channel first"
              }
              onClick={() => void doUpload()}
            >
              Upload →
            </button>
            <button
              type="button"
              className="btn-secondary w-full px-2 py-1.5 text-xs"
              disabled={!canTransfer || files.remote.selected.length === 0}
              title="Download the selected remote files into the local folder"
              onClick={() => void doDownload()}
            >
              ← Download
            </button>
          </div>

          <FilePane
            pane="remote"
            title={`Remote, ${hostName}`}
            state={files.remote}
            files={files}
            focused={focused === "remote"}
            onFocus={() => setFocused("remote")}
            renaming={renaming?.pane === "remote" ? renaming : null}
            setRenaming={setRenaming}
            onRequestDelete={(paths) => setConfirmDelete({ pane: "remote", paths })}
            disabled={conn.state !== "connected"}
          />
        </div>

        {/* ------------------------------------------------------ toolbar */}
        <div className="flex items-center gap-2 border-t border-subtle px-3 py-2">
          <button
            type="button"
            className="btn-secondary px-2.5 py-1 text-xs"
            disabled={focused === "remote" && conn.state !== "connected"}
            onClick={() => setCreating({ pane: focused, name: "New folder" })}
          >
            <IconPlus size={13} className="mr-1 inline" />
            New folder
          </button>
          <button
            type="button"
            className="btn-secondary px-2.5 py-1 text-xs"
            disabled={activePane.selected.length !== 1}
            onClick={() => {
              const path = activePane.selected[0];
              const entry = activePane.entries.find((e) => e.path === path);
              if (entry) setRenaming({ pane: focused, path, name: entry.name });
            }}
          >
            Rename (F2)
          </button>
          <button
            type="button"
            className="btn-secondary px-2.5 py-1 text-xs text-danger"
            disabled={activePane.selected.length === 0}
            onClick={() => setConfirmDelete({ pane: focused, paths: activePane.selected })}
          >
            <IconTrash size={13} className="mr-1 inline" />
            Delete
          </button>
          <span className="flex-1" />
          <span className="text-2xs text-tertiary">
            Enter opens · Backspace goes up · Ctrl/⌘+A selects all · F2 renames · Del removes
          </span>
        </div>

        {/* -------------------------------------------------------- queue */}
        <TransferQueue files={files} />
      </div>

      {creating ? (
        <NamePrompt
          title={`New folder in ${creating.pane === "local" ? "the local" : "the remote"} folder`}
          initial={creating.name}
          confirmLabel="Create"
          onCancel={() => setCreating(null)}
          onConfirm={(name) => {
            void files.mkdir(creating.pane, name);
            setCreating(null);
          }}
        />
      ) : null}

      {renaming ? (
        <NamePrompt
          title="Rename"
          initial={renaming.name}
          confirmLabel="Rename"
          onCancel={() => setRenaming(null)}
          onConfirm={(name) => {
            void files.rename(renaming.pane, renaming.path, name);
            setRenaming(null);
          }}
        />
      ) : null}

      {confirmDelete ? (
        <ConfirmDelete
          count={confirmDelete.paths.length}
          where={confirmDelete.pane === "local" ? "this computer" : hostName}
          onCancel={() => setConfirmDelete(null)}
          onConfirm={() => {
            void files.remove(confirmDelete.pane, confirmDelete.paths);
            setConfirmDelete(null);
          }}
        />
      ) : null}
    </div>
  );
}

// -------------------------------------------------------------------- pane

interface FilePaneProps {
  pane: Pane;
  title: string;
  state: PaneState;
  files: FilesApi;
  focused: boolean;
  disabled: boolean;
  onFocus: () => void;
  renaming: { pane: Pane; path: string; name: string } | null;
  setRenaming: (v: { pane: Pane; path: string; name: string } | null) => void;
  onRequestDelete: (paths: string[]) => void;
}

function FilePane({
  pane,
  title,
  state,
  files,
  focused,
  disabled,
  onFocus,
  setRenaming,
  onRequestDelete,
}: FilePaneProps): ReactNode {
  const listRef = useRef<HTMLDivElement>(null);
  const [cursor, setCursor] = useState(0);

  const visible = useMemo(() => {
    const filtered = state.showHidden ? state.entries : state.entries.filter((e) => !isHidden(e.name));
    return sortEntries(filtered, state.sort, state.sortAsc);
  }, [state.entries, state.showHidden, state.sort, state.sortAsc]);

  useEffect(() => {
    setCursor(0);
  }, [state.path]);

  const toggle = useCallback(
    (entry: PaneEntry, e: React.MouseEvent): void => {
      const additive = e.metaKey || e.ctrlKey;
      const range = e.shiftKey;
      const index = visible.findIndex((v) => v.path === entry.path);
      if (range && state.selected.length > 0) {
        const anchor = visible.findIndex((v) => v.path === state.selected[state.selected.length - 1]);
        const [from, to] = anchor < index ? [anchor, index] : [index, anchor];
        files.setSelection(
          pane,
          visible.slice(Math.max(0, from), to + 1).map((v) => v.path),
        );
      } else if (additive) {
        files.setSelection(
          pane,
          state.selected.includes(entry.path)
            ? state.selected.filter((p) => p !== entry.path)
            : [...state.selected, entry.path],
        );
      } else {
        files.setSelection(pane, [entry.path]);
      }
      setCursor(Math.max(0, index));
    },
    [files, pane, state.selected, visible],
  );

  const open = useCallback(
    (entry: PaneEntry): void => {
      if (entry.isDir) files.navigate(pane, entry.path);
    },
    [files, pane],
  );

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent): void => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key.toLowerCase() === "a") {
        e.preventDefault();
        files.setSelection(pane, visible.map((v) => v.path));
        return;
      }
      switch (e.key) {
        case "ArrowDown": {
          e.preventDefault();
          const next = Math.min(visible.length - 1, cursor + 1);
          setCursor(next);
          if (visible[next]) files.setSelection(pane, [visible[next].path]);
          break;
        }
        case "ArrowUp": {
          e.preventDefault();
          const next = Math.max(0, cursor - 1);
          setCursor(next);
          if (visible[next]) files.setSelection(pane, [visible[next].path]);
          break;
        }
        case "Enter": {
          e.preventDefault();
          const entry = visible[cursor];
          if (entry) open(entry);
          break;
        }
        case "Backspace":
          e.preventDefault();
          files.goUp(pane);
          break;
        case "F2": {
          e.preventDefault();
          const entry = visible[cursor];
          if (entry) setRenaming({ pane, path: entry.path, name: entry.name });
          break;
        }
        case "Delete":
        case "Del": {
          e.preventDefault();
          if (state.selected.length > 0) onRequestDelete(state.selected);
          break;
        }
        default:
          break;
      }
    },
    [cursor, files, onRequestDelete, open, pane, setRenaming, state.selected, visible],
  );

  const crumbs = breadcrumbs(state.path);

  return (
    <section
      className={classNames(
        "flex min-w-0 flex-1 flex-col",
        focused ? "bg-surface" : "bg-surface/70",
      )}
      aria-label={title}
      onPointerDown={() => {
        onFocus();
        listRef.current?.focus();
      }}
    >
      <header className="flex items-center gap-2 border-b border-subtle px-3 py-1.5">
        <span className="shrink-0 text-2xs font-medium uppercase tracking-wide text-tertiary">
          {title}
        </span>
        <span className="flex-1" />
        <button
          type="button"
          className={classNames(
            "rounded-sm p-1",
            state.showHidden ? "text-accent" : "text-tertiary hover:text-primary",
          )}
          aria-pressed={state.showHidden}
          title={state.showHidden ? "Hide dot-files" : "Show hidden files"}
          onClick={() => files.setShowHidden(pane, !state.showHidden)}
        >
          <IconEye size={14} />
        </button>
        <button
          type="button"
          className="rounded-sm p-1 text-tertiary hover:text-primary"
          title="Refresh"
          onClick={() => files.refresh(pane)}
        >
          <IconRefresh size={14} />
        </button>
      </header>

      {/* breadcrumbs */}
      <nav className="flex flex-wrap items-center gap-0.5 border-b border-subtle px-3 py-1 text-xs" aria-label={`${title} location`}>
        {crumbs.length === 0 ? (
          <span className="text-tertiary">-</span>
        ) : (
          crumbs.map((c, i) => (
            <span key={`${c.path}-${i}`} className="flex items-center">
              {i > 0 ? <IconChevronRight size={11} className="text-tertiary" /> : null}
              <button
                type="button"
                className="max-w-40 truncate rounded-sm px-1 py-0.5 text-secondary hover:bg-inset hover:text-primary"
                onClick={() => files.navigate(pane, c.path)}
              >
                {c.label}
              </button>
            </span>
          ))
        )}
      </nav>

      {/* column headers / sort */}
      <div className="grid grid-cols-[1fr_5rem_9rem] items-center gap-2 border-b border-subtle px-3 py-1 text-2xs text-tertiary">
        <SortButton label="Name" active={state.sort === "name"} asc={state.sortAsc} onClick={() => files.setSort(pane, "name")} />
        <SortButton label="Size" active={state.sort === "size"} asc={state.sortAsc} onClick={() => files.setSort(pane, "size")} align="right" />
        <SortButton label="Modified" active={state.sort === "date"} asc={state.sortAsc} onClick={() => files.setSort(pane, "date")} align="right" />
      </div>

      {/* rows */}
      <div
        ref={listRef}
        tabIndex={0}
        role="listbox"
        aria-multiselectable="true"
        aria-label={`${title} files`}
        className="min-h-0 flex-1 overflow-y-auto outline-none"
        onKeyDown={onKeyDown}
      >
        {disabled ? (
          <p className="p-4 text-xs text-tertiary">
            The file-transfer channel is not connected.
          </p>
        ) : state.loading ? (
          <p className="p-4 text-xs text-tertiary">Loading…</p>
        ) : state.error ? (
          <p className="flex items-start gap-2 p-4 text-xs text-danger">
            <IconAlert size={14} className="mt-px shrink-0" />
            <span className="min-w-0 break-words">{state.error}</span>
          </p>
        ) : visible.length === 0 ? (
          <p className="p-4 text-xs text-tertiary">This folder is empty.</p>
        ) : (
          visible.map((entry, i) => {
            const selected = state.selected.includes(entry.path);
            return (
              <div
                key={entry.path}
                role="option"
                aria-selected={selected}
                tabIndex={-1}
                className={classNames(
                  "grid cursor-default grid-cols-[1fr_5rem_9rem] items-center gap-2 px-3 py-1 text-xs",
                  selected ? "bg-accent/15 text-primary" : "text-secondary hover:bg-inset",
                  i === cursor && focused ? "ring-1 ring-inset ring-(--accent)" : "",
                )}
                onClick={(e) => toggle(entry, e)}
                onDoubleClick={() => open(entry)}
              >
                <span className="flex min-w-0 items-center gap-1.5">
                  <span className={entry.isDir ? "text-accent" : "text-tertiary"}>
                    {entry.isDir ? <IconFolder size={14} /> : <IconFile size={14} />}
                  </span>
                  <span className="truncate">{entry.name}</span>
                  {entry.isSymlink ? <span className="shrink-0 text-2xs text-tertiary">↗</span> : null}
                </span>
                <span className="text-right tabular-nums text-tertiary">
                  {entry.isDir ? "-" : formatBytes(entry.size)}
                </span>
                <span className="truncate text-right tabular-nums text-tertiary">
                  {formatWhen(entry.modified)}
                </span>
              </div>
            );
          })
        )}
      </div>

      <footer className="border-t border-subtle px-3 py-1 text-2xs text-tertiary">
        {visible.length} item{visible.length === 1 ? "" : "s"}
        {state.selected.length > 0 ? ` · ${state.selected.length} selected` : ""}
      </footer>
    </section>
  );
}

function SortButton({
  label,
  active,
  asc,
  onClick,
  align = "left",
}: {
  label: string;
  active: boolean;
  asc: boolean;
  onClick: () => void;
  align?: "left" | "right";
}): ReactNode {
  return (
    <button
      type="button"
      className={classNames(
        "rounded-sm px-1 py-0.5 hover:text-primary",
        active ? "text-accent" : "",
        align === "right" ? "text-right" : "text-left",
      )}
      onClick={onClick}
    >
      {label}
      {active ? (asc ? " ▲" : " ▼") : ""}
    </button>
  );
}

// ------------------------------------------------------------------ queue

function TransferQueue({ files }: { files: FilesApi }): ReactNode {
  const running = files.active;
  const finished = files.transfers.filter((t) => t.state !== "running");

  return (
    <div className="max-h-56 shrink-0 overflow-y-auto border-t border-subtle bg-inset/30">
      <div className="flex items-center gap-2 px-3 py-1.5">
        <span className="text-2xs font-medium uppercase tracking-wide text-tertiary">
          Transfers{running.length > 0 ? ` (${running.length} active)` : ""}
        </span>
        <span className="flex-1" />
        {finished.length > 0 ? (
          <button
            type="button"
            className="text-2xs text-tertiary hover:text-primary"
            onClick={files.clearFinished}
          >
            Clear completed
          </button>
        ) : null}
      </div>

      {files.transfers.length === 0 ? (
        <p className="px-3 pb-2 text-2xs text-tertiary">
          No transfers yet. Drag files onto the session window, or use Upload / Download.
        </p>
      ) : (
        <ul className="space-y-0.5 px-3 pb-2">
          {files.transfers.map((t) => (
            <TransferRow key={t.id} transfer={t} onCancel={() => files.cancel(t.id)} />
          ))}
        </ul>
      )}
    </div>
  );
}

function TransferRow({
  transfer,
  onCancel,
}: {
  transfer: Transfer;
  onCancel: () => void;
}): ReactNode {
  const pct =
    transfer.total > 0 ? Math.min(100, Math.round((transfer.transferred / transfer.total) * 100)) : 0;
  const running = transfer.state === "running";
  const tone =
    transfer.state === "failed"
      ? "bg-danger"
      : transfer.state === "cancelled"
        ? "bg-tertiary"
        : transfer.state === "completed"
          ? "bg-success"
          : "bg-accent";

  return (
    <li className="grid grid-cols-[1.25rem_1fr_7rem_5rem_4rem_1.5rem] items-center gap-2 text-2xs">
      <span className="text-tertiary" aria-hidden="true">
        {transfer.direction === "upload" ? "↑" : "↓"}
      </span>
      <span className="min-w-0">
        <span className="block truncate text-secondary">{transfer.name}</span>
        <span className="mt-0.5 block h-1 overflow-hidden rounded-pill bg-inset">
          <span
            className={classNames("block h-full", tone)}
            style={{ width: `${transfer.state === "running" ? pct : 100}%` }}
          />
        </span>
      </span>
      <span className="tabular-nums text-tertiary">
        {running ? `${pct}% · ${formatBytes(transfer.transferred)}` : stateLabel(transfer)}
      </span>
      <span className="tabular-nums text-tertiary">{running ? formatRate(transfer.bytesPerSec) : ""}</span>
      <span className="tabular-nums text-tertiary">
        {running ? formatEta(transfer.transferred, transfer.total, transfer.bytesPerSec) : ""}
      </span>
      {running ? (
        <button
          type="button"
          aria-label={`Cancel transfer of ${transfer.name}`}
          title="Cancel"
          className="justify-self-end rounded-sm p-0.5 text-tertiary hover:text-danger"
          onClick={onCancel}
        >
          <IconX size={12} />
        </button>
      ) : (
        <span />
      )}
    </li>
  );
}

function stateLabel(t: Transfer): string {
  switch (t.state) {
    case "completed":
      return `Done · ${formatBytes(t.total)}`;
    case "cancelled":
      return "Cancelled";
    case "failed":
      return t.error ?? "Failed";
    default:
      return "";
  }
}

// ------------------------------------------------------------- host keys

function HostKeyPrompt({
  host,
  port,
  keyType,
  fingerprint,
  onAccept,
  onCancel,
}: {
  host: string;
  port: number;
  keyType: string;
  fingerprint: string;
  onAccept: () => void;
  onCancel: () => void;
}): ReactNode {
  return (
    <div className="border-b border-subtle bg-raised px-4 py-3">
      <p className="flex items-center gap-2 text-sm font-medium text-primary">
        <IconLock size={15} className="text-warning" />
        First connection to {host}:{port}
      </p>
      <p className="mt-1 text-xs text-secondary">
        This computer&apos;s SSH identity has not been seen before. Check the fingerprint against the
        server before trusting it.
      </p>
      <p className="mono mt-2 break-all text-xs text-primary">
        {keyType} {fingerprint}
      </p>
      <p className="mt-0.5 text-2xs text-tertiary">{fingerprintMnemonic(fingerprint)}</p>
      <div className="mt-3 flex justify-end gap-2">
        <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={onCancel}>
          Cancel
        </button>
        <button type="button" className="btn-primary px-3 py-1 text-xs" onClick={onAccept}>
          Trust and connect
        </button>
      </div>
    </div>
  );
}

function HostKeyChanged({
  host,
  port,
  expected,
  actual,
  onClose,
}: {
  host: string;
  port: number;
  expected: string;
  actual: string;
  onClose: () => void;
}): ReactNode {
  return (
    <div className="border-b border-danger bg-danger-subtle px-4 py-3">
      <p className="flex items-center gap-2 text-sm font-semibold text-danger">
        <IconAlert size={15} />
        The SSH identity of {host}:{port} has changed
      </p>
      <p className="mt-1 text-xs text-secondary">
        File transfer is blocked. This is either a reinstalled server or someone intercepting the
        connection, there is no &ldquo;continue anyway&rdquo;. Verify the new key out of band and
        remove the stored pin before reconnecting.
      </p>
      <dl className="mono mt-2 space-y-0.5 break-all text-2xs">
        <div>
          <dt className="inline text-tertiary">expected </dt>
          <dd className="inline text-primary">{expected}</dd>
        </div>
        <div>
          <dt className="inline text-tertiary">received </dt>
          <dd className="inline text-danger">{actual}</dd>
        </div>
      </dl>
      <div className="mt-3 flex justify-end">
        <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
}

// --------------------------------------------------------------- prompts

function NamePrompt({
  title,
  initial,
  confirmLabel,
  onConfirm,
  onCancel,
}: {
  title: string;
  initial: string;
  confirmLabel: string;
  onConfirm: (name: string) => void;
  onCancel: () => void;
}): ReactNode {
  const [value, setValue] = useState(initial);
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);
  const valid = value.trim().length > 0 && !/[/\\]/.test(value) && value !== "." && value !== "..";

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-scrim">
      <form
        className="w-80 rounded-lg border border-subtle bg-surface p-4 shadow-(--shadow-pop)"
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) onConfirm(value.trim());
        }}
      >
        <p className="mb-2 text-sm font-medium text-primary">{title}</p>
        <input
          ref={inputRef}
          className="field w-full"
          value={value}
          aria-label={title}
          onChange={(e) => setValue(e.target.value)}
        />
        {!valid ? (
          <p className="mt-1 text-2xs text-danger">
            A name cannot be empty, contain a slash, or be “.” or “..”.
          </p>
        ) : null}
        <div className="mt-3 flex justify-end gap-2">
          <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="btn-primary px-3 py-1 text-xs" disabled={!valid}>
            {confirmLabel}
          </button>
        </div>
      </form>
    </div>
  );
}

function ConfirmDelete({
  count,
  where,
  onConfirm,
  onCancel,
}: {
  count: number;
  where: string;
  onConfirm: () => void;
  onCancel: () => void;
}): ReactNode {
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-scrim">
      <div className="w-96 max-w-[calc(100vw-32px)] rounded-lg border border-danger bg-surface p-4 shadow-(--shadow-pop)">
        <p className="text-sm font-semibold text-primary">
          Delete {count} item{count === 1 ? "" : "s"} on {where}?
        </p>
        <p className="mt-1 text-xs text-secondary">
          Folders are removed with everything inside them. This cannot be undone.
        </p>
        <div className="mt-3 flex justify-end gap-2">
          <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={onCancel}>
            Cancel
          </button>
          <button
            type="button"
            data-autofocus
            className="btn-primary bg-danger px-3 py-1 text-xs"
            onClick={onConfirm}
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}

// -------------------------------------------------------- drop overlay

/**
 * Full-window overlay shown while files are dragged over the session
 * (PRD/08 §3.1): "Drop to send 3 files to Living Room Mac → ~/Desktop".
 */
export function DropOverlay({
  count,
  hostName,
  remoteDir,
}: {
  count: number;
  hostName: string;
  remoteDir: string;
}): ReactNode {
  return (
    <div
      className="fade-in pointer-events-none absolute inset-0 z-40 flex items-center justify-center bg-scrim"
      role="status"
      aria-live="polite"
    >
      <div className="rounded-lg border-2 border-dashed border-(--accent) bg-raised/95 px-8 py-6 text-center shadow-(--shadow-pop)">
        <p className="text-base font-semibold text-primary">
          Drop to send {count > 0 ? count : ""} file{count === 1 ? "" : "s"} to {hostName}
        </p>
        <p className="mono mt-1 text-xs text-secondary">→ {remoteDir}</p>
      </div>
    </div>
  );
}
