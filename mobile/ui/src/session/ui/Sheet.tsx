/** A bottom sheet: slides up, dims what is behind, closes on the backdrop. */
import { useEffect, useState, type ReactNode } from "react";
import { IconClose } from "./icons";

export function Sheet({
  title,
  icon,
  tone = "normal",
  onClose,
  children,
  dismissable = true,
}: {
  title: string;
  icon?: ReactNode;
  tone?: "normal" | "warning";
  onClose?: () => void;
  children: ReactNode;
  dismissable?: boolean;
}) {
  const [shown, setShown] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(true));
    return () => cancelAnimationFrame(id);
  }, []);
  return (
    <div className={`dv-s-sheet-wrap${shown ? " is-shown" : ""}`} role="presentation">
      <div className="dv-s-backdrop" onClick={dismissable ? onClose : undefined} />
      <section className={`dv-s-sheet tone-${tone}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="dv-s-grabber" aria-hidden="true" />
        <header className="dv-s-sheet-head">
          {icon ? <span className="dv-s-sheet-icon">{icon}</span> : null}
          <h2>{title}</h2>
          {dismissable && onClose ? (
            <button type="button" className="dv-s-close" onClick={onClose} aria-label="Close">
              <IconClose size={22} />
            </button>
          ) : null}
        </header>
        <div className="dv-s-sheet-body">{children}</div>
      </section>
    </div>
  );
}
