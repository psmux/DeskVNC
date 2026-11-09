/** Big friendly text fields and toggles. */
import { useId, useState, type InputHTMLAttributes, type ReactNode } from "react";
import { IconEye } from "../art/Icons";
import { haptic } from "../lib/haptics";

interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "size"> {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  icon?: ReactNode;
  trailing?: ReactNode;
}

export function Field({ label, hint, error, icon, trailing, type, className = "", ...rest }: FieldProps) {
  const id = useId();
  const [show, setShow] = useState(false);
  const secret = type === "password";
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-2 block px-1 text-sm font-semibold text-ink-dim">
        {label}
      </label>
      <div
        className={`flex min-h-14 items-center gap-3 rounded-2xl border-2 bg-surface-2 px-4 transition-colors focus-within:border-accent focus-within:bg-surface ${error ? "border-danger" : "border-transparent"}`}
      >
        {icon && <span className="text-ink-dim">{icon}</span>}
        <input
          id={id}
          type={secret && show ? "text" : type}
          className="min-w-0 flex-1 bg-transparent py-3 text-lg text-ink outline-none placeholder:text-ink-dim/60"
          aria-invalid={!!error}
          {...rest}
        />
        {secret && (
          <button type="button" className="-mr-2 flex h-12 w-12 items-center justify-center text-ink-dim" aria-label={show ? "Hide password" : "Show password"} onClick={() => setShow((v) => !v)}>
            <IconEye off={show} />
          </button>
        )}
        {trailing}
      </div>
      {error ? (
        <p role="alert" className="mt-2 px-1 text-sm font-medium text-danger">
          {error}
        </p>
      ) : hint ? (
        <p className="mt-2 px-1 text-sm text-ink-dim">{hint}</p>
      ) : null}
    </div>
  );
}

export function Toggle({ on, onChange, label }: { on: boolean; onChange: (on: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      onClick={() => {
        haptic("select");
        onChange(!on);
      }}
      className={`relative h-9 w-16 shrink-0 rounded-full transition-colors ${on ? "bg-ok" : "bg-line"}`}
    >
      <span className={`absolute top-1 h-7 w-7 rounded-full bg-white shadow transition-[left] duration-200 ${on ? "left-8" : "left-1"}`} />
    </button>
  );
}

/** A row of big choices where one is picked. */
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: string; art?: ReactNode }[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="flex gap-2 rounded-[1.25rem] bg-surface-2 p-1.5">
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={on}
            onClick={() => {
              haptic("select");
              onChange(o.value);
            }}
            className={`flex min-h-12 flex-1 flex-col items-center justify-center gap-1 rounded-2xl px-2 py-2 text-sm font-semibold transition-all ${on ? "bg-surface text-accent shadow-card" : "text-ink-dim"}`}
          >
            {o.art}
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
