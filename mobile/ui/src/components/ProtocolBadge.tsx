import type { Protocol } from "../api/contract";
import { PROTOCOL_LABEL, ProtocolIcon } from "../art/ProtocolArt";

/**
 * The protocol as a quiet chip with its icon. The same neutral look for all
 * three ways in; the icon tells them apart. `solid` for over pictures.
 */
export function ProtocolBadge({ protocol, solid = false, className = "" }: { protocol: Protocol; solid?: boolean; className?: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full py-0.5 pl-0.5 pr-2 text-caption font-medium text-ink ${
        solid ? "bg-surface/90 shadow-card backdrop-blur" : "border border-line bg-surface-2"
      } ${className}`}
    >
      <ProtocolIcon protocol={protocol} size={18} />
      {PROTOCOL_LABEL[protocol]}
    </span>
  );
}
