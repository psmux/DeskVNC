import type { Protocol } from "../api/contract";
import { PROTOCOL_LABEL, ProtocolIcon, protocolColor, protocolSoft } from "../art/ProtocolArt";

/** The protocol as a coloured pill with its icon. `solid` for over pictures. */
export function ProtocolBadge({ protocol, solid = false, className = "" }: { protocol: Protocol; solid?: boolean; className?: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full py-1 pl-1 pr-3 text-sm font-semibold ${className}`}
      style={solid ? { background: "rgba(255,255,255,0.92)", color: protocolColor(protocol) } : { background: protocolSoft(protocol), color: protocolColor(protocol) }}
    >
      <ProtocolIcon protocol={protocol} size={22} />
      {PROTOCOL_LABEL[protocol]}
    </span>
  );
}
