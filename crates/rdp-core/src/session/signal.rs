//! What one PDU means to the lifecycle (PRDRDP/06 §2.3).
//!
//! Between the framer and everything else sits one function,
//! [`super::run_loop::RunLoop::dispatch`], which parses one framed PDU and
//! says what the lifecycle has to do about it. It is pure with respect to
//! I/O: it never writes, so it can be called from the body of a match arm,
//! and it can be unit tested against a byte slice with no socket and no
//! runtime.
//!
//! [`SessionSignal`] is that function's return type. It exists so the
//! lifecycle has a small closed vocabulary of "things that happened to this
//! session", and so a new member of that vocabulary is a compile error at
//! every match site rather than something a wildcard swallows. Two rules
//! follow and both are enforced at the one match site:
//!
//! * **No wildcard arm.** It is our enum, it is not `#[non_exhaustive]`, and
//!   adding a variant must break every match that has to change.
//! * **`dispatch` never writes.** It returns the bytes to send inside
//!   [`SessionSignal::Handled`], and the loop body hands them to the writer
//!   channel. That is what keeps the "no write inside a `select!` arm" rule
//!   true without anybody having to remember it, and it is what makes the
//!   whole dispatcher testable from a fixture file.
//!
//! # Two documents, one enum
//!
//! PRDRDP/12 §4.5 declares a competing return type called `Produced`, with
//! `Wire`, `Cursor`, `CursorAt`, `Clipboard`, `Protocol`, `Reactivate`,
//! `Terminate` and `Ignored`, and PRDRDP/06 §2.3 records the disagreement
//! without resolving it: the gap is grain, not spelling, and the owner has to
//! pick one list. This file follows PRDRDP/06's names, with one departure the
//! next section argues for.
//!
//! # One output variant rather than five
//!
//! PRDRDP/06 §2.3 lists `Graphics`, `Pointer`, `ErrorInfo`, `SaveSessionInfo`
//! and the rest as separate members of this vocabulary. They are one variant
//! here, [`SessionSignal::Output`], and the reason is the fast path: one
//! `TS_FP_UPDATE_PDU` (MS-RDPBCGR 2.2.9.1.2) carries a sequence of records, so
//! a single frame can produce a bitmap update, a cursor shape and a cursor
//! position together. With five variants the dispatcher would have to return a
//! `Vec<SessionSignal>` and the loop would match on each element, which is the
//! same code with an extra allocation and an extra layer.
//!
//! What the loop does with them is identical in every case: emit them in
//! order, which is the ordering the server chose and the only one that is
//! right. So the distinction the five variants would carry buys nothing at the
//! one match site, and the finer grain is kept where it belongs, in
//! [`remote_core::SessionEvent`], which the shell already matches on.

use bytes::Bytes;

/// One PDU in, one signal out.
///
/// Every variant names the specification section that produces it, because
/// that is the only way this can be reviewed against the document.
#[derive(Debug)]
pub enum SessionSignal {
    /// A PDU a channel handler consumed in full and the lifecycle has no
    /// opinion about. Carries whatever has to go back on the wire, so the
    /// loop writes at most once per inbound PDU.
    Handled {
        /// Bytes to queue for the writer task, already encoded.
        reply: Option<Bytes>,
    },

    /// Decoded output: dirty rectangles, cursor news and protocol news, in the
    /// order the server sent them, plus whatever has to go back on the wire.
    ///
    /// Produced by the fast path update PDU (MS-RDPBCGR 2.2.9.1.2), the Server
    /// Graphics Update PDU (2.2.9.1.1.3), the Server Pointer Update PDU
    /// (2.2.9.1.1.4), the Save Session Info PDU (2.2.10.1) and the Set Error
    /// Info PDU (2.2.5.1.1). The `reply` half carries the Confirm Active and
    /// finalisation batch a Demand Active during a reactivation needs
    /// (2.2.1.13, PRDRDP/06 §6.1).
    Output {
        /// Events to emit, in order. The renderer presents once per
        /// `FramebufferUpdate`, so several bitmap records out of one fast path
        /// PDU arrive as one event and not as one per rectangle.
        events: Vec<remote_core::SessionEvent>,
        /// Bytes to queue for the writer task, already encoded.
        reply: Option<Bytes>,
    },

    /// A PDU we deliberately ignore, with a reason for the trace.
    ///
    /// The specification has PDUs we do not implement, servers send them, and
    /// skipping one by its length is what a tolerant client does. The reason
    /// is a `&'static str` so the trace says which PDU was dropped and why,
    /// rather than discarding silently.
    Ignored(&'static str),

    /// The session is over from the server's side.
    Terminate(DisconnectSignal),
}

/// Why the server ended it (PRDRDP/06 §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectSignal {
    /// MCS Disconnect Provider Ultimatum with `rn-user-requested` (3), which
    /// is a logoff rather than a failure (MS-RDPBCGR 2.2.2.3).
    UserRequested,
    /// The same PDU with `rn-provider-initiated` (1).
    ProviderInitiated,
    /// An ultimatum with any other reason code.
    ///
    /// MS-RDPBCGR 3.1.5.1.2 says the client MUST ignore a reason code that is
    /// neither of the two above, so this is a variant rather than a value: it
    /// exists so the log line can name what arrived while the rule stays
    /// visible in the type.
    UnknownReason(u8),
    /// The socket ended with no ultimatum at all. Legitimate, because
    /// MS-RDPBCGR 1.3.1.4.2 makes every one of the three closing PDUs
    /// optional.
    Eof,
}

impl DisconnectSignal {
    /// The reason code of an MCS Disconnect Provider Ultimatum, classified
    /// (T.125 §7, `rdp_pdu::mcs::disconnect_reason`).
    #[must_use]
    pub fn from_reason(reason: u8) -> Self {
        use rdp_pdu::mcs::disconnect_reason as r;
        match reason {
            r::USER_REQUESTED => DisconnectSignal::UserRequested,
            r::PROVIDER_INITIATED => DisconnectSignal::ProviderInitiated,
            other => DisconnectSignal::UnknownReason(other),
        }
    }

    /// True when the server said a user asked for this, which is the one
    /// case that is not a failure and must not put a red banner on the
    /// window.
    #[must_use]
    pub const fn is_user_requested(self) -> bool {
        matches!(self, DisconnectSignal::UserRequested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_reason_codes_the_client_may_act_on_are_told_apart() {
        use rdp_pdu::mcs::disconnect_reason as r;
        assert_eq!(
            DisconnectSignal::from_reason(r::USER_REQUESTED),
            DisconnectSignal::UserRequested
        );
        assert_eq!(
            DisconnectSignal::from_reason(r::PROVIDER_INITIATED),
            DisconnectSignal::ProviderInitiated
        );
        assert!(DisconnectSignal::UserRequested.is_user_requested());
        assert!(!DisconnectSignal::ProviderInitiated.is_user_requested());
    }

    /// MS-RDPBCGR 3.1.5.1.2 says the client MUST ignore any other reason
    /// code, so it is kept for the log line and classified as if none had
    /// arrived.
    #[test]
    fn any_other_reason_code_is_kept_for_the_log_and_not_acted_on() {
        for reason in [rdp_pdu::mcs::disconnect_reason::TOKEN_PURGED, 200] {
            let signal = DisconnectSignal::from_reason(reason);
            assert_eq!(signal, DisconnectSignal::UnknownReason(reason));
            assert!(!signal.is_user_requested());
        }
    }
}
