//! Error codes, the hint that goes with each one, and the exit code the CLI
//! leaves behind.
//!
//! ## Why the code is a string and not an enum
//!
//! Three vocabularies meet here and none of them is a superset of the others.
//! `02 §3.4`'s [`RefusalCode`] is eleven canonical codes and is
//! `#[non_exhaustive]`. `agent-plane`'s [`RefusalReason`] adds five the runtime
//! genuinely has to make and that `02` predates. `04 §4.4` names ten for the
//! MCP boundary, and two of those (`CREDENTIALS_REQUIRED`, `WRONG_PROTOCOL`)
//! exist nowhere below.
//!
//! An enum here would be a fourth vocabulary plus three mappings, and every
//! mapping is a place the sets drift. So the code an agent matches on is the
//! plane's own string, passed through verbatim, which is `06 §5.5`'s rule: a
//! model that has to parse prose to find out what happened will parse it wrong
//! on the day the prose is edited. [`hint_for`] is the one table, keyed on the
//! string, with a default that is still useful.
//!
//! [`RefusalCode`]: limb_core::observation::RefusalCode
//! [`RefusalReason`]: agent_plane::RefusalReason

use agent_plane::{PlaneError, RefusalReason};

/// The version this build reports in `server/discover` and in `dvv version`.
pub const DVV_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The codes this adapter mints itself, beside the ones the plane produces.
///
/// Named constants rather than literals so a grep finds every site, and
/// `04 §4.4`'s list is the reason each one exists.
pub mod codes {
    /// The grant does not carry what the call costs, or there is no grant yet.
    pub const POLICY_DENIED: &str = "POLICY_DENIED";
    /// Built, wired to nothing. The honest answer while the shell wiring is
    /// owed, and the only answer that does not waste an agent's turn.
    pub const NOT_IMPLEMENTED: &str = "NOT_IMPLEMENTED";
    /// The limb id resolved to nothing, or the selector named no limb.
    pub const LIMB_GONE: &str = "LIMB_GONE";
    /// A desktop verb on a terminal limb, or the reverse.
    pub const WRONG_PROTOCOL: &str = "WRONG_PROTOCOL";
    /// The machine is asking a PERSON for a password. `04 §4.4` gives this one
    /// its hint verbatim and it is the whole of D7 in a sentence.
    pub const CREDENTIALS_REQUIRED: &str = "CREDENTIALS_REQUIRED";
    /// The arguments do not describe a call this tool can make.
    pub const BAD_REQUEST: &str = "BAD_REQUEST";
    /// A wait or a control acquire ran out of time with nothing settled.
    pub const TIMEOUT: &str = "TIMEOUT";
    /// Arbitration said no.
    pub const LEASE_NOT_HELD: &str = "LEASE_NOT_HELD";
    /// The lease went away underneath a call that had it.
    pub const LEASE_REVOKED: &str = "LEASE_REVOKED";
}

/// A tool execution error: something the model can read and self correct from.
///
/// Not a protocol error. `04 §4.4` keeps the specification's own division: a
/// malformed call is a JSON-RPC error object, and everything else is an
/// ordinary result carrying `isError: true`, because a model that is handed a
/// transport failure for a refusal it caused cannot tell the two apart.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct ToolError {
    /// The identifier an agent matches on, in capitals.
    pub code: String,
    /// The sentence an agent reads. Never a code repeated: an agent told "no"
    /// learns nothing, an agent told "a PTY has no pointer, use type" stops
    /// asking.
    pub message: String,
}

impl ToolError {
    /// An error with an explicit code.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> ToolError {
        ToolError {
            code: code.into(),
            message: message.into(),
        }
    }

    /// The arguments do not describe a call this tool can make.
    pub fn bad_request(message: impl Into<String>) -> ToolError {
        ToolError::new(codes::BAD_REQUEST, message)
    }

    /// Built, wired to nothing, with a sentence naming what is missing.
    pub fn not_implemented(message: impl Into<String>) -> ToolError {
        ToolError::new(codes::NOT_IMPLEMENTED, message)
    }

    /// The next action, per code (`04 §4.4`).
    pub fn hint(&self) -> &'static str {
        hint_for(&self.code)
    }

    /// What `dvv` exits with when this error ends a CLI verb (`04 §7.2`).
    pub fn exit_code(&self) -> i32 {
        exit_code_for(&self.code)
    }
}

impl From<PlaneError> for ToolError {
    /// A plane operation was refused.
    ///
    /// The sentence is the error's own `Display`, which every variant of
    /// [`PlaneError`] already writes with the repair in it, so nothing is
    /// rewritten here and nothing can be softened on the way out.
    fn from(error: PlaneError) -> ToolError {
        let code = match &error {
            PlaneError::TooManyLimbs { .. } => "RATE_LIMITED",
            PlaneError::HostNotInGrant { .. } | PlaneError::MissingCapability { .. } => {
                codes::POLICY_DENIED
            }
            PlaneError::NoSuchLimb { .. } | PlaneError::IdentityCollision { .. } => {
                codes::LIMB_GONE
            }
            PlaneError::SlotRefused(_) => "SLOT_REFUSED",
            PlaneError::BadLimbId(_) => codes::BAD_REQUEST,
            PlaneError::Lease(_) => codes::LEASE_NOT_HELD,
            // `PlaneError` is `#[non_exhaustive]`, so a variant added by a
            // later build lands here. `BAD_REQUEST` is the wrong guess to make
            // in that position, since a new plane refusal is far more likely to
            // be a policy one, and a wrong hint sends an agent to fix the call
            // rather than the grant.
            _ => codes::POLICY_DENIED,
        };
        ToolError::new(code, error.to_string())
    }
}

/// The code a settlement's refusal reports at this boundary.
///
/// The plane's own precise reason wins where it has one, because it is the
/// name with the repair attached. See [`RefusalReason::as_str`], whose values
/// are exactly `02 §3.4`'s eleven plus the five `08 §4.6` and `09 §2` needed.
pub fn code_for_refusal(reason: RefusalReason) -> &'static str {
    reason.as_str()
}

/// The next action to take, per code.
///
/// One table, and every entry is an instruction rather than a restatement.
/// `04 §4.4` requires it and `packages/automation/src/mcp/format.ts:52` is
/// where the habit comes from.
pub fn hint_for(code: &str) -> &'static str {
    match code {
        "LEASE_NOT_HELD" => {
            "Call dvv_control with action acquire before acting. If it refuses, call it with action yield_status: if humanTookOver is true, a PERSON is driving and the right move is to stop and report back, not to retry."
        }
        "LEASE_REVOKED" => {
            "Call dvv_control with action yield_status before anything else. If humanTookOver is true, STOP: do not reacquire and do not act on this machine. Tell the user."
        }
        "NOT_READY" | "NOT_CONNECTED" => {
            "The limb is not connected yet. Call dvv_wait with until connected, or read dvv_status for the retry time and back off rather than spinning."
        }
        "WRONG_PROTOCOL" => {
            "This verb does not exist on this kind of limb. Call dvv_limbs and pick the sibling that does: read through the terminal, act through the desktop."
        }
        "POLICY_DENIED" => {
            "This grant does not carry what the call costs, and a grant's capabilities and hosts are fixed when a person approves it. Tell the user which capability is missing and ask them to reapprove in DeskVNCViewer."
        }
        "HOST_NOT_IN_GRANT" => {
            "The grant names its hosts literally and there is no wildcard, so a different spelling will not work. Tell the user which host you needed."
        }
        "NOT_IMPLEMENTED" | "NOT_SUPPORTED" => {
            "This build cannot do that. The message names what is missing. Do not retry: pick a different tool or a different limb."
        }
        "TIMEOUT" => {
            "Nothing settled inside the window. This is an ordinary result and not a failure: call again, or read dvv_status to see whether the limb is still connected."
        }
        "LIMB_GONE" => {
            "That limb is not attached. Call dvv_limbs for the current ids; a limb id is reproducible, so the same machine at the same slot has the same id when it comes back."
        }
        "CREDENTIALS_REQUIRED" => {
            "This machine is asking for a password. You cannot supply one. Tell the user to answer the prompt in DeskVNCViewer, then call dvv_status again."
        }
        "RATE_LIMITED" | "INTENT_IN_FLIGHT" | "INTENT_BLOCKED" => {
            "Slow down. One batch at a time per limb, and the message says which limit was reached. Wait for the call you already made to settle."
        }
        "GEOMETRY_CHANGED" => {
            "The screen resized under this action and nothing was delivered. Call dvv_screen again and recompute the coordinate against the new generation."
        }
        "UNFENCED" => {
            "This action carries a coordinate and no geometry generation. Read the generation from dvv_screen or dvv_status and send it back as generation."
        }
        "OUT_OF_BOUNDS" => {
            "The coordinate is outside the framebuffer and is rejected rather than clamped. Read the size from dvv_status first."
        }
        "UNKNOWN_KEY" => {
            "That key name is not in the fixed table. Use a DOM code or key spelling such as Enter, Escape, Tab, ControlLeft. A numeric code is a different action and needs the scancode capability, which is in no role bundle."
        }
        "NOT_EXPRESSIBLE" => {
            "The wire cannot carry what you asked for and the plane will not invent a conversion. The message says what it can carry instead."
        }
        "SLOT_REFUSED" => {
            "This protocol will not give you that many concurrent sessions against one machine. Use slot 0, which attaches to whatever is already open."
        }
        "NO_NATIVE_VARIANT" => {
            "The limb serves this intent itself and the wire variant that would carry it does not exist in this build. Do not retry. Use dvv_term_send, which lowers to bytes that do exist."
        }
        "BAD_REQUEST" => {
            "The arguments do not describe a call this tool can make. The message says which one is wrong."
        }
        _ => "Read the message: it names what happened and what can be done about it.",
    }
}

/// The process exit code for a CLI verb that ended with this code.
///
/// `04 §7.2`. Exit codes are the interface: 0 success, 1 a plane error, 2 bad
/// usage, 3 policy denied, 4 lease not held, 5 timed out with nothing settled,
/// 64 and up reserved.
pub fn exit_code_for(code: &str) -> i32 {
    match code {
        "POLICY_DENIED" | "HOST_NOT_IN_GRANT" => 3,
        "LEASE_NOT_HELD" | "LEASE_REVOKED" => 4,
        "TIMEOUT" => 5,
        "BAD_REQUEST" => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_hint_is_an_instruction_rather_than_a_restatement() {
        // The failure this guards against is a hint that says "the lease is not
        // held", which is the code again in lower case and tells an agent
        // nothing it did not already have.
        for code in [
            "LEASE_NOT_HELD",
            "LEASE_REVOKED",
            "NOT_READY",
            "WRONG_PROTOCOL",
            "POLICY_DENIED",
            "NOT_IMPLEMENTED",
            "TIMEOUT",
            "LIMB_GONE",
            "CREDENTIALS_REQUIRED",
            "RATE_LIMITED",
            "GEOMETRY_CHANGED",
            "UNFENCED",
            "OUT_OF_BOUNDS",
            "UNKNOWN_KEY",
            "NOT_EXPRESSIBLE",
            "NO_NATIVE_VARIANT",
        ] {
            let hint = hint_for(code);
            assert!(hint.len() > 40, "{code} has a hint too short to be advice");
            assert!(
                !hint.contains(code),
                "{code}'s hint repeats the code instead of saying what to do"
            );
        }
    }

    #[test]
    fn the_credentials_hint_is_the_whole_of_d7() {
        // `04 §4.4` writes this one out, because it is the sentence that stops
        // an agent trying to find a password somewhere.
        let hint = hint_for(codes::CREDENTIALS_REQUIRED);
        assert!(hint.contains("You cannot supply one"));
        assert!(hint.contains("DeskVNCViewer"));
    }

    #[test]
    fn exit_codes_follow_the_cli_contract() {
        assert_eq!(exit_code_for("POLICY_DENIED"), 3);
        assert_eq!(exit_code_for("LEASE_NOT_HELD"), 4);
        assert_eq!(exit_code_for("TIMEOUT"), 5);
        assert_eq!(exit_code_for("BAD_REQUEST"), 2);
        assert_eq!(exit_code_for("LIMB_GONE"), 1);
    }
}
