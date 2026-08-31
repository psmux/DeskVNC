//! What a limb is called, and why the name is derived rather than minted.
//!
//! `00 R31` and `02 §4`. The MCP revision of 2026-07-28 removed protocol level
//! sessions, so a caller keeps no handle between turns and the limb id is the
//! whole mechanism by which it addresses a machine on turn forty. That makes
//! reproducibility a correctness property rather than a convenience: an agent
//! restarted tomorrow has to reach the same machine, and the only way to
//! promise that without a persistent map is to derive the name from the
//! machine.
//!
//! The format is `lmb_<protocol>_<12 hex>_<slot>`, and every part of it is
//! forced by something. `lmb_` and the underscores because
//! `validate_session_id` (`src-tauri/src/windows.rs:18`) accepts 1 to 64
//! characters of `[A-Za-z0-9_-]` and nothing else, since the id becomes a
//! window label. The hex because the address of a machine is not a caller's
//! business. The slot because two agents asking for one host must be able to
//! get two sessions (`§4.4`).

use remote_core::driver::ProtocolKind;
use sha2::{Digest, Sha256};

/// The identity a limb id is derived from: one machine, as the shell already
/// understands the word.
///
/// This mirrors `MachineKey` at `src-tauri/src/state.rs:69` field for field.
/// It is a copy rather than a reuse because `src-tauri` sits above every crate
/// in the workspace and nothing down here may depend on it, and because the
/// shell's copy is a hash map key while this one is a hashing input with a
/// pinned byte encoding. The two must agree on what counts as one machine, so
/// [`MachineKey::endpoint`] takes an address that is ALREADY normalised: see
/// its doc comment, which is the one sharp edge in this module.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MachineKey {
    /// A saved host. A profile already carries its protocol, which is why this
    /// variant does not.
    Profile(String),
    /// An address typed into QuickConnect. Carries the protocol as well,
    /// because somebody who has genuinely put RDP on 5900 must not have their
    /// VNC limb handed back instead (PRDRDP/07 §4.12).
    Endpoint {
        protocol: ProtocolKind,
        address: String,
        port: u16,
    },
}

impl MachineKey {
    /// A saved host profile.
    pub fn profile(id: impl Into<String>) -> Self {
        MachineKey::Profile(id.into())
    }

    /// An endpoint, whose address the CALLER has already normalised.
    ///
    /// The normalisation belongs to `vnc_store::normalize_address`, reached
    /// through `src-tauri/src/state.rs:98`, and it lower cases the host and
    /// drops the trailing dot an mDNS name carries. It is not applied here
    /// because this crate cannot depend on `vnc-store` without dragging a
    /// database into the agent plane, and applying a second, private copy of
    /// the rule is exactly how the plane's idea of "the same machine" and the
    /// window de-duplication's idea of it drift apart.
    ///
    /// So the plane normalises once, at the point where it already holds the
    /// store, and hands the result here. An un-normalised address does not
    /// fail: it produces a DIFFERENT limb id for the same machine, which is
    /// the failure this comment exists to prevent somebody discovering.
    pub fn endpoint(
        protocol: ProtocolKind,
        normalized_address: impl Into<String>,
        port: u16,
    ) -> Self {
        MachineKey::Endpoint {
            protocol,
            address: normalized_address.into(),
            port,
        }
    }

    /// The canonical encoding fed to SHA-256, exactly as `02 §4.3` tabulates
    /// it.
    ///
    /// The leading discriminator byte and the `\0` separators are what make
    /// the encoding injective. Without them a profile called `evnc` and an
    /// endpoint on `vnc` could in principle produce the same bytes, and a
    /// collision between two machines is the one failure this whole scheme is
    /// meant to be immune to.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            MachineKey::Profile(id) => {
                out.extend_from_slice(b"p\0");
                out.extend_from_slice(id.as_bytes());
            }
            MachineKey::Endpoint {
                protocol,
                address,
                port,
            } => {
                out.extend_from_slice(b"e\0");
                out.extend_from_slice(protocol.as_str().as_bytes());
                out.push(0);
                out.extend_from_slice(address.as_bytes());
                out.push(0);
                out.extend_from_slice(port.to_string().as_bytes());
            }
        }
        out
    }
}

/// Which concurrent session against one machine this limb is.
///
/// Slot 0 attaches to whatever is already live for that machine, so an agent
/// asking for a host the person already has open in a pane gets THAT session
/// and the two are watching the same thing. A slot above zero always opens its
/// own and never adopts (`02 §4.4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Slot(pub u16);

impl Slot {
    /// The slot that attaches rather than opening.
    pub const ATTACH: Slot = Slot(0);
}

impl std::fmt::Display for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A limb's name, and the session id it doubles as.
///
/// One string, not two. `connect_session` already accepts a caller supplied
/// session id and mints a uuid only when none is given
/// (`src-tauri/src/commands/session.rs:798`), so the plane supplying the id is
/// a use of an existing door rather than a new one. One namespace means the
/// plane's registry needs no second map and a reader has one thing to learn.
///
/// The inner string is private. A [`LimbId`] can only be built by deriving one
/// ([`LimbId::derive`]) or by validating a string a caller sent back
/// ([`LimbId::from_caller`]), and neither path lets a malformed id exist.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LimbId(String);

impl LimbId {
    /// The prefix, so a log line or a grep can tell a limb id from a uuid at a
    /// glance.
    pub const PREFIX: &'static str = "lmb_";

    /// The longest a derived id can be: `lmb_` plus three for the protocol,
    /// twelve hex, five decimal digits of slot and two separators. Well inside
    /// the shell's sixty four, and asserted by a test so that a fourth
    /// protocol with a longer name is a failure here rather than a window that
    /// refuses to open.
    pub const MAX_LEN: usize = 26;

    /// Derive the name of one machine at one slot.
    ///
    /// The twelve hex digits are the first six bytes of `SHA-256` over
    /// [`MachineKey::canonical_bytes`]. `02 §4.3` says "the low 48 bits"; a
    /// digest has no numeric endianness, so this reads that as the first six
    /// bytes in the order the hash produced them, which is the rule a second
    /// implementation cannot get wrong.
    ///
    /// Forty eight bits over the few hundred machines a person has is far past
    /// any birthday concern, and a collision would be DETECTED rather than
    /// acted on: the plane holds the canonical address beside the id and
    /// compares before opening, so a collision is a refusal and never a wrong
    /// machine.
    pub fn derive(protocol: ProtocolKind, machine: &MachineKey, slot: Slot) -> LimbId {
        let digest = Sha256::digest(machine.canonical_bytes());
        let mut hex = String::with_capacity(12);
        for byte in &digest[..6] {
            hex.push_str(&format!("{byte:02x}"));
        }
        LimbId(format!(
            "{}{}_{}_{}",
            Self::PREFIX,
            protocol.as_str(),
            hex,
            slot.0
        ))
    }

    /// Take an id back from a caller.
    ///
    /// This validates the SHAPE and nothing more, and the distinction is the
    /// whole point of the method. It does not read the protocol out of the
    /// string, it does not read the slot out, and it does not check that the
    /// hex belongs to a machine, because a caller can type anything and the
    /// plane's registry is the only authority on which limbs exist. What it
    /// does guarantee is that the string is legal under `validate_session_id`,
    /// so an id that reaches a window label cannot carry a path separator or a
    /// quote.
    pub fn from_caller(s: &str) -> Result<LimbId, LimbIdError> {
        if s.is_empty() || s.len() > 64 {
            return Err(LimbIdError::Length { len: s.len() });
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(LimbIdError::Charset);
        }
        if !s.starts_with(Self::PREFIX) {
            return Err(LimbIdError::NotALimbId);
        }
        Ok(LimbId(s.to_string()))
    }

    /// The string, for a map key, a window label or a log line.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The same id as `agent-lease` names the contended resource.
    ///
    /// `agent-lease` carries its own `LimbId`, and that is correct rather than
    /// duplication: it is a string that crate never interprets, existing so a
    /// lease transition reaching a trace says which limb it belongs to
    /// (`10 §3`), and giving arbitration the derivation rules from `§4.3`
    /// would teach it what a limb is, which `08 §5` deliberately refuses to
    /// do.
    ///
    /// What must not happen is the plane building the lease key by hand from a
    /// different string. This method is the one conversion, so the lease and
    /// the limb are keyed on the same characters.
    pub fn lease_key(&self) -> agent_lease::LimbId {
        agent_lease::LimbId::from(self.0.as_str())
    }
}

impl std::fmt::Display for LimbId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A caller sent something that is not a limb id.
///
/// Three distinct reasons rather than one, because the plane reports the
/// refusal to an agent verbatim and "invalid session id", which is what the
/// shell says, teaches the agent nothing about which of its assumptions was
/// wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LimbIdError {
    #[error("a limb id is 1 to 64 characters, this one is {len}")]
    Length { len: usize },
    #[error(
        "a limb id carries only letters, digits, '-' and '_', because it becomes a window label"
    )]
    Charset,
    #[error("a limb id starts with 'lmb_'")]
    NotALimbId,
}

/// The protocol will not give this agent the slot it asked for.
///
/// Without this refusal an agent asking for eight RDP limbs on one Windows box
/// discovers the server's session policy by watching seven of them disconnect
/// the eighth (`00 R31`). A sentence up front costs nothing and a destructive
/// surprise costs somebody their work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("this protocol supports {max_slots} concurrent session(s) against one machine, so slot {} cannot be opened", .slot.0)]
pub struct SlotRefused {
    pub slot: Slot,
    pub max_slots: u16,
}
