//! What one attachment is allowed to do, and to which machines.
//!
//! `00 R19` and `09 §2`. This is the control that does not depend on
//! recognising an injection, and it is why the security case is as good as it
//! is: an injection saying "connect to the domain controller and run this"
//! dies at attach with a host refusal before the model's decision reaches
//! anything.
//!
//! Three rules, and none of them is negotiable.
//!
//! **Deny by default.** [`CapabilitySet::default`] is empty and
//! [`CapabilitySet::allows`] is a membership test with no hierarchy in it, so
//! this file does not have to enforce that: the bitset cannot express a
//! hierarchy, so nobody can add one without changing the type in `limb-core`.
//!
//! **Hosts are resolved at issue time, with no wildcard.** A grant carries the
//! literal names of the machines a person approved. There is no suffix match,
//! no glob, no inheritance and no "every host in the library", because the
//! whole value of the control is that the set was fixed before the model saw
//! anything.
//!
//! **`exec` and `scancode` are absent from every bundle**, which is
//! `Capability::NEVER_BUNDLED` in `limb-core` and is asserted there. A grant
//! may still carry them, by naming the literal string, which is BrowserGlass's
//! treatment of `evaluate` and `cdp` copied for the same reason: a capability
//! nobody can ever hold is a capability nobody reviews.
//!
//! The residual risk is stated rather than smoothed over, in the words
//! `09 §13.1` asks for: a user grants over eight machines they administer, one
//! is compromised, an injection on its screen causes destructive work on the
//! other seven, no confirmation gate fires because nothing on the gated list
//! was touched, and the audit trail faithfully records an authorised grant
//! used exactly as authorised. That is not a failure of the design. That is
//! the design working.

use crate::error::{Refusal, RefusalReason};
use limb_core::capability::{Capability, CapabilitySet, RoleBundle};
use limb_core::party::GrantId;
use std::collections::BTreeSet;

/// A grant could not be issued.
///
/// Refused at ISSUE time rather than at use time, deliberately. A wildcard
/// caught when the first intent arrives is a wildcard that was already shown
/// to a person in an approval dialog and approved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GrantError {
    /// `00 R19`: no wildcard, at all.
    #[error(
        "host pattern {pattern:?} is not a host name; a grant names its hosts literally and resolved at issue time, so there is no wildcard and no suffix match"
    )]
    Wildcard { pattern: String },
    /// A blank host in the list is almost always a trailing separator in a
    /// caller's parse, and a blank string would otherwise sit in the set
    /// matching nothing while looking like it matched something.
    #[error("a grant's host list carries an empty name")]
    EmptyHost,
    /// A grant over no machines can do nothing, and issuing one silently would
    /// present later as every intent being refused for a reason nobody wrote
    /// down.
    #[error("a grant names at least one host; this one names none")]
    NoHosts,
}

/// One attachment's authority: what it may do, and where.
///
/// Immutable once issued. There is no `add_host` and no `grant` method, and
/// the absence is the point: a grant's scope is what a person approved, and a
/// grant that could widen itself after approval is not a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    id: GrantId,
    capabilities: CapabilitySet,
    hosts: BTreeSet<String>,
}

impl Grant {
    /// Issue a grant over an explicit list of hosts.
    ///
    /// Host names are trimmed and lower cased, which is the same rule
    /// `vnc_store::normalize_address` applies and the same reason: host names
    /// are case insensitive and mDNS hands out fully qualified names with a
    /// trailing dot, and neither should split one machine into two. The
    /// trailing dot is dropped here for that reason.
    ///
    /// This normalisation is deliberately the SAME rule and deliberately not
    /// the same code. `limb-core`'s [`MachineKey::endpoint`] carries the sharp
    /// edge in its own doc comment and this crate cannot depend on `vnc-store`
    /// without dragging a database into the plane. What matters is that the
    /// plane normalises once, at the point where it already holds the store,
    /// and that the two idea of "the same machine" do not drift, which
    /// `00 B7` already shows they can.
    ///
    /// [`MachineKey::endpoint`]: limb_core::identity::MachineKey::endpoint
    ///
    /// # Errors
    ///
    /// [`GrantError`], each naming what the caller can do about it.
    pub fn issue(
        id: impl Into<GrantId>,
        capabilities: CapabilitySet,
        hosts: impl IntoIterator<Item = String>,
    ) -> Result<Grant, GrantError> {
        let mut set = BTreeSet::new();
        for host in hosts {
            let name = normalise_host(&host);
            if name.is_empty() {
                return Err(GrantError::EmptyHost);
            }
            // A wildcard is refused rather than escaped or literalised. There
            // is no legitimate host name carrying one of these, so a caller
            // that sent one meant a pattern, and a pattern is exactly what
            // this design refuses to hold.
            if name.contains('*') || name.contains('?') {
                return Err(GrantError::Wildcard { pattern: host });
            }
            set.insert(name);
        }
        if set.is_empty() {
            return Err(GrantError::NoHosts);
        }
        Ok(Grant {
            id: id.into(),
            capabilities,
            hosts: set,
        })
    }

    /// Issue a grant whose capabilities come from a role bundle.
    ///
    /// The bundle is expanded here and then discarded: never stored, never
    /// sent, never consulted in a decision (`02 §5.3`). A grant carries
    /// capabilities, and which bundle they came from is a fact about the
    /// approval dialog rather than about the authority.
    ///
    /// # Errors
    ///
    /// [`GrantError`], as [`Grant::issue`].
    pub fn from_bundle(
        id: impl Into<GrantId>,
        bundle: RoleBundle,
        hosts: impl IntoIterator<Item = String>,
    ) -> Result<Grant, GrantError> {
        Grant::issue(id, bundle.expand(), hosts)
    }

    /// Which attachment this is.
    pub fn id(&self) -> &GrantId {
        &self.id
    }

    /// What this grant carries, before it is intersected with what a limb can
    /// ever offer.
    pub fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    /// The hosts this grant names, in sorted order.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }

    /// Is this host one of the ones a person approved?
    ///
    /// An exact match on the normalised name. Not a suffix match: a grant over
    /// `build.example.com` does not reach `evil-build.example.com`, and a
    /// grant over `example.com` reaches nothing but `example.com`.
    pub fn allows_host(&self, host: &str) -> bool {
        self.hosts.contains(&normalise_host(host))
    }

    /// Does this grant carry every capability in `needed`?
    pub fn allows_all(&self, needed: CapabilitySet) -> bool {
        self.capabilities.allows_all(needed)
    }

    /// Which of `needed` is missing. Empty means the check passed.
    ///
    /// Returned rather than a boolean because a refusal that does not name
    /// what was missing teaches the agent nothing and it will ask again.
    pub fn missing(&self, needed: CapabilitySet) -> Vec<Capability> {
        self.capabilities.missing(needed)
    }

    /// The refusal for an intent aimed at a machine outside this grant.
    ///
    /// Built here so that the sentence is written once. It names the host and
    /// the grant and says why there is no way to widen either, because an
    /// agent that thinks a retry with a different spelling might work will
    /// spend its turn finding out.
    pub fn host_refusal(&self, host: &str) -> Refusal {
        Refusal::plane(
            RefusalReason::HostNotInGrant,
            format!(
                "grant {} names {} host(s) and {host} is not one of them; a grant's hosts are resolved when a person approves it and there is no wildcard, so this cannot be retried",
                self.id,
                self.hosts.len(),
            ),
        )
    }
}

/// Trim, lower case, and drop the trailing dot an mDNS name carries.
///
/// ASCII case only, matching the store. A non ASCII host name arrives here
/// already punycoded on every path that reaches us, and lower casing Unicode
/// would introduce a second, different notion of the same machine.
fn normalise_host(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    trimmed.to_ascii_lowercase()
}
