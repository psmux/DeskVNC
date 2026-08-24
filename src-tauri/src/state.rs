//! Shared application state managed by Tauri (PRD/01 §6).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use vnc_core::{ProtocolDriver, ProtocolKind, SessionHandle, VncDriver};

use crate::thumbnail::ThumbnailPolicy;

/// Global app state, `app.manage`d in `lib.rs::run`.
pub struct AppState {
    pub store: Arc<vnc_store::Store>,
    pub credentials: Arc<vnc_store::CredentialStore>,
    pub sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    pub discovery: Arc<DiscoveryState>,
    /// Credentials the user asked to remember, keyed by session id, held in
    /// memory ONLY until that session proves them by reaching `Connected`.
    pub pending_credentials: Arc<Mutex<HashMap<String, PendingCredentialSave>>>,
    /// The credential prompt a session is currently blocked on, keyed by
    /// session id.
    ///
    /// Tauri events are fire-and-forget: anything emitted before the session
    /// window's `listen()` registration completes is dropped, and the handshake
    /// can reach the auth prompt in milliseconds on a LAN host. Recording the
    /// outstanding request lets the frontend ask for it after subscribing
    /// (`pending_credential_request`) instead of waiting forever for an event
    /// that already went past. Cleared as soon as it is answered or the session
    /// leaves the authenticating state. Contains no secrets, only the
    /// *question* (method, kind, attempt), never an answer.
    pub pending_prompts: Arc<Mutex<HashMap<String, vnc_core::CredentialRequest>>>,
    /// Session windows that have been created but whose webview has not called
    /// `connect_session` yet, keyed by session id.
    ///
    /// One-window-per-machine is decided from `sessions`, but that map is only
    /// populated once the new window's webview has booted and connected, /// hundreds of milliseconds later. Two connect gestures inside that gap
    /// would each see an empty registry and open a window. This records the
    /// intent the moment the window is built, so the second gesture finds it.
    pub opening_windows: Arc<Mutex<HashMap<String, PendingWindow>>>,
    /// The protocols this build can speak. `connect_session` dispatches
    /// through it rather than calling one protocol's spawn directly.
    pub protocols: Arc<ProtocolRegistry>,
}

/// A session window that exists but has not registered a session yet.
pub struct PendingWindow {
    pub key: MachineKey,
    pub window_label: String,
    pub opened_at: Instant,
}

/// Identity of "the same machine" for session de-duplication.
///
/// A saved profile wins over the endpoint, so renaming or re-addressing a host
/// keeps its identity, and two tiles that happen to point at the same address
/// stay distinct if they are distinct profiles. Ad-hoc connects (Nearby band,
/// quick connect) have no profile, so they fall back to the endpoint, which is
/// also what makes two Nearby tiles for one machine collapse onto one window.
///
/// The endpoint variant carries the protocol as well as the address and the
/// port. Two protocols on one box normally use different ports, so the key
/// was already unique in practice, but "in practice" was doing load bearing
/// work in a de-duplication rule: somebody who has genuinely put RDP on 5900
/// would otherwise have their VNC window focused instead of getting a
/// connection (PRDRDP/07 §4.12). `Profile` needs no protocol, a profile
/// already carries one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MachineKey {
    Profile(String),
    Endpoint {
        protocol: ProtocolKind,
        address: String,
        port: u16,
    },
}

impl MachineKey {
    pub fn new(protocol: ProtocolKind, profile_id: Option<&str>, address: &str, port: u16) -> Self {
        match profile_id.map(str::trim).filter(|id| !id.is_empty()) {
            Some(id) => MachineKey::Profile(id.to_string()),
            None => MachineKey::Endpoint {
                protocol,
                address: normalize_address(address),
                port,
            },
        }
    }
}

/// Host names are case-insensitive and mDNS hands out fully-qualified names
/// with a trailing dot; neither should split one machine into two.
///
/// Delegated to the store so that "the same machine" means the same thing to
/// the live-session registry and to the host library: a quick connect that
/// adopts its endpoint as a host (see `Store::adopt_endpoint`) is matched
/// against saved hosts by this exact rule.
fn normalize_address(address: &str) -> String {
    vnc_store::normalize_address(address)
}

/// An already-open session window that a repeat connect should focus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingWindow {
    pub session_id: String,
    pub window_label: String,
}

/// How long a just-built window counts as "this machine is already opening".
///
/// Only bridges the gap between building the window and its webview calling
/// `connect_session`; after that the live-session lookup takes over. Kept short
/// so a window that never manages to connect can't block a retry forever.
pub const OPENING_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

/// A "remember this password" intent that has not been earned yet.
///
/// SECURITY INVARIANT (PRD/10 §3.4): a password is never written to the
/// keychain until the server has actually accepted it. This lives in memory
/// between `provide_credentials` and `SessionState::Connected`, and is dropped
/// without a write on cancel, failure or disconnect. `Debug` is hand-written
/// so the secret can never leak into a log line or a crash report.
#[derive(Clone)]
pub struct PendingCredentialSave {
    /// Which protocol proved this credential, so the merge knows which
    /// fields of the blob it belongs in.
    pub protocol: ProtocolKind,
    pub username: Option<String>,
    /// Logon domain. `None` on every VNC path, and on an RDP logon with a
    /// local account or a UPN in `username`.
    pub domain: Option<String>,
    pub password: String,
}

impl std::fmt::Debug for PendingCredentialSave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingCredentialSave")
            .field("protocol", &self.protocol)
            .field("username", &self.username)
            // Printed rather than redacted: a wrong or missing domain is the
            // commonest reason an NLA logon is refused, and a support log
            // that hides it hides the answer. It is configuration, not a
            // secret; the password below is the secret.
            .field("domain", &self.domain)
            .field("password", &"***")
            .finish()
    }
}

impl PendingCredentialSave {
    /// Map onto the at-rest blob, dispatching on the protocol that proved it.
    ///
    /// The per protocol rules live on [`vnc_store::StoredCredentials`]
    /// (`set_rdp_identity`, `set_vnc_credential`) rather than here, so the
    /// dialog write and the post-connect write cannot disagree about which
    /// fields belong to which protocol. Any other field already stored for
    /// the host (an SSH passphrase, the other protocol's password) is
    /// preserved by merging into `existing`.
    pub fn merge_into(
        &self,
        existing: Option<vnc_store::StoredCredentials>,
    ) -> vnc_store::StoredCredentials {
        let mut creds = existing.unwrap_or_default();
        match self.protocol {
            ProtocolKind::Rdp => creds.set_rdp_identity(
                self.username.as_deref(),
                self.domain.as_deref(),
                &self.password,
            ),
            // `ProtocolKind` is `#[non_exhaustive]`, and VNC is the shape
            // every protocol this build does not know about would be stored
            // as today, which is the safe reading of "some password".
            _ => creds.set_vnc_credential(self.username.as_deref(), &self.password),
        }
        creds
    }
}

/// The protocols this build can speak, one driver each.
///
/// Adding a protocol is one line in [`ProtocolRegistry::new`] plus the crate
/// that implements [`ProtocolDriver`] (PRDRDP/02 §4.4). A lookup for a
/// protocol that is not built in returns `None`, so the caller reports it
/// rather than panicking.
pub struct ProtocolRegistry {
    drivers: Vec<Arc<dyn ProtocolDriver>>,
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        Self {
            drivers: vec![
                Arc::new(VncDriver::new()),
                Arc::new(rdp_core::RdpDriver::new()),
            ],
        }
    }

    pub fn get(&self, kind: ProtocolKind) -> Option<&Arc<dyn ProtocolDriver>> {
        self.drivers.iter().find(|d| d.kind() == kind)
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A live VNC session known to the shell.
pub struct SessionEntry {
    pub handle: SessionHandle,
    /// Label of the window whose channel receives this session's frames and
    /// whose webview receives `session://event` control events.
    pub window_label: String,
    /// Saved host profile backing this session, if any (ad-hoc connects have
    /// none).
    pub profile_id: Option<String>,
    /// Remote endpoint, needed to persist (host, port)-keyed TOFU cert pins.
    pub address: String,
    pub port: u16,
    pub started_at: Instant,
    /// Debounce state for `capture_thumbnail` (PRD/03 §3.1). Session-scoped,
    /// so every new connection starts with a clean budget.
    pub thumbnails: ThumbnailPolicy,
    /// Button mask of the most recent pointer event `send_input` looked at for
    /// this session, `-1` meaning none yet. Lets `send_input` tell a
    /// motion-only pointer event (safe to shed under backpressure) apart from
    /// one that changes button state (must never be dropped), see
    /// `commands::session::send_input`.
    pub last_pointer_mask: Arc<std::sync::atomic::AtomicI32>,
}

impl SessionEntry {
    /// Which protocol this session speaks.
    ///
    /// Read off the handle rather than stored a second time on the entry:
    /// `SessionHandle::kind` is set by the driver that spawned the task, so
    /// the two can never disagree.
    pub fn protocol(&self) -> ProtocolKind {
        self.handle.kind
    }

    /// Which machine this session is talking to (see [`MachineKey`]).
    pub fn machine_key(&self) -> MachineKey {
        MachineKey::new(
            self.protocol(),
            self.profile_id.as_deref(),
            &self.address,
            self.port,
        )
    }

    /// Is this session still worth focusing?
    ///
    /// Entries are removed by the event-forwarding task when the session's
    /// event stream ends, which happens *after* the session is gone, so the
    /// registry briefly holds corpses. A cancelled token or a closed command
    /// channel both mean "this one is on its way out"; treating it as live
    /// would focus a dead window instead of connecting, i.e. a lockout.
    pub fn is_live(&self) -> bool {
        !self.handle.cancel.is_cancelled() && !self.handle.commands.is_closed()
    }
}

/// The live session for `key`, if there is one whose window still exists.
///
/// `window_exists` is injected rather than looked up here so the rule stays
/// testable without a running Tauri app. When several sessions match (the
/// user has opted into multiple windows per machine and is now connecting
/// with the setting back off) the most recent one is focused.
pub fn find_live_session(
    sessions: &HashMap<String, SessionEntry>,
    key: &MachineKey,
    window_exists: &dyn Fn(&str) -> bool,
) -> Option<ExistingWindow> {
    sessions
        .iter()
        .filter(|(_, entry)| {
            entry.machine_key() == *key && entry.is_live() && window_exists(&entry.window_label)
        })
        .max_by_key(|(id, entry)| (entry.started_at, (*id).clone()))
        .map(|(id, entry)| ExistingWindow {
            session_id: id.clone(),
            window_label: entry.window_label.clone(),
        })
}

/// The just-opened (not yet connected) window for `key`, if any.
///
/// Entries whose window has gone away, or that are older than
/// [`OPENING_GRACE`], are ignored, and pruned by
/// [`AppState::existing_window_for_machine`].
pub fn find_opening_window(
    opening: &HashMap<String, PendingWindow>,
    key: &MachineKey,
    now: Instant,
    window_exists: &dyn Fn(&str) -> bool,
) -> Option<ExistingWindow> {
    opening
        .iter()
        .filter(|(_, pending)| {
            pending.key == *key
                && now.saturating_duration_since(pending.opened_at) < OPENING_GRACE
                && window_exists(&pending.window_label)
        })
        .max_by_key(|(id, pending)| (pending.opened_at, (*id).clone()))
        .map(|(id, pending)| ExistingWindow {
            session_id: id.clone(),
            window_label: pending.window_label.clone(),
        })
}

/// Discovery machinery state. The mDNS browse and the subnet scan are both
/// cancellation-token driven; a `Some` token means "running".
#[derive(Default)]
pub struct DiscoveryState {
    pub browse_cancel: Mutex<Option<tokio_util::sync::CancellationToken>>,
    pub scan_cancel: Mutex<Option<tokio_util::sync::CancellationToken>>,
}

impl DiscoveryState {
    /// Cancel everything (app exit).
    pub fn cancel_all(&self) {
        if let Some(token) = self.browse_cancel.lock().take() {
            token.cancel();
        }
        if let Some(token) = self.scan_cancel.lock().take() {
            token.cancel();
        }
    }
}

impl AppState {
    pub fn new(store: Arc<vnc_store::Store>, credentials: Arc<vnc_store::CredentialStore>) -> Self {
        Self {
            store,
            credentials,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            discovery: Arc::new(DiscoveryState::default()),
            pending_credentials: Arc::new(Mutex::new(HashMap::new())),
            pending_prompts: Arc::new(Mutex::new(HashMap::new())),
            opening_windows: Arc::new(Mutex::new(HashMap::new())),
            protocols: Arc::new(ProtocolRegistry::new()),
        }
    }

    /// The window a repeat connect to `key` should focus instead of opening a
    /// second one, if there is one.
    ///
    /// Live sessions win; a window that was built moments ago but has not
    /// connected yet is the fallback (a double-click fires two connects well
    /// inside that gap). `window_exists` lets a closed window fall through to
    /// "just connect", as does a session that is already unwinding.
    pub fn existing_window_for_machine(
        &self,
        key: &MachineKey,
        now: Instant,
        window_exists: &dyn Fn(&str) -> bool,
    ) -> Option<ExistingWindow> {
        if let Some(found) = find_live_session(&self.sessions.lock(), key, window_exists) {
            return Some(found);
        }
        let mut opening = self.opening_windows.lock();
        // Prune first: a window that has gone away must never be focused, and
        // this is the only place the map is swept.
        opening.retain(|_, pending| {
            now.saturating_duration_since(pending.opened_at) < OPENING_GRACE
                && window_exists(&pending.window_label)
        });
        find_opening_window(&opening, key, now, window_exists)
    }

    /// Record a session window that has just been built (see
    /// [`AppState::opening_windows`]).
    pub fn note_opening_window(&self, session_id: &str, key: MachineKey, window_label: String) {
        self.opening_windows.lock().insert(
            session_id.to_string(),
            PendingWindow {
                key,
                window_label,
                opened_at: Instant::now(),
            },
        );
    }

    /// Clone the command sender for a session, or a user-facing error.
    pub fn command_sender(
        &self,
        session_id: &str,
    ) -> Result<tokio::sync::mpsc::Sender<vnc_core::ClientCommand>, String> {
        self.sessions
            .lock()
            .get(session_id)
            .map(|e| e.handle.commands.clone())
            .ok_or_else(|| format!("unknown session: {session_id}"))
    }

    /// Clone the command sender for a session together with its shared
    /// last-pointer-button-mask cell (see [`SessionEntry::last_pointer_mask`]),
    /// or a user-facing error.
    pub fn command_channel(
        &self,
        session_id: &str,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<vnc_core::ClientCommand>,
            Arc<std::sync::atomic::AtomicI32>,
        ),
        String,
    > {
        self.sessions
            .lock()
            .get(session_id)
            .map(|e| (e.handle.commands.clone(), e.last_pointer_mask.clone()))
            .ok_or_else(|| format!("unknown session: {session_id}"))
    }

    /// Claim the right to store a thumbnail for a session right now, returning
    /// the host profile it belongs to.
    ///
    /// `None` is the normal "do nothing" answer for an unknown session, an
    /// ad-hoc session (nothing to attach the image to) or a capture that
    /// arrived inside the debounce window, see
    /// [`crate::thumbnail::ThumbnailPolicy`].
    pub fn claim_thumbnail(&self, session_id: &str, now: Instant) -> Option<String> {
        let mut sessions = self.sessions.lock();
        let entry = sessions.get_mut(session_id)?;
        let profile_id = entry.profile_id.clone();
        let address = entry.address.clone();
        let port = entry.port;
        entry
            .thumbnails
            .claim(profile_id.as_deref(), Some((address.as_str(), port)), now)
    }

    /// Cancel every session bound to `window_label` (session window closing).
    pub fn shutdown_sessions_for_window(&self, window_label: &str) {
        // A window that never got as far as connecting still has an "opening"
        // entry; closing it must free the machine for the next connect.
        self.opening_windows
            .lock()
            .retain(|_, pending| pending.window_label != window_label);
        let sessions = self.sessions.lock();
        for (id, entry) in sessions.iter() {
            if entry.window_label == window_label {
                tracing::info!(session = %id, window = %window_label, "shutting down session (window closed)");
                entry.handle.shutdown();
            }
        }
        // Entries are removed by each session's event-forwarding task when its
        // event stream ends, so state and UI notification stay consistent.
    }

    /// Cancel every session (app exit).
    pub fn shutdown_all_sessions(&self) {
        let sessions = self.sessions.lock();
        for (id, entry) in sessions.iter() {
            tracing::info!(session = %id, "shutting down session (app exit)");
            entry.handle.shutdown();
        }
    }
}

#[cfg(test)]
mod protocol_registry_tests {
    use super::*;

    #[test]
    fn the_vnc_driver_is_registered_and_answers_on_5900() {
        let registry = ProtocolRegistry::new();
        let driver = registry
            .get(ProtocolKind::Vnc)
            .expect("this build speaks VNC");
        assert_eq!(driver.kind(), ProtocolKind::Vnc);
        assert_eq!(driver.default_port(), 5900);
    }

    #[test]
    fn the_rdp_driver_is_registered_and_answers_on_3389() {
        let registry = ProtocolRegistry::new();
        let driver = registry
            .get(ProtocolKind::Rdp)
            .expect("this build speaks RDP");
        assert_eq!(driver.kind(), ProtocolKind::Rdp);
        assert_eq!(driver.default_port(), 3389);
    }

    /// The registry is what a third protocol changes, so pin its membership:
    /// a driver added without a decision here fails this test.
    #[test]
    fn two_protocols_are_registered_today() {
        let registry = ProtocolRegistry::new();
        let built: Vec<_> = ProtocolKind::ALL
            .iter()
            .copied()
            .filter(|k| registry.get(*k).is_some())
            .collect();
        assert_eq!(built, vec![ProtocolKind::Vnc, ProtocolKind::Rdp]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session registry plus the command receivers that keep its entries
    /// looking alive, `SessionEntry::is_live` reads the channel, so dropping
    /// the receiver is exactly how a test spells "this session has died".
    #[derive(Default)]
    struct Registry {
        sessions: HashMap<String, SessionEntry>,
        keepalive: Vec<tokio::sync::mpsc::Receiver<vnc_core::ClientCommand>>,
    }

    impl Registry {
        fn add(
            &mut self,
            id: &str,
            profile_id: Option<&str>,
            address: &str,
            port: u16,
        ) -> &mut Self {
            self.add_kind(ProtocolKind::Vnc, id, profile_id, address, port)
        }

        fn add_kind(
            &mut self,
            kind: ProtocolKind,
            id: &str,
            profile_id: Option<&str>,
            address: &str,
            port: u16,
        ) -> &mut Self {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            self.keepalive.push(rx);
            self.sessions.insert(
                id.to_string(),
                SessionEntry {
                    handle: SessionHandle {
                        id: id.to_string(),
                        kind,
                        commands: tx,
                        cancel: tokio_util::sync::CancellationToken::new(),
                    },
                    window_label: format!("session-{id}"),
                    profile_id: profile_id.map(str::to_string),
                    address: address.to_string(),
                    port,
                    started_at: Instant::now(),
                    thumbnails: Default::default(),
                    last_pointer_mask: Arc::new(std::sync::atomic::AtomicI32::new(-1)),
                },
            );
            self
        }

        /// Model a session that has died but whose registry entry has not been
        /// reaped yet.
        fn kill(&mut self, id: &str) -> &mut Self {
            self.keepalive.clear();
            self.sessions[id].handle.shutdown();
            self
        }
    }

    fn one(id: &str, profile_id: Option<&str>, address: &str, port: u16) -> Registry {
        let mut reg = Registry::default();
        reg.add(id, profile_id, address, port);
        reg
    }

    const ALL_WINDOWS_EXIST: &dyn Fn(&str) -> bool = &|_: &str| true;
    const NO_WINDOWS: &dyn Fn(&str) -> bool = &|_: &str| false;

    #[test]
    fn a_saved_profile_identifies_the_machine_even_if_its_address_changed() {
        let reg = one("s1", Some("host-a"), "10.0.0.5", 5900);
        // Same profile, new address (DHCP moved it), still the same machine.
        let key = MachineKey::new(ProtocolKind::Vnc, Some("host-a"), "10.0.0.99", 5901);
        assert_eq!(
            find_live_session(&reg.sessions, &key, ALL_WINDOWS_EXIST),
            Some(ExistingWindow {
                session_id: "s1".into(),
                window_label: "session-s1".into(),
            })
        );
    }

    #[test]
    fn different_profiles_at_one_endpoint_are_different_machines() {
        let reg = one("s1", Some("host-a"), "10.0.0.5", 5900);
        let key = MachineKey::new(ProtocolKind::Vnc, Some("host-b"), "10.0.0.5", 5900);
        assert_eq!(
            find_live_session(&reg.sessions, &key, ALL_WINDOWS_EXIST),
            None
        );
    }

    #[test]
    fn ad_hoc_sessions_fall_back_to_address_and_port() {
        let reg = one("s1", None, "Studio.local", 5900);
        // Case and the mDNS trailing dot must not split one machine in two.
        let same = MachineKey::new(ProtocolKind::Vnc, None, "studio.local.", 5900);
        assert!(find_live_session(&reg.sessions, &same, ALL_WINDOWS_EXIST).is_some());
    }

    /// Someone who has genuinely put RDP on 5900 must get a connection, not
    /// the VNC window they already had open at that address (PRDRDP/07 §4.12).
    #[test]
    fn two_protocols_at_one_endpoint_are_two_machines() {
        let mut reg = Registry::default();
        reg.add_kind(ProtocolKind::Vnc, "s1", None, "10.0.0.5", 5900);
        let rdp = MachineKey::new(ProtocolKind::Rdp, None, "10.0.0.5", 5900);
        assert_eq!(
            find_live_session(&reg.sessions, &rdp, ALL_WINDOWS_EXIST),
            None
        );

        let vnc = MachineKey::new(ProtocolKind::Vnc, None, "10.0.0.5", 5900);
        assert!(find_live_session(&reg.sessions, &vnc, ALL_WINDOWS_EXIST).is_some());
    }

    #[test]
    fn a_different_port_is_a_different_machine() {
        let reg = one("s1", None, "10.0.0.5", 5900);
        let other = MachineKey::new(ProtocolKind::Vnc, None, "10.0.0.5", 5901);
        assert_eq!(
            find_live_session(&reg.sessions, &other, ALL_WINDOWS_EXIST),
            None
        );
    }

    #[test]
    fn a_profile_session_is_not_matched_by_a_bare_endpoint_connect() {
        // Quick-connecting to the address a saved host happens to use is an
        // ad-hoc session; it gets its own window rather than hijacking the
        // profile's.
        let reg = one("s1", Some("host-a"), "10.0.0.5", 5900);
        let adhoc = MachineKey::new(ProtocolKind::Vnc, None, "10.0.0.5", 5900);
        assert_eq!(
            find_live_session(&reg.sessions, &adhoc, ALL_WINDOWS_EXIST),
            None
        );
    }

    #[test]
    fn a_dead_but_unreaped_session_does_not_block_reconnecting() {
        let mut reg = one("s1", Some("host-a"), "10.0.0.5", 5900);
        reg.kill("s1");
        let key = MachineKey::new(ProtocolKind::Vnc, Some("host-a"), "10.0.0.5", 5900);
        assert_eq!(
            find_live_session(&reg.sessions, &key, ALL_WINDOWS_EXIST),
            None
        );
    }

    #[test]
    fn a_session_whose_window_is_gone_does_not_block_reconnecting() {
        let reg = one("s1", Some("host-a"), "10.0.0.5", 5900);
        let key = MachineKey::new(ProtocolKind::Vnc, Some("host-a"), "10.0.0.5", 5900);
        assert_eq!(find_live_session(&reg.sessions, &key, NO_WINDOWS), None);
    }

    #[test]
    fn sessions_to_other_machines_are_never_focused() {
        let mut reg = Registry::default();
        reg.add("s1", Some("host-a"), "10.0.0.5", 5900)
            .add("s2", None, "10.0.0.7", 5900);
        let third = MachineKey::new(ProtocolKind::Vnc, Some("host-c"), "10.0.0.9", 5900);
        assert_eq!(
            find_live_session(&reg.sessions, &third, ALL_WINDOWS_EXIST),
            None
        );
    }

    #[test]
    fn the_most_recent_matching_session_is_the_one_focused() {
        let mut reg = Registry::default();
        reg.add("s1", Some("host-a"), "10.0.0.5", 5900)
            .add("s2", Some("host-a"), "10.0.0.5", 5900);
        let earlier = reg.sessions["s1"].started_at - std::time::Duration::from_secs(5);
        reg.sessions.get_mut("s1").unwrap().started_at = earlier;
        let key = MachineKey::new(ProtocolKind::Vnc, Some("host-a"), "10.0.0.5", 5900);
        assert_eq!(
            find_live_session(&reg.sessions, &key, ALL_WINDOWS_EXIST)
                .map(|w| w.session_id)
                .as_deref(),
            Some("s2")
        );
    }

    /// An RDP save fills the three `rdp_*` fields and leaves everything else
    /// alone. The SSH passphrase is the one that used to be lost.
    #[test]
    fn an_rdp_save_leaves_the_other_secrets_alone() {
        let mut existing = vnc_store::StoredCredentials::default();
        existing.set_vnc_credential(None, "vnc-pass");
        existing.ssh_passphrase = Some("ssh-pass".into());

        let merged = PendingCredentialSave {
            protocol: ProtocolKind::Rdp,
            username: Some("alice".into()),
            domain: Some("CORP".into()),
            password: "rdp-pass".into(),
        }
        .merge_into(Some(existing));

        assert_eq!(merged.rdp_user.as_deref(), Some("alice"));
        assert_eq!(merged.rdp_domain.as_deref(), Some("CORP"));
        assert_eq!(merged.rdp_password.as_deref(), Some("rdp-pass"));
        assert_eq!(merged.vnc_password.as_deref(), Some("vnc-pass"));
        assert_eq!(merged.ssh_passphrase.as_deref(), Some("ssh-pass"));
    }

    /// The VNC rule is unchanged: a username means an identity-carrying
    /// method, so it lands in the `vencrypt_*` pair, and no RDP field moves.
    #[test]
    fn a_vnc_save_still_splits_on_the_username() {
        let named = PendingCredentialSave {
            protocol: ProtocolKind::Vnc,
            username: Some("bob".into()),
            domain: None,
            password: "pw".into(),
        }
        .merge_into(None);
        assert_eq!(named.vencrypt_user.as_deref(), Some("bob"));
        assert_eq!(named.vencrypt_pass.as_deref(), Some("pw"));
        assert!(named.rdp_password.is_none());

        let anonymous = PendingCredentialSave {
            protocol: ProtocolKind::Vnc,
            username: None,
            domain: None,
            password: "pw".into(),
        }
        .merge_into(None);
        assert_eq!(anonymous.vnc_password.as_deref(), Some("pw"));
        assert!(anonymous.vencrypt_user.is_none());
    }

    /// The password never reaches a log line. The domain deliberately does:
    /// it is the commonest reason an NLA logon is refused.
    #[test]
    fn the_pending_save_prints_its_domain_and_hides_its_password() {
        let text = format!(
            "{:?}",
            PendingCredentialSave {
                protocol: ProtocolKind::Rdp,
                username: Some("alice".into()),
                domain: Some("CORP".into()),
                password: "hunter2".into(),
            }
        );
        assert!(text.contains("CORP"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
    }

    fn pending(id: &str, key: MachineKey, age: std::time::Duration) -> (String, PendingWindow) {
        (
            id.to_string(),
            PendingWindow {
                key,
                window_label: format!("session-{id}"),
                opened_at: Instant::now() - age,
            },
        )
    }

    #[test]
    fn a_window_that_is_still_booting_counts_as_already_open() {
        let key = MachineKey::new(ProtocolKind::Vnc, Some("host-a"), "10.0.0.5", 5900);
        let opening: HashMap<_, _> = vec![pending(
            "s1",
            key.clone(),
            std::time::Duration::from_millis(50),
        )]
        .into_iter()
        .collect();
        assert_eq!(
            find_opening_window(&opening, &key, Instant::now(), ALL_WINDOWS_EXIST)
                .map(|w| w.session_id)
                .as_deref(),
            Some("s1")
        );
    }

    #[test]
    fn a_window_that_never_connected_stops_blocking_after_the_grace_period() {
        let key = MachineKey::new(ProtocolKind::Vnc, Some("host-a"), "10.0.0.5", 5900);
        let opening: HashMap<_, _> = vec![pending("s1", key.clone(), OPENING_GRACE * 2)]
            .into_iter()
            .collect();
        assert_eq!(
            find_opening_window(&opening, &key, Instant::now(), ALL_WINDOWS_EXIST),
            None
        );
        // …and a closed window never blocks, however recent.
        let fresh: HashMap<_, _> = vec![pending(
            "s2",
            key.clone(),
            std::time::Duration::from_millis(1),
        )]
        .into_iter()
        .collect();
        assert_eq!(
            find_opening_window(&fresh, &key, Instant::now(), NO_WINDOWS),
            None
        );
    }
}
