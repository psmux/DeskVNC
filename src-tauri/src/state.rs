//! Shared application state managed by Tauri (PRD/01 §6).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use vnc_core::SessionHandle;

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MachineKey {
    Profile(String),
    Endpoint { address: String, port: u16 },
}

impl MachineKey {
    pub fn new(profile_id: Option<&str>, address: &str, port: u16) -> Self {
        match profile_id.map(str::trim).filter(|id| !id.is_empty()) {
            Some(id) => MachineKey::Profile(id.to_string()),
            None => MachineKey::Endpoint {
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
    pub username: Option<String>,
    pub password: String,
}

impl std::fmt::Debug for PendingCredentialSave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingCredentialSave")
            .field("username", &self.username)
            .field("password", &"***")
            .finish()
    }
}

impl PendingCredentialSave {
    /// Map onto the at-rest blob. A username means an identity-carrying method
    /// (VeNCrypt `*Plain`, Apple DH, MSLogonII, RA2 subtype 1), so it goes in
    /// the `vencrypt_*` pair; password-only methods use `vnc_password`.
    /// Any other field already stored for the host (e.g. an SSH passphrase) is
    /// preserved by merging into `existing`.
    pub fn merge_into(
        &self,
        existing: Option<vnc_store::StoredCredentials>,
    ) -> vnc_store::StoredCredentials {
        let mut creds = existing.unwrap_or_default();
        match &self.username {
            Some(user) if !user.is_empty() => {
                creds.vencrypt_user = Some(user.clone());
                creds.vencrypt_pass = Some(self.password.clone());
            }
            _ => creds.vnc_password = Some(self.password.clone()),
        }
        creds
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
}

impl SessionEntry {
    /// Which machine this session is talking to (see [`MachineKey`]).
    pub fn machine_key(&self) -> MachineKey {
        MachineKey::new(self.profile_id.as_deref(), &self.address, self.port)
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
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            self.keepalive.push(rx);
            self.sessions.insert(
                id.to_string(),
                SessionEntry {
                    handle: SessionHandle {
                        id: id.to_string(),
                        commands: tx,
                        cancel: tokio_util::sync::CancellationToken::new(),
                    },
                    window_label: format!("session-{id}"),
                    profile_id: profile_id.map(str::to_string),
                    address: address.to_string(),
                    port,
                    started_at: Instant::now(),
                    thumbnails: Default::default(),
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
        let key = MachineKey::new(Some("host-a"), "10.0.0.99", 5901);
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
        let key = MachineKey::new(Some("host-b"), "10.0.0.5", 5900);
        assert_eq!(
            find_live_session(&reg.sessions, &key, ALL_WINDOWS_EXIST),
            None
        );
    }

    #[test]
    fn ad_hoc_sessions_fall_back_to_address_and_port() {
        let reg = one("s1", None, "Studio.local", 5900);
        // Case and the mDNS trailing dot must not split one machine in two.
        let same = MachineKey::new(None, "studio.local.", 5900);
        assert!(find_live_session(&reg.sessions, &same, ALL_WINDOWS_EXIST).is_some());
    }

    #[test]
    fn a_different_port_is_a_different_machine() {
        let reg = one("s1", None, "10.0.0.5", 5900);
        let other = MachineKey::new(None, "10.0.0.5", 5901);
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
        let adhoc = MachineKey::new(None, "10.0.0.5", 5900);
        assert_eq!(
            find_live_session(&reg.sessions, &adhoc, ALL_WINDOWS_EXIST),
            None
        );
    }

    #[test]
    fn a_dead_but_unreaped_session_does_not_block_reconnecting() {
        let mut reg = one("s1", Some("host-a"), "10.0.0.5", 5900);
        reg.kill("s1");
        let key = MachineKey::new(Some("host-a"), "10.0.0.5", 5900);
        assert_eq!(
            find_live_session(&reg.sessions, &key, ALL_WINDOWS_EXIST),
            None
        );
    }

    #[test]
    fn a_session_whose_window_is_gone_does_not_block_reconnecting() {
        let reg = one("s1", Some("host-a"), "10.0.0.5", 5900);
        let key = MachineKey::new(Some("host-a"), "10.0.0.5", 5900);
        assert_eq!(find_live_session(&reg.sessions, &key, NO_WINDOWS), None);
    }

    #[test]
    fn sessions_to_other_machines_are_never_focused() {
        let mut reg = Registry::default();
        reg.add("s1", Some("host-a"), "10.0.0.5", 5900)
            .add("s2", None, "10.0.0.7", 5900);
        let third = MachineKey::new(Some("host-c"), "10.0.0.9", 5900);
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
        let key = MachineKey::new(Some("host-a"), "10.0.0.5", 5900);
        assert_eq!(
            find_live_session(&reg.sessions, &key, ALL_WINDOWS_EXIST)
                .map(|w| w.session_id)
                .as_deref(),
            Some("s2")
        );
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
        let key = MachineKey::new(Some("host-a"), "10.0.0.5", 5900);
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
        let key = MachineKey::new(Some("host-a"), "10.0.0.5", 5900);
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
