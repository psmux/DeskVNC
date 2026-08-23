//! The state that survives a reconnect (PRDRDP/12 §3.13, PRD/05 §6.2).
//!
//! The RDP counterpart of `SessionSettings` at
//! `crates/vnc-core/src/session/connection.rs:26`, which exists because of
//! "session state preservation": the supervisor owns one instance and
//! re-applies it on every fresh connection, so a user who turned view only on
//! and then lost their network does not find it off again.
//!
//! Note what is not here: nothing that came off the wire. A server supplied
//! value must be re-learned on every connection, because a reconnect may land
//! on a different machine behind a broker.

use remote_core::{ClientCommand, ConnectOptions, QualityPreset};

/// Settings the user changed and must not lose to a dropped connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpSessionSettings {
    /// The quality preset, which narrows the codec set and the performance
    /// flags at the next connect.
    pub quality: QualityPreset,
    /// Suppress every input PDU.
    pub view_only: bool,
    /// Prefer the remote layout's own scancode mapping over layout aware
    /// key events, the same choice the RFB path exposes.
    pub prefer_scancodes: bool,
    /// The last size the user asked for, re-applied through MS-RDPEDISP once
    /// the display control channel is up.
    pub requested_size: Option<(u16, u16)>,
    /// Whether audio redirection is on for this session.
    pub audio_enabled: bool,
}

impl RdpSessionSettings {
    /// The settings a fresh session starts with, from the host profile.
    #[must_use]
    pub fn from_options(options: &ConnectOptions) -> Self {
        Self {
            quality: options.quality,
            view_only: options.view_only,
            prefer_scancodes: true,
            requested_size: None,
            audio_enabled: options
                .rdp_options()
                .is_some_and(|r| matches!(r.audio, remote_core::AudioMode::PlayLocally)),
        }
    }

    /// Re-apply the profile's values that a reconnect should not reset.
    ///
    /// Called at the start of every attempt. Only the fields the user cannot
    /// change at runtime are taken from the options; everything else is
    /// whatever the running session last set.
    pub fn apply(&mut self, options: &ConnectOptions) {
        if let Some(rdp) = options.rdp_options() {
            self.audio_enabled = matches!(rdp.audio, remote_core::AudioMode::PlayLocally);
        }
    }

    /// Absorb a command that arrived while the session was disconnected, so a
    /// setting changed during a reconnect wait is not silently discarded.
    ///
    /// The RFB supervisor does exactly this in `wait_backoff`
    /// (`crates/vnc-core/src/session/reconnect.rs`), and the list of commands
    /// worth keeping is the same one.
    pub fn absorb(&mut self, cmd: &ClientCommand) {
        match cmd {
            ClientCommand::SetQuality(q) => self.quality = *q,
            ClientCommand::SetViewOnly(v) => self.view_only = *v,
            ClientCommand::SetPreferScancodes(p) => self.prefer_scancodes = *p,
            ClientCommand::RequestResize { width, height } => {
                self.requested_size = Some((*width, *height));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A setting the user changed during a reconnect wait has to survive into
    /// the next attempt, or the reconnect quietly undoes what they asked for.
    #[test]
    fn settings_changed_while_disconnected_survive_the_next_attempt() {
        let options = ConnectOptions::rdp("host", 3389);
        let mut settings = RdpSessionSettings::from_options(&options);
        assert!(!settings.view_only);

        settings.absorb(&ClientCommand::SetViewOnly(true));
        settings.absorb(&ClientCommand::SetQuality(QualityPreset::Low));
        settings.absorb(&ClientCommand::RequestResize {
            width: 1920,
            height: 1080,
        });
        settings.absorb(&ClientCommand::SetPreferScancodes(false));

        settings.apply(&options);
        assert!(
            settings.view_only,
            "re-applying the profile must not reset it"
        );
        assert_eq!(settings.quality, QualityPreset::Low);
        assert_eq!(settings.requested_size, Some((1920, 1080)));
        assert!(!settings.prefer_scancodes);
    }

    /// A command with nothing to preserve is dropped rather than stored, so
    /// the struct stays the list of things that genuinely survive.
    #[test]
    fn a_command_with_no_surviving_state_changes_nothing() {
        let options = ConnectOptions::rdp("host", 3389);
        let mut settings = RdpSessionSettings::from_options(&options);
        let before = settings.clone();
        settings.absorb(&ClientCommand::Refresh);
        settings.absorb(&ClientCommand::ReleaseAllKeys);
        settings.absorb(&ClientCommand::Disconnect);
        assert_eq!(settings, before);
    }
}
