//! Connect options: what the shell hands a driver to start a session.
//!
//! Moved out of `vnc-core/src/types.rs` (PRDRDP/02 §2.1, §5). `QualityPreset`
//! arrives without its `settings()` method: that method returns
//! `vnc_core::QualitySettings`, an RFB struct which stays where it is, so it
//! is now `vnc_core::quality::QualityResolve::settings` (PRDRDP/02 §2.2.1).

use crate::credentials::Credentials;
use crate::driver::ProtocolKind;
use crate::pins::CertPins;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Quality presets (PRD/09)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum QualityPreset {
    #[default]
    Auto,
    High,
    Medium,
    Low,
    BlackAndWhite,
}

// ---------------------------------------------------------------------------
// Connection options
// ---------------------------------------------------------------------------

/// An injected transport (today: the SSH tunnel), see
/// [`vnc_transport::StreamConnector`]. Newtype so `ConnectOptions` can keep
/// deriving `Debug` without asking every connector to implement it.
#[derive(Clone)]
pub struct Connector(pub std::sync::Arc<dyn vnc_transport::StreamConnector>);

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Connector")
            .field(&self.0.describe())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    /// When set, the byte stream comes from here instead of a direct TCP
    /// connect; `host`/`port` are interpreted by the connector (for an SSH
    /// tunnel, resolved on the far side).
    pub connector: Option<Connector>,
    pub credentials: Credentials,
    pub quality: QualityPreset,
    pub view_only: bool,
    /// Pinned SHA-256 SPKI fingerprints for TOFU (hex), one per scheme.
    pub cert_pins: CertPins,
    pub connect_timeout: std::time::Duration,
    /// Auto-reconnect policy (PRD/05 §6).
    pub reconnect: ReconnectPolicy,
    /// The protocol specific half. Its discriminant is the session's
    /// [`ProtocolKind`].
    pub protocol: ProtocolOptions,
}

impl ConnectOptions {
    /// A VNC session with today's defaults. This is the old
    /// `ConnectOptions::new`, renamed rather than kept as an alias: a
    /// constructor called `new` on a type that is no longer about VNC is how
    /// an RDP session ends up with `shared: true` (PRDRDP/02 §5.1).
    pub fn vnc(host: impl Into<String>, port: u16) -> Self {
        Self::with_protocol(host, port, ProtocolOptions::Vnc(VncOptions::default()))
    }

    /// The same common defaults with an RDP protocol half.
    pub fn rdp(host: impl Into<String>, port: u16) -> Self {
        Self::with_protocol(host, port, ProtocolOptions::Rdp(RdpOptions::default()))
    }

    /// Options for a remote shell.
    pub fn ssh(host: impl Into<String>, port: u16) -> Self {
        Self::with_protocol(host, port, ProtocolOptions::Ssh(SshOptions::default()))
    }

    fn with_protocol(host: impl Into<String>, port: u16, protocol: ProtocolOptions) -> Self {
        Self {
            host: host.into(),
            port,
            connector: None,
            credentials: Credentials::default(),
            quality: QualityPreset::Auto,
            view_only: false,
            cert_pins: CertPins::default(),
            connect_timeout: std::time::Duration::from_secs(15),
            reconnect: ReconnectPolicy::default(),
            protocol,
        }
    }

    pub fn kind(&self) -> ProtocolKind {
        self.protocol.kind()
    }

    /// The VNC half, or `None` when these are not VNC options.
    pub fn vnc_options(&self) -> Option<&VncOptions> {
        match &self.protocol {
            ProtocolOptions::Vnc(v) => Some(v),
            _ => None,
        }
    }

    /// The RDP half, or `None` when these are not RDP options.
    /// The SSH half, or `None` when these are not SSH options.
    pub fn ssh_options(&self) -> Option<&SshOptions> {
        match &self.protocol {
            ProtocolOptions::Ssh(o) => Some(o),
            _ => None,
        }
    }

    /// The SSH half, for a driver that has already checked the kind.
    ///
    /// Panics when these are not SSH options, exactly as [`Self::rdp_mut`]
    /// does: reaching it means the registry handed a driver another
    /// protocol's options, which `spawn` rejects with `OptionsMismatch`
    /// before anything gets this far.
    pub fn ssh_mut(&mut self) -> &mut SshOptions {
        match &mut self.protocol {
            ProtocolOptions::Ssh(o) => o,
            other => panic!("ssh_mut on {:?} options", other.kind()),
        }
    }

    pub fn rdp_options(&self) -> Option<&RdpOptions> {
        match &self.protocol {
            ProtocolOptions::Rdp(r) => Some(r),
            _ => None,
        }
    }

    /// The VNC half, mutably, for a caller that built these options and
    /// already knows they are VNC.
    ///
    /// # Panics
    ///
    /// When the options are not VNC.
    pub fn vnc_mut(&mut self) -> &mut VncOptions {
        match &mut self.protocol {
            ProtocolOptions::Vnc(v) => v,
            other => panic!("expected VNC options, got {:?}", other.kind()),
        }
    }

    /// The RDP half, mutably, on the same terms as [`Self::vnc_mut`].
    ///
    /// # Panics
    ///
    /// When the options are not RDP.
    pub fn rdp_mut(&mut self) -> &mut RdpOptions {
        match &mut self.protocol {
            ProtocolOptions::Rdp(r) => r,
            other => panic!("expected RDP options, got {:?}", other.kind()),
        }
    }
}

/// The protocol specific half of [`ConnectOptions`].
///
/// A typed enum rather than a `Box<dyn Any>` payload: the downcast would land
/// in every driver, and `ConnectOptions` would lose the `Debug` and `Clone`
/// that the credential redaction test depends on (PRDRDP/02 §5.2).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProtocolOptions {
    Vnc(VncOptions),
    Rdp(RdpOptions),
    Ssh(SshOptions),
}

impl ProtocolOptions {
    pub fn kind(&self) -> ProtocolKind {
        match self {
            ProtocolOptions::Vnc(_) => ProtocolKind::Vnc,
            ProtocolOptions::Rdp(_) => ProtocolKind::Rdp,
            ProtocolOptions::Ssh(_) => ProtocolKind::Ssh,
        }
    }
}

/// RFB specific connect options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VncOptions {
    /// `None` = automatic strongest-first selection.
    ///
    /// A string rather than `vnc_core::SecurityType`, which stays in vnc-core
    /// because it is an RFB wire number. The shell already stores this setting
    /// as a string in the `security_pref` column, so the string is the honest
    /// representation; `SecurityType::parse_pref` maps it (PRDRDP/02 §5.3).
    pub security_pref: Option<String>,
    pub shared: bool,
    /// Sharpen lossily-painted regions once motion stops (PRD/09 §3.2). RFB
    /// only, and unchanged.
    pub lossless_refresh: bool,
    /// Allow security types that leave the session in cleartext. It lives
    /// here rather than on [`ConnectOptions`] because an SSH tunnel sets it
    /// and a tunnel proves nothing about an RDP host (PRDRDP/00 R26).
    pub allow_insecure: bool,
}

impl Default for VncOptions {
    fn default() -> Self {
        Self {
            security_pref: None,
            shared: true,
            lossless_refresh: true,
            allow_insecure: false,
        }
    }
}

/// RDP specific connect options.
///
/// Data only. Nothing in phase 0 reads any of it; the fields are here so the
/// `hosts.rdp_settings` column and the host editor form do not change shape
/// when the protocol lands (PRDRDP/02 §5.4).
///
/// Serialized into that column, so every field is `#[serde(default)]` and no
/// field holds a secret: the username and password travel in
/// [`ConnectOptions::credentials`], which is not serializable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RdpOptions {
    /// The name used for SNI, certificate verification, pin lookup and the
    /// Kerberos SPN. `None` means "use [`ConnectOptions::host`]". Separate
    /// from the dial address so all four survive an SSH tunnel, where the
    /// dial address is frequently `localhost` (PRDRDP/00 R26).
    pub server_name: Option<String>,

    /// NetBIOS or DNS domain for the logon. MS-RDPBCGR 2.2.1.11.1.1
    /// TS_INFO_PACKET `Domain`. Empty and `None` are the same thing: a local
    /// account logon.
    pub domain: Option<String>,

    /// Whether CredSSP (MS-CSSP) is required.
    pub nla: NlaPolicy,

    /// Permit the TLS 1.0 and 1.1 backend for this host.
    ///
    /// rustls speaks TLS 1.2 and 1.3 only, so reaching a Windows 7 SP1 or
    /// Server 2008 R2 era host means the second, vendored OpenSSL backend
    /// (PRDRDP/00 R55). This field is permission, never a request: with it
    /// false and the server offering nothing above TLS 1.1 the attempt fails
    /// rather than downgrading, and with it true the connection still prefers
    /// the highest version the server will negotiate.
    pub legacy_tls: bool,

    /// Colour depth to request. MS-RDPBCGR 2.2.1.3.2 TS_UD_CS_CORE
    /// `highColorDepth` plus `supportedColorDepths`.
    pub color_depth: RdpColorDepth,

    /// Which bitmap and graphics codecs we advertise. A codec the user turned
    /// off is never advertised, so the server cannot pick it.
    pub codecs: CodecSet,

    /// Audio output redirection. MS-RDPEA.
    pub audio: AudioMode,

    /// Which of the server's monitors to attach to. MS-RDPBCGR 2.2.1.3.6
    /// TS_UD_CS_MONITOR and 2.2.1.3.9 Client Monitor Extended Data; the
    /// specification caps the list at 16 entries.
    pub monitors: MonitorPolicy,

    /// What desktop size to ask for, and whether to keep asking.
    pub resolution: RdpResolution,

    /// The window's size in physical pixels, as the shell measured it.
    ///
    /// `None` means nothing measured it, which is the case for a headless
    /// caller such as an example or a test; the resolver then falls back to
    /// the specification's own default rather than inventing one.
    pub window_size: Option<(u16, u16)>,

    /// Windows keyboard layout identifier (KLID), MS-RDPBCGR 2.2.1.3.2
    /// `keyboardLayout`. 0 means "let the client pick from the host OS".
    /// 0x0000_0409 is US English.
    pub keyboard_layout: u32,

    /// Reported client machine name, MS-RDPBCGR 2.2.1.3.2 `clientName`. The
    /// field on the wire is 32 bytes of UTF-16, so 15 characters plus a null;
    /// longer names are truncated by the driver, not here.
    pub client_name: String,

    /// TS_EXTENDED_INFO_PACKET `performanceFlags`, MS-RDPBCGR 2.2.1.11.1.1.1.
    pub performance: PerformanceFlags,

    /// RD Gateway. Phase 3. Carried earlier as a placeholder so the store
    /// column and the UI form do not change shape later; the driver rejects a
    /// connect with `Some(_)` until it lands, with a clear message rather
    /// than a silent direct connect.
    pub gateway: Option<GatewayOptions>,

    /// Send credentials in the Info PDU so the server skips its own logon
    /// screen. MS-RDPBCGR 2.2.1.11.1.1 INFO_AUTOLOGON (0x00000008).
    pub autologon: bool,

    /// KDC proxy (MS-KKDCP) URL for Kerberos through an HTTPS proxy. Phase 3
    /// with the rest of Kerberos; `None` means plain KDC discovery over DNS
    /// SRV when that phase arrives.
    pub kdc_proxy_url: Option<String>,

    /// Whether the X.224 Connection Request carries the `Cookie: mstshash=`
    /// routing token (MS-RDPBCGR 2.2.1.1). Off by default: the token leaks
    /// the username into server and load balancer logs, and the brokers that
    /// need it are a phase 3 gateway concern.
    pub send_mstshash_cookie: bool,

    /// Offer the auto reconnect cookie on a re-dial so the same Windows
    /// session resumes. MS-RDPBCGR 2.2.4.
    pub allow_auto_reconnect: bool,

    /// HiDPI scale factor, percent, 100 to 500. MS-RDPBCGR 2.2.2.2.1
    /// DISPLAYCONTROL_MONITOR_LAYOUT `DeviceScaleFactor` and the connector's
    /// `desktopScaleFactor`. 100 means no scaling.
    pub desktop_scale_factor: u32,
}

impl Default for RdpOptions {
    fn default() -> Self {
        Self {
            server_name: None,
            domain: None,
            nla: NlaPolicy::Required,
            legacy_tls: false,
            color_depth: RdpColorDepth::Auto,
            codecs: CodecSet::default(),
            audio: AudioMode::PlayLocally,
            monitors: MonitorPolicy::Primary,
            resolution: RdpResolution::default(),
            window_size: None,
            keyboard_layout: 0,
            // The driver fills this from the OS hostname when it is empty.
            client_name: String::new(),
            performance: PerformanceFlags::default(),
            gateway: None,
            autologon: true,
            kdc_proxy_url: None,
            send_mstshash_cookie: false,
            allow_auto_reconnect: true,
            desktop_scale_factor: 100,
        }
    }
}

/// NLA on by default, with an explicit per host escape hatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NlaPolicy {
    /// CredSSP (MS-CSSP) must succeed or the connection fails.
    #[default]
    Required,
    /// Try CredSSP; if the server refuses it, continue with TLS only and let
    /// the server's own logon screen collect the credentials. Standard RDP
    /// security (RC4) is never used, so this still means TLS.
    ///
    /// Choosing this disables credential saving for the host: reaching
    /// `Connected` without CredSSP does not prove the password was right,
    /// because the server completes the connection either way (PRDRDP/00
    /// R14).
    AllowFallback,
}

/// MS-RDPBCGR 2.2.1.3.2 `highColorDepth` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RdpColorDepth {
    /// Let the quality preset choose.
    #[default]
    Auto,
    Bpp15,
    Bpp16,
    Bpp24,
    Bpp32,
}

/// Which codecs to advertise. A struct of flags rather than a bitmask so a
/// stored blob stays readable and a new codec is an added field with a
/// default, not a renumbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CodecSet {
    /// Always true, and not settable to false: uncompressed bitmap updates
    /// are the only thing every server can send. Present so the field list
    /// reads completely.
    pub uncompressed: bool,
    /// Interleaved RLE, MS-RDPBCGR 3.1.9, wire stream 2.2.9.1.1.3.1.2.4
    /// RLE_BITMAP_STREAM.
    pub interleaved_rle: bool,
    /// Planar (RDP 6.0) bitmap codec, MS-RDPBCGR 3.1.9.2.
    pub planar: bool,
    /// MS-RDPNSC.
    pub nscodec: bool,
    /// MS-RDPRFX, both image and video modes.
    pub remotefx: bool,
    /// MS-RDPEGFX RDPGFX_CODECID_CLEARCODEC (0x0008).
    pub clearcodec: bool,
    /// MS-RDPEGFX progressive (RFX_PROGRESSIVE).
    pub progressive: bool,
    /// MS-RDPEGFX 2.2.4.4 RFX_AVC420_METABLOCK.
    pub avc420: bool,
    /// MS-RDPEGFX 2.2.4.5 RFX_AVC444_METABLOCK.
    pub avc444: bool,
}

impl Default for CodecSet {
    /// Everything on. The quality preset narrows it; a user who wants less
    /// turns individual codecs off in the host dialog.
    fn default() -> Self {
        Self {
            uncompressed: true,
            interleaved_rle: true,
            planar: true,
            nscodec: true,
            remotefx: true,
            clearcodec: true,
            progressive: true,
            avc420: true,
            avc444: true,
        }
    }
}

/// MS-RDPEA. The three modes mstsc offers; the second and third differ only
/// in whether the client opens the rdpsnd channel at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AudioMode {
    /// Redirect to this machine.
    #[default]
    PlayLocally,
    /// Leave the sound on the server: do not open rdpsnd.
    LeaveAtServer,
    /// Mute: do not open rdpsnd and ask the server not to play either.
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MonitorPolicy {
    #[default]
    Primary,
    All,
    /// Monitor indices into the server's reported layout. MS-RDPBCGR caps a
    /// monitor list at 16 entries (2.2.1.3.6); the driver truncates.
    Selected(Vec<u32>),
}

/// What desktop size an RDP session asks the server for.
///
/// The three are one choice rather than a size plus a flag, because the two
/// are not independent: a fixed size that also tracked the window would stop
/// being fixed the moment the window moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", tag = "mode")]
pub enum RdpResolution {
    /// Connect at the window's size and send a new monitor layout whenever it
    /// changes (MS-RDPEDISP, DISPLAYCONTROL_MONITOR_LAYOUT_PDU).
    FollowWindow,
    /// Connect at the window's size and leave the desktop there. The client
    /// scales afterwards, which is what mstsc does and why it is the default:
    /// a desktop that reflows every time a window edge moves rearranges the
    /// icons of the machine on the other end.
    #[default]
    WindowAtConnect,
    /// A fixed size, whatever the window does.
    Fixed { width: u16, height: u16 },
}

impl RdpResolution {
    /// Whether a window resize should reach the server.
    #[must_use]
    pub const fn follows_window(self) -> bool {
        matches!(self, Self::FollowWindow)
    }

    /// The size to ask for, given what the shell measured.
    ///
    /// Zero in either axis is treated as nothing measured: a window that has
    /// not been laid out yet reports zero, and asking a server for a desktop
    /// no pixels wide is worse than asking for the default.
    #[must_use]
    pub fn size(self, window: Option<(u16, u16)>) -> Option<(u16, u16)> {
        match self {
            Self::Fixed { width, height } => Some((width, height)),
            Self::FollowWindow | Self::WindowAtConnect => window.filter(|(w, h)| *w > 0 && *h > 0),
        }
    }
}

/// TS_EXTENDED_INFO_PACKET `performanceFlags`, MS-RDPBCGR 2.2.1.11.1.1.1.
/// Named booleans rather than a `u32` so a stored blob is legible and the
/// quality preset mapping is readable. The PERF_DISABLE_* bit values belong
/// in the PDU layer, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PerformanceFlags {
    pub disable_wallpaper: bool,
    pub disable_full_window_drag: bool,
    pub disable_menu_animations: bool,
    pub disable_theming: bool,
    pub disable_cursor_shadow: bool,
    pub disable_cursor_blinking: bool,
    pub enable_font_smoothing: bool,
    pub enable_desktop_composition: bool,
}

/// RD Gateway (MS-TSGU). Phase 3 placeholder, see [`RdpOptions::gateway`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
#[non_exhaustive]
pub struct GatewayOptions {
    pub host: String,
    pub port: u16,
    /// Reuse the session credentials, or prompt separately.
    pub separate_credentials: bool,
}

// ---------------------------------------------------------------------------
// Reconnect policy (PRD/05 §6.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReconnectPolicy {
    pub enabled: bool,
    /// None = retry forever while the session window is open.
    pub max_attempts: Option<u32>,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub multiplier: f64,
    /// Jitter fraction (0.0..=1.0) applied to each delay.
    pub jitter: f64,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        // 250ms -> 500 -> 1s -> 2s -> 4s -> 8s -> capped 15s, ±20% jitter.
        Self {
            enabled: true,
            max_attempts: None,
            initial_delay_ms: 250,
            max_delay_ms: 15_000,
            multiplier: 2.0,
            jitter: 0.2,
        }
    }
}

impl ReconnectPolicy {
    /// Delay before attempt `attempt` (1-based), with jitter applied.
    pub fn delay_for(&self, attempt: u32, rand_unit: f64) -> std::time::Duration {
        let base =
            (self.initial_delay_ms as f64) * self.multiplier.powi(attempt.saturating_sub(1) as i32);
        let capped = base.min(self.max_delay_ms as f64);
        let jitter_span = capped * self.jitter;
        // rand_unit in [0,1) -> symmetric jitter around `capped`
        let jittered = capped - jitter_span + (2.0 * jitter_span * rand_unit);
        std::time::Duration::from_millis(jittered.max(0.0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The webview parses this blob, so its shape is a contract and not an
    /// implementation detail. `ui/src/lib/rdp.ts` carries the matching reader,
    /// and a change here without a change there is a setting that silently
    /// reverts to its default the next time a profile is opened.
    #[test]
    fn the_resolution_serialises_the_way_the_webview_reads_it() {
        let json = |r: RdpResolution| serde_json::to_string(&r).expect("serialises");
        assert_eq!(
            json(RdpResolution::FollowWindow),
            r#"{"mode":"follow-window"}"#
        );
        assert_eq!(
            json(RdpResolution::WindowAtConnect),
            r#"{"mode":"window-at-connect"}"#
        );
        assert_eq!(
            json(RdpResolution::Fixed {
                width: 1920,
                height: 1080
            }),
            r#"{"mode":"fixed","width":1920,"height":1080}"#
        );

        // And back, because the webview writes it too.
        let back: RdpResolution =
            serde_json::from_str(r#"{"mode":"fixed","width":2560,"height":1440}"#).expect("parses");
        assert_eq!(
            back,
            RdpResolution::Fixed {
                width: 2560,
                height: 1440
            }
        );
    }

    /// Only one of the three tracks the window, and the default is not it.
    #[test]
    fn only_follow_window_tracks_the_window() {
        assert!(RdpResolution::FollowWindow.follows_window());
        assert!(!RdpResolution::WindowAtConnect.follows_window());
        assert!(!RdpResolution::Fixed {
            width: 1920,
            height: 1080
        }
        .follows_window());
        assert!(!RdpResolution::default().follows_window());
    }

    /// A window that has not been laid out reports zero, and a desktop no
    /// pixels wide must never reach the wire.
    #[test]
    fn a_zero_sized_window_is_treated_as_nothing_measured() {
        let m = RdpResolution::WindowAtConnect;
        assert_eq!(m.size(Some((1712, 1067))), Some((1712, 1067)));
        assert_eq!(m.size(Some((0, 1067))), None);
        assert_eq!(m.size(Some((1712, 0))), None);
        assert_eq!(m.size(None), None);
        // A fixed size does not consult the window at all.
        let f = RdpResolution::Fixed {
            width: 1920,
            height: 1080,
        };
        assert_eq!(f.size(None), Some((1920, 1080)));
    }
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

/// Which terminal multiplexer to attach to on the far side.
///
/// This is the setting that decides whether a reconnect returns the user to
/// their work or to an empty prompt. An SSH connection owns the remote PTY:
/// when the link dies the PTY is destroyed, `SIGHUP` goes to everything under
/// it, and the shell dies with the socket. Reconnecting automatically does not
/// change that, it just gets the user to a fresh prompt faster. Only moving
/// the shell's lifetime onto the remote machine preserves anything, which is
/// what all of these do.
///
/// Lives here rather than in `ssh-core` for the same reason [`RdpOptions`]
/// does rather than in `rdp-core`: it is serialized into a host profile
/// column, so the store and the host editor need the type without depending
/// on the protocol implementation. `ssh-core` owns the *behaviour* (probing
/// for it, building its command line); this is only the data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum MultiplexerKind {
    /// Ask the far side what it has and use the best of it, falling back to a
    /// plain login shell when it has nothing. The default, and the only
    /// setting that is right across a mixed fleet.
    #[default]
    Auto,
    /// A plain login shell. Honest about the cost: a drop loses the session.
    None,
    /// psmux, the tmux-compatible multiplexer that runs natively on Windows
    /// (<https://github.com/psmux/psmux>). Speaks tmux's command language.
    Psmux,
    Tmux,
    Screen,
    Zellij,
    /// A command supplied by the user. `{session}` is substituted.
    Custom,
}

/// The default `TERM`.
///
/// `xterm-256color` is the widest-compatible name that still gets colour: it
/// is in every terminfo database going back decades, so a remote `vim` or
/// `htop` finds an entry and renders properly. Advertising a name the remote
/// has never heard of (`alacritty`, `xterm-kitty`) makes ncurses fall back to
/// dumb-terminal behaviour, which reads to the user as a bug in us.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// Everything a remote shell needs beyond where to dial and who to be.
///
/// Data only, and the same rules as [`RdpOptions`]: serialized into the
/// `hosts.ssh_settings` column, so every field is `#[serde(default)]` and no
/// field holds a secret. The password, passphrase and key path travel in
/// [`ConnectOptions::credentials`], which is not serializable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshOptions {
    /// What to advertise as `TERM`.
    pub term: String,
    /// Initial geometry, in character cells. The UI overwrites both before
    /// the shell starts; 80x24 is the VT100 default and the only size every
    /// remote program is guaranteed to cope with.
    pub cols: u16,
    pub rows: u16,
    /// Which multiplexer to attach to, or how to find one.
    pub multiplexer: MultiplexerKind,
    /// The session to attach to or create. One name per profile means the
    /// user returns to the same place every time.
    pub session_name: String,
    /// The command template for [`MultiplexerKind::Custom`].
    pub custom_command: Option<String>,
    /// Open a plain login shell when nothing suitable is installed, rather
    /// than failing the connection. Ignored by `Auto`, which treats "nothing
    /// installed" as a valid answer rather than a failure.
    pub fallback_to_shell: bool,
    /// A command to run instead of the login shell, for a profile that should
    /// land straight in a log tail or a REPL. Runs *inside* the multiplexer
    /// when there is one, so it is still persistent.
    pub startup_command: Option<String>,
}

impl Default for SshOptions {
    fn default() -> Self {
        Self {
            term: DEFAULT_TERM.to_string(),
            cols: 80,
            rows: 24,
            multiplexer: MultiplexerKind::Auto,
            session_name: "deskvnc".to_string(),
            custom_command: None,
            fallback_to_shell: true,
            startup_command: None,
        }
    }
}

impl SshOptions {
    /// Geometry clamped to what a `pty-req` and every remote program can
    /// actually represent.
    ///
    /// The zero is the dangerous one: a webview measuring a hidden or
    /// not-yet-laid-out element reports 0x0, and a PTY zero columns wide makes
    /// remote programs divide by zero or spin. One by one is useless but
    /// harmless, which is the right direction to be wrong in.
    pub fn clamped(&self) -> (u16, u16) {
        (self.cols.clamp(1, 10_000), self.rows.clamp(1, 10_000))
    }
}
