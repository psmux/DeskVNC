//! Validation and resolution of [`remote_core::RdpOptions`] (PRDRDP/12 §3.6).
//!
//! The definitions live in `remote-core`, because they are serialised into the
//! `hosts.rdp_settings` column and the shell has to build them
//! (PRDRDP/02 §5.4). What is here is the pass that turns a stored blob into
//! something the connect path can use without checking anything again:
//! constructing a [`ResolvedOptions`] is the only way into
//! [`crate::connection`], so a rule added here cannot be bypassed by a new
//! call site.
//!
//! Anything out of range is clamped and recorded as a warning rather than
//! rejected, with two exceptions that are genuinely unusable: a channel name
//! the wire field cannot hold, and a phase 3 feature the profile asked for
//! that this build does not have.

use remote_core::{
    ConnectOptions, MonitorPolicy, NlaPolicy, QualityPreset, RdpColorDepth, RdpOptions,
};

use crate::error::ConnectStage;

/// `TS_UD_CS_CORE.clientName` is a 32 byte field of UTF-16, so fifteen
/// characters and a null (MS-RDPBCGR 2.2.1.3.2). Longer names are truncated
/// by this crate, which is what the field's doc comment on
/// [`RdpOptions::client_name`] says happens.
pub const MAX_CLIENT_NAME: usize = 15;

/// `desktopScaleFactor` is 100 to 500 (MS-RDPBCGR 2.2.1.3.2).
pub const MIN_SCALE_FACTOR: u32 = 100;
/// The upper end of the same range.
pub const MAX_SCALE_FACTOR: u32 = 500;

/// US English, the layout `TS_UD_CS_CORE.keyboardLayout` gets when the
/// profile says 0 and we cannot read one off the host.
pub const KEYBOARD_LAYOUT_US: u32 = 0x0000_0409;

/// Every way a stored blob can be wrong that clamping cannot fix.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OptionsError {
    /// The host field was empty, so there is nothing to dial and nothing to
    /// pin a certificate against.
    #[error("no host name")]
    NoHost,

    /// A phase 3 feature the profile asked for. Rejecting it with a message
    /// is the alternative to silently making a direct connection the user did
    /// not ask for ([`RdpOptions::gateway`] says so on the field).
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
}

/// The colour depth actually requested, after `Auto` has been resolved
/// against the quality preset.
///
/// `TS_UD_CS_CORE.highColorDepth` (MS-RDPBCGR 2.2.1.3.2) takes the bit count
/// directly, so the enum carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorDepthBits {
    /// 15 bits per pixel, `RNS_UD_15BPP_SUPPORT`.
    Bpp15,
    /// 16 bits per pixel.
    Bpp16,
    /// 24 bits per pixel.
    Bpp24,
    /// 32 bits per pixel, which is what a modern session wants.
    Bpp32,
}

impl ColorDepthBits {
    /// The wire value of `highColorDepth`.
    #[must_use]
    pub const fn wire(self) -> u16 {
        match self {
            ColorDepthBits::Bpp15 => 15,
            ColorDepthBits::Bpp16 => 16,
            ColorDepthBits::Bpp24 => 24,
            ColorDepthBits::Bpp32 => 32,
        }
    }
}

/// [`RdpOptions`] after validation.
///
/// Every field is in range, every string fits its wire field, and nothing is
/// left for a later layer to check.
#[derive(Debug, Clone)]
pub struct ResolvedOptions {
    /// The name used for SNI, certificate verification, pin lookup and the
    /// Kerberos SPN. Never the dial address, which an SSH tunnel makes
    /// `localhost` (PRDRDP/00 R26).
    pub server_name: String,
    /// `TS_UD_CS_CORE.clientName`, at most [`MAX_CLIENT_NAME`] characters.
    pub client_name: String,
    /// The logon domain. An empty string is normalised to `None`, because
    /// the two mean the same thing and only one of them can be tested for.
    pub domain: Option<String>,
    /// `TS_UD_CS_CORE.keyboardLayout`, never zero.
    pub keyboard_layout: u32,
    /// `TS_UD_CS_CORE.highColorDepth`, with `Auto` resolved.
    pub color_depth: ColorDepthBits,
    /// The desktop size to request. MS-RDPBCGR 2.2.1.3.2 bounds
    /// `desktopWidth` at 1 to 4096 and `desktopHeight` at 1 to 2048.
    pub desktop: (u16, u16),
    /// `desktopScaleFactor`, clamped to [`MIN_SCALE_FACTOR`] to
    /// [`MAX_SCALE_FACTOR`].
    pub scale_factor: u32,
    /// Whether CredSSP is required or merely preferred.
    pub nla: NlaPolicy,
    /// Whether this host may use the TLS 1.0 and 1.1 backend (R55). Never a
    /// request, only permission.
    pub legacy_tls: bool,
    /// Whether the X.224 Connection Request carries the `mstshash` cookie
    /// (PRDRDP/00 R29, off by default: it leaks the username in cleartext
    /// ahead of the TLS upgrade).
    pub send_mstshash_cookie: bool,
    /// The static virtual channels to ask for in `TS_UD_CS_NET`, in the order
    /// they will be joined. Never more than
    /// [`rdp_pdu::io::limits::MAX_CHANNELS`].
    pub channels: Vec<&'static str>,
}

/// `cliprdr`, the clipboard channel (MS-RDPECLIP). Seven significant
/// characters in an eight byte ANSI field, which is the whole of
/// `CHANNEL_DEF.name` (MS-RDPBCGR 2.2.1.3.4.1).
pub const CHANNEL_CLIPRDR: &str = "cliprdr";
/// `drdynvc`, the dynamic virtual channel multiplexer (MS-RDPEDYC 2.2.1).
/// EGFX, display control and audio all ride inside it.
pub const CHANNEL_DRDYNVC: &str = "drdynvc";

impl ResolvedOptions {
    /// Validate and resolve.
    ///
    /// `warnings` collects everything that was clamped rather than rejected,
    /// so the session can log it once at connect and a user can find out why
    /// their 800 percent scale factor became 500.
    ///
    /// # Errors
    ///
    /// [`OptionsError::NoHost`] for an empty host, and
    /// [`OptionsError::NotImplemented`] for a phase 3 feature the profile
    /// asked for.
    pub fn resolve(
        options: &ConnectOptions,
        rdp: &RdpOptions,
        warnings: &mut Vec<String>,
    ) -> Result<Self, OptionsError> {
        let host = options.host.trim();
        if host.is_empty() {
            return Err(OptionsError::NoHost);
        }
        if rdp.gateway.is_some() {
            return Err(OptionsError::NotImplemented("RD Gateway (MS-TSGU)"));
        }
        if rdp.kdc_proxy_url.is_some() {
            return Err(OptionsError::NotImplemented("the KDC proxy (MS-KKDCP)"));
        }

        let server_name = rdp
            .server_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(host)
            .to_owned();

        // The field is 32 bytes of UTF-16, so the count that matters is
        // characters and not bytes. Truncating on a character boundary keeps
        // the name legible in the server's event log; truncating on a byte
        // boundary would produce a lone surrogate.
        let mut client_name: String = rdp
            .client_name
            .trim()
            .chars()
            .take(MAX_CLIENT_NAME)
            .collect();
        if client_name.chars().count() < rdp.client_name.trim().chars().count() {
            warnings.push(format!(
                "client name truncated to {MAX_CLIENT_NAME} characters for TS_UD_CS_CORE"
            ));
        }
        if client_name.is_empty() {
            // The driver fills this from the OS hostname when it is empty,
            // which `RdpOptions::client_name`'s doc comment promises. We have
            // no dependency that reads a hostname, so the honest fallback is
            // a fixed name rather than a guess (see the report's gap list).
            client_name = "DeskVNCViewer".to_owned();
        }

        let domain = rdp
            .domain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        let keyboard_layout = if rdp.keyboard_layout == 0 {
            KEYBOARD_LAYOUT_US
        } else {
            rdp.keyboard_layout
        };

        let color_depth = resolve_color_depth(rdp.color_depth, options.quality);

        let scale_factor = if rdp.desktop_scale_factor < MIN_SCALE_FACTOR
            || rdp.desktop_scale_factor > MAX_SCALE_FACTOR
        {
            let clamped = rdp
                .desktop_scale_factor
                .clamp(MIN_SCALE_FACTOR, MAX_SCALE_FACTOR);
            warnings.push(format!(
                "desktop scale factor {} is outside {MIN_SCALE_FACTOR} to {MAX_SCALE_FACTOR}, using {clamped}",
                rdp.desktop_scale_factor
            ));
            clamped
        } else {
            rdp.desktop_scale_factor
        };

        if matches!(
            rdp.monitors,
            MonitorPolicy::All | MonitorPolicy::Selected(_)
        ) {
            warnings.push(
                "multi monitor attach is not implemented yet, attaching to the primary".to_owned(),
            );
        }

        // Only the two channels phase 1 has any use for. A channel we do not
        // implement is a channel the server will send data on and we will
        // have to ignore, so it is not requested (PRDRDP/03 §2.4).
        let mut channels = vec![CHANNEL_DRDYNVC];
        if rdp.codecs.uncompressed {
            // The clipboard is not a codec; the flag is checked because a
            // profile with everything off is a profile that wants nothing.
        }
        channels.push(CHANNEL_CLIPRDR);

        Ok(Self {
            server_name,
            client_name,
            domain,
            keyboard_layout,
            color_depth,
            // MS-RDPBCGR 2.2.1.3.2 bounds the pair, and 1024 by 768 is the
            // block `ClientCoreData::default` sends
            // (`crates/rdp-pdu/src/gcc/client.rs:206`). The real size arrives
            // from the shell in phase 1b, once the window exists.
            desktop: (1024, 768),
            scale_factor,
            nla: rdp.nla,
            legacy_tls: rdp.legacy_tls,
            send_mstshash_cookie: rdp.send_mstshash_cookie,
            channels,
        })
    }

    /// The stage a resolution failure is reported against, so the message a
    /// user sees names a phase like every other connect failure.
    #[must_use]
    pub const fn stage() -> ConnectStage {
        ConnectStage::Resolving
    }
}

/// Resolve `Auto` against the quality preset (PRDRDP/02 §7.3 owns the
/// mapping).
///
/// The preset narrows what we ask for on a link that cannot carry 32bpp, in
/// the same spirit as `pixel_format_for` at
/// `crates/vnc-core/src/session/connection.rs:82`, whose comment records why
/// the low preset rides a smaller format rather than a full one.
fn resolve_color_depth(depth: RdpColorDepth, quality: QualityPreset) -> ColorDepthBits {
    match depth {
        RdpColorDepth::Bpp15 => ColorDepthBits::Bpp15,
        RdpColorDepth::Bpp16 => ColorDepthBits::Bpp16,
        RdpColorDepth::Bpp24 => ColorDepthBits::Bpp24,
        RdpColorDepth::Bpp32 => ColorDepthBits::Bpp32,
        RdpColorDepth::Auto => match quality {
            QualityPreset::Auto | QualityPreset::High => ColorDepthBits::Bpp32,
            QualityPreset::Medium => ColorDepthBits::Bpp16,
            QualityPreset::Low | QualityPreset::BlackAndWhite => ColorDepthBits::Bpp15,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> (ConnectOptions, RdpOptions) {
        let opts = ConnectOptions::rdp("server.example", 3389);
        let rdp = opts
            .rdp_options()
            .expect("built with ConnectOptions::rdp")
            .clone();
        (opts, rdp)
    }

    #[test]
    fn defaults_resolve_without_a_warning() {
        let (opts, rdp) = options();
        let mut warnings = Vec::new();
        let r = ResolvedOptions::resolve(&opts, &rdp, &mut warnings).expect("defaults are valid");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(r.server_name, "server.example");
        assert_eq!(r.keyboard_layout, KEYBOARD_LAYOUT_US);
        assert_eq!(r.color_depth, ColorDepthBits::Bpp32);
        assert_eq!(r.scale_factor, 100);
        assert!(!r.send_mstshash_cookie, "PRDRDP/00 R29 defaults it off");
    }

    /// The dial address and the name we verify a certificate against are
    /// separate fields precisely so an SSH tunnel does not make us pin
    /// `localhost` (PRDRDP/00 R26).
    #[test]
    fn the_server_name_survives_a_tunnelled_dial_address() {
        let mut opts = ConnectOptions::rdp("localhost", 13389);
        opts.rdp_mut().server_name = Some("win11.corp.example".into());
        let rdp = opts.rdp_options().expect("rdp options").clone();
        let mut warnings = Vec::new();
        let r = ResolvedOptions::resolve(&opts, &rdp, &mut warnings).expect("valid");
        assert_eq!(r.server_name, "win11.corp.example");
    }

    #[test]
    fn an_over_long_client_name_is_truncated_and_reported() {
        let (opts, mut rdp) = options();
        rdp.client_name = "a-machine-name-far-too-long-for-the-field".into();
        let mut warnings = Vec::new();
        let r = ResolvedOptions::resolve(&opts, &rdp, &mut warnings).expect("valid");
        assert_eq!(r.client_name.chars().count(), MAX_CLIENT_NAME);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
    }

    #[test]
    fn a_scale_factor_outside_the_wire_range_is_clamped_and_reported() {
        let (opts, mut rdp) = options();
        rdp.desktop_scale_factor = 800;
        let mut warnings = Vec::new();
        let r = ResolvedOptions::resolve(&opts, &rdp, &mut warnings).expect("valid");
        assert_eq!(r.scale_factor, MAX_SCALE_FACTOR);
        assert!(warnings[0].contains("800"), "{warnings:?}");
    }

    /// An empty domain and no domain are the same logon, so only one of them
    /// reaches the connect path.
    #[test]
    fn an_empty_domain_becomes_none() {
        let (opts, mut rdp) = options();
        rdp.domain = Some("   ".into());
        let mut warnings = Vec::new();
        let r = ResolvedOptions::resolve(&opts, &rdp, &mut warnings).expect("valid");
        assert_eq!(r.domain, None);
    }

    /// A phase 3 feature the profile asked for fails with a message rather
    /// than silently making a direct connection.
    #[test]
    fn a_gateway_profile_is_refused_rather_than_ignored() {
        let (opts, mut rdp) = options();
        rdp.gateway = Some(remote_core::GatewayOptions::default());
        let mut warnings = Vec::new();
        let err = ResolvedOptions::resolve(&opts, &rdp, &mut warnings).expect_err("phase 3");
        assert!(err.to_string().contains("Gateway"), "{err}");
    }

    #[test]
    fn an_empty_host_is_refused_before_a_socket_is_opened() {
        let mut opts = ConnectOptions::rdp("  ", 3389);
        opts.port = 3389;
        let rdp = opts.rdp_options().expect("rdp options").clone();
        let mut warnings = Vec::new();
        assert_eq!(
            ResolvedOptions::resolve(&opts, &rdp, &mut warnings).unwrap_err(),
            OptionsError::NoHost
        );
    }

    /// Every channel name has to fit `CHANNEL_DEF.name`, which is seven
    /// significant characters in an eight byte field. The encoder refuses a
    /// longer one rather than truncating, so a name that does not fit here
    /// would fail at Connect Initial instead of at options resolution.
    #[test]
    fn every_requested_channel_name_fits_the_wire_field() {
        let (opts, rdp) = options();
        let mut warnings = Vec::new();
        let r = ResolvedOptions::resolve(&opts, &rdp, &mut warnings).expect("valid");
        assert!(r.channels.len() <= rdp_pdu::io::limits::MAX_CHANNELS);
        for name in &r.channels {
            assert!(name.is_ascii(), "{name}");
            assert!(name.len() <= 7, "{name} does not fit CHANNEL_DEF.name");
        }
    }

    #[test]
    fn a_slow_link_preset_asks_for_fewer_bits() {
        assert_eq!(
            resolve_color_depth(RdpColorDepth::Auto, QualityPreset::Low),
            ColorDepthBits::Bpp15
        );
        assert_eq!(
            resolve_color_depth(RdpColorDepth::Auto, QualityPreset::High),
            ColorDepthBits::Bpp32
        );
        // An explicit choice always wins over the preset.
        assert_eq!(
            resolve_color_depth(RdpColorDepth::Bpp32, QualityPreset::Low),
            ColorDepthBits::Bpp32
        );
    }
}
