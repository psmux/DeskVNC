//! RFB authentication (PRD/10).
//!
//! [`authenticate`] is the single entry point: given the security types a
//! server offered, it picks the strongest one we are willing to use, runs that
//! handshake, reads the SecurityResult, and hands back the, possibly
//! TLS-upgraded or AES-EAX-wrapped, stream the rest of the session runs over.
//!
//! ## Threat model
//!
//! Everything on the wire is attacker-controlled. Every length the server sends
//! is bounds-checked before it is used to allocate, and no credential ever
//! reaches a log line or a `Debug` impl.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vnc_transport::{BoxedStream, TransportError, TrustDecision};

use crate::error::{Result, VncError};
use crate::types::{ConnectOptions, PinScheme, SecurityType};

pub mod apple_dh;
pub mod mslogon;
pub mod none;
pub mod prompt;
pub mod ra2;
pub mod tight;
pub mod vencrypt;
pub mod vnc_auth;

pub use prompt::{CredentialAsk, CredentialPrompt, CredentialSource, MAX_CREDENTIAL_ATTEMPTS};
pub use vencrypt::VeNCryptSubtype;

// ---------------------------------------------------------------------------
// Protocol version
// ---------------------------------------------------------------------------

/// The negotiated RFB protocol version, plus the one vendor quirk that changes
/// handshake framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersionInfo {
    pub major: u8,
    pub minor: u8,
    /// The banner was `RFB 003.889`, macOS Screen Sharing / ARD.
    pub is_apple: bool,
}

impl ProtocolVersionInfo {
    pub const fn new(major: u8, minor: u8) -> Self {
        Self {
            major,
            minor,
            is_apple: false,
        }
    }

    /// Parse an `RFB 003.008\n` banner. `003.889` (Apple) is normalised to 3.8
    /// with [`is_apple`](Self::is_apple) set, because Apple's server otherwise
    /// speaks 3.8 framing.
    pub fn parse(banner: &str) -> Result<Self> {
        let b = banner.trim_end_matches(['\n', '\r']);
        let rest = b
            .strip_prefix("RFB ")
            .ok_or_else(|| VncError::UnsupportedVersion(b.to_string()))?;
        let (major, minor) = rest
            .split_once('.')
            .ok_or_else(|| VncError::UnsupportedVersion(b.to_string()))?;
        let major: u32 = major
            .parse()
            .map_err(|_| VncError::UnsupportedVersion(b.to_string()))?;
        let minor: u32 = minor
            .parse()
            .map_err(|_| VncError::UnsupportedVersion(b.to_string()))?;
        if major != 3 {
            return Err(VncError::UnsupportedVersion(b.to_string()));
        }
        Ok(match minor {
            889 => Self {
                major: 3,
                minor: 8,
                is_apple: true,
            },
            // 3.4/3.5 in the wild are really 3.3; anything above 3.8 we clamp.
            m if m >= 8 => Self::new(3, 8),
            m if m >= 7 => Self::new(3, 7),
            _ => Self::new(3, 3),
        })
    }

    /// RFB 3.7+ lets the *client* choose from a list; 3.3 has the server
    /// dictate a single type as a u32 and no selection byte is sent back.
    pub fn client_selects_security(&self) -> bool {
        self.major > 3 || self.minor >= 7
    }

    /// RFB 3.8 always sends a SecurityResult, and appends a reason string on
    /// failure.
    pub fn has_security_result_for_all(&self) -> bool {
        self.major > 3 || self.minor >= 8
    }
}

// ---------------------------------------------------------------------------
// Error plumbing
// ---------------------------------------------------------------------------

impl From<TransportError> for VncError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Io(e) => VncError::Io(e),
            TransportError::Timeout => VncError::Timeout,
            TransportError::Refused(a) => VncError::ConnectionRefused(a),
            TransportError::Resolve(h) => VncError::ResolveFailed(h),
            TransportError::Tls(m) => VncError::Tls(m),
            TransportError::CertificateMismatch { expected, actual } => {
                VncError::CertificateMismatch { expected, actual }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bounds-checked stream helpers
// ---------------------------------------------------------------------------

/// Nothing in any authentication handshake is legitimately larger than this.
pub(crate) const MAX_AUTH_FIELD: usize = 64 * 1024;

pub(crate) fn map_io(e: std::io::Error) -> VncError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        VncError::ConnectionClosed
    } else {
        VncError::Io(e)
    }
}

pub(crate) async fn read_u8(s: &mut BoxedStream) -> Result<u8> {
    s.read_u8().await.map_err(map_io)
}

pub(crate) async fn read_u16(s: &mut BoxedStream) -> Result<u16> {
    s.read_u16().await.map_err(map_io)
}

pub(crate) async fn read_u32(s: &mut BoxedStream) -> Result<u32> {
    s.read_u32().await.map_err(map_io)
}

/// Read exactly `len` bytes, refusing absurd lengths before allocating.
pub(crate) async fn read_bytes(s: &mut BoxedStream, len: usize, what: &str) -> Result<Vec<u8>> {
    read_bytes_max(s, len, MAX_AUTH_FIELD, what).await
}

pub(crate) async fn read_bytes_max(
    s: &mut BoxedStream,
    len: usize,
    max: usize,
    what: &str,
) -> Result<Vec<u8>> {
    if len > max {
        return Err(VncError::Protocol(format!(
            "server sent an implausible {what} length: {len} (max {max})"
        )));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await.map_err(map_io)?;
    Ok(buf)
}

pub(crate) async fn write_all(s: &mut BoxedStream, bytes: &[u8]) -> Result<()> {
    s.write_all(bytes).await.map_err(map_io)?;
    s.flush().await.map_err(map_io)
}

// ---------------------------------------------------------------------------
// Handler contract
// ---------------------------------------------------------------------------

/// Whether the generic SecurityResult still has to be read after a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResultMode {
    /// Follow the protocol version rules.
    Auto,
    /// Always read one, whatever the version says (VeNCrypt).
    Always,
    /// The handler consumed it (or the server sends none).
    #[allow(dead_code)]
    Skip,
}

/// How a handshake judged the server's identity, and which key it judged.
///
/// The two travel together on purpose: a decision without its scheme cannot be
/// turned into a pin without guessing what was fingerprinted, and guessing is
/// exactly what produces a cross-scheme false mismatch.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerIdentity {
    /// Which server key `decision` describes.
    pub scheme: PinScheme,
    pub decision: TrustDecision,
}

pub(crate) struct AuthOutcome {
    pub stream: BoxedStream,
    pub result_mode: ResultMode,
    /// Set when the handshake authenticated a server key (VeNCrypt's TLS
    /// upgrade, RA2's RSA key), so the session layer can raise the TOFU prompt.
    pub trust: Option<ServerIdentity>,
}

impl AuthOutcome {
    pub fn auto(stream: BoxedStream) -> Self {
        Self {
            stream,
            result_mode: ResultMode::Auto,
            trust: None,
        }
    }
    #[allow(dead_code)]
    pub fn always(stream: BoxedStream) -> Self {
        Self {
            stream,
            result_mode: ResultMode::Always,
            trust: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Selection (PRD/10 §2)
// ---------------------------------------------------------------------------

// The client no longer refuses any security type the server offers, and the
// history of that is worth keeping, because both halves were learned from
// real servers rather than reasoned out.
//
// `VncAuth` was gated first, per PRD/10 §2, and it made the client useless
// against most of the installed base: the TightVNC/TigerVNC/UltraVNC/x11vnc
// family advertises `[VncAuth, Tight]` and nothing stronger by default. The
// gate did not even hold, since `Tight` (16) was never gated and its inner
// auth is the same cleartext DES exchange, so blocking VncAuth only pushed
// the connection down the Tight path. A gate with a side door is worse than
// no gate, because it looks like protection.
//
// `None` was gated for longer, and failed the same way for the same reason:
// a stock `x11vnc` with no password offers exactly one security type, so the
// refusal made a whole class of server unreachable while telling the user to
// enable a control that was never built (issue #1). Taking the only type on
// offer is not a downgrade in any case.
//
// Both still get the loud treatment where it matters: the 8-character
// truncation warning in the credentials dialog, and the persistent
// "unencrypted" badge on the session (`SecurityType::encrypts_session`).
// Warning about a real risk beats refusing to connect and being replaced by
// a client that does.

/// True if we have an implementation for this type at all.
pub fn is_supported(t: SecurityType) -> bool {
    matches!(
        t,
        SecurityType::None
            | SecurityType::VncAuth
            | SecurityType::Tight
            | SecurityType::VeNCrypt
            | SecurityType::Ra2
            | SecurityType::Ra2ne
            | SecurityType::Ra2_256
            | SecurityType::Ra2ne256
            | SecurityType::AppleDh
            | SecurityType::MsLogonII
    )
}

/// Pick the strongest mutually-supported security type (PRD/10 §2).
///
/// * `opts.security_pref` pins the choice, if the server does not offer it we
///   fail rather than silently downgrading ("never silently downgrade").
/// * `opts.allow_insecure` gates `None` and `VncAuth`.
pub fn select_security_type(offered: &[u8], opts: &ConnectOptions) -> Result<SecurityType> {
    if offered.is_empty() {
        return Err(VncError::NoSupportedSecurityType(Vec::new()));
    }

    let types: Vec<SecurityType> = offered
        .iter()
        .copied()
        .map(SecurityType::from_wire)
        .collect();

    // An explicit user choice is honoured exactly, or not at all.
    if let Some(pref) = opts.security_pref {
        if !types.contains(&pref) {
            return Err(VncError::NoSupportedSecurityType(offered.to_vec()));
        }
        if !is_supported(pref) {
            return Err(VncError::UnsupportedSecurityType(pref.to_wire()));
        }
        return Ok(pref);
    }

    let mut usable: Vec<SecurityType> =
        types.iter().copied().filter(|t| is_supported(*t)).collect();
    if usable.is_empty() {
        return Err(VncError::NoSupportedSecurityType(offered.to_vec()));
    }

    // Strongest first; ties broken by the wire number so selection is stable.
    usable.sort_by(|a, b| {
        b.strength()
            .cmp(&a.strength())
            .then_with(|| a.to_wire().cmp(&b.to_wire()))
    });

    // The strongest type the server actually offered. `None` is reached only
    // when it is the only thing on the list, because the sort puts every
    // other supported type ahead of it, so taking it is never a downgrade:
    // there was nothing better to downgrade from.
    //
    // This used to be gated behind an `allow_insecure` opt-in, which made a
    // passwordless server (a stock `x11vnc` with no `-passwd`, or the
    // loopback-only server behind an SSH tunnel) impossible to reach: the
    // refusal told the user to enable "Allow an unencrypted connection",
    // and no such control existed anywhere in the app. The gate also did not
    // match how VncAuth is treated a few lines up, whose session is equally
    // cleartext and has never been refused. The session carries the
    // unencrypted badge either way (`SecurityType::encrypts_session`), which
    // is the honest treatment: warn about a real risk rather than refuse to
    // connect and be replaced by a client that does not.
    Ok(usable[0])
}

// ---------------------------------------------------------------------------
// The dispatcher
// ---------------------------------------------------------------------------

/// Pick the strongest mutually-supported security type and run its handshake.
///
/// May upgrade the stream to TLS (VeNCrypt X509) or wrap it in RA2's AES-EAX
/// framing, so the returned stream, not the one passed in, is what the rest
/// of the session must use.
pub async fn authenticate<S: vnc_transport::Stream + 'static>(
    stream: S,
    version: ProtocolVersionInfo,
    offered: &[u8],
    opts: &ConnectOptions,
) -> Result<(BoxedStream, SecurityType)> {
    let (stream, security, _trust) =
        authenticate_with_trust(stream, version, offered, opts, &CredentialSource::none()).await?;
    Ok((stream, security))
}

/// As [`authenticate`], but also reports how the server's identity was judged
/// (`None` when the chosen security type authenticates no server key at all).
///
/// Two handshakes produce a decision: VeNCrypt's TLS upgrade (X.509 SPKI) and
/// RA2's raw RSA key. Both are fingerprinted the same way, but they are
/// different keys, so each carries its [`PinScheme`] and is pinned separately.
///
/// The session layer needs this to raise `SessionEvent::CertificatePrompt` on
/// [`TrustDecision::Unknown`], first contact is accepted so the fingerprint
/// can be shown, and the UI decides whether to keep the connection. A
/// [`TrustDecision::Changed`] never reaches here: it is a hard stop reported as
/// `VncError::CertificateMismatch`.
pub async fn authenticate_with_trust<S: vnc_transport::Stream + 'static>(
    stream: S,
    version: ProtocolVersionInfo,
    offered: &[u8],
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<(BoxedStream, SecurityType, Option<ServerIdentity>)> {
    let chosen = select_security_type(offered, opts)?;
    tracing::info!(security_type = ?chosen, "selected security type");

    let mut stream: BoxedStream = Box::pin(stream);

    // RFB 3.7+: echo the chosen type back. 3.3: the server already decided.
    if version.client_selects_security() {
        write_all(&mut stream, &[chosen.to_wire()]).await?;
    }

    let outcome = match chosen {
        SecurityType::None => none::handshake(stream, opts).await?,
        SecurityType::VncAuth => vnc_auth::handshake(stream, opts, creds).await?,
        SecurityType::Tight => tight::handshake(stream, version, opts, creds).await?,
        SecurityType::VeNCrypt => vencrypt::handshake(stream, opts, creds).await?,
        SecurityType::Ra2
        | SecurityType::Ra2ne
        | SecurityType::Ra2_256
        | SecurityType::Ra2ne256 => ra2::handshake(stream, chosen, opts, creds).await?,
        SecurityType::AppleDh => apple_dh::handshake(stream, opts, creds).await?,
        SecurityType::MsLogonII => mslogon::handshake(stream, opts, creds).await?,
        SecurityType::Unknown(v) => return Err(VncError::UnsupportedSecurityType(v)),
    };

    let AuthOutcome {
        mut stream,
        result_mode,
        trust,
    } = outcome;

    let read_result = match result_mode {
        ResultMode::Skip => false,
        ResultMode::Always => true,
        // 3.8 always sends one. Before 3.8, `None` is the only type that
        // skips it (there is nothing to report).
        ResultMode::Auto => {
            version.has_security_result_for_all() || !matches!(chosen, SecurityType::None)
        }
    };

    if read_result {
        read_security_result(&mut stream, version).await?;
    }

    Ok((stream, chosen, trust))
}

/// Read the u32 SecurityResult. 0 = OK, anything else = failure; RFB 3.8
/// appends a u32-prefixed reason string.
pub(crate) async fn read_security_result(
    stream: &mut BoxedStream,
    version: ProtocolVersionInfo,
) -> Result<()> {
    let result = read_u32(stream).await?;
    if result == 0 {
        return Ok(());
    }

    let mut reason = match result {
        1 => "the server rejected the credentials".to_string(),
        2 => "too many authentication attempts; the server is throttling".to_string(),
        other => format!("the server reported authentication status {other}"),
    };

    if version.has_security_result_for_all() {
        // Best effort: some 3.8 servers just close the socket here.
        if let Ok(len) = read_u32(stream).await {
            if let Ok(bytes) =
                read_bytes_max(stream, len as usize, 8192, "auth failure reason").await
            {
                let text: String = String::from_utf8_lossy(&bytes)
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(512)
                    .collect();
                if !text.trim().is_empty() {
                    reason = text;
                }
            }
        }
    }

    Err(VncError::AuthFailed(reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Credentials;

    fn opts() -> ConnectOptions {
        ConnectOptions::new("host", 5900)
    }

    #[test]
    fn parses_versions() {
        assert_eq!(
            ProtocolVersionInfo::parse("RFB 003.008\n").unwrap(),
            ProtocolVersionInfo::new(3, 8)
        );
        assert_eq!(
            ProtocolVersionInfo::parse("RFB 003.003\n").unwrap(),
            ProtocolVersionInfo::new(3, 3)
        );
        assert_eq!(
            ProtocolVersionInfo::parse("RFB 003.007\n").unwrap(),
            ProtocolVersionInfo::new(3, 7)
        );
        let apple = ProtocolVersionInfo::parse("RFB 003.889\n").unwrap();
        assert!(apple.is_apple);
        assert_eq!((apple.major, apple.minor), (3, 8));
        assert!(ProtocolVersionInfo::parse("HTTP/1.1 200 OK").is_err());
        assert!(ProtocolVersionInfo::parse("RFB 004.001\n").is_err());
    }

    #[test]
    fn version_framing_rules() {
        assert!(!ProtocolVersionInfo::new(3, 3).client_selects_security());
        assert!(ProtocolVersionInfo::new(3, 7).client_selects_security());
        assert!(!ProtocolVersionInfo::new(3, 7).has_security_result_for_all());
        assert!(ProtocolVersionInfo::new(3, 8).has_security_result_for_all());
    }

    #[test]
    fn prefers_vencrypt_over_everything() {
        let o = opts();
        assert_eq!(
            select_security_type(&[2, 19, 1], &o).unwrap(),
            SecurityType::VeNCrypt
        );
    }

    #[test]
    fn ranking_follows_prd_order() {
        let o = opts();
        // RA2_256 beats RA2 beats AppleDh beats MSLogon beats Tight.
        assert_eq!(
            select_security_type(&[5, 129], &o).unwrap(),
            SecurityType::Ra2_256
        );
        assert_eq!(
            select_security_type(&[30, 5], &o).unwrap(),
            SecurityType::Ra2
        );
        assert_eq!(
            select_security_type(&[113, 30], &o).unwrap(),
            SecurityType::AppleDh
        );
        assert_eq!(
            select_security_type(&[16, 113], &o).unwrap(),
            SecurityType::MsLogonII
        );
        // Tight now ranks BELOW plain VncAuth: its inner auth is the same DES
        // exchange, so preferring it bought nothing and added the tunnel +
        // extended-ServerInit failure surface.
        assert_eq!(
            select_security_type(&[2, 16], &o).unwrap(),
            SecurityType::VncAuth
        );
    }

    #[test]
    fn unknown_types_are_ignored_when_something_usable_exists() {
        let o = opts();
        assert_eq!(
            select_security_type(&[250, 251, 30], &o).unwrap(),
            SecurityType::AppleDh
        );
        assert!(matches!(
            select_security_type(&[250, 251], &o),
            Err(VncError::NoSupportedSecurityType(_))
        ));
    }

    #[test]
    fn no_auth_is_taken_only_when_it_is_all_there_is() {
        let o = opts();
        // Issue #1: a stock `x11vnc` with no password offers exactly this,
        // and refusing it made that server unreachable while telling the
        // user to enable a control the app never had.
        assert_eq!(select_security_type(&[1], &o).unwrap(), SecurityType::None);
        // It is still the last resort: anything else on the list wins, so
        // taking it is never a downgrade.
        assert_eq!(
            select_security_type(&[1, 2], &o).unwrap(),
            SecurityType::VncAuth
        );
        assert_eq!(
            select_security_type(&[1, 19], &o).unwrap(),
            SecurityType::VeNCrypt
        );
    }

    /// VncAuth must work out of the box. Gating it made the client fail against
    /// the default configuration of most real servers, and the gate leaked
    /// anyway via the ungated Tight path (same DES exchange underneath).
    #[test]
    fn vnc_auth_connects_without_any_optin() {
        let o = opts();
        assert!(!o.allow_insecure);
        assert_eq!(
            select_security_type(&[2], &o).unwrap(),
            SecurityType::VncAuth
        );
        // The exact offer made by the TightVNC/TigerVNC family.
        assert_eq!(
            select_security_type(&[2, 16], &o).unwrap(),
            SecurityType::VncAuth
        );
        // Tight-only servers still connect, via the full Tight handshake.
        assert_eq!(
            select_security_type(&[16], &o).unwrap(),
            SecurityType::Tight
        );
    }

    #[test]
    fn a_secure_option_wins_over_a_gated_one() {
        let o = opts();
        assert_eq!(
            select_security_type(&[1, 2, 30], &o).unwrap(),
            SecurityType::AppleDh
        );
    }

    #[test]
    fn preference_is_honoured_and_never_downgraded() {
        let mut o = opts();
        o.security_pref = Some(SecurityType::AppleDh);
        assert_eq!(
            select_security_type(&[19, 30], &o).unwrap(),
            SecurityType::AppleDh
        );
        // Not offered -> hard failure, no silent downgrade to VeNCrypt.
        assert!(select_security_type(&[19, 2], &o).is_err());
        // Pinning a type is the user's decision and is honoured as given,
        // including "None" against a server that offers something stronger.
        o.security_pref = Some(SecurityType::None);
        assert_eq!(select_security_type(&[1], &o).unwrap(), SecurityType::None);
        assert_eq!(
            select_security_type(&[1, 2], &o).unwrap(),
            SecurityType::None
        );
    }

    #[test]
    fn empty_offer_is_an_error() {
        assert!(select_security_type(&[], &opts()).is_err());
    }

    #[tokio::test]
    async fn end_to_end_vnc_auth_on_3_8() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            let mut selected = [0u8; 1];
            server.read_exact(&mut selected).await.unwrap();
            server.write_all(&[0x7fu8; 16]).await.unwrap(); // challenge
            let mut response = [0u8; 16];
            server.read_exact(&mut response).await.unwrap();
            server.write_all(&0u32.to_be_bytes()).await.unwrap(); // SecurityResult OK
            (selected[0], response)
        });

        let mut o = opts();
        o.allow_insecure = true;
        o.credentials = Credentials::password("swordfish");
        let (_stream, chosen) = authenticate(client, ProtocolVersionInfo::new(3, 8), &[2], &o)
            .await
            .unwrap();
        assert_eq!(chosen, SecurityType::VncAuth);

        let (selected, response) = task.await.unwrap();
        assert_eq!(selected, 2, "the chosen type is echoed back on 3.7+");
        assert_eq!(
            response,
            vnc_auth::respond_to_challenge("swordfish", &[0x7fu8; 16])
        );
    }

    #[tokio::test]
    async fn security_result_failure_carries_the_server_reason() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut selected = [0u8; 1];
            server.read_exact(&mut selected).await.unwrap();
            server.write_all(&[0u8; 16]).await.unwrap();
            let mut response = [0u8; 16];
            server.read_exact(&mut response).await.unwrap();
            let reason = b"Too many authentication failures";
            server.write_all(&1u32.to_be_bytes()).await.unwrap();
            server
                .write_all(&(reason.len() as u32).to_be_bytes())
                .await
                .unwrap();
            server.write_all(reason).await.unwrap();
        });

        let mut o = opts();
        o.allow_insecure = true;
        o.credentials = Credentials::password("pw");
        match authenticate(client, ProtocolVersionInfo::new(3, 8), &[2], &o).await {
            Err(VncError::AuthFailed(reason)) => {
                assert_eq!(reason, "Too many authentication failures")
            }
            other => panic!("expected AuthFailed, got {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn rfb_3_3_does_not_echo_the_security_type() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            // A 3.3 server goes straight to the challenge, if the client wrote
            // a selection byte it would be read here as challenge input.
            server.write_all(&[0x22u8; 16]).await.unwrap();
            let mut response = [0u8; 16];
            server.read_exact(&mut response).await.unwrap();
            server.write_all(&0u32.to_be_bytes()).await.unwrap();
            response
        });

        let mut o = opts();
        o.allow_insecure = true;
        o.credentials = Credentials::password("pw");
        authenticate(client, ProtocolVersionInfo::new(3, 3), &[2], &o)
            .await
            .unwrap();
        assert_eq!(
            task.await.unwrap(),
            vnc_auth::respond_to_challenge("pw", &[0x22u8; 16])
        );
    }

    #[tokio::test]
    async fn rfb_3_3_none_reads_no_security_result() {
        // The server sends nothing at all after the (implicit) selection; if we
        // tried to read a SecurityResult this would hang and then time out.
        let (client, _server) = tokio::io::duplex(16);
        let mut o = opts();
        o.allow_insecure = true;
        let (_s, chosen) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            authenticate(client, ProtocolVersionInfo::new(3, 3), &[1], &o),
        )
        .await
        .expect("must not block on a SecurityResult")
        .unwrap();
        assert_eq!(chosen, SecurityType::None);
    }

    #[test]
    fn credentials_never_leak_through_debug() {
        let c = Credentials::user_pass("alice", "hunter2");
        let shown = format!("{c:?}");
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("alice"));
    }
}

#[cfg(test)]
mod selection_regression {
    use super::*;
    use crate::types::{ConnectOptions, SecurityType};

    /// TightVNC/TigerVNC-family servers advertise `[VncAuth, Tight]`. We must
    /// take plain VncAuth: Tight's inner auth resolves to the same DES
    /// exchange, but adds tunnel negotiation and the extended ServerInit as
    /// failure surface (that omission was the "rect 64512x512 exceeds
    /// framebuffer" stream desync).
    #[test]
    fn prefers_plain_vnc_auth_over_tight_when_both_offered() {
        let mut opts = ConnectOptions::new("h", 5900);
        opts.allow_insecure = true;
        assert_eq!(
            select_security_type(&[2, 16], &opts).unwrap(),
            SecurityType::VncAuth
        );
    }

    /// ...but a server offering ONLY Tight must still work.
    #[test]
    fn still_selects_tight_when_it_is_the_only_option() {
        let mut opts = ConnectOptions::new("h", 5900);
        opts.allow_insecure = true;
        assert_eq!(
            select_security_type(&[16], &opts).unwrap(),
            SecurityType::Tight
        );
    }
}
