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
use crate::types::{ConnectOptions, PinScheme, SecurityType, VncOptions};

pub mod apple_dh;
pub mod apple_srp;
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
    /// Set by the macOS SRP logins: the key that unwraps the server's first
    /// session rekey, which the Apple encrypted session starts from.
    pub apple_wrap_key: Option<[u8; 16]>,
}

impl AuthOutcome {
    pub fn auto(stream: BoxedStream) -> Self {
        Self {
            stream,
            result_mode: ResultMode::Auto,
            trust: None,
            apple_wrap_key: None,
        }
    }
    #[allow(dead_code)]
    pub fn always(stream: BoxedStream) -> Self {
        Self {
            stream,
            result_mode: ResultMode::Always,
            trust: None,
            apple_wrap_key: None,
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
            | SecurityType::AppleRsaSrp
            | SecurityType::AppleSrp
            | SecurityType::MsLogonII
    )
}

/// The RFB half of the options, or its defaults.
///
/// The `None` arm is unreachable in a running session: `VncDriver::spawn`
/// rejects options that are not VNC before a task exists (PRDRDP/02 §4.3).
pub(crate) fn vnc_opts(opts: &ConnectOptions) -> std::borrow::Cow<'_, VncOptions> {
    match opts.vnc_options() {
        Some(v) => std::borrow::Cow::Borrowed(v),
        None => std::borrow::Cow::Owned(VncOptions::default()),
    }
}

/// Whether the user opted into a security type that leaves the session in
/// cleartext.
pub(crate) fn allow_insecure(opts: &ConnectOptions) -> bool {
    vnc_opts(opts).allow_insecure
}

/// The pinned security type, if the profile names one this build knows.
pub(crate) fn security_pref(opts: &ConnectOptions) -> Option<SecurityType> {
    SecurityType::parse_pref(vnc_opts(opts).security_pref.as_deref())
}

/// Pick the strongest mutually-supported security type (PRD/10 §2).
///
/// * `VncOptions::security_pref` pins the choice, if the server does not offer
///   it we fail rather than silently downgrading ("never silently downgrade").
/// * `VncOptions::allow_insecure` gates `None` and `VncAuth`.
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
    if let Some(pref) = security_pref(opts) {
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
    let a = authenticate_full(stream, version, offered, opts, creds).await?;
    Ok((a.stream, a.security, a.trust))
}

/// Everything a finished security handshake hands to the session.
pub struct Authenticated {
    pub stream: BoxedStream,
    pub security: SecurityType,
    pub trust: Option<ServerIdentity>,
    /// For the macOS SRP logins, the key the Apple encrypted session starts
    /// from (see [`crate::apple`]).
    pub apple_wrap_key: Option<[u8; 16]>,
}

/// As [`authenticate_with_trust`], also returning the Apple session key.
pub async fn authenticate_full<S: vnc_transport::Stream + 'static>(
    stream: S,
    version: ProtocolVersionInfo,
    offered: &[u8],
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<Authenticated> {
    let chosen = select_security_type(offered, opts)?;
    tracing::info!(security_type = ?chosen, "selected security type");

    let mut stream: BoxedStream = Box::pin(stream);

    // RFB 3.7+: echo the chosen type back. 3.3: the server already decided.
    //
    // macOS reads the type byte of its SRP logins in one read together with
    // the client's first message, and closes the connection when the byte
    // arrives alone. Those two handshakes put the byte in front of their
    // first write instead.
    let joins_first_message = matches!(chosen, SecurityType::AppleRsaSrp | SecurityType::AppleSrp);
    let mut type_prefix = Vec::new();
    if version.client_selects_security() {
        if joins_first_message {
            type_prefix.push(chosen.to_wire());
        } else {
            write_all(&mut stream, &[chosen.to_wire()]).await?;
        }
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
        SecurityType::AppleRsaSrp => {
            apple_srp::handshake_33(stream, &type_prefix, opts, creds).await?
        }
        SecurityType::AppleSrp => {
            apple_srp::handshake_36(stream, &type_prefix, opts, creds).await?
        }
        SecurityType::MsLogonII => mslogon::handshake(stream, opts, creds).await?,
        SecurityType::Unknown(v) => return Err(VncError::UnsupportedSecurityType(v)),
    };

    let AuthOutcome {
        mut stream,
        result_mode,
        trust,
        apple_wrap_key,
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
        if let Some(refusal) = read_security_status(&mut stream, version).await? {
            return Err(refine_apple_refusal(chosen, refusal));
        }
    }

    Ok(Authenticated {
        stream,
        security: chosen,
        trust,
        apple_wrap_key,
    })
}

/// The hint a refused type 30 login carries.
pub const APPLE_DH_HINT: &str = "If the password is right, the Mac may need this account \
allowed under Remote Management, Options.";

/// What a refused type 30 login reports. Type 30 has no signal that tells a
/// wrong password from an account the Mac will not let in: macOS 26 answers
/// both with SecurityResult 1 and the same reason, "Authentication or
/// authorization failure". So the reason carries the hint, and it is what
/// the credential prompt shows when it asks again.
pub const APPLE_DH_REFUSED: &str = "The Mac refused the login. If the password is right, the \
Mac may need this account allowed under Remote Management, Options.";

/// What the user is told when a Mac proved it knew the password (its SRP
/// proof verified) and still refused the login.
pub const APPLE_ACCESS_DENIED: &str = "The Mac accepted the password but did not let this \
account share its screen. If Remote Management is on, allow the account under System \
Settings, General, Sharing, Remote Management, Options; otherwise add it under Screen Sharing.";

/// A SecurityResult other than 0: the status word and the reason, ours when
/// the server gave none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub status: u32,
    pub reason: String,
}

/// Turn a refused SecurityResult into what it means for a Mac.
///
/// Types 33 and 36 read the result only after the Mac's own SRP proof has
/// verified, which it cannot produce without the right password: a wrong
/// password is refused earlier, in place of that proof. So status 1 there is
/// the Mac declining this account (on macOS 26 with Remote Management on, an
/// account without its privileges gets exactly that), not a wrong password.
/// It becomes [`VncError::AccessDenied`] and the user is not asked for the
/// password again. The Mac's reason text is the same generic sentence either
/// way, so only the status word and where it arrived are looked at. Type 30
/// gives no such signal and gets the hint instead. Throttling (status 2) and
/// every other server keep the plain refusal.
fn refine_apple_refusal(chosen: SecurityType, refusal: Refusal) -> VncError {
    let srp = matches!(chosen, SecurityType::AppleRsaSrp | SecurityType::AppleSrp);
    match refusal.status {
        1 if srp => VncError::AccessDenied(APPLE_ACCESS_DENIED.into()),
        1 if chosen == SecurityType::AppleDh => VncError::AuthFailed(APPLE_DH_REFUSED.into()),
        _ => VncError::AuthFailed(refusal.reason),
    }
}

/// Read the u32 SecurityResult. 0 = OK, anything else = failure; RFB 3.8
/// appends a u32-prefixed reason string. A refusal comes back as data, with
/// its status word, so the caller can say what it means for the type it chose.
pub(crate) async fn read_security_status(
    stream: &mut BoxedStream,
    version: ProtocolVersionInfo,
) -> Result<Option<Refusal>> {
    let status = read_u32(stream).await?;
    if status == 0 {
        return Ok(None);
    }

    let mut reason = match status {
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

    tracing::info!(status, %reason, "the server refused the login");
    Ok(Some(Refusal { status, reason }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Credentials;

    fn opts() -> ConnectOptions {
        ConnectOptions::vnc("host", 5900)
    }

    /// A Mac's refusal says what it can know: after a verified SRP proof the
    /// password was right; type 30 cannot tell, so it gets the hint. Other
    /// servers, and a throttling status, keep their old wording.
    #[test]
    fn apple_refusals_say_what_they_mean() {
        // What macOS 26 sends with every refusal, whatever the cause.
        let mac = |status| Refusal {
            status,
            reason: "Authentication or authorization failure".into(),
        };
        for t in [SecurityType::AppleRsaSrp, SecurityType::AppleSrp] {
            let e = refine_apple_refusal(t, mac(1));
            assert!(matches!(e, VncError::AccessDenied(_)), "{t:?}");
            assert_eq!(e.user_message(), APPLE_ACCESS_DENIED);
            assert!(e.needs_user_action() && !e.is_transient());
        }
        let dh = refine_apple_refusal(SecurityType::AppleDh, mac(1));
        assert!(matches!(&dh, VncError::AuthFailed(r) if r == APPLE_DH_REFUSED));
        assert_eq!(
            dh.user_message(),
            "The password was not accepted. If the password is right, the Mac may need this \
             account allowed under Remote Management, Options."
        );
        let other = refine_apple_refusal(
            SecurityType::VncAuth,
            Refusal {
                status: 1,
                reason: "Authentication failed".into(),
            },
        );
        assert!(matches!(&other, VncError::AuthFailed(r) if r == "Authentication failed"));
        assert_eq!(other.user_message(), "The password was not accepted.");
        assert!(matches!(
            refine_apple_refusal(SecurityType::AppleSrp, mac(2)),
            VncError::AuthFailed(_)
        ));
    }

    /// A whole type 30 login that the Mac refuses comes back with the hint.
    #[tokio::test]
    async fn a_refused_type_30_login_carries_the_hint() {
        use num_bigint_dig::BigUint;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let p = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
              020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
              4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
              EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
            16,
        )
        .unwrap();
        let server_public = BigUint::from(2u32).modpow(&BigUint::from(0x1234_5678u32), &p);
        let (client, mut server) = tokio::io::duplex(8192);
        let mac = tokio::spawn(async move {
            server.write_all(&[0, 2, 0, 128]).await.unwrap();
            server.write_all(&p.to_bytes_be()).await.unwrap();
            let mut pubv = server_public.to_bytes_be();
            while pubv.len() < 128 {
                pubv.insert(0, 0);
            }
            server.write_all(&pubv).await.unwrap();
            let mut answer = vec![0u8; 128 + 128];
            server.read_exact(&mut answer).await.unwrap();
            // SecurityResult 1 and the reason macOS 26 gives, then it hangs up.
            let reason = b"Authentication or authorization failure";
            server.write_all(&1u32.to_be_bytes()).await.unwrap();
            server
                .write_all(&(reason.len() as u32).to_be_bytes())
                .await
                .unwrap();
            server.write_all(reason).await.unwrap();
            drop(server);
        });
        let mut o = opts();
        o.credentials = Credentials::user_pass("someone", "pw");
        o.vnc_mut().security_pref = Some("apple-dh".into());
        let version = ProtocolVersionInfo::parse("RFB 003.889\n").unwrap();
        let err =
            match authenticate_full(client, version, &[30], &o, &CredentialSource::none()).await {
                Err(e) => e,
                Ok(_) => panic!("the refused login succeeded"),
            };
        let _ = mac.await;
        assert!(
            matches!(&err, VncError::AuthFailed(r) if r == APPLE_DH_REFUSED),
            "{err:?}"
        );
        assert!(
            err.user_message().contains("Remote Management, Options"),
            "{}",
            err.user_message()
        );
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
        assert!(!o.vnc_options().unwrap().allow_insecure);
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
        o.vnc_mut().security_pref = Some("apple-dh".into());
        assert_eq!(
            select_security_type(&[19, 30], &o).unwrap(),
            SecurityType::AppleDh
        );
        // Not offered -> hard failure, no silent downgrade to VeNCrypt.
        assert!(select_security_type(&[19, 2], &o).is_err());
        // Pinning a type is the user's decision and is honoured as given,
        // including "None" against a server that offers something stronger.
        o.vnc_mut().security_pref = Some("none".into());
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
        o.vnc_mut().allow_insecure = true;
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
        o.vnc_mut().allow_insecure = true;
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
        o.vnc_mut().allow_insecure = true;
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
        o.vnc_mut().allow_insecure = true;
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
        let mut opts = ConnectOptions::vnc("h", 5900);
        opts.vnc_mut().allow_insecure = true;
        assert_eq!(
            select_security_type(&[2, 16], &opts).unwrap(),
            SecurityType::VncAuth
        );
    }

    /// ...but a server offering ONLY Tight must still work.
    #[test]
    fn still_selects_tight_when_it_is_the_only_option() {
        let mut opts = ConnectOptions::vnc("h", 5900);
        opts.vnc_mut().allow_insecure = true;
        assert_eq!(
            select_security_type(&[16], &opts).unwrap(),
            SecurityType::Tight
        );
    }
}
