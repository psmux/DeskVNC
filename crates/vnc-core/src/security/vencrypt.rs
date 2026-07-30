//! Security type 19, VeNCrypt.
//!
//! VeNCrypt is a wrapper: it negotiates a *subtype* which decides whether the
//! stream is wrapped in TLS and what authentication runs inside it. This is the
//! main modern path (TigerVNC, QEMU/libvirt, wayvnc, x11vnc, UltraVNC ≥ 1.4.4).
//!
//! Wire sequence (PRD/10 §1):
//!
//! ```text
//! S->C  u8 major, u8 minor
//! C->S  u8 major, u8 minor        (the version we support; 0.0 aborts)
//! S->C  u8 ack                    (0 = OK)
//! S->C  u8 count, subtype list    (u32 each in 0.2, u8 each in 0.1)
//! C->S  chosen subtype            (u32 in 0.2, u8 in 0.1)
//! S->C  u8 ack                    (1 = proceed), TLS*/X509* only
//!       <TLS handshake>, TLS*/X509* only
//!       <inner authentication: None | VncAuth | Plain>
//! S->C  u32 SecurityResult
//! ```
//!
//! ## rustls and the anonymous-TLS subtypes
//!
//! The `TLS*` (non-X509) subtypes use anonymous Diffie-Hellman ciphersuites
//! (`ADH`/`AECDH`): the server presents no certificate at all. rustls does not
//! implement anonymous ciphersuites and has stated it will not, so those
//! subtypes cannot be completed with our TLS stack. We still negotiate them, //! the subtype list is parsed and ranked exactly as the PRD specifies, but if
//! the *only* usable options are anonymous-TLS ones we stop with a clear error
//! telling the operator to enable an X509 subtype. (An `openssl`/`native-tls`
//! fallback behind a feature flag is the escape hatch the PRD contemplates;
//! it is not built.)

use vnc_transport::{BoxedStream, TrustDecision};

use super::prompt::CredentialSource;
use super::{read_bytes, read_u8, write_all, AuthOutcome, ResultMode, ServerIdentity};
use crate::error::{Result, VncError};
use crate::types::{ConnectOptions, CredentialKind, PinScheme};

// ---------------------------------------------------------------------------
// Subtypes
// ---------------------------------------------------------------------------

/// VeNCrypt subtypes we can reason about. The two numbering schemes map onto
/// the same set, v0.2 uses U32 values 256..=262, v0.1 used U8 values 19..=25.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VeNCryptSubtype {
    /// 256 / 19, username+password in the clear. No TLS at all.
    Plain,
    /// 257 / 20, anonymous TLS, no inner auth.
    TlsNone,
    /// 258 / 21, anonymous TLS + VNC auth.
    TlsVnc,
    /// 259 / 22, anonymous TLS + plain user/pass.
    TlsPlain,
    /// 260 / 23, X.509 TLS, no inner auth.
    X509None,
    /// 261 / 24, X.509 TLS + VNC auth.
    X509Vnc,
    /// 262 / 25, X.509 TLS + plain user/pass.
    X509Plain,
}

impl VeNCryptSubtype {
    /// v0.2 numbering.
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            256 => Self::Plain,
            257 => Self::TlsNone,
            258 => Self::TlsVnc,
            259 => Self::TlsPlain,
            260 => Self::X509None,
            261 => Self::X509Vnc,
            262 => Self::X509Plain,
            // 263/264 (SASL) and 265..=267 (Ident) are recognised as valid but
            // unimplemented; treat as unknown so they are simply skipped.
            _ => return None,
        })
    }

    /// v0.1 (legacy) numbering.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            19 => Self::Plain,
            20 => Self::TlsNone,
            21 => Self::TlsVnc,
            22 => Self::TlsPlain,
            23 => Self::X509None,
            24 => Self::X509Vnc,
            25 => Self::X509Plain,
            _ => return None,
        })
    }

    pub fn to_u32(self) -> u32 {
        match self {
            Self::Plain => 256,
            Self::TlsNone => 257,
            Self::TlsVnc => 258,
            Self::TlsPlain => 259,
            Self::X509None => 260,
            Self::X509Vnc => 261,
            Self::X509Plain => 262,
        }
    }

    pub fn to_u8(self) -> u8 {
        (self.to_u32() - 256) as u8 + 19
    }

    /// Does the stream get wrapped in TLS?
    pub fn uses_tls(self) -> bool {
        !matches!(self, Self::Plain)
    }

    /// Is that TLS certificate-authenticated (as opposed to anonymous DH)?
    pub fn uses_x509(self) -> bool {
        matches!(self, Self::X509None | Self::X509Vnc | Self::X509Plain)
    }

    /// True for the anonymous-DH subtypes rustls cannot complete.
    pub fn is_anonymous_tls(self) -> bool {
        matches!(self, Self::TlsNone | Self::TlsVnc | Self::TlsPlain)
    }

    /// Sends the password in the clear over an unencrypted channel.
    pub fn is_cleartext(self) -> bool {
        matches!(self, Self::Plain)
    }

    /// Uses the legacy 8-character DES auth, the UI shows a truncation warning.
    pub fn truncates_password(self) -> bool {
        matches!(self, Self::TlsVnc | Self::X509Vnc)
    }

    /// What the inner authentication needs from the user, if anything.
    ///
    /// The `*None` subtypes authenticate nothing, the `*Vnc` ones run the
    /// legacy DES password exchange, and the `*Plain` ones send a user name and
    /// password (over TLS, except for bare `Plain`).
    pub fn credential_kind(self) -> Option<CredentialKind> {
        match self {
            Self::TlsNone | Self::X509None => None,
            Self::TlsVnc | Self::X509Vnc => Some(CredentialKind::PasswordOnly),
            Self::Plain | Self::TlsPlain | Self::X509Plain => {
                Some(CredentialKind::UsernameAndPassword)
            }
        }
    }

    /// The name the credential dialog shows, e.g. `VeNCrypt (X509Plain)`.
    pub fn method_name(self) -> String {
        format!("VeNCrypt ({self:?})")
    }

    /// Preference rank, higher = stronger (PRD/10 §2).
    pub fn rank(self) -> u8 {
        match self {
            Self::X509Plain => 6,
            Self::X509Vnc => 5,
            Self::X509None => 4,
            Self::TlsPlain => 3,
            Self::TlsVnc => 2,
            Self::TlsNone => 1,
            Self::Plain => 0,
        }
    }
}

const ANON_TLS_MESSAGE: &str = "anonymous TLS (VeNCrypt TLS* subtypes) is not supported; \
                                ask the server admin to enable an X509 subtype";

/// Choose the strongest subtype we can actually complete.
///
/// Anonymous-TLS subtypes are ranked but never selected (see the module docs);
/// `Plain` is gated behind the unencrypted-connection opt-in because it puts
/// the password on the wire in the clear.
pub fn select_subtype(
    offered: &[VeNCryptSubtype],
    opts: &ConnectOptions,
) -> Result<VeNCryptSubtype> {
    if offered.is_empty() {
        return Err(VncError::Protocol(
            "server offered no VeNCrypt subtypes".into(),
        ));
    }

    let mut ranked: Vec<VeNCryptSubtype> = offered.to_vec();
    ranked.sort_by(|a, b| b.rank().cmp(&a.rank()).then_with(|| a.cmp(b)));
    ranked.dedup();

    let usable = ranked.iter().copied().find(|s| {
        if s.is_anonymous_tls() {
            return false;
        }
        if s.is_cleartext() && !opts.allow_insecure {
            return false;
        }
        true
    });

    if let Some(s) = usable {
        return Ok(s);
    }

    if ranked.iter().any(|s| s.is_anonymous_tls()) {
        return Err(VncError::Tls(ANON_TLS_MESSAGE.into()));
    }
    if ranked.iter().any(|s| s.is_cleartext()) {
        return Err(VncError::Other(
            "this server only offers VeNCrypt Plain, which sends the password unencrypted; \
             enable \"Allow an unencrypted connection\" for this host to continue"
                .into(),
        ));
    }
    Err(VncError::Protocol("no usable VeNCrypt subtype".into()))
}

/// Parse a raw subtype list under either numbering scheme, dropping values we
/// do not recognise (SASL, Ident, vendor extensions).
pub fn parse_subtypes(raw: &[u8], four_byte: bool) -> Vec<VeNCryptSubtype> {
    if four_byte {
        raw.chunks_exact(4)
            .filter_map(|c| VeNCryptSubtype::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
            .collect()
    } else {
        raw.iter()
            .filter_map(|b| VeNCryptSubtype::from_u8(*b))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// The most subtypes a sane server advertises; the count is a u8 anyway.
const MAX_SUBTYPES: usize = 255;

pub(crate) async fn handshake(
    mut stream: BoxedStream,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<AuthOutcome> {
    // --- version -----------------------------------------------------------
    let server_major = read_u8(&mut stream).await?;
    let server_minor = read_u8(&mut stream).await?;

    let (major, minor) = match (server_major, server_minor) {
        (0, m) if m >= 2 => (0u8, 2u8),
        (0, 1) => (0, 1),
        other => {
            // Tell the server we are giving up, then report it.
            let _ = write_all(&mut stream, &[0, 0]).await;
            return Err(VncError::Protocol(format!(
                "unsupported VeNCrypt version {}.{}",
                other.0, other.1
            )));
        }
    };
    write_all(&mut stream, &[major, minor]).await?;
    tracing::debug!(server = ?(server_major, server_minor), chosen = ?(major, minor), "vencrypt version");

    let ack = read_u8(&mut stream).await?;
    if ack != 0 {
        return Err(VncError::Protocol(format!(
            "server rejected VeNCrypt version {major}.{minor} (ack {ack})"
        )));
    }

    // --- subtype list ------------------------------------------------------
    let four_byte = minor >= 2;
    let count = read_u8(&mut stream).await? as usize;
    if count == 0 {
        return Err(VncError::Protocol(
            "server advertised no VeNCrypt subtypes (it may have rejected our version)".into(),
        ));
    }
    let width = if four_byte { 4 } else { 1 };
    let raw = read_bytes(
        &mut stream,
        count.min(MAX_SUBTYPES) * width,
        "VeNCrypt subtype list",
    )
    .await?;
    let offered = parse_subtypes(&raw, four_byte);
    tracing::debug!(?offered, "vencrypt subtypes offered");

    let chosen = select_subtype(&offered, opts)?;
    tracing::info!(?chosen, "vencrypt subtype selected");

    if four_byte {
        write_all(&mut stream, &chosen.to_u32().to_be_bytes()).await?;
    } else {
        write_all(&mut stream, &[chosen.to_u8()]).await?;
    }

    // --- TLS ---------------------------------------------------------------
    let mut trust = None;
    if chosen.uses_tls() {
        let proceed = read_u8(&mut stream).await?;
        if proceed != 1 {
            return Err(VncError::Protocol(format!(
                "server refused VeNCrypt subtype {:?} (ack {proceed})",
                chosen
            )));
        }

        if !chosen.uses_x509() {
            // Unreachable via `select_subtype`, but keep the guard: never start
            // a TLS handshake we know cannot authenticate the peer.
            return Err(VncError::Tls(ANON_TLS_MESSAGE.into()));
        }

        // Only the TLS pin is offered to the verifier. An RA2 pin for the same
        // endpoint describes a different key entirely, and comparing it here
        // would abort an honest connection as a forged one.
        let (upgraded, decision) = vnc_transport::tls::upgrade(
            stream,
            &opts.host,
            opts.cert_pins.for_scheme(PinScheme::Tls),
        )
        .await?;
        match &decision {
            TrustDecision::VerifiedByCa => tracing::info!("server certificate verified by CA"),
            TrustDecision::PinnedMatch => tracing::info!("server certificate matches stored pin"),
            TrustDecision::Unknown { fingerprint, .. } => {
                // First contact. The session layer surfaces the TOFU prompt;
                // see `authenticate_with_trust`.
                tracing::warn!(%fingerprint, "server certificate is not yet trusted (TOFU prompt required)");
            }
            // `tls::upgrade` turns a mismatch into an error before we get here.
            TrustDecision::Changed { .. } => unreachable!("mismatch is reported as an error"),
        }
        trust = Some(ServerIdentity {
            scheme: PinScheme::Tls,
            decision,
        });
        stream = upgraded;
    }

    // --- inner authentication ---------------------------------------------
    let method = chosen.method_name();
    let stream = match chosen {
        VeNCryptSubtype::TlsNone | VeNCryptSubtype::X509None => stream,
        VeNCryptSubtype::TlsVnc | VeNCryptSubtype::X509Vnc => {
            super::vnc_auth::handshake_named(stream, opts, creds, &method)
                .await?
                .stream
        }
        VeNCryptSubtype::Plain | VeNCryptSubtype::TlsPlain | VeNCryptSubtype::X509Plain => {
            plain_auth(stream, opts, creds, &method).await?
        }
    };

    // VeNCrypt always reports a SecurityResult, including for the *None
    // subtypes and on RFB 3.7.
    Ok(AuthOutcome {
        stream,
        result_mode: ResultMode::Always,
        trust,
    })
}

/// The `Plain` inner authentication: two u32 lengths, then the two UTF-8
/// strings back to back.
async fn plain_auth(
    mut stream: BoxedStream,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
    method: &str,
) -> Result<BoxedStream> {
    let supplied = creds
        .obtain(method, CredentialKind::UsernameAndPassword, false, opts)
        .await?;
    let user = supplied.username.unwrap_or_default();
    let password = supplied.password.unwrap_or_default();
    if user.is_empty() {
        return Err(VncError::CredentialsRequired(
            "this server requires a username and password".into(),
        ));
    }

    let mut msg = Vec::with_capacity(8 + user.len() + password.len());
    msg.extend_from_slice(&(user.len() as u32).to_be_bytes());
    msg.extend_from_slice(&(password.len() as u32).to_be_bytes());
    msg.extend_from_slice(user.as_bytes());
    msg.extend_from_slice(password.as_bytes());

    let r = write_all(&mut stream, &msg).await;
    // The buffer held the password; don't leave it lying in the allocator.
    zeroize::Zeroize::zeroize(&mut msg);
    r?;

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(allow_insecure: bool) -> ConnectOptions {
        let mut o = ConnectOptions::new("h", 5900);
        o.allow_insecure = allow_insecure;
        o
    }

    #[test]
    fn numbering_schemes_agree() {
        for v in 256u32..=262 {
            let s = VeNCryptSubtype::from_u32(v).unwrap();
            assert_eq!(s.to_u32(), v);
            assert_eq!(VeNCryptSubtype::from_u8(s.to_u8()), Some(s));
        }
        assert_eq!(VeNCryptSubtype::from_u8(19), Some(VeNCryptSubtype::Plain));
        assert_eq!(
            VeNCryptSubtype::from_u8(25),
            Some(VeNCryptSubtype::X509Plain)
        );
        assert_eq!(VeNCryptSubtype::X509Plain.to_u8(), 25);
        // SASL / Ident / junk are not recognised.
        assert_eq!(VeNCryptSubtype::from_u32(263), None);
        assert_eq!(VeNCryptSubtype::from_u32(0), None);
        assert_eq!(VeNCryptSubtype::from_u8(2), None);
    }

    #[test]
    fn parses_v02_u32_list() {
        let raw = [
            0, 0, 1, 0, // 256 Plain
            0, 0, 1, 6, // 262 X509Plain
            0, 0, 1, 7, // 263 TLSSASL -> dropped
        ];
        assert_eq!(
            parse_subtypes(&raw, true),
            vec![VeNCryptSubtype::Plain, VeNCryptSubtype::X509Plain]
        );
    }

    #[test]
    fn parses_v01_u8_list() {
        let raw = [19u8, 24, 2];
        assert_eq!(
            parse_subtypes(&raw, false),
            vec![VeNCryptSubtype::Plain, VeNCryptSubtype::X509Vnc]
        );
    }

    #[test]
    fn selects_strongest_x509_v02() {
        let offered = parse_subtypes(
            &[
                0, 0, 1, 4, /*260*/ 0, 0, 1, 5, /*261*/ 0, 0, 1, 6, /*262*/
            ],
            true,
        );
        assert_eq!(
            select_subtype(&offered, &opts(false)).unwrap(),
            VeNCryptSubtype::X509Plain
        );
    }

    #[test]
    fn selects_strongest_x509_v01() {
        let offered = parse_subtypes(&[23u8, 24, 20], false);
        assert_eq!(
            select_subtype(&offered, &opts(false)).unwrap(),
            VeNCryptSubtype::X509Vnc
        );
    }

    #[test]
    fn x509_beats_anonymous_tls() {
        let offered = parse_subtypes(&[22u8 /*TLSPlain*/, 23 /*X509None*/], false);
        assert_eq!(
            select_subtype(&offered, &opts(false)).unwrap(),
            VeNCryptSubtype::X509None
        );
    }

    #[test]
    fn anonymous_tls_only_is_a_clear_error() {
        let offered = parse_subtypes(&[20u8, 21, 22], false);
        match select_subtype(&offered, &opts(true)) {
            Err(VncError::Tls(m)) => assert!(m.contains("anonymous TLS")),
            other => panic!("expected a TLS error, got {other:?}"),
        }
    }

    #[test]
    fn plain_needs_the_insecure_optin() {
        let offered = vec![VeNCryptSubtype::Plain];
        assert!(select_subtype(&offered, &opts(false)).is_err());
        assert_eq!(
            select_subtype(&offered, &opts(true)).unwrap(),
            VeNCryptSubtype::Plain
        );
    }

    #[test]
    fn empty_list_is_rejected() {
        assert!(select_subtype(&[], &opts(true)).is_err());
    }

    #[test]
    fn classification_flags() {
        assert!(VeNCryptSubtype::X509Vnc.uses_tls());
        assert!(VeNCryptSubtype::X509Vnc.uses_x509());
        assert!(!VeNCryptSubtype::Plain.uses_tls());
        assert!(VeNCryptSubtype::TlsVnc.is_anonymous_tls());
        assert!(!VeNCryptSubtype::X509Vnc.is_anonymous_tls());
        assert!(VeNCryptSubtype::X509Vnc.truncates_password());
        assert!(!VeNCryptSubtype::X509Plain.truncates_password());
    }

    #[test]
    fn credential_kinds_and_method_names_match_the_dialog_contract() {
        use CredentialKind::*;
        assert_eq!(VeNCryptSubtype::X509None.credential_kind(), None);
        assert_eq!(VeNCryptSubtype::TlsNone.credential_kind(), None);
        assert_eq!(
            VeNCryptSubtype::X509Vnc.credential_kind(),
            Some(PasswordOnly)
        );
        assert_eq!(
            VeNCryptSubtype::TlsVnc.credential_kind(),
            Some(PasswordOnly)
        );
        assert_eq!(
            VeNCryptSubtype::X509Plain.credential_kind(),
            Some(UsernameAndPassword)
        );
        assert_eq!(
            VeNCryptSubtype::Plain.credential_kind(),
            Some(UsernameAndPassword)
        );
        assert_eq!(
            VeNCryptSubtype::X509Plain.method_name(),
            "VeNCrypt (X509Plain)"
        );
        assert_eq!(VeNCryptSubtype::X509Vnc.method_name(), "VeNCrypt (X509Vnc)");
    }

    #[tokio::test]
    async fn negotiates_v02_and_rejects_anon_only_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            server.write_all(&[0, 2]).await.unwrap(); // version
            let mut echoed = [0u8; 2];
            server.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, [0, 2]);
            server.write_all(&[0]).await.unwrap(); // ack
            server.write_all(&[1]).await.unwrap(); // one subtype
            server.write_all(&257u32.to_be_bytes()).await.unwrap(); // TLSNone
        });

        let s: BoxedStream = Box::pin(client);
        match handshake(s, &opts(true), &CredentialSource::none()).await {
            Err(VncError::Tls(m)) => assert!(m.contains("anonymous TLS")),
            other => panic!("expected an anon-TLS error, got {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn falls_back_to_v01_numbering() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            server.write_all(&[0, 1]).await.unwrap();
            let mut echoed = [0u8; 2];
            server.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, [0, 1], "must echo 0.1 for a 0.1 server");
            server.write_all(&[0]).await.unwrap();
            server.write_all(&[2, 19, 21]).await.unwrap(); // Plain, TLSVnc
            let mut chosen = [0u8; 1];
            server.read_exact(&mut chosen).await.unwrap();
            chosen[0]
        });

        let s: BoxedStream = Box::pin(client);
        // allow_insecure lets Plain through; TLSVnc is unusable.
        let _ = handshake(s, &opts(true), &CredentialSource::none()).await;
        assert_eq!(task.await.unwrap(), 19, "must answer in the u8 numbering");
    }

    #[tokio::test]
    async fn rejects_unknown_vencrypt_version() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(64);
        server.write_all(&[1, 0]).await.unwrap();
        let s: BoxedStream = Box::pin(client);
        assert!(matches!(
            handshake(s, &opts(true), &CredentialSource::none()).await,
            Err(VncError::Protocol(_))
        ));
    }
}
