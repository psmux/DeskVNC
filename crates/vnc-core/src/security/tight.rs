//! Security type 16, the TightVNC security wrapper.
//!
//! Like VeNCrypt, Tight negotiates *inside* the security type, but with
//! capability records rather than plain numbers:
//!
//! ```text
//! S->C  u32 tunnel_count
//! S->C  capability[tunnel_count]   (only when tunnel_count > 0)
//! C->S  u32 tunnel_code            (only when tunnel_count > 0; 0 = NOTUNNEL)
//! S->C  u32 auth_count
//! S->C  capability[auth_count]     (only when auth_count > 0)
//! C->S  u32 auth_code              (only when auth_count > 0)
//!       <the selected authentication runs>
//! ```
//!
//! A capability record is 16 bytes: `{ s32 code, u8 vendor[4], u8 signature[8] }`.
//!
//! We only ever select the no-tunnel option, Tight's "tunnels" were never
//! implemented by anything in the wild, and then delegate to the matching
//! authentication handler (typically code 2 = VNC auth, or 1 = none).

use vnc_transport::BoxedStream;

use super::prompt::CredentialSource;
use super::{read_bytes_max, read_u32, write_all, AuthOutcome, ProtocolVersionInfo};
use crate::error::{Result, VncError};
use crate::types::ConnectOptions;

/// No tunnelling, the only tunnel type anyone implements.
pub const TUNNEL_NOTUNNEL: i32 = 0;

/// Tight authentication capability codes.
pub mod auth_code {
    pub const NONE: i32 = 1;
    pub const VNC: i32 = 2;
    /// TightVNC "Unix login" (plain user/pass), not implemented.
    pub const UNIX_LOGIN: i32 = 129;
    /// TightVNC "external" authentication, not implemented.
    pub const EXTERNAL: i32 = 130;
}

/// A server can advertise a handful of capabilities; anything more is junk.
const MAX_CAPABILITIES: usize = 256;
const CAPABILITY_LEN: usize = 16;

/// One 16-byte capability record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub code: i32,
    pub vendor: [u8; 4],
    pub signature: [u8; 8],
}

impl Capability {
    pub fn parse_list(raw: &[u8]) -> Vec<Capability> {
        raw.chunks_exact(CAPABILITY_LEN)
            .map(|c| {
                let mut vendor = [0u8; 4];
                vendor.copy_from_slice(&c[4..8]);
                let mut signature = [0u8; 8];
                signature.copy_from_slice(&c[8..16]);
                Capability {
                    code: i32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                    vendor,
                    signature,
                }
            })
            .collect()
    }
}

/// Rank the authentication capabilities we can actually run.
///
/// VNC auth beats none, an authenticated cleartext session is still better
/// than an unauthenticated one.
pub fn select_auth_code(caps: &[Capability], opts: &ConnectOptions) -> Result<i32> {
    select_auth_code_with(caps, opts, false)
}

/// As [`select_auth_code`], but `can_prompt` says whether a missing password
/// can still be asked for interactively, in which case VNC auth is selectable
/// even with nothing stored.
pub fn select_auth_code_with(
    caps: &[Capability],
    opts: &ConnectOptions,
    can_prompt: bool,
) -> Result<i32> {
    let has = |code: i32| caps.iter().any(|c| c.code == code);

    if has(auth_code::VNC)
        && (opts.allow_insecure || opts.credentials.password.is_some() || can_prompt)
    {
        return Ok(auth_code::VNC);
    }
    if has(auth_code::VNC) {
        // No password to try: report it as a credentials prompt rather than
        // "unsupported", so the UI knows what to ask for.
        return Err(VncError::CredentialsRequired(
            "this server requires a VNC password".into(),
        ));
    }
    if has(auth_code::NONE) {
        // Taking the only capability on offer is not a downgrade. This used
        // to be refused unless `allow_insecure` was set, which no UI could
        // set, so a passwordless server was unreachable (issue #1); the
        // session's unencrypted badge is the honest signal instead.
        tracing::warn!("Tight server offers no authentication");
        return Ok(auth_code::NONE);
    }
    Err(VncError::NoSupportedSecurityType(
        caps.iter().map(|c| c.code.clamp(0, 255) as u8).collect(),
    ))
}

/// What the credential dialog calls Tight's inner VNC authentication.
const VNC_METHOD: &str = "TightVNC (VNC Authentication)";

pub(crate) async fn handshake(
    mut stream: BoxedStream,
    _version: ProtocolVersionInfo,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<AuthOutcome> {
    // --- tunnels -----------------------------------------------------------
    let tunnel_count = read_u32(&mut stream).await? as usize;
    if tunnel_count > MAX_CAPABILITIES {
        return Err(VncError::Protocol(format!(
            "Tight server advertised {tunnel_count} tunnel types"
        )));
    }
    if tunnel_count > 0 {
        let raw = read_bytes_max(
            &mut stream,
            tunnel_count * CAPABILITY_LEN,
            MAX_CAPABILITIES * CAPABILITY_LEN,
            "Tight tunnel capabilities",
        )
        .await?;
        let tunnels = Capability::parse_list(&raw);
        if !tunnels.iter().any(|c| c.code == TUNNEL_NOTUNNEL) {
            return Err(VncError::Protocol(
                "Tight server requires a tunnel type we do not implement".into(),
            ));
        }
        write_all(&mut stream, &TUNNEL_NOTUNNEL.to_be_bytes()).await?;
    }

    // --- authentication ----------------------------------------------------
    let auth_count = read_u32(&mut stream).await? as usize;
    if auth_count > MAX_CAPABILITIES {
        return Err(VncError::Protocol(format!(
            "Tight server advertised {auth_count} authentication types"
        )));
    }
    if auth_count == 0 {
        // No authentication at all, the same exposure as security type 1,
        // and allowed for the same reason: the server offered nothing else.
        tracing::warn!("Tight server requires no authentication");
        return Ok(AuthOutcome::auto(stream));
    }

    let raw = read_bytes_max(
        &mut stream,
        auth_count * CAPABILITY_LEN,
        MAX_CAPABILITIES * CAPABILITY_LEN,
        "Tight authentication capabilities",
    )
    .await?;
    let caps = Capability::parse_list(&raw);
    tracing::debug!(codes = ?caps.iter().map(|c| c.code).collect::<Vec<_>>(), "tight auth capabilities");

    let chosen = select_auth_code_with(&caps, opts, creds.can_prompt())?;
    write_all(&mut stream, &chosen.to_be_bytes()).await?;

    let outcome = match chosen {
        auth_code::NONE => super::none::handshake(stream, opts).await?,
        auth_code::VNC => super::vnc_auth::handshake_named(stream, opts, creds, VNC_METHOD).await?,
        other => {
            return Err(VncError::Protocol(format!(
                "Tight authentication type {other} is not implemented"
            )))
        }
    };

    // Tight always reports a SecurityResult, even for the "none" sub-type.
    Ok(AuthOutcome::auto(outcome.stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Credentials;

    fn cap(code: i32) -> Capability {
        Capability {
            code,
            vendor: *b"TGHT",
            signature: *b"NOTUNNEL",
        }
    }

    fn opts_with_password() -> ConnectOptions {
        let mut o = ConnectOptions::new("h", 5900);
        o.credentials = Credentials::password("pw");
        o
    }

    #[test]
    fn parses_capability_records() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&2i32.to_be_bytes());
        raw.extend_from_slice(b"STDV");
        raw.extend_from_slice(b"VNCAUTH_");
        // A trailing partial record is ignored, not fatal.
        raw.extend_from_slice(&[0u8; 3]);

        let caps = Capability::parse_list(&raw);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].code, 2);
        assert_eq!(&caps[0].vendor, b"STDV");
        assert_eq!(&caps[0].signature, b"VNCAUTH_");
    }

    #[test]
    fn prefers_vnc_auth_over_none() {
        let caps = [cap(auth_code::NONE), cap(auth_code::VNC)];
        assert_eq!(
            select_auth_code(&caps, &opts_with_password()).unwrap(),
            auth_code::VNC
        );
    }

    #[test]
    fn none_is_accepted_when_it_is_the_only_capability() {
        // Issue #1: the Tight path refused a no-auth server the same way the
        // plain security-type path did, behind an opt-in nothing could set.
        let caps = [cap(auth_code::NONE)];
        assert_eq!(
            select_auth_code(&caps, &ConnectOptions::new("h", 5900)).unwrap(),
            auth_code::NONE
        );
    }

    #[test]
    fn vnc_auth_without_a_password_prompts() {
        let caps = [cap(auth_code::VNC)];
        assert!(matches!(
            select_auth_code(&caps, &ConnectOptions::new("h", 5900)),
            Err(VncError::CredentialsRequired(_))
        ));
    }

    #[test]
    fn vnc_auth_is_selectable_when_we_can_ask_the_user() {
        let caps = [cap(auth_code::VNC)];
        assert_eq!(
            select_auth_code_with(&caps, &ConnectOptions::new("h", 5900), true).unwrap(),
            auth_code::VNC
        );
    }

    #[test]
    fn unimplemented_codes_are_rejected() {
        let caps = [cap(auth_code::UNIX_LOGIN), cap(auth_code::EXTERNAL)];
        assert!(select_auth_code(&caps, &opts_with_password()).is_err());
    }

    #[tokio::test]
    async fn runs_the_no_tunnel_vnc_auth_path() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            // one tunnel: NOTUNNEL
            server.write_all(&1u32.to_be_bytes()).await.unwrap();
            server.write_all(&0i32.to_be_bytes()).await.unwrap();
            server.write_all(b"TGHT").await.unwrap();
            server.write_all(b"NOTUNNEL").await.unwrap();
            let mut chosen_tunnel = [0u8; 4];
            server.read_exact(&mut chosen_tunnel).await.unwrap();
            assert_eq!(i32::from_be_bytes(chosen_tunnel), 0);

            // one auth type: VNC auth
            server.write_all(&1u32.to_be_bytes()).await.unwrap();
            server.write_all(&2i32.to_be_bytes()).await.unwrap();
            server.write_all(b"STDV").await.unwrap();
            server.write_all(b"VNCAUTH_").await.unwrap();
            let mut chosen_auth = [0u8; 4];
            server.read_exact(&mut chosen_auth).await.unwrap();

            server.write_all(&[0x11u8; 16]).await.unwrap(); // challenge
            let mut response = [0u8; 16];
            server.read_exact(&mut response).await.unwrap();
            (i32::from_be_bytes(chosen_auth), response)
        });

        let s: BoxedStream = Box::pin(client);
        handshake(
            s,
            ProtocolVersionInfo::new(3, 8),
            &opts_with_password(),
            &CredentialSource::none(),
        )
        .await
        .unwrap();

        let (code, response) = task.await.unwrap();
        assert_eq!(code, auth_code::VNC);
        assert_eq!(
            response,
            super::super::vnc_auth::respond_to_challenge("pw", &[0x11u8; 16])
        );
    }

    #[tokio::test]
    async fn rejects_an_absurd_capability_count() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(64);
        server.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let s: BoxedStream = Box::pin(client);
        assert!(matches!(
            handshake(
                s,
                ProtocolVersionInfo::new(3, 8),
                &opts_with_password(),
                &CredentialSource::none()
            )
            .await,
            Err(VncError::Protocol(_))
        ));
    }
}
