//! The RDSTLS sign in, client side (MS-RDPBCGR 5.4.5.3).
//!
//! Runs inside the TLS tunnel when the server selected `PROTOCOL_RDSTLS`,
//! which this client offers only on the connection that follows a Server
//! Redirection carrying a password cookie. GNOME Remote Login is the server
//! that needs it today: once the user signs in at the remote login screen,
//! gnome-remote-desktop redirects the client to the same address with a
//! routing token, a one time user name and a password cookie, and the
//! connection that presents them has to authenticate with RDSTLS.
//!
//! The exchange is three fixed shape PDUs, see [`rdp_pdu::rdstls`]. What
//! this module adds is the order, the timeouts and the error a user sees.

use rdp_pdu::io::{Decode, Encode, Writer};
use rdp_pdu::rdstls::{
    result_code, RdstlsAuthResponse, RdstlsCapabilities, RdstlsPasswordRequest, AUTH_RESPONSE_LEN,
    CAPABILITIES_LEN,
};
use rdp_pdu::{Reader, SecretBytes};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::error::{ConnectStage, RdpError, Result};
use crate::transport::framer::{Expect, Framer};
use crate::transport::{with_timeout, X224_TIMEOUT};

/// What a Server Redirection handed over for the next connection's RDSTLS
/// sign in.
///
/// Scoped to one attempt, like the routing token: it is taken out of
/// [`crate::session::Continuity`] by the attempt that presents it and is gone
/// afterwards, so a reconnect after a dropped link goes back to the address
/// and the credentials of the profile.
#[derive(Clone)]
pub struct RdstlsCredentials {
    /// `RedirectionGuid` from the redirection, unchanged. Empty when the
    /// redirection carried none.
    pub redirection_guid: Vec<u8>,
    /// The user name to present: the redirection's, else the profile's.
    pub username: String,
    /// The domain to present, often empty.
    pub domain: String,
    /// The redirection's `Password` field, byte for byte. With
    /// `LB_PASSWORD_IS_PK_ENCRYPTED` set it is opaque to us.
    pub password: Zeroizing<Vec<u8>>,
}

/// Neither the cookie nor the GUID reaches a log line.
impl std::fmt::Debug for RdstlsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdstlsCredentials")
            .field("redirection_guid_len", &self.redirection_guid.len())
            .field("username", &"***")
            .field("password_len", &self.password.len())
            .finish()
    }
}

/// Run the three PDU exchange.
///
/// # Errors
///
/// [`RdpError::Timeout`] against [`ConnectStage::Rdstls`] when the server
/// goes quiet, [`RdpError::Pdu`] for a PDU of the wrong shape,
/// [`RdpError::Protocol`] for a server that does not speak version 1, and
/// [`RdpError::AuthFailed`] when the server refused the credentials.
pub async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    framer: &mut Framer<S>,
    creds: &RdstlsCredentials,
) -> Result<()> {
    let caps = with_timeout(
        ConnectStage::Rdstls,
        X224_TIMEOUT,
        framer.read_expect(Expect::Exact(CAPABILITIES_LEN)),
    )
    .await?;
    let caps = RdstlsCapabilities::decode(&mut Reader::new(&caps))?;
    if !caps.supports_version_1() {
        return Err(RdpError::Protocol(format!(
            "the server's RDSTLS versions ({:#06x}) do not include version 1 (MS-RDPBCGR 2.2.17.1)",
            caps.supported_versions
        )));
    }

    let request = RdstlsPasswordRequest {
        redirection_guid: creds.redirection_guid.clone(),
        username: creds.username.clone(),
        domain: creds.domain.clone(),
        password: SecretBytes::new(creds.password.to_vec()),
    };
    let mut buf = Zeroizing::new(Vec::with_capacity(request.size()));
    request.encode_checked(&mut Writer::new(&mut buf))?;
    tracing::debug!(
        guid_len = request.redirection_guid.len(),
        password_len = creds.password.len(),
        "sending the rdstls authentication request"
    );
    framer.write_pdu(&buf).await?;

    let rsp = with_timeout(
        ConnectStage::Rdstls,
        X224_TIMEOUT,
        framer.read_expect(Expect::Exact(AUTH_RESPONSE_LEN)),
    )
    .await?;
    let rsp = RdstlsAuthResponse::decode(&mut Reader::new(&rsp))?;
    match rsp.result_code {
        result_code::SUCCESS => {
            tracing::info!("rdstls authentication succeeded");
            Ok(())
        }
        code => Err(RdpError::AuthFailed(format!(
            "the server refused the sign in it handed this session over with: {} \
             (RDSTLS result {code:#010x}, MS-RDPBCGR 2.2.17.3)",
            result_sentence(code)
        ))),
    }
}

/// A sentence for an RDSTLS result code.
fn result_sentence(code: u32) -> &'static str {
    match code {
        result_code::ACCESS_DENIED => "access denied",
        result_code::LOGON_FAILURE => "the one time credentials did not match",
        result_code::INVALID_LOGON_HOURS => "the account may not sign in at this time",
        result_code::PASSWORD_EXPIRED => "the password has expired",
        result_code::ACCOUNT_DISABLED => "the account is disabled",
        result_code::PASSWORD_MUST_CHANGE => "the password must be changed",
        result_code::ACCOUNT_LOCKED_OUT => "the account is locked out",
        _ => "an unrecognised result",
    }
}
