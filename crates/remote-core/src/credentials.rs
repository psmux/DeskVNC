//! Credentials and the interactive credential request.
//!
//! Moved out of `vnc-core/src/types.rs` (PRDRDP/02 §2.1, §6). The one change
//! is the `domain` field, which VNC never sets and RDP puts in
//! TS_INFO_PACKET `Domain` (MS-RDPBCGR 2.2.1.11.1.1) and in the CredSSP
//! identity (MS-CSSP).

use serde::{Deserialize, Serialize};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
    /// NetBIOS or DNS domain for the logon. VNC never sets it.
    pub domain: Option<String>,
}

impl Credentials {
    pub fn password(pw: impl Into<String>) -> Self {
        Self {
            username: None,
            password: Some(pw.into()),
            domain: None,
        }
    }
    pub fn user_pass(user: impl Into<String>, pw: impl Into<String>) -> Self {
        Self {
            username: Some(user.into()),
            password: Some(pw.into()),
            domain: None,
        }
    }
    pub fn domain_user_pass(
        domain: impl Into<String>,
        user: impl Into<String>,
        pw: impl Into<String>,
    ) -> Self {
        Self {
            username: Some(user.into()),
            password: Some(pw.into()),
            domain: Some(domain.into()),
        }
    }
}

// Never leak secrets into logs.
//
// The domain is redacted with the other two. It is not a secret the way a
// password is, but it is usually the customer's internal AD name, logs get
// pasted into issue trackers, and "present or absent" is all a support reader
// needs (PRDRDP/02 §6.2).
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username.as_deref().map(|_| "***"))
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("domain", &self.domain.as_deref().map(|_| "***"))
            .finish()
    }
}

/// What a security type needs from the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialKind {
    /// Classic VNC Authentication, VeNCrypt `*Vnc` subtypes, RA2 subtype 2.
    PasswordOnly,
    /// VeNCrypt `*Plain`, Apple DH (30), MSLogonII (113), RA2 subtype 1.
    UsernameAndPassword,
}

/// A pending interactive credential request raised from inside the security
/// handshake (PRD/10 §3.4).
///
/// The session emits [`SessionEvent::CredentialsRequired`] carrying this, then
/// waits for [`ClientCommand::ProvideCredentials`] or
/// [`ClientCommand::CancelCredentials`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    /// Human-readable method name, e.g. "VNC Authentication",
    /// "VeNCrypt (X509Plain)", "Apple Remote Desktop".
    pub method: String,
    pub kind: CredentialKind,
    /// 1-based. Greater than 1 means a previous attempt was rejected.
    pub attempt: u32,
    /// Why the previous attempt failed, when there was one.
    pub error: Option<String>,
    /// True for DES-based methods, which silently truncate to 8 characters.
    /// The UI must warn (PRD/10 §3.4).
    pub truncates_password: bool,
    /// Prefill for the username field (saved profile value, or the OS user).
    pub username_hint: Option<String>,
}
