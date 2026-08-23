//! Who we are, and the three ways Windows spells it.
//!
//! PRDRDP/14 §6.1 owns the SPN, §6.2 the username and domain splitting. Both
//! are pure functions resolved once, before any state machine is built, which
//! is what lets the whole unit suite run with no network.

use zeroize::Zeroizing;

use crate::error::AuthError;

/// `"TERMSRV/<name>"`, the RDP service principal name (MS-KILE 3.1.5.11,
/// MS-RDPBCGR 5.4).
///
/// `server_name` is the name the user typed or the name from the stored
/// profile (R26), never the dial address: over an SSH tunnel the dial address
/// is `localhost` and an SPN of `TERMSRV/localhost` matches nothing.
///
/// The service class is `TERMSRV`, uppercase. The host part is used as
/// supplied, not lowercased, not uppercased and not resolved to an FQDN.
/// Kerberos SPN matching is case insensitive on the class and, in Active
/// Directory, on the host, so the case does not matter. Resolving would
/// matter, and would be wrong: the name the user typed is the name the
/// certificate was checked against and the name the pin is keyed on. One
/// name, three uses, decided once at connect time.
///
/// The trailing dot of a fully qualified DNS name is stripped, because
/// `TERMSRV/host.example.com.` matches nothing.
#[must_use]
pub fn service_principal_name(server_name: &str) -> String {
    format!("TERMSRV/{}", server_name.trim_end_matches('.'))
}

/// Split `DOMAIN\user`, `user@domain.example.com` or a bare `user` into
/// (user, domain) as MS-NLMP 3.3.2's `User` and `UserDom` arguments want them
/// (PRDRDP/14 §6.2).
///
/// A user principal name goes in the user field whole, with an empty domain.
/// A UPN is already fully qualified, and splitting it into `user` and
/// `domain.example.com` produces `NTOWFv2("user", "domain.example.com")`,
/// which is not what the domain controller computes. Windows itself passes a
/// UPN through whole.
///
/// A bare name means a local account on the remote computer: with an empty
/// domain the server authenticates against its own SAM database. A user who
/// meant a domain account has to say which domain, and the credential prompt
/// has a separate domain field for exactly that (R13).
#[must_use]
pub fn split_qualified_username(raw: &str) -> (String, String) {
    if let Some((dom, user)) = raw.split_once('\\') {
        // Down-level logon name: DOMAIN\user.
        (user.to_owned(), dom.to_owned())
    } else {
        // A user principal name (user@domain) or a bare local account name.
        // Both pass through whole with no domain.
        (raw.to_owned(), String::new())
    }
}

/// The three forms, resolved once, before any exchange starts.
///
/// The password is `Zeroizing`, so it is overwritten when the `Identity` drops
/// wherever it drops (PRDRDP/14 §8.2). `user` and `domain` are skipped: they
/// are not secrets, and zeroizing them would only make the redaction rule
/// harder to reason about.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct Identity {
    /// The account name with no qualifier, or the whole UPN.
    #[zeroize(skip)]
    pub user: String,
    /// The domain, or empty for a local account or a UPN logon.
    #[zeroize(skip)]
    pub domain: String,
    /// The password. Never printed, never logged.
    pub password: Zeroizing<String>,
}

impl Identity {
    /// The one constructor. Applies every rule of PRDRDP/14 §6.2.
    ///
    /// An explicit `domain` from the prompt's domain field wins over anything
    /// parsed out of the username box. A username containing `\` when the
    /// domain field is also filled is a user error we resolve in favour of the
    /// domain field; the alternative, concatenating them, produces
    /// `DOMAIN\OTHER\user`.
    ///
    /// `.\user` is the local machine shorthand. It becomes user `user`, domain
    /// `.`, and the `.` is normalised away to an empty domain.
    ///
    /// # Errors
    ///
    /// [`AuthError::NoUserName`] when the user name is empty after splitting.
    /// Anonymous authentication is refused (PRDRDP/14 §8.5).
    pub fn from_prompt(username: &str, domain: &str, password: &str) -> Result<Self, AuthError> {
        let (mut user, parsed_domain) = split_qualified_username(username);
        let mut dom = if domain.is_empty() {
            parsed_domain
        } else {
            if !parsed_domain.is_empty() {
                tracing::debug!(
                    "both the user name and the domain field name a domain; using the domain field"
                );
            }
            domain.to_owned()
        };
        if dom == "." {
            // The local machine shorthand. An empty domain means the same
            // thing to the server and is what MS-NLMP 3.3.2 wants.
            dom.clear();
        }
        user = user.trim().to_owned();
        if user.is_empty() {
            return Err(AuthError::NoUserName);
        }
        Ok(Identity {
            user,
            domain: dom,
            password: Zeroizing::new(password.to_owned()),
        })
    }
}

impl std::fmt::Debug for Identity {
    /// Redacts the password, following `crates/vnc-core/src/types.rs:316`,
    /// which prints `"***"` for both fields of `Credentials`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("user", &self.user)
            .field("domain", &self.domain)
            .field("password", &"***")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spn_is_termsrv_over_the_name_as_typed() {
        assert_eq!(service_principal_name("host"), "TERMSRV/host");
        assert_eq!(
            service_principal_name("Host.Example.COM"),
            "TERMSRV/Host.Example.COM"
        );
        // A fully qualified name ending in a dot is valid input and would
        // produce an SPN nothing matches.
        assert_eq!(
            service_principal_name("host.example.com."),
            "TERMSRV/host.example.com"
        );
    }

    #[test]
    fn the_three_spellings_split_as_windows_splits_them() {
        assert_eq!(
            split_qualified_username("DOMAIN\\user"),
            ("user".to_owned(), "DOMAIN".to_owned())
        );
        assert_eq!(
            split_qualified_username("user@corp.example.com"),
            ("user@corp.example.com".to_owned(), String::new())
        );
        assert_eq!(
            split_qualified_username("user"),
            ("user".to_owned(), String::new())
        );
        assert_eq!(
            split_qualified_username(".\\user"),
            ("user".to_owned(), ".".to_owned())
        );
        // Both separators: the backslash wins, because it is the one that
        // actually delimits a domain.
        assert_eq!(
            split_qualified_username("DOMAIN\\user@corp"),
            ("user@corp".to_owned(), "DOMAIN".to_owned())
        );
        assert_eq!(
            split_qualified_username("DOMAIN\\"),
            (String::new(), "DOMAIN".to_owned())
        );
    }

    #[test]
    fn from_prompt_applies_every_rule() {
        let id = Identity::from_prompt("DOMAIN\\alice", "", "pw").unwrap();
        assert_eq!((id.user.as_str(), id.domain.as_str()), ("alice", "DOMAIN"));

        // The domain field wins over the one in the username box.
        let id = Identity::from_prompt("OTHER\\alice", "DOMAIN", "pw").unwrap();
        assert_eq!((id.user.as_str(), id.domain.as_str()), ("alice", "DOMAIN"));

        // The local machine shorthand normalises to an empty domain.
        let id = Identity::from_prompt(".\\alice", "", "pw").unwrap();
        assert_eq!((id.user.as_str(), id.domain.as_str()), ("alice", ""));

        // A UPN stays whole.
        let id = Identity::from_prompt("alice@corp.example.com", "", "pw").unwrap();
        assert_eq!(
            (id.user.as_str(), id.domain.as_str()),
            ("alice@corp.example.com", "")
        );

        assert_eq!(
            Identity::from_prompt("DOMAIN\\", "", "pw").unwrap_err(),
            AuthError::NoUserName
        );
        assert_eq!(
            Identity::from_prompt("   ", "", "pw").unwrap_err(),
            AuthError::NoUserName
        );
    }
}
