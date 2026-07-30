//! Interactive credential prompting (PRD/10 §3.4).
//!
//! The security handshake is a linear async function, but "ask the user for a
//! password" is inherently a round trip to another task. This module is the
//! bridge: a security module that needs a secret it does not have raises a
//! [`CredentialAsk`] on a channel, then awaits a one-shot answer.
//!
//! ```text
//!  security::vnc_auth ──ask──▶ CredentialPrompt ──▶ session::connection
//!                                                        │
//!                                                        ├─ emits SessionEvent::CredentialsRequired
//!                                                        └─ pumps ClientCommand::ProvideCredentials
//!                     ◀──oneshot reply (Some/None)───────┘
//! ```
//!
//! When no prompt is wired up, the library used headlessly, or the
//! `authenticate` convenience entry point, every module behaves exactly as it
//! did before this existed: a missing secret is
//! [`VncError::CredentialsRequired`] and the caller decides what to do.
//!
//! Nothing here logs a credential, and [`Credentials`] keeps its redacting
//! `Debug`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tokio::sync::{mpsc, oneshot};

use crate::error::{Result, VncError};
use crate::types::{ConnectOptions, CredentialKind, CredentialRequest, Credentials};

/// A pending question for the user, raised from inside the handshake.
///
/// The session answers by sending on [`reply`](Self::reply): `Some` with what
/// the user typed, or `None` if they cancelled (or the session is tearing
/// down).
#[derive(Debug)]
pub struct CredentialAsk {
    pub request: CredentialRequest,
    pub reply: oneshot::Sender<Option<Credentials>>,
}

/// The channel the session hands to the security layer so it can reach the
/// user mid-handshake.
pub type CredentialPrompt = mpsc::Sender<CredentialAsk>;

/// How many times we ask before giving up on one connection (PRD/10 §3.4).
/// The first attempt counts, so this is "one prompt plus two retries".
pub const MAX_CREDENTIAL_ATTEMPTS: u32 = 3;

/// Everything a security module needs to obtain a secret it does not already
/// have: the (optional) channel to the user, plus the retry context the dialog
/// renders, which attempt this is and why the last one was rejected.
///
/// Construct one per connection attempt; [`prompted`](Self::prompted) then
/// reports whether the credentials actually used came from the user, which is
/// what makes "re-ask on rejection" safe (a *stored* credential that the server
/// rejects must fail once and stop, never loop).
pub struct CredentialSource<'a> {
    prompt: Option<&'a CredentialPrompt>,
    attempt: u32,
    error: Option<String>,
    username_hint: Option<String>,
    /// Set once the user has actually answered a prompt in this attempt.
    used: AtomicBool,
    /// The user name the user last supplied, so a retry can prefill it.
    last_username: Mutex<Option<String>>,
}

impl std::fmt::Debug for CredentialSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialSource")
            .field("interactive", &self.prompt.is_some())
            .field("attempt", &self.attempt)
            .field("error", &self.error)
            .finish()
    }
}

impl Default for CredentialSource<'_> {
    fn default() -> Self {
        Self::none()
    }
}

impl<'a> CredentialSource<'a> {
    /// Non-interactive: a missing secret is an error, exactly as it was before
    /// interactive prompting existed. Used by [`super::authenticate`] and by
    /// every unit test that drives a handshake directly.
    pub fn none() -> Self {
        Self {
            prompt: None,
            attempt: 1,
            error: None,
            username_hint: None,
            used: AtomicBool::new(false),
            last_username: Mutex::new(None),
        }
    }

    /// Interactive: missing secrets are asked for over `prompt`.
    ///
    /// `attempt` is 1-based; `error` is the server's reason for rejecting the
    /// previous attempt (`None` on the first).
    pub fn interactive(
        prompt: &'a CredentialPrompt,
        attempt: u32,
        error: Option<String>,
        username_hint: Option<String>,
    ) -> Self {
        Self {
            prompt: Some(prompt),
            attempt,
            error,
            username_hint,
            used: AtomicBool::new(false),
            last_username: Mutex::new(None),
        }
    }

    /// True when a prompt is wired up at all.
    pub fn can_prompt(&self) -> bool {
        self.prompt.is_some()
    }

    /// True when the credentials this attempt used came from the user.
    ///
    /// The retry loop keys off this: only interactively-supplied credentials
    /// are worth re-asking for. Stored credentials that the server rejects stop
    /// the session immediately (and, critically, never open a second TCP
    /// connection).
    pub fn prompted(&self) -> bool {
        self.used.load(Ordering::Relaxed)
    }

    /// The user name the user supplied, for prefilling the retry prompt.
    pub fn last_username(&self) -> Option<String> {
        self.last_username.lock().expect("not poisoned").clone()
    }

    /// Resolve credentials for one security method.
    ///
    /// Returns immediately with what `opts` already carries when that satisfies
    /// `kind`. Otherwise asks the user, if we can; if we cannot, this is the
    /// pre-existing [`VncError::CredentialsRequired`].
    ///
    /// * `method`, human-readable, shown in the dialog title ("VNC
    ///   Authentication", "VeNCrypt (X509Plain)", …).
    /// * `truncates_password`, DES-based methods silently use only the first
    ///   8 characters; the UI must warn.
    pub(crate) async fn obtain(
        &self,
        method: &str,
        kind: CredentialKind,
        truncates_password: bool,
        opts: &ConnectOptions,
    ) -> Result<Credentials> {
        let stored_user = non_empty(opts.credentials.username.clone());
        let stored_pass = opts.credentials.password.clone();

        let satisfied = match kind {
            CredentialKind::PasswordOnly => stored_pass.is_some(),
            CredentialKind::UsernameAndPassword => stored_pass.is_some() && stored_user.is_some(),
        };
        if satisfied {
            return Ok(Credentials {
                username: stored_user,
                password: stored_pass,
            });
        }

        let Some(prompt) = self.prompt else {
            return Err(VncError::CredentialsRequired(missing_message(method, kind)));
        };

        let request = CredentialRequest {
            method: method.to_string(),
            kind,
            attempt: self.attempt,
            error: self.error.clone(),
            truncates_password,
            username_hint: stored_user
                .clone()
                .or_else(|| self.username_hint.clone())
                .or_else(|| match kind {
                    // Apple's server misbehaves with an empty user name, and
                    // the OS user is right far more often than not.
                    CredentialKind::UsernameAndPassword => os_username(),
                    CredentialKind::PasswordOnly => None,
                }),
        };

        let (reply, answer) = oneshot::channel();
        if prompt.send(CredentialAsk { request, reply }).await.is_err() {
            // Nobody is listening, behave as if there were no prompt at all.
            return Err(VncError::CredentialsRequired(missing_message(method, kind)));
        }

        // `Err` here means the session dropped the reply channel: it is tearing
        // down (cancelled, disconnected, or the shell went away).
        let Ok(Some(supplied)) = answer.await else {
            return Err(VncError::Cancelled);
        };
        self.used.store(true, Ordering::Relaxed);

        let mut username = non_empty(supplied.username).or(stored_user);
        let password = supplied.password.or(stored_pass);

        if matches!(kind, CredentialKind::UsernameAndPassword) {
            // Never send an empty user name for a method that needs one: fall
            // back to what the dialog was prefilled with, then to the OS user.
            username = username
                .or_else(|| self.username_hint.clone())
                .or_else(os_username);
            if username.is_none() {
                return Err(VncError::CredentialsRequired(missing_message(method, kind)));
            }
        }
        if password.is_none() {
            return Err(VncError::CredentialsRequired(missing_message(method, kind)));
        }

        *self.last_username.lock().expect("not poisoned") = username.clone();
        Ok(Credentials { username, password })
    }
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

fn missing_message(method: &str, kind: CredentialKind) -> String {
    match kind {
        CredentialKind::PasswordOnly => format!("{method} requires a password"),
        CredentialKind::UsernameAndPassword => {
            format!("{method} requires a user name and password")
        }
    }
}

/// The account name of the user running the client, when the OS tells us.
/// Used only as a *hint* the dialog prefills, never as a silent default for a
/// stored profile.
fn os_username() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|u| !u.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ConnectOptions {
        ConnectOptions::new("h", 5900)
    }

    #[tokio::test]
    async fn stored_password_short_circuits_the_prompt() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut o = opts();
        o.credentials = Credentials::password("swordfish");
        let src = CredentialSource::interactive(&tx, 1, None, None);
        let got = src
            .obtain("VNC Authentication", CredentialKind::PasswordOnly, true, &o)
            .await
            .unwrap();
        assert_eq!(got.password.as_deref(), Some("swordfish"));
        assert!(!src.prompted(), "no prompt should have been raised");
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn without_a_prompt_a_missing_secret_is_credentials_required() {
        let src = CredentialSource::none();
        assert!(matches!(
            src.obtain(
                "VNC Authentication",
                CredentialKind::PasswordOnly,
                true,
                &opts()
            )
            .await,
            Err(VncError::CredentialsRequired(_))
        ));
    }

    #[tokio::test]
    async fn asks_and_uses_the_answer() {
        let (tx, mut rx) = mpsc::channel(1);
        let src = CredentialSource::interactive(&tx, 2, Some("nope".into()), None);
        let answerer = tokio::spawn(async move {
            let ask = rx.recv().await.unwrap();
            assert_eq!(ask.request.attempt, 2);
            assert_eq!(ask.request.error.as_deref(), Some("nope"));
            assert!(ask.request.truncates_password);
            assert_eq!(ask.request.kind, CredentialKind::PasswordOnly);
            ask.reply
                .send(Some(Credentials::password("typed")))
                .unwrap();
        });
        let got = src
            .obtain(
                "VNC Authentication",
                CredentialKind::PasswordOnly,
                true,
                &opts(),
            )
            .await
            .unwrap();
        answerer.await.unwrap();
        assert_eq!(got.password.as_deref(), Some("typed"));
        assert!(src.prompted());
    }

    #[tokio::test]
    async fn cancelling_aborts_with_cancelled() {
        let (tx, mut rx) = mpsc::channel(1);
        let src = CredentialSource::interactive(&tx, 1, None, None);
        tokio::spawn(async move {
            let ask = rx.recv().await.unwrap();
            ask.reply.send(None).unwrap();
        });
        assert!(matches!(
            src.obtain(
                "VNC Authentication",
                CredentialKind::PasswordOnly,
                true,
                &opts()
            )
            .await,
            Err(VncError::Cancelled)
        ));
        assert!(!src.prompted());
    }

    #[tokio::test]
    async fn a_dropped_reply_channel_is_cancellation_not_a_hang() {
        let (tx, mut rx) = mpsc::channel(1);
        let src = CredentialSource::interactive(&tx, 1, None, None);
        tokio::spawn(async move {
            let ask = rx.recv().await.unwrap();
            drop(ask.reply);
        });
        assert!(matches!(
            src.obtain(
                "Apple Remote Desktop",
                CredentialKind::UsernameAndPassword,
                false,
                &opts()
            )
            .await,
            Err(VncError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn user_and_password_needs_both_before_it_short_circuits() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut o = opts();
        // Password but no user name: still has to ask.
        o.credentials = Credentials::password("pw");
        let src = CredentialSource::interactive(&tx, 1, None, None);
        tokio::spawn(async move {
            let ask = rx.recv().await.unwrap();
            assert_eq!(ask.request.kind, CredentialKind::UsernameAndPassword);
            ask.reply
                .send(Some(Credentials::user_pass("alice", "pw2")))
                .unwrap();
        });
        let got = src
            .obtain(
                "Apple Remote Desktop",
                CredentialKind::UsernameAndPassword,
                false,
                &o,
            )
            .await
            .unwrap();
        assert_eq!(got.username.as_deref(), Some("alice"));
        assert_eq!(got.password.as_deref(), Some("pw2"));
        assert_eq!(src.last_username().as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn an_empty_username_answer_falls_back_to_the_hint() {
        let (tx, mut rx) = mpsc::channel(1);
        let src = CredentialSource::interactive(&tx, 1, None, Some("bob".into()));
        tokio::spawn(async move {
            let ask = rx.recv().await.unwrap();
            assert_eq!(ask.request.username_hint.as_deref(), Some("bob"));
            ask.reply
                .send(Some(Credentials {
                    username: Some(String::new()),
                    password: Some("pw".into()),
                }))
                .unwrap();
        });
        let got = src
            .obtain(
                "Apple Remote Desktop",
                CredentialKind::UsernameAndPassword,
                false,
                &opts(),
            )
            .await
            .unwrap();
        assert_eq!(got.username.as_deref(), Some("bob"));
    }

    #[test]
    fn credentials_still_redact_in_debug() {
        let ask_debug = format!("{:?}", CredentialSource::none());
        assert!(ask_debug.contains("interactive: false"));
        let c = Credentials::user_pass("alice", "hunter2");
        let shown = format!("{c:?}");
        assert!(!shown.contains("hunter2") && !shown.contains("alice"));
    }
}
