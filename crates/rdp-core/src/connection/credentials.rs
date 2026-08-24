//! The credential gate, and the prompt that makes it answerable
//! (PRD/10 §3.4, PRDRDP/00 R13).
//!
//! # What was wrong before this file
//!
//! [`super::nla::credssp_client`] answered a missing password with
//! [`RdpError::CredentialsRequired`], which is an error, so the attempt died
//! rather than asking. `crates/remote-core/src/events.rs:132` states the
//! contract that was being broken in as many words: the session "must not
//! fail the connection instead of asking". The shell side was already
//! complete and the event simply never arrived.
//!
//! # Where the gate sits, and why it is after the certificate gate
//!
//! [`super::trust`]'s module documentation has the argument and this module
//! keeps to it: CredSSP hands the user's password, encrypted under the
//! session key, to whoever holds the private key of the certificate we
//! accepted (MS-CSSP 3.1.5). Asking for a password before the user has
//! approved the identity it will be handed to would be asking them to trust a
//! machine they have not been shown. So [`super::connect`] runs
//! `trust::approve` first and this second, and nothing between the two sends
//! a byte.
//!
//! # Two rejections, two different answers
//!
//! A credential can be refused in two places and they are not the same event.
//!
//! Before anything goes out, [`missing`] refuses credentials CredSSP cannot
//! even be started with: no user name, or no password. Nothing has been sent,
//! so [`ensure`] simply asks again on the same socket, which is the loop in
//! this file.
//!
//! After the exchange has started, the server refuses them, and that is not
//! recoverable here. MS-CSSP 3.1.5 has the client fail immediately on the
//! server's error code, and the server has finished with the exchange by the
//! time we see it; a second `TSRequest` on that TLS session goes to a peer
//! that has already stopped listening. So the re-ask happens on a fresh
//! connection, driven by `crate::session::connect::establish`, and [`Ask`]
//! is the state that survives from one connection to the next. That is the
//! same shape `vnc-core` uses (`establish_interactive`,
//! `crates/vnc-core/src/session/connection.rs:366`), for the same reason.

use remote_core::{ClientCommand, CredentialKind, CredentialRequest, Credentials, SessionEvent};
use tokio::sync::mpsc;

use crate::error::{RdpError, Result};

use super::prompt::Prompt;

/// How many credential prompts one chain of attempts may raise.
///
/// Three, which is `vnc_core::security::MAX_CREDENTIAL_ATTEMPTS`
/// (`crates/vnc-core/src/security/prompt.rs:49`) and is deliberately the same
/// number: the two protocols share a shell and a user, and a bound that
/// differed between them would be a bound nobody could predict. It also
/// bounds the connections, because each re-ask past the first opens one.
///
/// The ceiling matters more here than it does for RFB. Active Directory locks
/// an account after three to five bad passwords, and a client that keeps
/// asking is a client that helps the user lock themselves out of their own
/// laptop.
pub const MAX_CREDENTIAL_PROMPTS: u32 = 3;

/// The `method` the prompt names, which is what the UI puts in its title.
///
/// A constant rather than a value read off the negotiation because phase 1
/// and phase 2 are NTLMv2 only (D6, and `super::nla::credssp_client` says the
/// same on the configuration it builds). When SPNEGO over Kerberos lands this
/// becomes a question the mechanism answers.
pub const METHOD: &str = "Network Level Authentication (NTLM)";

/// What one chain of connection attempts has already asked the user.
///
/// It lives above the connection sequence, in
/// `crate::session::connect::establish`, because a password typed at a
/// prompt has to be able to reach the connection *after* the one it was typed
/// on: see this module's documentation for why a server side rejection cannot
/// be answered on the socket that produced it.
#[derive(Debug, Default)]
pub struct Ask {
    /// Prompts raised so far, which is what
    /// [`CredentialRequest::attempt`] counts.
    raised: u32,
    /// Why the last answer was refused, when it was, and the flag that makes
    /// the next [`ensure`] ask even though the credentials on hand look
    /// usable.
    refused: Option<String>,
}

impl Ask {
    /// Nothing asked yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the credentials in force came from the user rather than from
    /// the profile or the keychain.
    ///
    /// This is the test that stops a stored password being replayed: a saved
    /// credential the server rejects fails once, opening exactly one TCP
    /// connection, because looping on it locks the account out. Only what a
    /// human just typed is worth trying again.
    #[must_use]
    pub fn prompted(&self) -> bool {
        self.raised > 0
    }

    /// Prompts raised so far.
    #[must_use]
    pub fn raised(&self) -> u32 {
        self.raised
    }

    /// Whether another prompt is inside [`MAX_CREDENTIAL_PROMPTS`].
    #[must_use]
    pub fn may_ask_again(&self) -> bool {
        self.raised < MAX_CREDENTIAL_PROMPTS
    }

    /// Record a rejection the next prompt should show, and make it ask.
    ///
    /// `why` is a sentence from [`RdpError::user_message`], which never
    /// carries a credential, a token or a byte of remote data
    /// (PRDRDP/12 §6.4).
    pub fn refused(&mut self, why: String) {
        self.refused = Some(why);
    }
}

/// What CredSSP is missing from these credentials, or `None` when it has
/// everything it needs to build its first token.
///
/// The one definition of "these credentials are unusable", called both by the
/// gate below and by [`super::nla::credssp_client`], so the sentence the user
/// is shown and the error the sequence returns cannot disagree about which
/// half is missing.
#[must_use]
pub fn missing(creds: &Credentials) -> Option<&'static str> {
    if creds
        .username
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .is_none()
    {
        return Some("no user name");
    }
    if creds.password.is_none() {
        return Some("no password");
    }
    None
}

/// Make sure `creds` is something CredSSP can be started with, asking the
/// user for whatever is not there.
///
/// With `prompt` as `None` the credentials are refused rather than asked for,
/// which is what a headless caller and every unit test that drives the phases
/// directly get. That is deliberately the same behaviour this gate had before
/// the prompt existed: no path in this module invents a credential.
///
/// `creds` is replaced in place by what the user types, so the caller keeps
/// it for the next connection. That matters because the connection this was
/// typed on may not be the one it is used on: see the module documentation.
///
/// # Errors
///
/// * [`RdpError::CredentialsRequired`] when there is nobody to ask, when the
///   user dismissed the dialog, and when [`MAX_CREDENTIAL_PROMPTS`] is spent.
/// * [`RdpError::Cancelled`] when the session is torn down while the dialog
///   is open.
pub async fn ensure(
    creds: &mut Credentials,
    events: &mpsc::Sender<SessionEvent>,
    prompt: Option<Prompt<'_>>,
) -> Result<()> {
    let mut prompt = prompt;
    loop {
        // Two reasons to ask, in the order they can happen. The credentials
        // on hand cannot start an exchange, or they could and a server has
        // already said no to them.
        let why = match missing(creds) {
            Some(gap) => gap.to_owned(),
            None => match prompt.as_mut().and_then(|p| p.ask.refused.take()) {
                Some(refusal) => refusal,
                None => return Ok(()),
            },
        };

        let Some(prompt) = prompt.as_mut() else {
            return Err(RdpError::CredentialsRequired(why));
        };
        if !prompt.ask.may_ask_again() {
            // The user has answered as many times as the bound allows. Report
            // it as needing user action rather than as a transient failure,
            // so the backoff ladder does not walk straight back into the same
            // dialog.
            return Err(RdpError::CredentialsRequired(format!(
                "the sign in was refused {MAX_CREDENTIAL_PROMPTS} times"
            )));
        }
        prompt.ask.raised += 1;

        let request = CredentialRequest {
            method: METHOD.to_owned(),
            // CredSSP has no password only form: MS-CSSP 3.1.5 needs an
            // identity to derive the NTLM response from, so the prompt always
            // shows both boxes.
            kind: CredentialKind::UsernameAndPassword,
            attempt: prompt.ask.raised,
            // The first prompt has no previous attempt to explain. What is
            // missing on the first one is "you have not typed it yet", which
            // is what an empty box already says.
            error: (prompt.ask.raised > 1).then_some(why),
            // DES truncation is a VNC Authentication property (PRD/10 §3.4).
            // NTLMv2 hashes the whole password.
            truncates_password: false,
            username_hint: creds.username.clone().filter(|u| !u.trim().is_empty()),
        };
        *creds = raise(request, creds, events, prompt.reborrow()).await?;
    }
}

/// Emit one prompt and pump the command channel until it is answered.
///
/// The loop is [`super::trust::ask`]'s, arm for arm, and for the same
/// reasons: a dismissed dialog, a dropped shell and a cancelled session are
/// three different endings, and input can arrive while a dialog is open
/// because the shell has a window by then.
async fn raise(
    request: CredentialRequest,
    base: &Credentials,
    events: &mpsc::Sender<SessionEvent>,
    prompt: Prompt<'_>,
) -> Result<Credentials> {
    tracing::info!(
        method = %request.method,
        attempt = request.attempt,
        "asking the user for rdp credentials"
    );
    remote_core::emit(events, SessionEvent::CredentialsRequired(request)).await?;

    let Prompt {
        commands, cancel, ..
    } = prompt;
    loop {
        let cmd = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(RdpError::Cancelled),
            cmd = commands.recv() => cmd,
        };
        match cmd {
            // The shell dropped the handle: nobody can answer and nobody is
            // waiting for the answer either.
            None => return Err(RdpError::Cancelled),
            // The tail of the answer is the "remember these" checkbox, and
            // this crate never reads it: the shell owns the keychain and
            // persists only after the session actually reaches `Connected`,
            // so a rejected password is never stored
            // (`crates/remote-core/src/commands.rs:64`). `vnc-core` drops it
            // in the same place (`session/connection.rs:337`).
            Some(ClientCommand::ProvideCredentials {
                username, password, ..
            }) => {
                return Ok(Credentials {
                    username: username.filter(|u| !u.trim().is_empty()),
                    password: Some(password),
                    // There is no domain field on the command and there
                    // deliberately is not one: the shell folds the domain box
                    // into the user name as `DOMAIN\user` and
                    // `super::nla::logon_identity` splits it back out, so
                    // there is one place that decides which authority the
                    // logon goes to. The profile's domain is kept as the
                    // fallback for an answer that names none.
                    domain: base.domain.clone(),
                });
            }
            // The dialog's cancel button, and the disconnect that a user who
            // closes the window instead produces. Both mean the same thing:
            // the user is not signing in, so nothing more may be sent.
            Some(ClientCommand::CancelCredentials) | Some(ClientCommand::Disconnect) => {
                return Err(RdpError::CredentialsRequired(
                    "the sign in prompt was dismissed".to_owned(),
                ));
            }
            // Input, quality and clipboard commands can arrive while the
            // dialog is open because the shell has a window by now. There is
            // no session to apply them to, and holding them would replay a
            // burst of stale pointer motion the moment the session starts.
            Some(other) => {
                tracing::trace!(
                    ?other,
                    "a command arrived while the sign in prompt was open"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    fn prompt<'a>(
        commands: &'a mut mpsc::Receiver<ClientCommand>,
        cancel: &'a CancellationToken,
        ask: &'a mut Ask,
    ) -> Prompt<'a> {
        Prompt {
            commands,
            cancel,
            ask,
        }
    }

    /// The one definition of "unusable", which the CredSSP client builder
    /// shares so the two cannot disagree about which half is missing.
    #[test]
    fn the_gap_is_named_and_a_blank_user_name_is_a_gap() {
        assert_eq!(missing(&Credentials::default()), Some("no user name"));
        assert_eq!(
            missing(&Credentials {
                username: Some("   ".into()),
                password: Some("pw".into()),
                domain: None,
            }),
            Some("no user name")
        );
        assert_eq!(
            missing(&Credentials {
                username: Some("alice".into()),
                ..Credentials::default()
            }),
            Some("no password")
        );
        assert_eq!(missing(&Credentials::user_pass("alice", "pw")), None);
        // An empty password is a password. Some hosts have accounts with one,
        // and refusing it here would be this client deciding what an account
        // may be.
        assert_eq!(missing(&Credentials::user_pass("alice", "")), None);
    }

    /// Headless, and every unit test that drives the phases directly: with
    /// nobody to ask, the gate behaves exactly as it did before the prompt
    /// existed.
    #[tokio::test]
    async fn without_a_prompt_a_missing_password_is_still_an_error() {
        let (events, _rx) = mpsc::channel(8);
        let mut creds = Credentials {
            username: Some("alice".into()),
            ..Credentials::default()
        };
        let err = ensure(&mut creds, &events, None)
            .await
            .expect_err("no password");
        assert!(matches!(err, RdpError::CredentialsRequired(_)), "{err}");
        assert!(err.to_string().contains("no password"), "{err}");
        assert!(err.needs_user_action());
    }

    /// Complete credentials never raise a prompt, which is what stops a
    /// session with a saved password showing a dialog on every reconnect.
    #[tokio::test]
    async fn complete_credentials_are_not_asked_about() {
        let (events, mut rx) = mpsc::channel(8);
        let (_tx, mut commands) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut ask = Ask::new();
        let mut creds = Credentials::user_pass("alice", "pw");

        ensure(
            &mut creds,
            &events,
            Some(prompt(&mut commands, &cancel, &mut ask)),
        )
        .await
        .expect("nothing to ask");
        assert!(!ask.prompted());
        assert_eq!(creds, Credentials::user_pass("alice", "pw"));
        drop(events);
        assert!(rx.recv().await.is_none(), "no prompt was emitted");
    }

    /// The whole point of the module: the prompt reaches the shell, the
    /// answer replaces the credentials in place, and the profile's domain
    /// survives an answer that names none.
    #[tokio::test]
    async fn an_answered_prompt_replaces_the_credentials() {
        let (events, mut rx) = mpsc::channel(8);
        let (tx, mut commands) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut ask = Ask::new();
        let mut creds = Credentials {
            username: Some("alice".into()),
            password: None,
            domain: Some("CORP".into()),
        };

        let answerer = tokio::spawn(async move {
            match rx.recv().await.expect("a prompt") {
                SessionEvent::CredentialsRequired(request) => {
                    assert_eq!(request.attempt, 1);
                    assert_eq!(request.error, None, "there was no previous attempt");
                    assert_eq!(request.kind, CredentialKind::UsernameAndPassword);
                    assert!(!request.truncates_password);
                    assert_eq!(request.username_hint.as_deref(), Some("alice"));
                    tx.send(ClientCommand::ProvideCredentials {
                        username: Some("alice".into()),
                        password: "secret".into(),
                        save: true,
                    })
                    .await
                    .expect("send");
                }
                other => panic!("expected a credential prompt, got {other:?}"),
            }
        });

        ensure(
            &mut creds,
            &events,
            Some(prompt(&mut commands, &cancel, &mut ask)),
        )
        .await
        .expect("answered");
        answerer.await.expect("answerer");
        assert_eq!(creds.username.as_deref(), Some("alice"));
        assert_eq!(creds.password.as_deref(), Some("secret"));
        assert_eq!(creds.domain.as_deref(), Some("CORP"));
        assert!(ask.prompted());
    }

    /// An answer that is still unusable is refused and asked again, with the
    /// reason and with the count the UI shows.
    #[tokio::test]
    async fn an_unusable_answer_is_asked_again_with_the_reason() {
        let (events, mut rx) = mpsc::channel(8);
        let (tx, mut commands) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut ask = Ask::new();
        let mut creds = Credentials::default();

        let answerer = tokio::spawn(async move {
            let first = rx.recv().await.expect("a first prompt");
            let SessionEvent::CredentialsRequired(first) = first else {
                panic!("expected a credential prompt, got {first:?}");
            };
            assert_eq!(first.attempt, 1);
            assert_eq!(first.error, None);
            // The user cleared the user name box, which CredSSP cannot start
            // from (MS-CSSP 3.1.5).
            tx.send(ClientCommand::ProvideCredentials {
                username: None,
                password: "secret".into(),
                save: false,
            })
            .await
            .expect("send");

            let second = rx.recv().await.expect("a second prompt");
            let SessionEvent::CredentialsRequired(second) = second else {
                panic!("expected a credential prompt, got {second:?}");
            };
            assert_eq!(second.attempt, 2);
            assert_eq!(second.error.as_deref(), Some("no user name"));
            tx.send(ClientCommand::ProvideCredentials {
                username: Some("CORP\\alice".into()),
                password: "secret".into(),
                save: false,
            })
            .await
            .expect("send");
        });

        ensure(
            &mut creds,
            &events,
            Some(prompt(&mut commands, &cancel, &mut ask)),
        )
        .await
        .expect("answered on the second try");
        answerer.await.expect("answerer");
        assert_eq!(creds.username.as_deref(), Some("CORP\\alice"));
        assert_eq!(ask.raised(), 2);
    }

    /// A rejection recorded from outside makes the next gate ask even though
    /// the credentials on hand look perfectly usable. That is how a server
    /// side refusal is re-asked: on the next connection, not on the socket
    /// that produced it (MS-CSSP 3.1.5).
    #[tokio::test]
    async fn a_recorded_rejection_makes_usable_credentials_ask_again() {
        let (events, mut rx) = mpsc::channel(8);
        let (tx, mut commands) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut ask = Ask::new();
        ask.raised = 1;
        ask.refused("authentication failed: the password was wrong".to_owned());
        let mut creds = Credentials::user_pass("alice", "stale");

        let answerer = tokio::spawn(async move {
            let SessionEvent::CredentialsRequired(request) = rx.recv().await.expect("a prompt")
            else {
                panic!("expected a credential prompt");
            };
            assert_eq!(request.attempt, 2);
            assert!(
                request
                    .error
                    .as_deref()
                    .unwrap_or_default()
                    .contains("wrong"),
                "{:?}",
                request.error
            );
            tx.send(ClientCommand::ProvideCredentials {
                username: Some("alice".into()),
                password: "fresh".into(),
                save: false,
            })
            .await
            .expect("send");
        });

        ensure(
            &mut creds,
            &events,
            Some(prompt(&mut commands, &cancel, &mut ask)),
        )
        .await
        .expect("answered");
        answerer.await.expect("answerer");
        assert_eq!(creds.password.as_deref(), Some("fresh"));
    }

    /// The bound. Active Directory locks an account after three to five bad
    /// passwords, so the client stops asking before it helps the user do it.
    #[tokio::test]
    async fn the_prompt_count_is_bounded() {
        let (events, mut rx) = mpsc::channel(8);
        let (tx, mut commands) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut ask = Ask::new();
        let mut creds = Credentials::default();

        // Answer every prompt with something still unusable, forever.
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                if tx
                    .send(ClientCommand::ProvideCredentials {
                        username: None,
                        password: "secret".into(),
                        save: false,
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });

        let err = ensure(
            &mut creds,
            &events,
            Some(prompt(&mut commands, &cancel, &mut ask)),
        )
        .await
        .expect_err("the bound is reached");
        assert!(matches!(err, RdpError::CredentialsRequired(_)), "{err}");
        assert!(err.needs_user_action());
        assert!(
            !err.is_transient(),
            "a backoff ladder must not walk back in"
        );
        assert_eq!(ask.raised(), MAX_CREDENTIAL_PROMPTS);
    }

    /// Dismissing the dialog ends the attempt, and ends it as "the user has to
    /// do something" rather than as a transient failure a backoff ladder would
    /// retry into the same dialog.
    #[tokio::test]
    async fn a_dismissed_prompt_ends_the_attempt() {
        for answer in [ClientCommand::CancelCredentials, ClientCommand::Disconnect] {
            let (events, mut rx) = mpsc::channel(8);
            let (tx, mut commands) = mpsc::channel(8);
            let cancel = CancellationToken::new();
            let mut ask = Ask::new();
            let mut creds = Credentials::default();
            tokio::spawn(async move {
                rx.recv().await;
                let _ = tx.send(answer).await;
                // Keep the receiver alive so the refusal comes from the
                // answer and not from a closed channel.
                std::future::pending::<()>().await;
            });
            let err = ensure(
                &mut creds,
                &events,
                Some(prompt(&mut commands, &cancel, &mut ask)),
            )
            .await
            .expect_err("dismissed");
            assert!(err.to_string().contains("dismissed"), "{err}");
            assert!(err.needs_user_action());
            assert!(!err.is_transient());
        }
    }

    /// A shell that goes away with the dialog open must not hold the attempt
    /// open forever, and neither must a cancelled session.
    #[tokio::test]
    async fn a_teardown_while_the_dialog_is_open_ends_the_attempt() {
        let (events, _rx) = mpsc::channel(8);

        let (tx, mut commands) = mpsc::channel(8);
        drop(tx);
        let cancel = CancellationToken::new();
        let mut ask = Ask::new();
        let mut creds = Credentials::default();
        let err = ensure(
            &mut creds,
            &events,
            Some(prompt(&mut commands, &cancel, &mut ask)),
        )
        .await
        .expect_err("the shell is gone");
        assert!(matches!(err, RdpError::Cancelled), "{err}");

        let (_tx, mut commands) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut ask = Ask::new();
        let mut creds = Credentials::default();
        let err = ensure(
            &mut creds,
            &events,
            Some(prompt(&mut commands, &cancel, &mut ask)),
        )
        .await
        .expect_err("cancelled");
        assert!(matches!(err, RdpError::Cancelled), "{err}");
    }

    /// Input arriving while the dialog is open is dropped rather than queued:
    /// there is no session to apply it to, and replaying a burst of stale
    /// pointer motion the moment one exists is worse than losing it.
    #[tokio::test]
    async fn commands_that_are_not_an_answer_are_dropped_and_the_wait_continues() {
        let (events, mut rx) = mpsc::channel(8);
        let (tx, mut commands) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut ask = Ask::new();
        let mut creds = Credentials::default();
        tokio::spawn(async move {
            rx.recv().await;
            tx.send(ClientCommand::Pointer {
                x: 1,
                y: 2,
                button_mask: 0,
            })
            .await
            .expect("send");
            tx.send(ClientCommand::SetViewOnly(true))
                .await
                .expect("send");
            tx.send(ClientCommand::ProvideCredentials {
                username: Some("alice".into()),
                password: "pw".into(),
                save: false,
            })
            .await
            .expect("send");
        });
        ensure(
            &mut creds,
            &events,
            Some(prompt(&mut commands, &cancel, &mut ask)),
        )
        .await
        .expect("answered after the noise");
        assert_eq!(creds.password.as_deref(), Some("pw"));
    }
}
