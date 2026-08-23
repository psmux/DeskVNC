//! The trust on first use gate, and the prompt that makes it answerable
//! (PRDRDP/00 R13, PRDRDP/03 §5.4).
//!
//! # Why this is its own file
//!
//! The gate used to be a private `check_trust` in [`super`] that refused an
//! unknown key with a sentence, because emitting the prompt means parking the
//! connection sequence on an answer and the command channel did not reach the
//! sequence. It does now, and parking is a small state machine with its own
//! failure modes (a dismissed dialog, a dropped shell, an answer to a
//! different question), so it gets a module rather than growing
//! [`super::connect`].
//!
//! # The ordering, and why it differs from the VNC path
//!
//! The prompt completes **before** CredSSP starts. `vnc-core` emits its
//! prompt and carries straight on
//! (`crates/vnc-core/src/session/connection.rs:257` sends
//! `SessionEvent::CertificatePrompt` and the next statement is
//! `emit_state(Negotiating)`), which that file records as a pre existing bug.
//! For RDP the ordering is not a nicety: CredSSP hands the user's plaintext
//! password, encrypted under the session key, to whoever holds the private
//! key of the certificate we accepted (MS-CSSP 3.1.5). Accepting afterwards
//! would be accepting a fact.
//!
//! So the invariant this module holds is: **nothing that depends on the
//! server's identity leaves the client until the user has approved that
//! identity**. The TLS handshake itself has already happened, because the
//! fingerprint being shown is the one the handshake produced, and the
//! handshake carries no secret of ours.
//!
//! # A changed pin is still a hard stop
//!
//! [`vnc_transport::TrustDecision::Changed`] is documented as a hard stop
//! (`crates/vnc-transport/src/lib.rs:78`) and this module keeps it one. The
//! prompt exists for a key with no pin, which is nearly every RDP host on
//! first contact; a key that replaced a pinned one is the case the pin was
//! stored to catch.

use remote_core::{ClientCommand, PinScheme, SessionEvent};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vnc_transport::TrustDecision;

use crate::error::{RdpError, Result};

/// What the sequence needs to raise a prompt and wait for its answer.
///
/// Borrowed rather than owned because the receiver belongs to the session
/// task's supervisor for the whole session and is only lent to the connection
/// sequence: nothing else reads it while the sequence runs, which is the same
/// arrangement `vnc-core` makes for its credential prompt
/// (`crates/vnc-core/src/session/connection.rs:315`, `serve_credential_ask`).
pub struct TrustPrompt<'a> {
    /// The command channel the shell answers on.
    pub commands: &'a mut mpsc::Receiver<ClientCommand>,
    /// Cancelled when the window is gone, so a dialog nobody will ever
    /// answer does not hold the attempt open.
    pub cancel: &'a CancellationToken,
}

/// Act on what the trust on first use verifier decided, asking the user when
/// there is somebody to ask.
///
/// With `prompt` as `None` an unknown key is refused rather than shown, which
/// is what a headless caller and every unit test that drives the phases
/// directly get. That is deliberately the same behaviour this gate had before
/// the prompt existed: no path in this module can approve a key without an
/// explicit answer.
///
/// # Errors
///
/// * [`RdpError::CertificateMismatch`] for a changed pin, which is never auto
///   retried.
/// * [`RdpError::CertificateUntrusted`] for a key with no pin and no prompt,
///   for a dismissed prompt, and for an answer that names a different key.
/// * [`RdpError::Cancelled`] when the session is torn down while the dialog
///   is open.
pub async fn approve(
    trust: &TrustDecision,
    events: &mpsc::Sender<SessionEvent>,
    prompt: Option<TrustPrompt<'_>>,
) -> Result<()> {
    match trust {
        TrustDecision::VerifiedByCa | TrustDecision::PinnedMatch => Ok(()),
        TrustDecision::Changed { expected, actual } => Err(RdpError::CertificateMismatch {
            expected: expected.clone(),
            actual: actual.clone(),
        }),
        TrustDecision::Unknown {
            fingerprint,
            subject,
        } => {
            let Some(prompt) = prompt else {
                return Err(RdpError::CertificateUntrusted(format!(
                    "{fingerprint} has not been approved and there is nobody to ask"
                )));
            };
            ask(fingerprint, subject, events, prompt).await
        }
    }
}

/// Emit the prompt and pump the command channel until it is answered.
///
/// The pin is looked up under [`PinScheme::RdpTls`]
/// (`crate::transport::upgrade_tls`), so the answer is stored against the RDP
/// key rather than against the VeNCrypt one for the same host (PRDRDP/02
/// §2.1). The scheme travels out on the prompt and has to come back unchanged
/// on the answer; an answer naming another scheme belongs to another dialog
/// and is refused rather than applied to this key.
async fn ask(
    fingerprint: &str,
    subject: &str,
    events: &mpsc::Sender<SessionEvent>,
    prompt: TrustPrompt<'_>,
) -> Result<()> {
    tracing::info!(
        %fingerprint,
        "asking the user to approve an unpinned rdp server key"
    );
    remote_core::emit(
        events,
        SessionEvent::CertificatePrompt {
            fingerprint: fingerprint.to_owned(),
            subject: subject.to_owned(),
            // The changed case never reaches here: it is a hard stop above.
            is_change: false,
            scheme: PinScheme::RdpTls,
        },
    )
    .await?;

    let TrustPrompt { commands, cancel } = prompt;
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
            Some(ClientCommand::TrustCertificate {
                fingerprint: answered,
                scheme,
                permanent,
            }) => return decide(fingerprint, &answered, scheme, permanent),
            // The dialog's cancel button, and the disconnect that a user who
            // closes the window instead produces. Both mean the same thing:
            // the key was not approved, so nothing more may be sent.
            Some(ClientCommand::CancelCredentials) | Some(ClientCommand::Disconnect) => {
                return Err(RdpError::CertificateUntrusted(format!(
                    "{fingerprint} was not approved"
                )));
            }
            // Input, quality and clipboard commands can arrive while the
            // dialog is open because the shell has a window by now. There is
            // no session to apply them to, and holding them would replay a
            // burst of stale pointer motion the moment the session starts.
            Some(other) => {
                tracing::trace!(?other, "a command arrived while the trust prompt was open");
            }
        }
    }
}

/// Check an answer against the question, then act on it.
///
/// Two properties, and both are the reason this is a function rather than
/// three lines inside the loop:
///
/// 1. The fingerprint has to match the one we showed. A stale answer to an
///    earlier dialog, or an answer for a different session multiplexed onto
///    the same shell, must not approve this key.
/// 2. The scheme has to be the one we asked under. `PinScheme::Tls` for the
///    same host is the VeNCrypt certificate, and one protocol's approval may
///    not vouch for another's (PRDRDP/02 §2.1).
///
/// `permanent` is the "remember this" checkbox. This crate never writes it
/// anywhere: the shell owns the pin store and persists the answer itself
/// (`src-tauri/src/commands/session.rs:994`), and the session's only job is
/// to stop blocking. It is read here so the trace records what the user
/// chose.
fn decide(asked: &str, answered: &str, scheme: PinScheme, permanent: bool) -> Result<()> {
    if scheme != PinScheme::RdpTls {
        return Err(RdpError::CertificateUntrusted(format!(
            "the approval named the {} key and this prompt was for the {} key",
            scheme.as_str(),
            PinScheme::RdpTls.as_str()
        )));
    }
    if !same_key(asked, answered) {
        return Err(RdpError::CertificateUntrusted(
            "the approval named a different key from the one that was shown".to_owned(),
        ));
    }
    tracing::info!(permanent, "the user approved the rdp server key");
    Ok(())
}

/// Compare two fingerprints the way a user pasting one would want.
///
/// `vnc_transport::normalize_fingerprint` strips separators and uppercases
/// (`crates/vnc-transport/src/lib.rs:94`), which is exactly the comparison the
/// pin store already makes, so an answer that round tripped through a UI that
/// dropped the colons still matches.
fn same_key(a: &str, b: &str) -> bool {
    vnc_transport::normalize_fingerprint(a) == vnc_transport::normalize_fingerprint(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unknown() -> TrustDecision {
        TrustDecision::Unknown {
            fingerprint: "AA:BB:CC".into(),
            subject: "CN=host".into(),
        }
    }

    /// A verified or pinned key never reaches the prompt, and a changed one
    /// is a hard stop that is never auto retried.
    #[tokio::test]
    async fn the_gate_passes_a_known_key_and_stops_on_a_changed_one() {
        let (events, _rx) = mpsc::channel(8);
        assert!(approve(&TrustDecision::VerifiedByCa, &events, None)
            .await
            .is_ok());
        assert!(approve(&TrustDecision::PinnedMatch, &events, None)
            .await
            .is_ok());

        let err = approve(
            &TrustDecision::Changed {
                expected: "AA".into(),
                actual: "BB".into(),
            },
            &events,
            None,
        )
        .await
        .expect_err("changed");
        assert!(matches!(err, RdpError::CertificateMismatch { .. }));
        assert!(err.needs_user_action());
        assert!(!err.is_transient());
    }

    /// Headless, and every unit test that drives the phases directly: the
    /// behaviour the gate had before the prompt existed is still what happens
    /// when there is nobody to ask.
    #[tokio::test]
    async fn without_a_prompt_an_unknown_key_is_still_refused() {
        let (events, _rx) = mpsc::channel(8);
        let err = approve(&unknown(), &events, None)
            .await
            .expect_err("unknown");
        assert!(err.to_string().contains("AA:BB:CC"), "{err}");
        assert!(err.needs_user_action());
    }

    /// The whole point of the module: the prompt reaches the shell carrying
    /// the RDP pin scheme, and an approval that names the same key lets the
    /// sequence continue.
    #[tokio::test]
    async fn an_approved_key_lets_the_sequence_continue() {
        let (events, mut rx) = mpsc::channel(8);
        let (tx, mut commands) = mpsc::channel(8);
        let cancel = CancellationToken::new();

        let answerer = tokio::spawn(async move {
            match rx.recv().await.expect("a prompt") {
                SessionEvent::CertificatePrompt {
                    fingerprint,
                    subject,
                    is_change,
                    scheme,
                } => {
                    assert_eq!(fingerprint, "AA:BB:CC");
                    assert_eq!(subject, "CN=host");
                    assert!(!is_change);
                    assert_eq!(scheme, PinScheme::RdpTls);
                    tx.send(ClientCommand::TrustCertificate {
                        // Round tripped through a UI that dropped the
                        // separators, which still names the same key.
                        fingerprint: "aabbcc".into(),
                        permanent: true,
                        scheme,
                    })
                    .await
                    .expect("send");
                }
                other => panic!("expected a certificate prompt, got {other:?}"),
            }
        });

        approve(
            &unknown(),
            &events,
            Some(TrustPrompt {
                commands: &mut commands,
                cancel: &cancel,
            }),
        )
        .await
        .expect("approved");
        answerer.await.expect("answerer");
    }

    /// Dismissing the dialog stops the attempt, and stops it as "the user has
    /// to do something" rather than as a transient failure a backoff ladder
    /// would retry into the same dialog.
    #[tokio::test]
    async fn a_dismissed_prompt_refuses_the_key() {
        for answer in [ClientCommand::CancelCredentials, ClientCommand::Disconnect] {
            let (events, mut rx) = mpsc::channel(8);
            let (tx, mut commands) = mpsc::channel(8);
            let cancel = CancellationToken::new();
            tokio::spawn(async move {
                rx.recv().await;
                let _ = tx.send(answer).await;
                // Keep the receiver alive so the refusal comes from the
                // answer and not from a closed channel.
                std::future::pending::<()>().await;
            });
            let err = approve(
                &unknown(),
                &events,
                Some(TrustPrompt {
                    commands: &mut commands,
                    cancel: &cancel,
                }),
            )
            .await
            .expect_err("dismissed");
            assert!(matches!(err, RdpError::CertificateUntrusted(_)), "{err}");
            assert!(err.needs_user_action());
        }
    }

    /// An answer that names another key, or the same key under another
    /// scheme, is not an approval of this one. A VeNCrypt certificate
    /// approved for port 5900 must not vouch for whatever is on 3389.
    #[tokio::test]
    async fn an_answer_to_a_different_question_does_not_approve_this_key() {
        assert!(decide("AA:BB", "AA:BB", PinScheme::RdpTls, false).is_ok());

        let err = decide("AA:BB", "AA:BB", PinScheme::Tls, false).expect_err("wrong scheme");
        assert!(err.to_string().contains("rdp-tls"), "{err}");

        let err = decide("AA:BB", "CC:DD", PinScheme::RdpTls, true).expect_err("wrong key");
        assert!(err.to_string().contains("different key"), "{err}");
    }

    /// A shell that goes away with the dialog open must not hold the attempt
    /// open forever, and neither must a cancelled session.
    #[tokio::test]
    async fn a_teardown_while_the_dialog_is_open_ends_the_attempt() {
        let (events, _rx) = mpsc::channel(8);

        let (tx, mut commands) = mpsc::channel(8);
        drop(tx);
        let cancel = CancellationToken::new();
        let err = approve(
            &unknown(),
            &events,
            Some(TrustPrompt {
                commands: &mut commands,
                cancel: &cancel,
            }),
        )
        .await
        .expect_err("the shell is gone");
        assert!(matches!(err, RdpError::Cancelled));

        let (_tx, mut commands) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = approve(
            &unknown(),
            &events,
            Some(TrustPrompt {
                commands: &mut commands,
                cancel: &cancel,
            }),
        )
        .await
        .expect_err("cancelled");
        assert!(matches!(err, RdpError::Cancelled));
    }

    /// Input arriving while the dialog is open is dropped rather than
    /// queued: there is no session to apply it to, and replaying a burst of
    /// stale pointer motion the moment one exists is worse than losing it.
    #[tokio::test]
    async fn commands_that_are_not_an_answer_are_dropped_and_the_wait_continues() {
        let (events, mut rx) = mpsc::channel(8);
        let (tx, mut commands) = mpsc::channel(8);
        let cancel = CancellationToken::new();
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
            tx.send(ClientCommand::TrustCertificate {
                fingerprint: "AA:BB:CC".into(),
                permanent: false,
                scheme: PinScheme::RdpTls,
            })
            .await
            .expect("send");
        });
        approve(
            &unknown(),
            &events,
            Some(TrustPrompt {
                commands: &mut commands,
                cancel: &cancel,
            }),
        )
        .await
        .expect("approved after the noise");
    }
}
