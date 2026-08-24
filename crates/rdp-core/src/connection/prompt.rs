//! The channel the connection sequence asks a question down, shared by the
//! two gates that have one (PRDRDP/00 R13, PRD/10 §3.4).
//!
//! # Why it is not called `TrustPrompt` any more
//!
//! It was, and it was the certificate gate's own type
//! ([`super::trust`]). The credential gate needs exactly the same three
//! things, and the sequence has only one command receiver to lend, so a
//! second type would have meant a second borrow of the same channel. The name
//! moved with the meaning: this is "somebody is there to answer", not
//! "somebody is there to answer about a certificate".
//!
//! # Why it is reborrowed rather than cloned or copied
//!
//! [`Prompt::reborrow`] exists because the two gates run one after the other
//! inside the same [`super::connect`] call and both need `&mut` to the same
//! receiver. `super::trust::approve` takes the prompt by value and consumes
//! it, so without a reborrow the certificate gate would swallow the only
//! handle and the credential gate that runs after it would have nobody to
//! ask, which is the bug this module was written to fix
//! (`crates/rdp-core/src/connection/mod.rs:262`).

use remote_core::ClientCommand;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::credentials::Ask;

/// What the sequence needs to raise a prompt and wait for its answer.
///
/// Borrowed rather than owned because the receiver belongs to the session
/// task's supervisor for the whole session and is only lent to the connection
/// sequence: nothing else reads it while the sequence runs, which is the same
/// arrangement `vnc-core` makes for its credential prompt
/// (`crates/vnc-core/src/session/connection.rs:315`, `serve_credential_ask`).
pub struct Prompt<'a> {
    /// The command channel the shell answers on.
    pub commands: &'a mut mpsc::Receiver<ClientCommand>,
    /// Cancelled when the window is gone, so a dialog nobody will ever
    /// answer does not hold the attempt open.
    pub cancel: &'a CancellationToken,
    /// How many credential prompts this chain of attempts has raised and why
    /// the last answer was refused.
    ///
    /// It lives outside the connection sequence because a password the user
    /// types can outlive the connection it was typed on: MS-CSSP 3.1.5 has
    /// the client fail immediately on the server's error code, and the server
    /// has ended the CredSSP exchange by then, so a second try is a second
    /// TCP connection. `crate::session::connect::establish` owns it and reads
    /// it after an attempt fails.
    pub ask: &'a mut Ask,
}

impl Prompt<'_> {
    /// Lend the prompt on to a gate that takes it by value.
    ///
    /// The lifetime is the borrow's rather than `'a`, which is what makes a
    /// second gate able to take it afterwards.
    pub fn reborrow(&mut self) -> Prompt<'_> {
        Prompt {
            commands: self.commands,
            cancel: self.cancel,
            ask: self.ask,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole module exists for: a gate that consumes the
    /// prompt does not consume the caller's, so the gate after it can still
    /// ask. Written as two consuming calls because that is exactly the shape
    /// `connect` has.
    #[tokio::test]
    async fn a_reborrowed_prompt_leaves_the_original_usable() {
        fn consume(p: Prompt<'_>) -> usize {
            p.commands.capacity()
        }

        let (tx, mut commands) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let mut ask = Ask::new();
        let mut prompt = Prompt {
            commands: &mut commands,
            cancel: &cancel,
            ask: &mut ask,
        };

        assert_eq!(consume(prompt.reborrow()), 4);
        assert_eq!(consume(prompt.reborrow()), 4);
        assert_eq!(consume(prompt), 4);
        drop(tx);
    }
}
