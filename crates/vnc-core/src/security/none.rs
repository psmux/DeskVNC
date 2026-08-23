//! Security type 1, "None".
//!
//! No authentication and no encryption. RFB 3.8 still sends a SecurityResult
//! afterwards; 3.3 and 3.7 do not (handled by the dispatcher).
//!
//! Taken when the server offers nothing stronger, which is the whole of what
//! a stock passwordless `x11vnc` offers. The session is flagged unencrypted
//! (`SecurityType::encrypts_session`) rather than refused: see the note above
//! `select_security_type` for why refusing made real servers unreachable
//! (issue #1).

use vnc_transport::BoxedStream;

use super::AuthOutcome;
use crate::error::Result;
use crate::types::ConnectOptions;

pub(crate) async fn handshake(stream: BoxedStream, _opts: &ConnectOptions) -> Result<AuthOutcome> {
    tracing::warn!("connecting with NO authentication and NO encryption");
    Ok(AuthOutcome::auto(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ConnectOptions {
        ConnectOptions::vnc("h", 5900)
    }

    /// Issue #1: this refused the handshake unless `allow_insecure` was set,
    /// which nothing in the app could set, so a passwordless server could
    /// not be reached at all.
    #[tokio::test]
    async fn connects_on_the_shipping_defaults() {
        let (a, _b) = tokio::io::duplex(16);
        let s: BoxedStream = Box::pin(a);
        assert!(handshake(s, &opts()).await.is_ok());
    }
}
