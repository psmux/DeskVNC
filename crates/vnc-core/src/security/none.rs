//! Security type 1, "None".
//!
//! No authentication and no encryption. RFB 3.8 still sends a SecurityResult
//! afterwards; 3.3 and 3.7 do not (handled by the dispatcher).
//!
//! Blocked unless the user has explicitly opted in for this host (PRD/10 §2).

use vnc_transport::BoxedStream;

use super::AuthOutcome;
use crate::error::{Result, VncError};
use crate::types::ConnectOptions;

pub(crate) async fn handshake(stream: BoxedStream, opts: &ConnectOptions) -> Result<AuthOutcome> {
    // Defence in depth: `select_security_type` already refuses this, but a
    // future caller (or a Tight/VeNCrypt sub-negotiation) must not be able to
    // route around the opt-in.
    if !opts.allow_insecure {
        return Err(VncError::Other(
            "this server offers no authentication at all; enable \
             \"Allow an unencrypted connection\" for this host to continue"
                .into(),
        ));
    }

    tracing::warn!("connecting with NO authentication and NO encryption");
    Ok(AuthOutcome::auto(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(allow: bool) -> ConnectOptions {
        let mut o = ConnectOptions::new("h", 5900);
        o.allow_insecure = allow;
        o
    }

    #[tokio::test]
    async fn refuses_without_optin() {
        let (a, _b) = tokio::io::duplex(16);
        let s: BoxedStream = Box::pin(a);
        assert!(handshake(s, &opts(false)).await.is_err());
    }

    #[tokio::test]
    async fn accepts_with_optin() {
        let (a, _b) = tokio::io::duplex(16);
        let s: BoxedStream = Box::pin(a);
        assert!(handshake(s, &opts(true)).await.is_ok());
    }
}
