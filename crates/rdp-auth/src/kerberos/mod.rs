//! Kerberos v5: RFC 4120, RFC 3961, RFC 3962 and RFC 4121.
//!
//! Phase 3 (D10). NTLMv2 covers every Windows host that has not been put
//! under a Kerberos only policy, and this is what covers the ones that have.
//!
//! ## The two halves, and why they are separate
//!
//! Getting a ticket needs a network round trip to a domain controller.
//! Using a ticket does not. So the lane splits in two:
//!
//! * [`kdc::KdcClient`] runs the AS and TGS exchanges and hands back a
//!   [`kdc::ServiceTicket`]. It is a state machine over byte slices and the
//!   session does the socket work, exactly as `CredSspClient` does.
//! * [`KerberosClient`] takes that ticket and is a
//!   [`GssMechanism`](crate::gss::GssMechanism), which is what
//!   [`SpnegoClient`](crate::spnego::SpnegoClient) and
//!   [`CredSspClient`](crate::credssp::CredSspClient) already know how to
//!   drive. Neither of them changed to accept it, which is what PRDRDP/14
//!   §2.8 designed the trait for.
//!
//! The split is what keeps `rdp-auth` free of I/O. A single
//! `KerberosClient::new(config)` that fetched its own ticket would need a
//! socket, a resolver and a clock, and D12 gives all three to the session.
//!
//! ## What the session does, end to end
//!
//! ```text
//! 1.  discovery::srv_queries(realm)      -> the DNS names to look up
//! 2.  the session resolves them and connects to a KDC on TCP 88
//! 3.  KdcClient::step in a loop over that socket   -> ServiceTicket
//! 4.  KerberosClient::new(ticket, ...)             -> a GssMechanism
//! 5.  SpnegoClient::new(vec![kerberos, ntlm])      -> a GssMechanism
//! 6.  CredSspClient::with_mechanism(config, spnego)
//! 7.  CredSspClient::step in a loop over the TLS stream
//! ```
//!
//! Step 5 is optional and step 6 accepts either: `CredSspClient` holds a
//! `Box<dyn GssMechanism>` and does not know which mechanism it has.
//! [`discovery`] describes step 1 and 2 in full, including what `rdp-core`
//! has to satisfy.
//!
//! ## What is behind the feature and what is not
//!
//! Everything here is behind the `kerberos` cargo feature except
//! [`kstatus`], which is a transcription of RFC 4120 §7.5.9's error code list
//! and needs no cryptography. It is unconditional so that
//! [`AuthError`](crate::error::AuthError) does not change shape with a
//! feature; the module comment on [`kstatus`] gives the whole reason.

pub mod kstatus;

#[cfg(feature = "kerberos")]
pub mod asn1;
#[cfg(feature = "kerberos")]
pub mod crypto;
#[cfg(feature = "kerberos")]
pub mod discovery;
#[cfg(feature = "kerberos")]
pub mod gss;
#[cfg(feature = "kerberos")]
pub mod kdc;

#[cfg(feature = "kerberos")]
mod mechanism;

#[cfg(feature = "kerberos")]
pub use mechanism::{KerberosClient, KerberosConfig};
