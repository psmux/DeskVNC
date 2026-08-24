//! Server Redirection: following a broker to the machine it names
//! (MS-RDPBCGR 1.3.8, 2.2.13, PRDRDP/06 §5.5, PRDRDP/07).
//!
//! A Remote Desktop Connection Broker answers the first connection with a
//! redirection packet rather than a session: it names the host that actually
//! holds the user's session, hands back a credential to reach it with, and
//! expects the client to hang up and dial the target. Without this, every
//! connection to a farm lands on the broker and stops.
//!
//! # The packet is hostile input, and one field of it is a password
//!
//! `rdp_pdu::rdp::ServerRedirectionPacket` already treats it that way: the
//! `Password` is a `SecretBytes`, redacted in `Debug` and zeroized on drop
//! (`crates/rdp-pdu/src/rdp/redirection.rs:155`). This module keeps that
//! property. The password is transcoded into a `Zeroizing<String>`, it is
//! never logged, never put in an error message, and never in
//! [`Redirection::describe`], which is what reaches the log and the
//! `RdpEvent::Redirected` event.
//!
//! `docs/RDP_SPEC_NOTES.md` §1.5 records two open readings in that decoder:
//! the order of the last four fields, and where the packet starts inside its
//! wrapper. Neither is settled without a captured broker redirection. What
//! this module adds is that a mis-read packet fails as a decode error or as a
//! target we refuse, rather than as a connection to a host name assembled out
//! of the middle of a password: [`Redirection::from_packet`] rejects a target
//! that is not a plausible host, and a packet that does not parse never gets
//! here at all.
//!
//! # What we do not do
//!
//! `LB_PASSWORD_IS_PK_ENCRYPTED` (MS-RDPBCGR 2.2.13.1) says the `Password`
//! is encrypted under the target's public key, taken from
//! `TargetCertificate`. Decrypting it is an RSA operation against a
//! certificate we would have to parse first, and phase 2 does neither: the
//! password is dropped and the redirection is followed with whatever
//! credentials the profile already has, which is what happens today for every
//! host. `LB_SMARTCARD_LOGON` is likewise carried and not acted on.

use rdp_pdu::rdp::redirection::redir_flags;
use rdp_pdu::rdp::ServerRedirectionPacket;
use remote_core::ConnectOptions;
use zeroize::Zeroizing;

/// The longest host name we will dial from a redirection.
///
/// RFC 1035 §2.3.4 bounds a domain name at 255 octets, and a redirection that
/// names something longer is a packet we have misread rather than a host that
/// exists.
const MAX_TARGET_LEN: usize = 255;

/// A redirection, reduced to what the next attempt needs.
///
/// Owned rather than borrowed: it outlives the receive buffer it was decoded
/// from by the whole of a reconnect.
pub struct Redirection {
    /// `SessionID` on the target, reported to the shell and used for nothing
    /// else: the session is reached through the cookie the broker gave us,
    /// not through this number.
    pub session_id: u32,
    /// Where to dial: `TargetNetAddress`, else the first of
    /// `TargetNetAddresses`, else `TargetFQDN`, else `TargetNetBiosName`.
    target: String,
    /// `TargetFQDN`, which is the name the target's certificate is issued to
    /// and therefore the name TLS has to verify against.
    fqdn: Option<String>,
    username: Option<String>,
    domain: Option<String>,
    /// `Password`, transcoded from UTF-16LE, absent when it was encrypted
    /// under the target's public key.
    password: Option<Zeroizing<String>>,
    /// `LoadBalanceInfo`, which goes back out as the routing token of the
    /// next X.224 Connection Request (MS-RDPBCGR 3.2.5.3.1).
    routing_token: Option<Vec<u8>>,
    /// `LB_DONTSTOREUSERNAME`: the user name in this packet is for this
    /// reconnection and must not be saved.
    dont_store_username: bool,
}

impl Redirection {
    /// Reduce a decoded packet, or refuse it.
    ///
    /// `None` for a packet we will not act on, with the reason logged:
    /// `LB_NOREDIRECT` (the packet is informational and the client stays
    /// where it is), or no usable target.
    #[must_use]
    pub fn from_packet(packet: &ServerRedirectionPacket<'_>) -> Option<Self> {
        if packet.is_no_redirect() {
            tracing::info!(
                session_id = packet.session_id,
                "the server sent a redirection with LB_NOREDIRECT: staying here"
            );
            return None;
        }

        let target = packet
            .target_net_address
            .as_deref()
            .or_else(|| packet.target_net_addresses.first().map(String::as_str))
            .or(packet.target_fqdn.as_deref())
            .or(packet.target_netbios_name.as_deref())
            .map(str::trim)
            .filter(|t| is_plausible_target(t))?;

        // The password is cleartext UTF-16LE unless the flag says it is
        // ciphertext under a key we do not have.
        let password = if packet.password_is_encrypted() {
            tracing::debug!(
                "the redirection password is public key encrypted, which this build cannot read"
            );
            None
        } else {
            packet.password.as_ref().map(|p| utf16_secret(p.expose()))
        };

        Some(Self {
            session_id: packet.session_id,
            target: target.to_owned(),
            fqdn: packet
                .target_fqdn
                .as_deref()
                .map(str::trim)
                .filter(|f| is_plausible_target(f))
                .map(str::to_owned),
            username: packet.username.clone().filter(|u| !u.is_empty()),
            domain: packet.domain.clone().filter(|d| !d.is_empty()),
            password,
            routing_token: packet
                .load_balance_info
                .as_ref()
                .map(|p| p.as_slice().to_vec()),
            dont_store_username: packet.redir_options & redir_flags::DONTSTOREUSERNAME != 0,
        })
    }

    /// The target host, for a log line and for the `RdpEvent::Redirected`
    /// event. Carries no credential and no token.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("redirected to {}", self.target)
    }

    /// True when the packet said not to save the user name it carried.
    ///
    /// The shell is what would save it, and it never sees these credentials,
    /// so today this is a fact we log rather than one we act on. It is read
    /// by the test that proves the bit survives the reduction.
    #[must_use]
    pub const fn dont_store_username(&self) -> bool {
        self.dont_store_username
    }

    /// Rewrite the profile for the next attempt.
    ///
    /// The port is left alone: MS-RDPBCGR 2.2.13.1 gives a redirection no
    /// port field, and a broker farm listens on the same port the broker
    /// does.
    ///
    /// `routing_token` is the caller's, because it belongs to the attempt and
    /// not to the profile: a token is presented once, to the host that issued
    /// it, and must not survive into an unrelated later connection.
    pub fn apply(self, options: &mut ConnectOptions, routing_token: &mut Option<Vec<u8>>) {
        let Self {
            target,
            fqdn,
            username,
            domain,
            password,
            routing_token: token,
            ..
        } = self;

        options.host = target;
        // The certificate the target presents is issued to its FQDN, so that
        // is what SNI, the trust on first use pin and the CredSSP service
        // principal have to use, not the address we dialled (PRDRDP/00 R26
        // makes `server_name` the identity and `host` the dial address).
        if let Some(fqdn) = fqdn {
            options.rdp_mut().server_name = Some(fqdn);
        }
        if let Some(username) = username {
            options.credentials.username = Some(username);
        }
        if let Some(domain) = domain {
            options.credentials.domain = Some(domain.clone());
            options.rdp_mut().domain = Some(domain);
        }
        if let Some(password) = password {
            // `Credentials::password` is a plain `String`, which is where
            // every other password in this product already lives. Our own
            // copy is zeroized as it is moved out of the `Zeroizing` wrapper
            // here; the profile's copy has the same lifetime as any typed
            // password.
            options.credentials.password = Some(password.to_string());
        }
        *routing_token = token;
    }
}

/// The sentence a log line or an error message shows: the target host, and
/// nothing that arrived with it.
impl std::fmt::Display for Redirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the server redirected this session to {}", self.target)
    }
}

/// `Debug` names the target and nothing else. The username, the domain, the
/// password and the routing token are all either a credential or a bearer
/// token.
impl std::fmt::Debug for Redirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redirection")
            .field("session_id", &self.session_id)
            .field("target", &self.target)
            .field("credentials", &self.username.as_ref().map(|_| "***"))
            .field(
                "routing_token_len",
                &self.routing_token.as_ref().map(Vec::len),
            )
            .finish()
    }
}

/// Whether a string is a host name or address we are willing to dial.
///
/// The point is not to validate a host name to the letter. It is that
/// `docs/RDP_SPEC_NOTES.md` §1.5 leaves the field order in this packet
/// inferred rather than known, so a wrong reading hands this function the
/// middle of some other field. A target with a control character, a space or
/// a slash in it is one of those, and dialling it is how a client ends up
/// connecting somewhere nobody named.
fn is_plausible_target(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= MAX_TARGET_LEN
        && target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_' | '[' | ']'))
}

/// Transcode a UTF-16LE field into a string that zeroizes when it drops.
///
/// Odd trailing bytes are dropped rather than refused: this runs on a field
/// whose length came off the wire, and a password we cannot read fully is a
/// password we do not use, which the caller finds out by it not working.
fn utf16_secret(bytes: &[u8]) -> Zeroizing<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        // Every string in this packet carries its terminator inside its own
        // length (`crates/rdp-pdu/src/rdp/redirection.rs:422`).
        .take_while(|u| *u != 0)
        .collect();
    Zeroizing::new(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_pdu::io::Payload;

    fn utf16(s: &str) -> Vec<u8> {
        let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend_from_slice(&[0, 0]);
        out
    }

    fn packet() -> ServerRedirectionPacket<'static> {
        let mut p = ServerRedirectionPacket::new(9);
        p.target_net_address = Some("10.0.0.7".to_owned());
        p.target_fqdn = Some("host.corp.example".to_owned());
        p.username = Some("alice".to_owned());
        p.domain = Some("CORP".to_owned());
        p
    }

    /// The whole point: the profile now names the target, and TLS verifies
    /// against the certificate name rather than against the address dialled.
    #[test]
    fn a_redirection_rewrites_the_host_and_the_tls_name() {
        let redirect = Redirection::from_packet(&packet()).expect("followed");
        assert_eq!(redirect.describe(), "redirected to 10.0.0.7");

        let mut options = ConnectOptions::rdp("broker.corp.example", 3389);
        let mut token = None;
        redirect.apply(&mut options, &mut token);
        assert_eq!(options.host, "10.0.0.7");
        assert_eq!(options.port, 3389, "a redirection carries no port");
        assert_eq!(
            options.rdp_options().expect("rdp").server_name.as_deref(),
            Some("host.corp.example")
        );
        assert_eq!(options.credentials.username.as_deref(), Some("alice"));
        assert_eq!(options.credentials.domain.as_deref(), Some("CORP"));
        assert!(token.is_none(), "no load balance info was sent");
    }

    /// `LB_NOREDIRECT` means the packet is informational. Following it anyway
    /// is how a client connects somewhere it was told not to.
    #[test]
    fn a_no_redirect_packet_is_not_followed() {
        let mut p = packet();
        p.redir_options |= redir_flags::NOREDIRECT;
        assert!(Redirection::from_packet(&p).is_none());
    }

    /// The load balance info becomes the routing token of the next connection
    /// request (MS-RDPBCGR 3.2.5.3.1), and it is scoped to the attempt rather
    /// than stored in the profile.
    #[test]
    fn the_load_balance_info_becomes_a_routing_token() {
        let blob = b"tsv://MS Terminal Services Plugin.1.farm";
        let mut p = packet();
        p.load_balance_info = Some(Payload::new(blob));
        let redirect = Redirection::from_packet(&p).expect("followed");

        let mut options = ConnectOptions::rdp("broker", 3389);
        let mut token = None;
        redirect.apply(&mut options, &mut token);
        assert_eq!(token.as_deref(), Some(&blob[..]));
    }

    /// A cleartext password is transcoded out of UTF-16LE and used. An
    /// encrypted one is dropped, because we have no key for it.
    #[test]
    fn the_password_is_read_only_when_it_is_cleartext() {
        let mut p = packet();
        p.password = Some(rdp_pdu::rdp::SecretBytes::new(utf16("hunter2")));
        let redirect = Redirection::from_packet(&p).expect("followed");
        let mut options = ConnectOptions::rdp("broker", 3389);
        redirect.apply(&mut options, &mut None);
        assert_eq!(options.credentials.password.as_deref(), Some("hunter2"));

        let mut p = packet();
        p.password = Some(rdp_pdu::rdp::SecretBytes::new(utf16("hunter2")));
        p.redir_options |= redir_flags::PASSWORD_IS_PK_ENCRYPTED;
        let redirect = Redirection::from_packet(&p).expect("followed");
        let mut options = ConnectOptions::rdp("broker", 3389);
        redirect.apply(&mut options, &mut None);
        assert_eq!(options.credentials.password, None);
    }

    /// `docs/RDP_SPEC_NOTES.md` §1.5 says the field order in this packet is
    /// inferred. A wrong reading hands us the middle of another field, and
    /// the failure has to be a refusal rather than a connection to whatever
    /// fell out.
    #[test]
    fn an_implausible_target_is_refused_rather_than_dialled() {
        for junk in [
            "",
            " ",
            "host name with spaces",
            "https://evil.example/",
            "host\u{0}name",
            "host\nname",
        ] {
            let mut p = ServerRedirectionPacket::new(1);
            p.target_net_address = Some(junk.to_owned());
            assert!(
                Redirection::from_packet(&p).is_none(),
                "{junk:?} was accepted as a target"
            );
        }

        // And the fallbacks are used in order when the first is absent.
        let mut p = ServerRedirectionPacket::new(1);
        p.target_net_addresses = vec!["10.1.2.3".to_owned()];
        assert_eq!(
            Redirection::from_packet(&p).expect("followed").describe(),
            "redirected to 10.1.2.3"
        );
        let mut p = ServerRedirectionPacket::new(1);
        p.target_netbios_name = Some("HOST7".to_owned());
        assert_eq!(
            Redirection::from_packet(&p).expect("followed").describe(),
            "redirected to HOST7"
        );
    }

    /// Neither the password nor the routing token reaches a log line.
    #[test]
    fn debug_carries_no_secret() {
        let mut p = packet();
        p.password = Some(rdp_pdu::rdp::SecretBytes::new(utf16("hunter2")));
        p.load_balance_info = Some(Payload::new(b"tsv://secret"));
        p.redir_options |= redir_flags::DONTSTOREUSERNAME;
        let redirect = Redirection::from_packet(&p).expect("followed");
        assert!(redirect.dont_store_username());

        let shown = format!("{redirect:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(!shown.contains("tsv://"), "{shown}");
        assert!(!shown.contains("alice"), "{shown}");
        assert!(shown.contains("10.0.0.7"), "{shown}");
    }
}
