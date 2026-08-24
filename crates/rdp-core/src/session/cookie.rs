//! The auto reconnect cookie (MS-RDPBCGR 2.2.4, 5.5, PRDRDP/06 §5.5).
//!
//! Without it, every reconnect signs the user into a **new** Windows session
//! while the old one keeps running, disconnected, with their applications and
//! unsaved work in it. On a link that flaps three times in an afternoon that
//! is three orphaned sessions.
//!
//! # The shape of it
//!
//! The server mints `ARC_SC_PRIVATE_PACKET` (2.2.4.2) and delivers it inside
//! a Save Session Info PDU whose `FieldsPresent` carries
//! `LOGON_EX_AUTORECONNECTCOOKIE` (2.2.10.1.1.4). The client answers on the
//! **next** connection with `ARC_CS_PRIVATE_PACKET` (2.2.4.3) in the
//! `autoReconnectCookie` field of `TS_EXTENDED_INFO_PACKET` (2.2.1.11.1.1.1),
//! carrying the same `LogonId` and a sixteen byte `SecurityVerifier`.
//!
//! # The derivation, and why the client random is zeros
//!
//! MS-RDPBCGR 5.5 step 4: `SecurityVerifier = HMAC(AutoReconnectRandom,
//! ClientRandom)`, HMAC per RFC 2104 with MD5 as the hash. The same section
//! says that under Enhanced RDP Security the client random is never generated
//! (5.3.2) and that thirty two zero bytes stand in for it. This client only
//! ever negotiates Enhanced RDP Security (PRDRDP/00 D6: TLS, with CredSSP by
//! default, never Standard RDP Security), so the client random is always
//! [`CLIENT_RANDOM_ZEROS`] and the verifier is a pure function of the cookie.
//!
//! Which means the verifier is not a secret independent of the cookie: anyone
//! holding the cookie can compute it. **The cookie is the credential**, and it
//! is treated like one: in memory only, never persisted, never logged, elided
//! from `Debug`, zeroized on drop.
//!
//! # No cryptography is written here
//!
//! The HMAC and the MD5 are library calls, per AGENT_BRIEF V3-A and
//! PRDRDP/00 R54. `hmac` over `md-5` are RustCrypto primitives already in the
//! workspace for the RFB security code. There is no key padding, no `ipad`
//! and no `opad` in this file, and the sixteen byte output is used whole so
//! there is no truncation to get wrong either.

use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use md5::Md5;
use rdp_pdu::rdp::client_info::{ArcClientPrivatePacket, ArcServerPrivatePacket};
use zeroize::Zeroize;

/// The client random MS-RDPBCGR 5.5 substitutes under Enhanced RDP Security:
/// thirty two zero bytes, because 5.3.2 never generates one.
pub const CLIENT_RANDOM_ZEROS: [u8; 32] = [0; 32];

/// How old a cookie may be and still be worth offering (PRDRDP/06 §5.5.5).
///
/// MS-RDPBCGR 5.5 says the server "invalidates and updates the cookie at
/// hourly intervals". Sixty five minutes rather than sixty, so a clock skew
/// or a slightly late rotation does not throw away a cookie that is still
/// good. The asymmetry is deliberate: offering a stale cookie costs one round
/// trip and a rejection, and failing to offer a good one costs the user their
/// session.
pub const MAX_AGE: Duration = Duration::from_secs(65 * 60);

/// A cookie the server minted for this session.
///
/// Never persisted (MS-RDPBCGR 5.5 step 2: "stores it in memory, never
/// allowing programmatic access to it"), never sent to the shell, and never
/// written to a log.
pub struct ReconnectCookie {
    logon_id: u32,
    random_bits: [u8; 16],
    received_at: Instant,
}

impl ReconnectCookie {
    /// Store the packet a Save Session Info PDU carried.
    #[must_use]
    pub fn from_server(packet: &ArcServerPrivatePacket, now: Instant) -> Self {
        Self {
            logon_id: packet.logon_id,
            random_bits: packet.arc_random_bits,
            received_at: now,
        }
    }

    /// The session on the server this cookie reconnects to. Not a secret: it
    /// is the one field worth putting in a support log.
    #[must_use]
    pub const fn logon_id(&self) -> u32 {
        self.logon_id
    }

    /// True when the server has almost certainly rotated it (§5.5.5).
    #[must_use]
    pub fn is_stale(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.received_at) > MAX_AGE
    }

    /// The packet to put in the next Client Info PDU, verifier computed.
    #[must_use]
    pub fn client_packet(&self) -> ArcClientPrivatePacket {
        ArcClientPrivatePacket {
            logon_id: self.logon_id,
            security_verifier: security_verifier(&self.random_bits, &CLIENT_RANDOM_ZEROS),
        }
    }
}

/// `Debug` prints the logon id and the age, and never the sixteen bytes.
impl std::fmt::Debug for ReconnectCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReconnectCookie")
            .field("logon_id", &self.logon_id)
            .field("random_bits", &"redacted")
            .field("age_s", &self.received_at.elapsed().as_secs())
            .finish()
    }
}

/// The cookie is a bearer credential, so it does not linger in freed memory
/// for the life of the process (PRDRDP/12 §6.4).
impl Drop for ReconnectCookie {
    fn drop(&mut self) {
        self.random_bits.zeroize();
    }
}

/// MS-RDPBCGR 5.5 step 4: HMAC-MD5 keyed with the server's sixteen byte
/// `ArcRandomBits`, over the client random.
///
/// The client random stays a parameter rather than being hard coded to
/// [`CLIENT_RANDOM_ZEROS`] so a specification vector can drive it. It is the
/// one place in this file where a mistake is invisible: a wrong verifier
/// still connects, it just lands in a new Windows session.
#[must_use]
pub fn security_verifier(arc_random_bits: &[u8; 16], client_random: &[u8]) -> [u8; 16] {
    // `new_from_slice` on a sixteen byte key cannot fail: `Hmac` accepts any
    // key length, padding or hashing it per RFC 2104 §2, which is the library's
    // job and not ours.
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(arc_random_bits)
        .expect("hmac accepts a key of any length (RFC 2104 section 2)");
    mac.update(client_random);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 2202 test case 1 for HMAC-MD5: a sixteen byte key of `0x0b` over
    /// "Hi There" produces `9294727a3638bb1c13f48ef8158bfc9d`.
    ///
    /// The key length is exactly the sixteen bytes MS-RDPBCGR 2.2.4.2 carries,
    /// which is why this published vector can drive our own function
    /// unmodified. It proves the plumbing: the right primitive, the key and
    /// the message the right way round, and the whole sixteen byte output
    /// used rather than a truncation.
    #[test]
    fn the_hmac_matches_the_rfc_2202_vector() {
        let key = [0x0b_u8; 16];
        let got = security_verifier(&key, b"Hi There");
        assert_eq!(
            hex::encode(got),
            "9294727a3638bb1c13f48ef8158bfc9d",
            "HMAC-MD5 (RFC 2202 test case 1)"
        );
    }

    /// The verifier a cookie produces is a pure function of the cookie, which
    /// MS-RDPBCGR 5.5 states plainly for Enhanced RDP Security and which is
    /// what lets it be computed at any point between arrival and reconnect.
    #[test]
    fn the_verifier_is_constant_for_a_given_cookie() {
        let packet = ArcServerPrivatePacket {
            logon_id: 7,
            arc_random_bits: [0xa5; 16],
        };
        let cookie = ReconnectCookie::from_server(&packet, Instant::now());
        let first = cookie.client_packet();
        let second = cookie.client_packet();
        assert_eq!(first, second);
        assert_eq!(first.logon_id, 7, "the logon id is echoed unchanged");
        assert_eq!(
            first.security_verifier,
            security_verifier(&[0xa5; 16], &CLIENT_RANDOM_ZEROS)
        );
    }

    /// Two different cookies must not produce the same verifier, which is the
    /// weakest possible statement that the key is actually being used.
    #[test]
    fn a_different_cookie_produces_a_different_verifier() {
        let a = security_verifier(&[0x01; 16], &CLIENT_RANDOM_ZEROS);
        let b = security_verifier(&[0x02; 16], &CLIENT_RANDOM_ZEROS);
        assert_ne!(a, b);
    }

    /// A cookie older than the server's rotation interval is treated as
    /// absent, and one inside it is offered.
    #[test]
    fn staleness_is_measured_against_the_documented_hourly_rotation() {
        let packet = ArcServerPrivatePacket {
            logon_id: 1,
            arc_random_bits: [0; 16],
        };
        let now = Instant::now();
        let cookie = ReconnectCookie::from_server(&packet, now);
        assert!(!cookie.is_stale(now));
        assert!(!cookie.is_stale(now + Duration::from_secs(59 * 60)));
        assert!(!cookie.is_stale(now + MAX_AGE));
        assert!(cookie.is_stale(now + MAX_AGE + Duration::from_secs(1)));
    }

    /// The sixteen secret bytes never reach a log line.
    #[test]
    fn debug_elides_the_secret() {
        let packet = ArcServerPrivatePacket {
            logon_id: 42,
            arc_random_bits: [0xde; 16],
        };
        let cookie = ReconnectCookie::from_server(&packet, Instant::now());
        let shown = format!("{cookie:?}");
        assert!(shown.contains("42"), "the logon id is diagnostic: {shown}");
        assert!(!shown.contains("de"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }
}
