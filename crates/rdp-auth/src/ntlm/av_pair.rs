//! The AV_PAIR list, MS-NLMP 2.2.2.1.
//!
//! ```text
//! AV_PAIR ::= { AvId u16, AvLen u16, Value[AvLen] }
//! ```
//!
//! The list is terminated by `MsvAvEOL`, which is `AvId = 0` and `AvLen = 0`,
//! four zero bytes.
//!
//! ## Copy through is the rule that matters
//!
//! MS-NLMP 3.1.5.1.2 builds `temp` from the server's AV pair list with our
//! additions, and the server verifies `NTProofStr` against the list it sent
//! plus the additions it expects. Reordering the server's pairs, dropping one
//! we do not understand, or normalising a string breaks `NTProofStr` and
//! produces a wrong password error against a correct password.
//!
//! So: keep the server's bytes in order; if a pair we need to set already
//! exists, replace that pair in place; otherwise append it after the last
//! pair; keep `MsvAvEOL` last. An unknown `AvId` is copied through unchanged,
//! which is why [`AvPair`] keeps the raw value bytes rather than a decoded
//! view.

use crate::error::AuthError;

/// End of the list. `AvLen` is 0.
pub const MSV_AV_EOL: u16 = 0x0000;
/// The server's NetBIOS computer name, UTF-16LE.
pub const MSV_AV_NB_COMPUTER_NAME: u16 = 0x0001;
/// The server's NetBIOS domain name, UTF-16LE.
pub const MSV_AV_NB_DOMAIN_NAME: u16 = 0x0002;
/// The server's fully qualified DNS host name, UTF-16LE.
pub const MSV_AV_DNS_COMPUTER_NAME: u16 = 0x0003;
/// The DNS domain name, UTF-16LE.
pub const MSV_AV_DNS_DOMAIN_NAME: u16 = 0x0004;
/// The forest name, UTF-16LE.
pub const MSV_AV_DNS_TREE_NAME: u16 = 0x0005;
/// A `u32` bit field. See [`AV_FLAG_MIC_PRESENT`].
pub const MSV_AV_FLAGS: u16 = 0x0006;
/// A FILETIME, 8 bytes.
pub const MSV_AV_TIMESTAMP: u16 = 0x0007;
/// A 48 byte machine identifier. Copied through if present; we never add one.
pub const MSV_AV_SINGLE_HOST: u16 = 0x0008;
/// The service principal name, UTF-16LE.
pub const MSV_AV_TARGET_NAME: u16 = 0x0009;
/// An MD5 of the `gss_channel_bindings_struct`, 16 bytes.
pub const MSV_AV_CHANNEL_BINDINGS: u16 = 0x000A;

/// `MsvAvFlags` bit 0x1: the account authentication is constrained. Server to
/// client information; we do not act on it.
pub const AV_FLAG_CONSTRAINED: u32 = 0x0000_0001;
/// `MsvAvFlags` bit 0x2: a MIC is present in the AUTHENTICATE message. We set
/// this, and MS-NLMP 3.2.5.1.2 has the server check the bit and then verify
/// the MIC, so a server that sees the bit and finds a zero MIC rejects the
/// logon. Setting the bit and filling the field happen in one function.
pub const AV_FLAG_MIC_PRESENT: u32 = 0x0000_0002;
/// `MsvAvFlags` bit 0x4: the SPN in `MsvAvTargetName` came from an untrusted
/// source. We do not set it. Our SPN is built from `RdpOptions::server_name`,
/// the name the user typed or the name from the stored profile, and the same
/// name drives SNI and the certificate pin, so it is exactly as trusted as the
/// rest of the connection. Behaviour note (D3): setting bit 0x4 causes some
/// server configurations to refuse the logon, which is the opposite of a
/// security gain here.
pub const AV_FLAG_UNTRUSTED_SPN: u32 = 0x0000_0004;

/// A hostile server does not get to make us allocate without limit
/// (PRDRDP/14 §5.4).
const MAX_TARGET_INFO_LEN: usize = 64 * 1024;
/// The same cap, counted in pairs.
const MAX_PAIRS: usize = 64;

/// One AV pair, with its value kept as the bytes that arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvPair {
    /// `AvId`.
    pub id: u16,
    /// `Value`, exactly `AvLen` bytes.
    pub value: Vec<u8>,
}

/// The server's list, in the server's order, without the `MsvAvEOL`
/// terminator. [`AvPairs::encode`] puts the terminator back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvPairs {
    pairs: Vec<AvPair>,
}

impl AvPairs {
    /// Parse a `TargetInfo` byte string.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] when a pair runs past the end of the
    /// buffer, when the terminator is missing, or when either cap is
    /// exceeded. Every read is a checked `get`, never an index (D11).
    pub fn decode(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() > MAX_TARGET_INFO_LEN {
            return Err(AuthError::MalformedMessage("TargetInfo is too long"));
        }
        let mut pairs = Vec::new();
        let mut at = 0usize;
        loop {
            let header = bytes
                .get(at..at + 4)
                .ok_or(AuthError::MalformedMessage("AV_PAIR header"))?;
            let id = u16::from_le_bytes([header[0], header[1]]);
            let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
            at += 4;
            if id == MSV_AV_EOL {
                if len != 0 {
                    return Err(AuthError::MalformedMessage("MsvAvEOL with a length"));
                }
                // Bytes after the terminator are not part of the list. The
                // specification says the list ends here, so we stop here.
                return Ok(AvPairs { pairs });
            }
            let value = bytes
                .get(at..at + len)
                .ok_or(AuthError::MalformedMessage("AV_PAIR value"))?;
            at += len;
            if pairs.len() >= MAX_PAIRS {
                return Err(AuthError::MalformedMessage("too many AV pairs"));
            }
            pairs.push(AvPair {
                id,
                value: value.to_vec(),
            });
        }
    }

    /// Serialise, terminator included.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(self.pairs.iter().map(|p| p.value.len() + 4).sum::<usize>() + 4);
        for p in &self.pairs {
            out.extend_from_slice(&p.id.to_le_bytes());
            // A value longer than u16::MAX cannot be constructed through
            // `decode` and `set` is called only with our own short values.
            let len = u16::try_from(p.value.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&p.value[..usize::from(len)]);
        }
        out.extend_from_slice(&MSV_AV_EOL.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// The value of the first pair with this id.
    #[must_use]
    pub fn get(&self, id: u16) -> Option<&[u8]> {
        self.pairs
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.value.as_slice())
    }

    /// Replace the pair with this id in place, or append it after the last
    /// pair if it is not there.
    ///
    /// In place matters: moving a pair to the end reorders the server's list
    /// and breaks `NTProofStr`.
    pub fn set(&mut self, id: u16, value: Vec<u8>) {
        if let Some(p) = self.pairs.iter_mut().find(|p| p.id == id) {
            p.value = value;
        } else {
            self.pairs.push(AvPair { id, value });
        }
    }

    /// Set `MsvAvFlags` bit 0x2, keeping any bits the server already set.
    pub fn set_mic_present(&mut self) {
        let mut flags = self
            .get(MSV_AV_FLAGS)
            .and_then(|v| v.get(..4))
            .map_or(0u32, |v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]));
        flags |= AV_FLAG_MIC_PRESENT;
        self.set(MSV_AV_FLAGS, flags.to_le_bytes().to_vec());
    }

    /// How many pairs, terminator excluded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// True when the server sent nothing but a terminator.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The pairs, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[AvPair] {
        &self.pairs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `TargetInfo` of MS-NLMP 4.2.4.3's CHALLENGE_MESSAGE, bytes 0x44 to
    /// 0x68 of that message: MsvAvNbDomainName "Domain", MsvAvNbComputerName
    /// "Server", MsvAvEOL.
    const SPEC_TARGET_INFO: &[u8] = &[
        0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e,
        0x00, 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn the_spec_list_round_trips_byte_for_byte() {
        let pairs = AvPairs::decode(SPEC_TARGET_INFO).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs.as_slice()[0].id, MSV_AV_NB_DOMAIN_NAME);
        assert_eq!(pairs.as_slice()[1].id, MSV_AV_NB_COMPUTER_NAME);
        assert_eq!(pairs.encode(), SPEC_TARGET_INFO);
    }

    #[test]
    fn set_replaces_in_place_and_appends_at_the_end() {
        let mut pairs = AvPairs::decode(SPEC_TARGET_INFO).unwrap();
        pairs.set(MSV_AV_NB_DOMAIN_NAME, b"xx".to_vec());
        assert_eq!(pairs.as_slice()[0].id, MSV_AV_NB_DOMAIN_NAME);
        assert_eq!(pairs.as_slice()[0].value, b"xx");
        assert_eq!(pairs.len(), 2, "replacing must not append");

        pairs.set(MSV_AV_CHANNEL_BINDINGS, vec![0u8; 16]);
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs.as_slice()[2].id, MSV_AV_CHANNEL_BINDINGS);
    }

    #[test]
    fn the_mic_flag_keeps_the_bits_the_server_set() {
        let mut pairs = AvPairs::decode(SPEC_TARGET_INFO).unwrap();
        pairs.set(MSV_AV_FLAGS, AV_FLAG_CONSTRAINED.to_le_bytes().to_vec());
        pairs.set_mic_present();
        let got = pairs.get(MSV_AV_FLAGS).unwrap();
        assert_eq!(
            u32::from_le_bytes([got[0], got[1], got[2], got[3]]),
            AV_FLAG_CONSTRAINED | AV_FLAG_MIC_PRESENT
        );
        // And it is created when the server sent none.
        let mut fresh = AvPairs::decode(SPEC_TARGET_INFO).unwrap();
        fresh.set_mic_present();
        assert_eq!(
            fresh.get(MSV_AV_FLAGS).unwrap(),
            AV_FLAG_MIC_PRESENT.to_le_bytes()
        );
    }

    #[test]
    fn every_prefix_of_a_valid_list_errors_rather_than_panicking() {
        for n in 0..SPEC_TARGET_INFO.len() {
            let r = AvPairs::decode(&SPEC_TARGET_INFO[..n]);
            assert!(r.is_err(), "prefix of {n} bytes parsed as a complete list");
        }
    }

    #[test]
    fn a_length_running_past_the_buffer_is_an_error() {
        // AvLen claims 0xffff with four bytes of buffer behind it.
        assert!(AvPairs::decode(&[0x01, 0x00, 0xff, 0xff, 0x00, 0x00]).is_err());
        // MsvAvEOL with a non zero length is malformed.
        assert!(AvPairs::decode(&[0x00, 0x00, 0x04, 0x00, 0, 0, 0, 0]).is_err());
        // No terminator at all.
        assert!(AvPairs::decode(&[]).is_err());
    }

    #[test]
    fn more_than_sixty_four_pairs_is_refused() {
        let mut bytes = Vec::new();
        for _ in 0..65 {
            bytes.extend_from_slice(&[0x99, 0x00, 0x00, 0x00]);
        }
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert!(AvPairs::decode(&bytes).is_err());
    }
}
