//! SRTP with AES-256-CM and an 80-bit HMAC-SHA1 tag (RFC 3711).
//!
//! The 46-byte key blob is 32 bytes of master key and 14 bytes of master
//! salt. Labels 0, 1 and 2 derive the SRTP cipher key, auth key and salt.
//!
//! One context holds the state of ONE SSRC. The rollover counter and the
//! sequence space are per SSRC (RFC 3711 §3.3.1), so the driver keeps one
//! context per stream and never mixes them.

use aes::Aes256;
use cipher::{BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// How many packets the replay window remembers. RFC 3711 recommends 64.
const REPLAY_WINDOW: u64 = 64;

/// What the receiver has seen. Read by the session for reporting.
#[derive(Default, Debug, Clone, Copy)]
pub struct SrtpStats {
    /// Packets that authenticated and were accepted.
    pub accepted: u64,
    /// Packets whose authentication tag did not verify.
    pub rejected: u64,
    /// Authenticated packets that had already been received.
    pub replayed: u64,
    /// Authenticated packets too old to be inside the replay window.
    pub too_old: u64,
    /// Packets that were not a well formed RTP packet.
    pub malformed: u64,
}

/// The window of recently received packet indices.
///
/// A packet index is the 48 bit value RFC 3711 builds from the rollover
/// counter and the 16 bit sequence number. The window remembers the last
/// [`REPLAY_WINDOW`] indices, so a packet that arrives twice is refused the
/// second time, and a packet that is too old to be new is refused as well.
#[derive(Clone, Default)]
struct ReplayWindow {
    highest: Option<u64>,
    seen: u64,
}

impl ReplayWindow {
    /// Whether `index` is new. Records it when it is.
    fn accept(&mut self, index: u64) -> bool {
        match self.highest {
            None => {
                self.highest = Some(index);
                self.seen = 1;
                true
            }
            Some(high) if index > high => {
                let shift = index - high;
                self.seen = if shift >= REPLAY_WINDOW {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.highest = Some(index);
                true
            }
            Some(high) => {
                let behind = high - index;
                if behind >= REPLAY_WINDOW {
                    return false;
                }
                let bit = 1u64 << behind;
                if self.seen & bit != 0 {
                    return false;
                }
                self.seen |= bit;
                true
            }
        }
    }
}

#[derive(Clone)]
pub struct SrtpContext {
    cipher_key: [u8; 32],
    auth_key: [u8; 20],
    salt: [u8; 14],
    /// The highest packet index accepted so far. It carries the rollover
    /// counter in its top bits, so the state can only ever move forward.
    highest: Option<u64>,
    replay: ReplayWindow,
    pub stats: SrtpStats,
}

impl SrtpContext {
    pub fn from_blob(blob: &[u8]) -> Option<Self> {
        if blob.len() != 46 {
            return None;
        }
        let mut master_key = [0u8; 32];
        let mut master_salt = [0u8; 14];
        master_key.copy_from_slice(&blob[..32]);
        master_salt.copy_from_slice(&blob[32..]);
        Some(Self {
            cipher_key: derive(&master_key, &master_salt, 0, 32).try_into().ok()?,
            auth_key: derive(&master_key, &master_salt, 1, 20).try_into().ok()?,
            salt: derive(&master_key, &master_salt, 2, 14).try_into().ok()?,
            highest: None,
            replay: ReplayWindow::default(),
            stats: SrtpStats::default(),
        })
    }

    /// Forget the packet numbers, and start a new epoch.
    ///
    /// A re-offer asks the Mac for a new stream, and the Mac's encoder may
    /// start its packet numbers again from the beginning. The keys are the
    /// same, so the packets still authenticate, but the replay window says
    /// they are old and refuses every one of them: the picture never comes
    /// back.
    ///
    /// The state is only reset when the session knows a new stream was
    /// asked for, so a replayed packet cannot use this to get in.
    pub fn new_epoch(&mut self) {
        self.highest = None;
        self.replay = ReplayWindow::default();
    }

    /// Verify and decrypt one SRTP packet.
    ///
    /// The authentication tag is checked before anything else is believed,
    /// and the packet only touches the replay window once it has
    /// authenticated. A forged packet therefore cannot make the receiver
    /// treat a genuine packet as a replay.
    pub fn unprotect(&mut self, packet: &[u8]) -> Option<Rtp> {
        if packet.len() < 12 + 10 {
            self.stats.malformed += 1;
            return None;
        }
        if packet[0] >> 6 != 2 {
            // Not RTP version 2.
            self.stats.malformed += 1;
            return None;
        }
        let tag_at = packet.len() - 10;
        let Some(header_len) = rtp_header_len(packet) else {
            self.stats.malformed += 1;
            return None;
        };
        if header_len > tag_at {
            self.stats.malformed += 1;
            return None;
        }
        // RTP padding is inside the encrypted payload (RFC 3711 section 3.1),
        // so the byte before the tag is ciphertext and only means anything
        // after decryption. Reading it in the clear rejected valid padded
        // packets and decrypted the wrong number of bytes.
        let padded = packet[0] & 0x20 != 0;
        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let ssrc = u32::from_be_bytes(packet[8..12].try_into().ok()?);
        for roc in self.candidate_rocs(seq) {
            let index = (u64::from(roc) << 16) | u64::from(seq);
            if !self.authenticates(packet, tag_at, roc) {
                continue;
            }
            // The packet is genuine. Now decide whether it is new.
            if !self.replay.accept(index) {
                if self
                    .highest
                    .is_some_and(|high| index + REPLAY_WINDOW <= high)
                {
                    self.stats.too_old += 1;
                } else {
                    self.stats.replayed += 1;
                }
                return None;
            }
            let mut payload = packet[header_len..tag_at].to_vec();
            let iv = packet_iv(&self.salt, ssrc, index);
            apply_keystream(&self.cipher_key, &iv, &mut payload);
            // The state only ever moves forward, so a packet that arrives
            // late cannot rewind the rollover counter.
            if self.highest.is_none_or(|high| index > high) {
                self.highest = Some(index);
            }
            if padded {
                // The count byte is the last plaintext byte and includes
                // itself. A malformed count is an authenticated packet with
                // an unusable payload: its packet index stays consumed, so
                // rejecting it cannot rewind the replay state.
                let pad = payload.last().copied().unwrap_or(0) as usize;
                if pad == 0 || pad > payload.len() {
                    self.stats.malformed += 1;
                    return None;
                }
                payload.truncate(payload.len() - pad);
            }
            self.stats.accepted += 1;
            return Some(Rtp {
                marker: packet[1] & 0x80 != 0,
                payload_type: packet[1] & 0x7f,
                seq,
                timestamp: u32::from_be_bytes(packet[4..8].try_into().ok()?),
                ssrc,
                payload,
            });
        }
        self.stats.rejected += 1;
        None
    }

    fn authenticates(&self, packet: &[u8], tag_at: usize, roc: u32) -> bool {
        let mut mac = match <HmacSha1 as Mac>::new_from_slice(&self.auth_key) {
            Ok(mac) => mac,
            Err(_) => return false,
        };
        mac.update(&packet[..tag_at]);
        mac.update(&roc.to_be_bytes());
        // SRTP authenticates with the LEFTMOST 80 bits, not the full SHA-1.
        mac.verify_truncated_left(&packet[tag_at..]).is_ok()
    }

    /// The rollover counters a packet could belong to.
    ///
    /// The receiver cannot know the rollover counter of a packet it has not
    /// seen: a packet may be the first of the next cycle, or a late one from
    /// the cycle before. The tag settles it, because the counter is part of
    /// what is authenticated, so each candidate is tried in turn.
    fn candidate_rocs(&self, seq: u16) -> Vec<u32> {
        let (roc, s_l) = self.roc_and_seq();
        let mut out = Vec::with_capacity(4);
        for candidate in [roc, roc.wrapping_add(1), roc.wrapping_sub(1)] {
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
        // The RFC 3711 §3.3.1 estimate, offered first so the common case
        // costs one authentication.
        let ahead = seq.wrapping_sub(s_l);
        let estimate = if s_l < 0x8000 {
            if ahead > 0x8000 {
                roc.wrapping_sub(1)
            } else {
                roc
            }
        } else if ahead > 0x8000 {
            roc.wrapping_add(1)
        } else {
            roc
        };
        if !out.contains(&estimate) {
            out.insert(0, estimate);
        }
        out
    }

    /// The rollover counter and highest sequence number seen so far.
    fn roc_and_seq(&self) -> (u32, u16) {
        match self.highest {
            None => (0, 0),
            Some(index) => ((index >> 16) as u32, (index & 0xffff) as u16),
        }
    }
}

pub struct Rtp {
    pub marker: bool,
    /// RTP payload type. Kept so a later pass can tell video from RTCP.
    #[allow(dead_code)]
    pub payload_type: u8,
    /// The 16 bit sequence number. The depacketizer needs it to see a hole.
    pub seq: u16,
    pub timestamp: u32,
    #[allow(dead_code)]
    pub ssrc: u32,
    pub payload: Vec<u8>,
}

/// The sending half of SRTP: encrypts and authenticates a packet.
///
/// The mirror of [`SrtpContext`], and the reason the media path can be
/// tested end to end: a packet that goes out of here is a packet the
/// receiver can authenticate and decrypt.
// The sending half of the media path. The viewer only receives media, so
// this is here for the tests that drive a whole stream through the wire.
#[allow(dead_code)]
#[derive(Clone)]
pub struct SrtpEncryptor {
    cipher_key: [u8; 32],
    auth_key: [u8; 20],
    salt: [u8; 14],
    /// The index of the next packet sent.
    index: u64,
}

#[allow(dead_code)]
impl SrtpEncryptor {
    pub fn from_blob(blob: &[u8]) -> Option<Self> {
        if blob.len() != 46 {
            return None;
        }
        let mut master_key = [0u8; 32];
        let mut master_salt = [0u8; 14];
        master_key.copy_from_slice(&blob[..32]);
        master_salt.copy_from_slice(&blob[32..]);
        Some(Self {
            cipher_key: derive(&master_key, &master_salt, 0, 32).try_into().ok()?,
            auth_key: derive(&master_key, &master_salt, 1, 20).try_into().ok()?,
            salt: derive(&master_key, &master_salt, 2, 14).try_into().ok()?,
            index: 0,
        })
    }

    /// Protect one RTP packet: the header travels in the clear, the payload
    /// is encrypted, and the tag is appended.
    ///
    /// The packet must already carry the sequence number and the timestamp;
    /// the index is taken from the sequence number, so the rollover counter
    /// follows the sequence number as it wraps.
    pub fn protect(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 12 {
            return None;
        }
        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let ssrc = u32::from_be_bytes(packet[8..12].try_into().ok()?);
        let roc = self.roc_for(seq);
        let index = (u64::from(roc) << 16) | u64::from(seq);
        let header_len = rtp_header_len(packet)?;
        if header_len > packet.len() {
            return None;
        }
        let mut body = packet[..header_len].to_vec();
        let mut payload = packet[header_len..].to_vec();
        let iv = packet_iv(&self.salt, ssrc, index);
        apply_keystream(&self.cipher_key, &iv, &mut payload);
        body.extend_from_slice(&payload);
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&self.auth_key).ok()?;
        mac.update(&body);
        mac.update(&roc.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        body.extend_from_slice(&tag[..10]);
        self.index = index.wrapping_add(1);
        Some(body)
    }

    /// The rollover counter for a sequence number, following the same rule
    /// as the receiver.
    fn roc_for(&self, seq: u16) -> u32 {
        let (roc, s_l) = self.roc_and_seq();
        let ahead = seq.wrapping_sub(s_l);
        if s_l < 0x8000 {
            if ahead > 0x8000 {
                roc.wrapping_sub(1)
            } else {
                roc
            }
        } else if ahead > 0x8000 {
            roc.wrapping_add(1)
        } else {
            roc
        }
    }

    fn roc_and_seq(&self) -> (u32, u16) {
        if self.index == 0 {
            return (0, 0);
        }
        let index = self.index - 1;
        ((index >> 16) as u32, (index & 0xffff) as u16)
    }
}

/// The sending half of SRTCP: encrypts and authenticates the feedback we
/// send back to the Mac.
///
/// The keys come from the same 46 byte blob as the media keys, but with
/// their own labels (3, 4 and 5), because the RTCP stream is keyed
/// separately from the RTP stream even though they share a socket.
///
/// The first eight bytes of an RTCP packet are the header and the sender's
/// SSRC; they travel in the clear, and the rest is encrypted. The index is
/// appended after the ciphertext and before the tag.
#[derive(Clone)]
pub struct SrtcpEncryptor {
    cipher_key: [u8; 32],
    auth_key: [u8; 20],
    salt: [u8; 14],
    /// The index of the next packet sent.
    index: u32,
}

impl SrtcpEncryptor {
    pub fn from_blob(blob: &[u8]) -> Option<Self> {
        if blob.len() != 46 {
            return None;
        }
        let mut master_key = [0u8; 32];
        let mut master_salt = [0u8; 14];
        master_key.copy_from_slice(&blob[..32]);
        master_salt.copy_from_slice(&blob[32..]);
        Some(Self {
            cipher_key: derive(&master_key, &master_salt, 3, 32).try_into().ok()?,
            auth_key: derive(&master_key, &master_salt, 4, 20).try_into().ok()?,
            salt: derive(&master_key, &master_salt, 5, 14).try_into().ok()?,
            index: 0,
        })
    }

    /// Protect one RTCP packet.
    pub fn protect(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 8 {
            return None;
        }
        let index = self.index;
        self.index = self.index.wrapping_add(1);
        let ssrc = u32::from_be_bytes(packet[4..8].try_into().ok()?);
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        iv[4] ^= (ssrc >> 24) as u8;
        iv[5] ^= (ssrc >> 16) as u8;
        iv[6] ^= (ssrc >> 8) as u8;
        iv[7] ^= ssrc as u8;
        iv[10] ^= (index >> 24) as u8;
        iv[11] ^= (index >> 16) as u8;
        iv[12] ^= (index >> 8) as u8;
        iv[13] ^= index as u8;
        let mut body = packet[..8].to_vec();
        let mut payload = packet[8..].to_vec();
        apply_keystream(&self.cipher_key, &iv, &mut payload);
        body.extend_from_slice(&payload);
        // The index travels with the packet, with the high bit set.
        body.extend_from_slice(&(0x8000_0000 | index).to_be_bytes());
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&self.auth_key).ok()?;
        mac.update(&body);
        let tag = mac.finalize().into_bytes();
        body.extend_from_slice(&tag[..10]);
        Some(body)
    }
}

fn rtp_header_len(packet: &[u8]) -> Option<usize> {
    let cc = (packet[0] & 0x0f) as usize;
    let mut len = 12 + 4 * cc;
    if len > packet.len() {
        return None;
    }
    if packet[0] & 0x10 != 0 {
        if packet.len() < len + 4 {
            return None;
        }
        let ext = u16::from_be_bytes([packet[len + 2], packet[len + 3]]) as usize;
        len += 4 + 4 * ext;
    }
    Some(len)
}

fn derive(master_key: &[u8; 32], master_salt: &[u8; 14], label: u8, out_len: usize) -> Vec<u8> {
    let cipher = Aes256::new(master_key.into());
    let mut x = [0u8; 16];
    x[..14].copy_from_slice(master_salt);
    x[7] ^= label;
    let mut out = Vec::with_capacity(out_len);
    while out.len() < out_len {
        let mut block = cipher::generic_array::GenericArray::clone_from_slice(&x);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        // Increment the 128-bit counter, big-endian.
        for byte in x.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
    out.truncate(out_len);
    out
}

fn packet_iv(salt: &[u8; 14], ssrc: u32, index: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(salt);
    iv[4] ^= (ssrc >> 24) as u8;
    iv[5] ^= (ssrc >> 16) as u8;
    iv[6] ^= (ssrc >> 8) as u8;
    iv[7] ^= ssrc as u8;
    iv[8] ^= (index >> 40) as u8;
    iv[9] ^= (index >> 32) as u8;
    iv[10] ^= (index >> 24) as u8;
    iv[11] ^= (index >> 16) as u8;
    iv[12] ^= (index >> 8) as u8;
    iv[13] ^= index as u8;
    iv
}

fn apply_keystream(key: &[u8; 32], iv: &[u8; 16], payload: &mut [u8]) {
    let cipher = Aes256::new(key.into());
    let mut counter = *iv;
    let mut offset = 0;
    while offset < payload.len() {
        let mut block = cipher::generic_array::GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut block);
        let n = (payload.len() - offset).min(16);
        for i in 0..n {
            payload[offset + i] ^= block[i];
        }
        offset += n;
        for byte in counter.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a genuine SRTP packet for a sequence number and rollover count.
    fn packet(receiver: &SrtpContext, seq: u16, roc: u32, ssrc: u32) -> Vec<u8> {
        let index = (u64::from(roc) << 16) | u64::from(seq);
        let mut payload = vec![0x65, 1, 2, 3];
        let iv = packet_iv(&receiver.salt, ssrc, index);
        apply_keystream(&receiver.cipher_key, &iv, &mut payload);
        let mut packet = vec![0x80, 0xe4];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&9u32.to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend(payload);
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&receiver.auth_key).unwrap();
        mac.update(&packet);
        mac.update(&roc.to_be_bytes());
        packet.extend_from_slice(&mac.finalize().into_bytes()[..10]);
        packet
    }

    #[test]
    fn accepts_80_bit_tag_and_rejects_tampering() {
        let mut receiver = SrtpContext::from_blob(&[42; 46]).unwrap();
        let mut payload = vec![0x65, 1, 2, 3];
        let iv = packet_iv(&receiver.salt, 7, 1);
        apply_keystream(&receiver.cipher_key, &iv, &mut payload);
        let mut packet = vec![0x80, 0xe4, 0, 1, 0, 0, 0, 9, 0, 0, 0, 7];
        packet.extend(payload);
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&receiver.auth_key).unwrap();
        mac.update(&packet);
        mac.update(&0u32.to_be_bytes());
        packet.extend_from_slice(&mac.finalize().into_bytes()[..10]);
        assert_eq!(
            receiver.unprotect(&packet).unwrap().payload,
            [0x65, 1, 2, 3]
        );
        packet[12] ^= 1;
        assert!(receiver.unprotect(&packet).is_none());
    }

    #[test]
    fn an_encrypted_feedback_packet_carries_its_index_and_tag() {
        let mut encryptor = SrtcpEncryptor::from_blob(&[7; 46]).unwrap();
        let packet = crate::rtcp::compound(
            0x1122_3344,
            &crate::rtcp::full_intra_request(0x1122_3344, 0x2222_3333, 1),
        );
        let protected = encryptor.protect(&packet).unwrap();
        // The header and the sender's SSRC travel in the clear.
        assert_eq!(&protected[..8], &packet[..8]);
        // The ciphertext, the index and the tag follow.
        assert_eq!(protected.len(), packet.len() + 4 + 10);
        let index = u32::from_be_bytes(
            protected[packet.len()..packet.len() + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(index, 0x8000_0000);
        // The second packet gets the next index.
        let second = encryptor.protect(&packet).unwrap();
        let index = u32::from_be_bytes(second[packet.len()..packet.len() + 4].try_into().unwrap());
        assert_eq!(index, 0x8000_0001);
    }

    #[test]
    fn the_feedback_keys_differ_from_the_media_keys() {
        let blob = [11u8; 46];
        let mut media = SrtpContext::from_blob(&blob).unwrap();
        let mut rtcp = SrtcpEncryptor::from_blob(&blob).unwrap();
        let packet = crate::rtcp::receiver_report(1);
        let protected = rtcp.protect(&packet).unwrap();
        // The feedback is not readable as the media stream: the media keys
        // are not the feedback keys.
        assert!(media.unprotect(&protected).is_none());
        // The header travels in the clear, and the rest is the index and
        // the tag.
        assert_eq!(&protected[..8], &packet[..8]);
        assert_eq!(protected.len(), packet.len() + 4 + 10);
    }

    #[test]
    fn a_protected_packet_is_read_back() {
        let blob = [5u8; 46];
        let mut sender = SrtpEncryptor::from_blob(&blob).unwrap();
        let mut receiver = SrtpContext::from_blob(&blob).unwrap();
        let payload = vec![0x65, 0xaa, 0xbb, 0xcc];
        for seq in 0..5u16 {
            let mut packet = vec![0x80, 123];
            packet.extend_from_slice(&seq.to_be_bytes());
            packet.extend_from_slice(&1000u32.to_be_bytes());
            packet.extend_from_slice(&9u32.to_be_bytes());
            packet.extend_from_slice(&payload);
            let protected = sender.protect(&packet).expect("protected");
            let rtp = receiver.unprotect(&protected).expect("authenticated");
            assert_eq!(rtp.payload, payload);
            assert_eq!(rtp.seq, seq);
        }
        // A packet that was tampered with is refused.
        let mut packet = vec![0x80, 123];
        packet.extend_from_slice(&9u16.to_be_bytes());
        packet.extend_from_slice(&1000u32.to_be_bytes());
        packet.extend_from_slice(&9u32.to_be_bytes());
        packet.extend_from_slice(&payload);
        let mut protected = sender.protect(&packet).expect("protected");
        protected[13] ^= 0x01;
        assert!(receiver.unprotect(&protected).is_none());
    }

    #[test]
    fn derived_keys_change_with_the_label() {
        let key = [9u8; 32];
        let salt = [4u8; 14];
        let a = derive(&key, &salt, 0, 32);
        let b = derive(&key, &salt, 1, 20);
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 20);
        assert_ne!(&a[..20], b.as_slice());
    }

    #[test]
    fn an_authenticated_duplicate_is_rejected() {
        let mut receiver = SrtpContext::from_blob(&[42; 46]).unwrap();
        let p = packet(&receiver, 100, 0, 7);
        assert!(receiver.unprotect(&p).is_some());
        assert!(receiver.unprotect(&p).is_none(), "a duplicate was accepted");
        assert_eq!(receiver.stats.replayed, 1);
    }

    #[test]
    fn an_unseen_late_packet_from_the_previous_cycle_is_accepted() {
        let mut receiver = SrtpContext::from_blob(&[42; 46]).unwrap();
        assert!(receiver
            .unprotect(&packet(&receiver, 65534, 0, 7))
            .is_some());
        assert!(receiver.unprotect(&packet(&receiver, 0, 1, 7)).is_some());
        assert!(
            receiver
                .unprotect(&packet(&receiver, 65535, 0, 7))
                .is_some(),
            "a valid packet from the previous rollover cycle was rejected"
        );
    }

    #[test]
    fn an_old_replay_does_not_move_the_state_backwards() {
        let mut receiver = SrtpContext::from_blob(&[42; 46]).unwrap();
        let old = packet(&receiver, 20000, 0, 7);
        assert!(receiver.unprotect(&old).is_some());
        assert!(receiver
            .unprotect(&packet(&receiver, 65534, 0, 7))
            .is_some());
        // The replay is refused and must not rewind the rollover counter.
        assert!(receiver.unprotect(&old).is_none());
        assert!(
            receiver.unprotect(&packet(&receiver, 0, 1, 7)).is_some(),
            "an old replay rewound the state and the next rollover failed"
        );
    }

    #[test]
    fn a_forged_packet_does_not_consume_a_replay_slot() {
        let mut receiver = SrtpContext::from_blob(&[42; 46]).unwrap();
        let genuine = packet(&receiver, 500, 0, 7);
        let mut forged = genuine.clone();
        forged[12] ^= 0xff;
        assert!(receiver.unprotect(&forged).is_none());
        // The genuine packet must still be accepted: a forged packet may not
        // mark a sequence number as seen.
        assert!(receiver.unprotect(&genuine).is_some());
    }

    #[test]
    fn a_packet_that_is_not_rtp_version_two_is_rejected() {
        let mut receiver = SrtpContext::from_blob(&[42; 46]).unwrap();
        let mut p = packet(&receiver, 1, 0, 7);
        p[0] = 0x40;
        assert!(receiver.unprotect(&p).is_none());
        assert_eq!(receiver.stats.malformed, 1);
    }

    /// A protected packet whose payload, padding included, is encrypted as
    /// one region, the way a sender writes it.
    fn padded_for(receiver: &SrtpContext, plain: &[u8], seq: u16, index: u64) -> Vec<u8> {
        let mut payload = plain.to_vec();
        let iv = packet_iv(&receiver.salt, 7, index);
        apply_keystream(&receiver.cipher_key, &iv, &mut payload);
        let mut p = vec![0x80 | 0x20, 0xe4];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&9u32.to_be_bytes());
        p.extend_from_slice(&7u32.to_be_bytes());
        p.extend(payload);
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&receiver.auth_key).unwrap();
        mac.update(&p);
        mac.update(&0u32.to_be_bytes());
        p.extend_from_slice(&mac.finalize().into_bytes()[..10]);
        p
    }

    #[test]
    fn padding_is_removed_from_the_payload() {
        let mut receiver = SrtpContext::from_blob(&[42; 46]).unwrap();
        // Three padding bytes, counted by the last one, all encrypted.
        let p = padded_for(&receiver, &[0x65, 1, 2, 3, 0xa5, 0xa5, 3], 1, 1);
        let rtp = receiver.unprotect(&p).expect("authenticated");
        assert_eq!(rtp.payload, [0x65, 1, 2, 3]);
    }

    #[test]
    fn a_payload_that_is_only_padding_becomes_empty() {
        let mut receiver = SrtpContext::from_blob(&[42; 46]).unwrap();
        let p = padded_for(&receiver, &[1], 1, 1);
        let rtp = receiver.unprotect(&p).expect("authenticated");
        assert!(rtp.payload.is_empty());
    }

    #[test]
    fn malformed_padding_is_rejected_without_rewinding_the_stream() {
        let mut receiver = SrtpContext::from_blob(&[42; 46]).unwrap();
        // The count claims more bytes than the payload has.
        let bad = padded_for(&receiver, &[0xa5, 0xa5, 0xa5, 9], 5, 5);
        assert!(receiver.unprotect(&bad).is_none());
        assert_eq!(receiver.stats.malformed, 1);
        // An authenticated packet consumed its index, so the next genuine
        // packet is still accepted and the rollover counter is intact.
        let good = packet(&receiver, 6, 0, 7);
        assert!(receiver.unprotect(&good).is_some());
        assert!(receiver.unprotect(&packet(&receiver, 0, 1, 7)).is_some());
    }
}
