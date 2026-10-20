//! AES-128-CBC control record layer.
//!
//! One record is `u16 ciphertext_len || ciphertext`. The plaintext is
//! `u16 body_len || body || filler || 20-byte SHA-1 trailer`. The trailer is
//! `SHA-1(u32_be(seq) || plaintext without the trailer)`. Each direction is
//! one CBC stream: the last ciphertext block is the next IV. The sequence
//! counters start at 0 and are not reset when the layer is activated.

use aes::Aes128;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use sha1::{Digest, Sha1};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes128EcbDec = ecb::Decryptor<Aes128>;

const TRAILER: usize = 20;

#[derive(Debug)]
pub struct RecordLayer {
    key: [u8; 16],
    /// IV for the next record we send.
    send_iv: [u8; 16],
    /// IV for the next record we receive.
    recv_iv: [u8; 16],
    send_seq: u32,
    recv_seq: u32,
}

impl RecordLayer {
    /// Install the key and IV recovered from a rekey. Both directions start
    /// from that IV; each then walks forward on its own ciphertext.
    pub fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            key,
            send_iv: iv,
            recv_iv: iv,
            send_seq: 0,
            recv_seq: 0,
        }
    }

    /// Install a new key and IV without touching the sequence counters.
    ///
    /// The counters belong to the session, not to the key: the reference
    /// protocol describes them as session-monotonic and explicitly not reset
    /// at activation or at a rekey. A rekey that started the counters again
    /// at zero would make the next record fail its integrity check on the
    /// peer's side, and the session would end for no visible reason.
    pub fn rekey(&mut self, key: [u8; 16], iv: [u8; 16]) {
        self.key = key;
        self.send_iv = iv;
        self.recv_iv = iv;
    }

    /// The sequence number of the next record this side will send.
    pub fn send_sequence(&self) -> u32 {
        self.send_seq
    }

    /// The sequence number the next record received is expected to carry.
    pub fn recv_sequence(&self) -> u32 {
        self.recv_seq
    }

    /// The content key is also the wrap key for the next rekey.
    pub fn wrap_key(&self) -> &[u8; 16] {
        &self.key
    }

    pub fn seal(&mut self, body: &[u8]) -> Vec<u8> {
        let filler = (16 - ((2 + body.len() + TRAILER) % 16)) % 16;
        let mut plain = Vec::with_capacity(2 + body.len() + filler + TRAILER);
        plain.extend_from_slice(&(body.len() as u16).to_be_bytes());
        plain.extend_from_slice(body);
        plain.resize(plain.len() + filler, 0);
        let mut hashed = Vec::with_capacity(4 + plain.len());
        hashed.extend_from_slice(&self.send_seq.to_be_bytes());
        hashed.extend_from_slice(&plain);
        plain.extend_from_slice(&Sha1::digest(&hashed));

        let key = cipher::generic_array::GenericArray::from(self.key);
        let iv = cipher::generic_array::GenericArray::from(self.send_iv);
        let mut enc = Aes128CbcEnc::new(&key, &iv);
        let n = plain.len() / 16;
        let mut blocks =
            vec![cipher::generic_array::GenericArray::<u8, cipher::consts::U16>::default(); n];
        for (i, block) in blocks.iter_mut().enumerate() {
            block.copy_from_slice(&plain[i * 16..(i + 1) * 16]);
        }
        enc.encrypt_blocks_mut(&mut blocks);
        let mut out = Vec::with_capacity(2 + plain.len());
        out.extend_from_slice(&(plain.len() as u16).to_be_bytes());
        for (i, block) in blocks.iter().enumerate() {
            if i + 1 == blocks.len() {
                self.send_iv.copy_from_slice(block);
            }
            out.extend_from_slice(block);
        }
        self.send_seq = self.send_seq.wrapping_add(1);
        out
    }

    /// Decrypt one record. `packet` is the ciphertext only, not the length.
    pub fn open(&mut self, packet: &[u8]) -> Result<Vec<u8>, RecordError> {
        if packet.is_empty() || !packet.len().is_multiple_of(16) || packet.len() < TRAILER + 2 {
            return Err(RecordError::Length);
        }
        let key = cipher::generic_array::GenericArray::from(self.key);
        let iv = cipher::generic_array::GenericArray::from(self.recv_iv);
        let mut dec = Aes128CbcDec::new(&key, &iv);
        let n = packet.len() / 16;
        let mut blocks =
            vec![cipher::generic_array::GenericArray::<u8, cipher::consts::U16>::default(); n];
        for (i, block) in blocks.iter_mut().enumerate() {
            block.copy_from_slice(&packet[i * 16..(i + 1) * 16]);
        }
        let last_cipher = *blocks.last().expect("length checked");
        dec.decrypt_blocks_mut(&mut blocks);
        let mut plain = Vec::with_capacity(packet.len());
        for block in &blocks {
            plain.extend_from_slice(block);
        }
        let trailer_at = plain.len() - TRAILER;
        let mut hashed = Vec::with_capacity(4 + trailer_at);
        hashed.extend_from_slice(&self.recv_seq.to_be_bytes());
        hashed.extend_from_slice(&plain[..trailer_at]);
        let expect = Sha1::digest(&hashed);
        if plain[trailer_at..] != expect[..] {
            return Err(RecordError::Integrity);
        }
        let body_len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
        if 2 + body_len > trailer_at {
            return Err(RecordError::Length);
        }
        self.recv_iv = last_cipher.into();
        self.recv_seq = self.recv_seq.wrapping_add(1);
        Ok(plain[2..2 + body_len].to_vec())
    }
}

/// AES-128-ECB single-block decrypt of the two halves of a rekey body.
pub fn unwrap_rekey(
    wrap_key: &[u8; 16],
    encrypted_key: &[u8; 16],
    encrypted_iv: &[u8; 16],
) -> ([u8; 16], [u8; 16]) {
    let key = cipher::generic_array::GenericArray::from(*wrap_key);
    let mut key_block =
        cipher::generic_array::GenericArray::<u8, cipher::consts::U16>::clone_from_slice(
            encrypted_key,
        );
    let mut iv_block =
        cipher::generic_array::GenericArray::<u8, cipher::consts::U16>::clone_from_slice(
            encrypted_iv,
        );
    // Independent blocks: a fresh ECB decryptor for each half.
    Aes128EcbDec::new(&key).decrypt_block_mut(&mut key_block);
    Aes128EcbDec::new(&key).decrypt_block_mut(&mut iv_block);
    (key_block.into(), iv_block.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("record length is not a positive multiple of the AES block")]
    Length,
    #[error("record integrity check failed")]
    Integrity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::BlockEncryptMut;

    #[test]
    fn a_record_round_trips_and_the_iv_advances() {
        let mut a = RecordLayer::new([0x11; 16], [0x22; 16]);
        let mut b = RecordLayer::new([0x11; 16], [0x22; 16]);
        let first = a.seal(b"hello apple");
        let second = a.seal(&[0x1d, 0x00, 0x00, 0x04]);
        let body1 = b.open(&first[2..]).unwrap();
        let body2 = b.open(&second[2..]).unwrap();
        assert_eq!(body1, b"hello apple");
        assert_eq!(body2, [0x1d, 0x00, 0x00, 0x04]);
        // A receiver that reset the IV between records would fail the second.
        assert_ne!(a.send_iv, [0x22; 16]);
    }

    #[test]
    fn a_tampered_record_is_rejected() {
        let mut a = RecordLayer::new([7; 16], [9; 16]);
        let mut b = RecordLayer::new([7; 16], [9; 16]);
        let mut packet = a.seal(b"intact");
        packet[4] ^= 0x01;
        assert_eq!(b.open(&packet[2..]), Err(RecordError::Integrity));
    }

    #[test]
    fn a_rekey_keeps_the_sequence_counters() {
        // The counters belong to the session. A rekey that started them
        // again at zero would make the next record fail its integrity check
        // on the peer's side, and the session would end for no visible
        // reason.
        let mut a = RecordLayer::new([0x11; 16], [0x22; 16]);
        let mut b = RecordLayer::new([0x11; 16], [0x22; 16]);
        let before = a.seal(b"before the rekey");
        assert_eq!(b.open(&before[2..]).unwrap(), b"before the rekey");
        assert_eq!(a.send_sequence(), 1);
        assert_eq!(b.recv_sequence(), 1);
        a.rekey([0x33; 16], [0x44; 16]);
        b.rekey([0x33; 16], [0x44; 16]);
        assert_eq!(
            a.send_sequence(),
            1,
            "the send counter was reset by the rekey"
        );
        assert_eq!(
            b.recv_sequence(),
            1,
            "the receive counter was reset by the rekey"
        );
        // And the session carries on across the rekey.
        let packet = a.seal(b"after the rekey");
        assert_eq!(b.open(&packet[2..]).unwrap(), b"after the rekey");
    }

    #[test]
    fn rekey_halves_decrypt_independently() {
        let wrap = [3u8; 16];
        let mut enc = ecb::Encryptor::<Aes128>::new((&wrap).into());
        let mut key = cipher::generic_array::GenericArray::clone_from_slice(&[1u8; 16]);
        let mut iv = cipher::generic_array::GenericArray::clone_from_slice(&[2u8; 16]);
        let plain_key = key;
        let plain_iv = iv;
        enc.encrypt_block_mut(&mut key);
        ecb::Encryptor::<Aes128>::new((&wrap).into()).encrypt_block_mut(&mut iv);
        let (got_key, got_iv) = unwrap_rekey(&wrap, &key.into(), &iv.into());
        assert_eq!(got_key, plain_key.as_slice());
        assert_eq!(got_iv, plain_iv.as_slice());
    }
}
