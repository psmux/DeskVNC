//! The AES-128 record layer macOS Screen Sharing switches to after its
//! cleartext prelude.
//!
//! Each record on the wire is `u16 cipher_len` followed by `cipher_len` bytes
//! of AES-128-CBC ciphertext, `cipher_len` a non-zero multiple of 16. Its
//! plaintext is
//!
//! ```text
//! u16 body_len | body | filler | SHA-1(u32 seq | everything before this)
//! ```
//!
//! with the filler (random, never checked) just long enough to make the
//! whole a multiple of 16. Both directions use the same key. Each starts its
//! CBC chain from the same IV and keeps it running across records, so the
//! last ciphertext block of one record is the IV of the next. Each direction
//! counts its records from zero for the check value.
//!
//! The key and IV come from a rekey message (encoding 1103) the server sends
//! as a FramebufferUpdate rectangle. Its 32 bytes of payload after the
//! generation word are the key and the IV, each one AES block encrypted under
//! the current wrap key. After a rekey the new content key is the wrap key
//! for the next one.
//!
//! One client message is always one record, and a record never carries two
//! messages. Server messages can run across several records; their bodies
//! are simply concatenated, which is what [`RecordStream`]'s read side does.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use parking_lot::Mutex;
use rand::Rng;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroize;

use vnc_transport::BoxedStream;

use crate::error::{Result, VncError};

/// Bytes of the SHA-1 check value at the end of every record.
pub const CHECK_LEN: usize = 20;
/// Largest ciphertext a u16 length can describe that is a multiple of 16.
pub const MAX_CIPHER: usize = 0xFFF0;
/// Largest body one record can carry.
pub const MAX_BODY: usize = MAX_CIPHER - 2 - CHECK_LEN;
/// Size of the rekey rectangle's payload.
pub const REKEY_LEN: usize = 36;

const BLOCK: usize = 16;

/// What a rekey message carries, once unwrapped.
#[derive(Clone, PartialEq, Eq)]
pub struct ContentKeys {
    pub generation: u32,
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

impl std::fmt::Debug for ContentKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentKeys")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Drop for ContentKeys {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

/// Unwrap a rekey payload: `u32 generation, wrapped key, wrapped IV`, the two
/// 16-byte values each AES-128 decrypted on its own under `wrap_key`.
pub fn unwrap_rekey(wrap_key: &[u8; 16], payload: &[u8]) -> Result<ContentKeys> {
    if payload.len() != REKEY_LEN {
        return Err(VncError::Protocol(format!(
            "rekey payload is {} bytes, expected {REKEY_LEN}",
            payload.len()
        )));
    }
    let generation = u32::from_be_bytes(payload[..4].try_into().expect("four bytes"));
    let cipher = Aes128::new(GenericArray::from_slice(wrap_key));
    let mut key = GenericArray::clone_from_slice(&payload[4..20]);
    let mut iv = GenericArray::clone_from_slice(&payload[20..36]);
    cipher.decrypt_block(&mut key);
    cipher.decrypt_block(&mut iv);
    let out = ContentKeys {
        generation,
        key: key.into(),
        iv: iv.into(),
    };
    if out.key.iter().all(|b| *b == 0) {
        return Err(VncError::Protocol(
            "rekey produced an all-zero content key".into(),
        ));
    }
    Ok(out)
}

/// One direction of the record layer: its cipher, CBC chain and counter.
pub struct Direction {
    cipher: Aes128,
    chain: [u8; BLOCK],
    seq: u32,
}

impl Direction {
    pub fn new(keys: &ContentKeys, seq: u32) -> Self {
        Self {
            cipher: Aes128::new(GenericArray::from_slice(&keys.key)),
            chain: keys.iv,
            seq,
        }
    }

    pub fn seq(&self) -> u32 {
        self.seq
    }

    fn check_value(seq: u32, plain: &[u8]) -> [u8; CHECK_LEN] {
        let mut h = Sha1::new();
        h.update(seq.to_be_bytes());
        h.update(plain);
        h.finalize().into()
    }

    /// Filler that brings `2 + body_len + 20` up to a multiple of 16.
    pub fn filler_len(body_len: usize) -> usize {
        (BLOCK - (2 + body_len + CHECK_LEN) % BLOCK) % BLOCK
    }

    /// Encrypt one record, returning it with its u16 length prefix.
    pub fn seal(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        if body.len() > MAX_BODY {
            return Err(VncError::Protocol(format!(
                "a {} byte message does not fit one record ({MAX_BODY} max)",
                body.len()
            )));
        }
        let fill = Self::filler_len(body.len());
        let total = 2 + body.len() + fill + CHECK_LEN;
        let mut out = Vec::with_capacity(2 + total);
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        let start = out.len();
        out.resize(start + fill, 0);
        rand::rng().fill_bytes(&mut out[start..]);
        let check = Self::check_value(self.seq, &out[2..]);
        out.extend_from_slice(&check);
        self.seq = self.seq.wrapping_add(1);

        for block in out[2..].as_chunks_mut::<BLOCK>().0 {
            for (b, c) in block.iter_mut().zip(self.chain.iter()) {
                *b ^= c;
            }
            self.cipher
                .encrypt_block(GenericArray::from_mut_slice(&mut block[..]));
            self.chain = *block;
        }
        Ok(out)
    }

    /// Decrypt one record's ciphertext (without its length prefix) and
    /// return its body.
    pub fn open(&mut self, cipher: &[u8]) -> Result<Vec<u8>> {
        if cipher.is_empty() || !cipher.len().is_multiple_of(BLOCK) {
            return Err(VncError::Protocol(format!(
                "record of {} bytes is not a whole number of AES blocks",
                cipher.len()
            )));
        }
        let mut plain = cipher.to_vec();
        for block in plain.as_chunks_mut::<BLOCK>().0 {
            let next_chain = *block;
            self.cipher
                .decrypt_block(GenericArray::from_mut_slice(&mut block[..]));
            for (b, c) in block.iter_mut().zip(self.chain.iter()) {
                *b ^= c;
            }
            self.chain = next_chain;
        }
        if plain.len() < 2 + CHECK_LEN {
            return Err(VncError::Protocol("record is too short".into()));
        }
        let body_len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
        let checked = plain.len() - CHECK_LEN;
        if 2 + body_len > checked {
            return Err(VncError::Protocol(format!(
                "record claims a {body_len} byte body in {} bytes",
                plain.len()
            )));
        }
        let expected = Self::check_value(self.seq, &plain[..checked]);
        if expected[..] != plain[checked..] {
            // Close without saying why; the caller tears the session down.
            return Err(VncError::Protocol(
                "record failed its integrity check".into(),
            ));
        }
        self.seq = self.seq.wrapping_add(1);
        Ok(plain[2..2 + body_len].to_vec())
    }
}

/// The record layer state both halves of the stream share with the rekey
/// handle.
struct Shared {
    send: Direction,
    recv: Direction,
    wrap_key: [u8; 16],
    generation: u32,
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.wrap_key.zeroize();
    }
}

/// Lets the session apply a rekey that arrives inside the record layer.
#[derive(Clone)]
pub struct RekeyHandle(Arc<Mutex<Shared>>);

impl std::fmt::Debug for RekeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RekeyHandle").finish_non_exhaustive()
    }
}

impl RekeyHandle {
    /// Install the keys from a rekey payload for both directions.
    ///
    /// The sequence counters keep running. Whether a Mac ever sends a second
    /// rekey, and whether it restarts the IV or the counters when it does, is
    /// unconfirmed; this restarts both chains from the new IV and keeps the
    /// counters, which is the reading that changes the least.
    pub fn rekey(&self, payload: &[u8]) -> Result<u32> {
        let mut s = self.0.lock();
        let keys = unwrap_rekey(&s.wrap_key, payload)?;
        let send_seq = s.send.seq;
        let recv_seq = s.recv.seq;
        s.send = Direction::new(&keys, send_seq);
        s.recv = Direction::new(&keys, recv_seq);
        s.wrap_key = keys.key;
        s.generation = keys.generation;
        tracing::info!(generation = keys.generation, "Apple session rekeyed");
        Ok(keys.generation)
    }

    pub fn generation(&self) -> u32 {
        self.0.lock().generation
    }
}

/// An RFB byte stream carried inside the record layer.
///
/// Reads decrypt one record at a time, and only when the caller has consumed
/// everything from the previous one. That matters for a rekey that arrives
/// inside the layer: the record after it must be opened with the new key,
/// and it can only be if it has not been opened already. A `BufReader` on
/// top keeps this property, because it asks for more only once its buffer
/// is empty and every read here returns at most one record.
///
/// Every `poll_write` becomes exactly one record, so callers must hand over
/// one whole client message per write call, which `write_all` with a
/// complete message does.
pub struct RecordStream {
    inner: BoxedStream,
    shared: Arc<Mutex<Shared>>,
    /// Ciphertext read from the socket and not yet opened.
    raw: Vec<u8>,
    /// Plaintext of the current record not yet handed to the caller.
    plain: Vec<u8>,
    plain_pos: usize,
    /// A sealed record not yet fully written.
    out: Vec<u8>,
    out_pos: usize,
    /// The socket hit end of file.
    eof: bool,
}

impl RecordStream {
    /// Start the record layer with the keys from the first rekey. `wrap_key`
    /// is the key that unwraps the next one, which is the content key.
    pub fn new(inner: BoxedStream, keys: &ContentKeys) -> (Self, RekeyHandle) {
        Self::with_leftover(inner, keys, Vec::new())
    }

    /// As [`Self::new`], with ciphertext bytes already read off the socket
    /// during the prelude.
    pub fn with_leftover(
        inner: BoxedStream,
        keys: &ContentKeys,
        leftover: Vec<u8>,
    ) -> (Self, RekeyHandle) {
        let shared = Arc::new(Mutex::new(Shared {
            send: Direction::new(keys, 0),
            recv: Direction::new(keys, 0),
            wrap_key: keys.key,
            generation: keys.generation,
        }));
        (
            Self {
                inner,
                shared: shared.clone(),
                raw: leftover,
                plain: Vec::new(),
                plain_pos: 0,
                out: Vec::new(),
                out_pos: 0,
                eof: false,
            },
            RekeyHandle(shared),
        )
    }

    /// Length of the first complete record in `raw`, if there is one.
    fn complete_record(&self) -> std::io::Result<Option<usize>> {
        if self.raw.len() < 2 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([self.raw[0], self.raw[1]]) as usize;
        if len == 0 || !len.is_multiple_of(BLOCK) {
            return Err(invalid(format!(
                "record length {len} is not a non-zero multiple of 16"
            )));
        }
        Ok((self.raw.len() >= 2 + len).then_some(len))
    }

    /// Flush the pending sealed record. Ready once it is all written.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

fn invalid(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

impl AsyncRead for RecordStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        loop {
            if me.plain_pos < me.plain.len() {
                let n = (me.plain.len() - me.plain_pos).min(buf.remaining());
                buf.put_slice(&me.plain[me.plain_pos..me.plain_pos + n]);
                me.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if let Some(len) = me.complete_record()? {
                let opened = me.shared.lock().recv.open(&me.raw[2..2 + len]);
                me.raw.drain(..2 + len);
                me.plain = opened.map_err(|e| invalid(e.to_string()))?;
                me.plain_pos = 0;
                // An empty body is legal; go round for the next record rather
                // than return zero bytes, which would read as end of file.
                continue;
            }
            if me.eof {
                if me.raw.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
            }
            let mut chunk = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut chunk);
            match Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        me.eof = true;
                    } else {
                        me.raw.extend_from_slice(rb.filled());
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RecordStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = &mut *self;
        match me.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other.map(|r| r.map(|_| 0)),
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // A message larger than one record has to be split. That breaks the
        // one message per record rule, but only a clipboard of more than 64
        // KB can get here, and losing the paste beats losing the session.
        let n = buf.len().min(MAX_BODY);
        if n < buf.len() {
            tracing::warn!(
                len = buf.len(),
                "client message larger than one Apple record; splitting it"
            );
        }
        let sealed = me
            .shared
            .lock()
            .send
            .seal(&buf[..n])
            .map_err(|e| invalid(e.to_string()))?;
        me.out = sealed;
        me.out_pos = 0;
        // Start writing straight away; whatever does not go now goes on the
        // next write or flush.
        match me.poll_drain(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(n)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        match me.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        match me.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Wrap `keys` the way a server does, for tests and the fake server.
pub fn wrap_rekey(wrap_key: &[u8; 16], keys: &ContentKeys) -> [u8; REKEY_LEN] {
    let cipher = Aes128::new(GenericArray::from_slice(wrap_key));
    let mut out = [0u8; REKEY_LEN];
    out[..4].copy_from_slice(&keys.generation.to_be_bytes());
    let mut k = GenericArray::clone_from_slice(&keys.key);
    let mut v = GenericArray::clone_from_slice(&keys.iv);
    cipher.encrypt_block(&mut k);
    cipher.encrypt_block(&mut v);
    out[4..20].copy_from_slice(&k);
    out[20..].copy_from_slice(&v);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn keys(seed: u8) -> ContentKeys {
        ContentKeys {
            generation: 1,
            key: [seed; 16],
            iv: [seed.wrapping_add(1); 16],
        }
    }

    #[test]
    fn filler_reaches_a_block_boundary_with_the_minimum() {
        for body in 0..64 {
            let f = Direction::filler_len(body);
            assert!(f < 16);
            assert_eq!((2 + body + f + CHECK_LEN) % 16, 0, "body {body}");
        }
        // 2 + 10 + 20 = 32 already aligned: no filler at all.
        assert_eq!(Direction::filler_len(10), 0);
    }

    #[test]
    fn seal_then_open_round_trips_and_counts() {
        let k = keys(3);
        let mut tx = Direction::new(&k, 0);
        let mut rx = Direction::new(&k, 0);
        for i in 0..5u8 {
            let body = vec![i; 7 + i as usize * 13];
            let rec = tx.seal(&body).unwrap();
            let len = u16::from_be_bytes([rec[0], rec[1]]) as usize;
            assert_eq!(len + 2, rec.len());
            assert_eq!(len % 16, 0);
            assert_eq!(rx.open(&rec[2..]).unwrap(), body);
        }
        assert_eq!(tx.seq(), 5);
        assert_eq!(rx.seq(), 5);
    }

    /// The chain runs across records: the IV of record n + 1 is the last
    /// ciphertext block of record n, not the starting IV again.
    #[test]
    fn cbc_chaining_carries_across_records() {
        let k = keys(9);
        let mut tx = Direction::new(&k, 0);
        let first = tx.seal(b"one").unwrap();
        let second = tx.seal(b"two").unwrap();

        // Decrypt the second record by hand with the first's last block as IV.
        let cipher = Aes128::new(GenericArray::from_slice(&k.key));
        let mut chain: [u8; 16] = first[first.len() - 16..].try_into().unwrap();
        let mut plain = second[2..].to_vec();
        for block in plain.as_chunks_mut::<16>().0 {
            let saved = *block;
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut block[..]));
            for (b, c) in block.iter_mut().zip(chain.iter()) {
                *b ^= c;
            }
            chain = saved;
        }
        assert_eq!(&plain[..5], &[0, 3, b't', b'w', b'o']);

        // A receiver that resets to the starting IV for record two fails.
        let mut fresh = Direction::new(&k, 1);
        assert!(fresh.open(&second[2..]).is_err());
    }

    /// The check value is plain SHA-1 over the counter and the plaintext up
    /// to the check value, filler included.
    #[test]
    fn check_value_is_sha1_over_seq_and_plaintext() {
        let k = keys(5);
        let mut tx = Direction::new(&k, 41);
        let rec = tx.seal(b"hello").unwrap();
        let cipher = Aes128::new(GenericArray::from_slice(&k.key));
        let mut chain = k.iv;
        let mut plain = rec[2..].to_vec();
        for block in plain.as_chunks_mut::<16>().0 {
            let saved = *block;
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut block[..]));
            for (b, c) in block.iter_mut().zip(chain.iter()) {
                *b ^= c;
            }
            chain = saved;
        }
        let split = plain.len() - 20;
        let mut h = Sha1::new();
        h.update(41u32.to_be_bytes());
        h.update(&plain[..split]);
        assert_eq!(h.finalize()[..], plain[split..]);
    }

    #[test]
    fn a_corrupt_record_is_refused() {
        let k = keys(1);
        let mut tx = Direction::new(&k, 0);
        let mut rec = tx.seal(b"payload").unwrap();
        let last = rec.len() - 1;
        rec[last] ^= 0x01;
        let mut rx = Direction::new(&k, 0);
        assert!(matches!(rx.open(&rec[2..]), Err(VncError::Protocol(_))));
    }

    #[test]
    fn a_record_out_of_sequence_is_refused() {
        let k = keys(1);
        let mut tx = Direction::new(&k, 0);
        let rec = tx.seal(b"payload").unwrap();
        // Same key and IV, wrong counter: the check value cannot match.
        let mut rx = Direction::new(&k, 7);
        assert!(rx.open(&rec[2..]).is_err());
    }

    #[test]
    fn misaligned_and_empty_records_are_refused() {
        let mut rx = Direction::new(&keys(1), 0);
        assert!(rx.open(&[]).is_err());
        assert!(rx.open(&[0u8; 17]).is_err());
    }

    #[test]
    fn rekey_unwraps_with_aes_ecb_per_block() {
        let wrap = [0x42u8; 16];
        let k = keys(0x11);
        let payload = wrap_rekey(&wrap, &k);
        assert_eq!(&payload[..4], &[0, 0, 0, 1]);
        let got = unwrap_rekey(&wrap, &payload).unwrap();
        assert_eq!(got, k);
        // The two blocks are independent: changing the IV's ciphertext leaves
        // the key alone, which CBC unwrapping would not.
        let mut p2 = payload;
        p2[25] ^= 0xff;
        let got2 = unwrap_rekey(&wrap, &p2).unwrap();
        assert_eq!(got2.key, k.key);
        assert_ne!(got2.iv, k.iv);
        assert!(unwrap_rekey(&wrap, &payload[..35]).is_err());
    }

    /// End to end through the stream: messages are records, bodies come out
    /// concatenated, a truncated record waits, and a rekey through the handle
    /// takes effect from the next record.
    #[tokio::test]
    async fn stream_round_trip_and_rekey() {
        let (a, mut b) = tokio::io::duplex(1 << 16);
        let k = keys(7);
        let (mut stream, handle) = RecordStream::new(Box::pin(a), &k);

        // Client to server: one write, one record.
        stream
            .write_all(b"\x04\x01\x00\x00\x00\x00\x00\x61")
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let mut server_rx = Direction::new(&k, 0);
        let mut len = [0u8; 2];
        b.read_exact(&mut len).await.unwrap();
        let mut rec = vec![0u8; u16::from_be_bytes(len) as usize];
        b.read_exact(&mut rec).await.unwrap();
        assert_eq!(
            server_rx.open(&rec).unwrap(),
            b"\x04\x01\x00\x00\x00\x00\x00\x61"
        );

        // Server to client: a message split over two records reads as one.
        let mut server_tx = Direction::new(&k, 0);
        let r1 = server_tx.seal(b"abc").unwrap();
        let r2 = server_tx.seal(b"defg").unwrap();
        // Deliver the second record in two pieces to exercise truncation.
        b.write_all(&r1).await.unwrap();
        b.write_all(&r2[..5]).await.unwrap();
        let mut got = [0u8; 3];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"abc");
        b.write_all(&r2[5..]).await.unwrap();
        let mut got = [0u8; 4];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"defg");

        // Rekey: the next record uses the new key, chains from the new IV,
        // and the counters carry on.
        let next = ContentKeys {
            generation: 2,
            key: [0x55; 16],
            iv: [0x66; 16],
        };
        let wrapped = wrap_rekey(&k.key, &next);
        assert_eq!(handle.rekey(&wrapped).unwrap(), 2);
        let mut server_tx = Direction::new(&next, server_tx.seq());
        b.write_all(&server_tx.seal(b"after").unwrap())
            .await
            .unwrap();
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"after");
        assert_eq!(handle.generation(), 2);
    }

    /// A record whose check value is wrong ends the stream with an error.
    #[tokio::test]
    async fn stream_refuses_a_tampered_record() {
        let (a, mut b) = tokio::io::duplex(4096);
        let k = keys(2);
        let (mut stream, _h) = RecordStream::new(Box::pin(a), &k);
        let mut tx = Direction::new(&k, 0);
        let mut rec = tx.seal(b"xyz").unwrap();
        rec[4] ^= 0x80;
        b.write_all(&rec).await.unwrap();
        let mut got = [0u8; 3];
        assert!(stream.read_exact(&mut got).await.is_err());
    }

    /// A record length that is not a multiple of 16 is refused before any
    /// decryption.
    #[tokio::test]
    async fn stream_refuses_a_bad_length() {
        let (a, mut b) = tokio::io::duplex(4096);
        let (mut stream, _h) = RecordStream::new(Box::pin(a), &keys(2));
        b.write_all(&[0x00, 0x11]).await.unwrap();
        b.write_all(&[0u8; 0x11]).await.unwrap();
        let mut got = [0u8; 1];
        assert!(stream.read_exact(&mut got).await.is_err());
    }

    /// The socket closing halfway through a record is an error, not a short
    /// read that looks like a clean end.
    #[tokio::test]
    async fn stream_reports_a_record_cut_short() {
        let (a, mut b) = tokio::io::duplex(4096);
        let k = keys(2);
        let (mut stream, _h) = RecordStream::new(Box::pin(a), &k);
        let mut tx = Direction::new(&k, 0);
        let rec = tx.seal(b"truncated").unwrap();
        b.write_all(&rec[..rec.len() - 3]).await.unwrap();
        drop(b);
        let mut got = [0u8; 1];
        let err = stream.read_exact(&mut got).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
