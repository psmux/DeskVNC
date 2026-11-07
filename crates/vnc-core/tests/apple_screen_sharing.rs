//! macOS Screen Sharing security types 33 and 36 and the encrypted session,
//! end to end against a fake Mac.
//!
//! The fake server is written from the protocol description alone and shares
//! no code with the client beyond the public message builders it uses to
//! check what it receives: its SRP side uses the server's own equations
//! (`B = kv + g^b`, `S = (A v^u)^b`) in plain `BigUint` arithmetic, and its
//! record layer is a second implementation of the AES-CBC framing. A client
//! that agrees with it has had every formula checked from the other side.
//!
//! Some of what the fake server insists on is known from a single source or
//! is disputed, and only a real Mac can settle it. Each such point is listed
//! in [`live_must_confirm`] with a test that pins the current reading, so a
//! live run that disagrees changes one named test.

#[allow(unused_imports)]
mod common;

use std::sync::Arc;
use std::time::Duration;

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use num_bigint_dig::BigUint;
use parking_lot::Mutex;
use rand::Rng;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::*;
use vnc_core::apple::wire as apple_wire;
use vnc_core::proto::messages::encode_pixel_format;
use vnc_core::security::apple_srp::{GROUP_4096_G, GROUP_4096_HEX};
use vnc_core::security::select_security_type;
use vnc_core::types::{
    ClientCommand, ConnectOptions, Credentials, PinScheme, PixelFormat, SecurityType, SessionEvent,
};

const USER: &str = "tester";
const PASSWORD: &str = "correct horse battery";
const OPTIONS: &[u8] =
    b"mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2";
const ITERATIONS: u64 = 1000;
const WIDTH: u16 = 64;
const HEIGHT: u16 = 48;

// ---------------------------------------------------------------------------
// The fake server's own SRP, written from the server's side
// ---------------------------------------------------------------------------

fn h512(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

fn pad512(v: &BigUint) -> Vec<u8> {
    let b = v.to_bytes_be();
    let mut out = vec![0u8; 512 - b.len()];
    out.extend_from_slice(&b);
    out
}

struct ServerSrp {
    n: BigUint,
    g: BigUint,
    salt: Vec<u8>,
    v: BigUint,
    b: BigUint,
    b_pub: BigUint,
}

impl ServerSrp {
    /// What the Mac stores for an account (salt and verifier) and the
    /// server's ephemeral key pair.
    fn new(password: &str) -> Self {
        let n = BigUint::parse_bytes(GROUP_4096_HEX.as_bytes(), 16).unwrap();
        let g = BigUint::from(GROUP_4096_G);
        let mut salt = vec![0u8; 32];
        rand::rng().fill_bytes(&mut salt);
        let mut derived = [0u8; 128];
        pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), &salt, ITERATIONS as u32, &mut derived);
        let inner = h512(&[b":", &derived]);
        let x = BigUint::from_bytes_be(&h512(&[&salt, &inner]));
        let v = g.modpow(&x, &n);
        let k = BigUint::from_bytes_be(&h512(&[&pad512(&n), &pad512(&g)]));
        let mut b_bytes = [0u8; 64];
        rand::rng().fill_bytes(&mut b_bytes);
        let b = BigUint::from_bytes_be(&b_bytes);
        let b_pub = (k * &v + g.modpow(&b, &n)) % &n;
        Self {
            n,
            g,
            salt,
            v,
            b,
            b_pub,
        }
    }

    /// The challenge payload: control, N, g, salt, B, iterations, options.
    fn challenge(&self) -> Vec<u8> {
        let mut p = vec![0u8];
        let n = self.n.to_bytes_be();
        p.extend_from_slice(&(n.len() as u16).to_be_bytes());
        p.extend_from_slice(&n);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.push(GROUP_4096_G as u8);
        p.push(self.salt.len() as u8);
        p.extend_from_slice(&self.salt);
        p.extend_from_slice(&512u16.to_be_bytes());
        p.extend_from_slice(&pad512(&self.b_pub));
        p.extend_from_slice(&ITERATIONS.to_be_bytes());
        p.extend_from_slice(&(OPTIONS.len() as u16).to_be_bytes());
        p.extend_from_slice(OPTIONS);
        p
    }

    /// Check the client's M1 and return `(M2, K)`, or `None` if it is wrong.
    fn verify(&self, a_pub: &[u8], m1: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let a = BigUint::from_bytes_be(a_pub);
        let u = BigUint::from_bytes_be(&h512(&[&pad512(&a), &pad512(&self.b_pub)]));
        let s = (a * self.v.modpow(&u, &self.n)).modpow(&self.b, &self.n);
        let key = h512(&[&pad512(&s)]);
        let hn = h512(&[&self.n.to_bytes_be()]);
        let hg = h512(&[&pad512(&self.g)]);
        let xor: Vec<u8> = hn.iter().zip(&hg).map(|(x, y)| x ^ y).collect();
        let expected = h512(&[
            &xor,
            &h512(&[b""]),
            &self.salt,
            a_pub,
            &pad512(&self.b_pub),
            &key,
        ]);
        if expected != m1 {
            return None;
        }
        let m2 = h512(&[a_pub, m1, &key]);
        Some((m2, key))
    }
}

/// A server SRP message as a Mac sends it. Inside is always `u32 len,
/// payload`; type 33 puts `u32 total, u16 0, u16 2, u16 len` in front of
/// that, type 36 only `u32 len`. Both shapes were read off a real Mac.
fn server_frame(login: Login, payload: &[u8]) -> Vec<u8> {
    let mut buffer = (payload.len() as u32).to_be_bytes().to_vec();
    buffer.extend_from_slice(payload);
    let mut f = Vec::new();
    match login {
        Login::Rsa33 => {
            f.extend_from_slice(&((6 + buffer.len()) as u32).to_be_bytes());
            f.extend_from_slice(&[0, 0, 0, 2]);
            f.extend_from_slice(&(buffer.len() as u16).to_be_bytes());
        }
        Login::Srp36 => f.extend_from_slice(&(buffer.len() as u32).to_be_bytes()),
    }
    f.extend_from_slice(&buffer);
    f
}

/// `n` bytes that must already be waiting. A Mac takes the type byte of its
/// SRP logins and the first message from one read, and drops a client whose
/// first message is not there yet.
fn read_waiting(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match s.try_read(&mut b[got..]) {
            Ok(0) => panic!("client closed"),
            Ok(k) => got += k,
            Err(e) => panic!("the first message did not travel with the type byte: {e}"),
        }
    }
    b
}

fn server_proof_payload(m2: &[u8]) -> Vec<u8> {
    let mut p = vec![m2.len() as u8];
    p.extend_from_slice(m2);
    p.push(16);
    p.extend_from_slice(&[0x5a; 16]);
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p
}

// ---------------------------------------------------------------------------
// The fake server's own record layer
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Dir {
    key: [u8; 16],
    chain: [u8; 16],
    seq: u32,
}

impl Dir {
    fn new(key: [u8; 16], iv: [u8; 16], seq: u32) -> Self {
        Self {
            key,
            chain: iv,
            seq,
        }
    }

    fn seal(&mut self, body: &[u8]) -> Vec<u8> {
        let mut plain = (body.len() as u16).to_be_bytes().to_vec();
        plain.extend_from_slice(body);
        while !(plain.len() + 20).is_multiple_of(16) {
            plain.push(0xA5);
        }
        let mut h = Sha1::new();
        h.update(self.seq.to_be_bytes());
        h.update(&plain);
        plain.extend_from_slice(&h.finalize());
        self.seq += 1;
        let aes = Aes128::new(GenericArray::from_slice(&self.key));
        for block in plain.as_chunks_mut::<16>().0 {
            for (b, c) in block.iter_mut().zip(self.chain) {
                *b ^= c;
            }
            aes.encrypt_block(GenericArray::from_mut_slice(&mut block[..]));
            self.chain = *block;
        }
        let mut out = (plain.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&plain);
        out
    }

    fn open(&mut self, cipher: &[u8]) -> Option<Vec<u8>> {
        let aes = Aes128::new(GenericArray::from_slice(&self.key));
        let mut plain = cipher.to_vec();
        let mut chain = self.chain;
        for block in plain.as_chunks_mut::<16>().0 {
            let saved = *block;
            aes.decrypt_block(GenericArray::from_mut_slice(&mut block[..]));
            for (b, c) in block.iter_mut().zip(chain) {
                *b ^= c;
            }
            chain = saved;
        }
        let split = plain.len() - 20;
        let mut h = Sha1::new();
        h.update(self.seq.to_be_bytes());
        h.update(&plain[..split]);
        if h.finalize()[..] != plain[split..] {
            return None;
        }
        let len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
        self.chain = chain;
        self.seq += 1;
        Some(plain[2..2 + len].to_vec())
    }
}

/// Wrap a content key and IV for a rekey: `u32 generation`, then each value
/// AES encrypted on its own under the wrap key.
fn rekey_payload(wrap: &[u8; 16], generation: u32, key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let aes = Aes128::new(GenericArray::from_slice(wrap));
    let mut out = generation.to_be_bytes().to_vec();
    for v in [key, iv] {
        let mut b = GenericArray::clone_from_slice(v);
        aes.encrypt_block(&mut b);
        out.extend_from_slice(&b);
    }
    out
}

/// `(x, y, w, h, encoding, body)` of one rectangle.
type RectBytes = (u16, u16, u16, u16, i32, Vec<u8>);

fn fbu(rects: &[RectBytes]) -> Vec<u8> {
    let mut m = vec![0, 0];
    m.extend_from_slice(&(rects.len() as u16).to_be_bytes());
    for (x, y, w, h, enc, body) in rects {
        for v in [x, y, w, h] {
            m.extend_from_slice(&v.to_be_bytes());
        }
        m.extend_from_slice(&enc.to_be_bytes());
        m.extend_from_slice(body);
    }
    m
}

fn raw_pixels(w: u16, h: u16, bgra: [u8; 4]) -> Vec<u8> {
    bgra.repeat(w as usize * h as usize)
}

fn layout(backing: (u16, u16), logical: (u16, u16)) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&5u16.to_be_bytes());
    b.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    b.extend_from_slice(&0x0200_0000u32.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    for v in [logical.0, logical.1, backing.0, backing.1] {
        b.extend_from_slice(&v.to_be_bytes());
    }
    let mut r = vec![0u8; 56];
    r[..8].copy_from_slice(&2.0f64.to_be_bytes());
    r[8..16].copy_from_slice(&2.0f64.to_be_bytes());
    r[16..20].copy_from_slice(&1u32.to_be_bytes());
    r[24..26].copy_from_slice(&backing.0.to_be_bytes());
    r[26..28].copy_from_slice(&backing.1.to_be_bytes());
    r[32..34].copy_from_slice(&logical.0.to_be_bytes());
    r[34..36].copy_from_slice(&logical.1.to_be_bytes());
    r[36..40].copy_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&r);
    let mut out = (b.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&b);
    out
}

/// A zlib stream ended with a sync flush and no final block, as a Mac sends
/// its clipboard.
fn zlib_flushed(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.flush().unwrap();
    e.get_ref().clone()
}

fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn clipboard_message(text: &str) -> Vec<u8> {
    let kind = b"public.utf8-plain-text";
    let mut inner = 1u32.to_be_bytes().to_vec();
    inner.extend_from_slice(&(kind.len() as u32).to_be_bytes());
    inner.extend_from_slice(kind);
    inner.extend_from_slice(&0u32.to_be_bytes());
    inner.extend_from_slice(&0u32.to_be_bytes());
    inner.extend_from_slice(&(text.len() as u32).to_be_bytes());
    inner.extend_from_slice(text.as_bytes());
    let z = zlib_flushed(&inner);
    let mut m = vec![0x1f, 0, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    m.extend_from_slice(&(z.len() as u32).to_be_bytes());
    m.extend_from_slice(&z);
    m
}

fn cursor_rect() -> RectBytes {
    // 2x2, hotspot (1, 1): BGRA then the alpha plane.
    let mut raw = Vec::new();
    for _ in 0..4 {
        raw.extend_from_slice(&[0, 0, 255, 0]);
    }
    raw.extend_from_slice(&[255, 255, 0, 0]);
    let z = zlib(&raw);
    let mut body = 1000u32.to_be_bytes().to_vec();
    body.extend_from_slice(&(z.len() as u32).to_be_bytes());
    body.extend_from_slice(&z);
    (1, 1, 2, 2, apple_wire::encoding::CURSOR, body)
}

// ---------------------------------------------------------------------------
// The fake Mac
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Login {
    Rsa33,
    Srp36,
}

#[derive(Default)]
struct Seen {
    selected: Option<u8>,
    client_banner: Option<[u8; 12]>,
    identity: Option<Vec<u8>>,
    client_init: Option<u8>,
    prelude: Vec<Vec<u8>>,
    /// Decrypted client records, in order.
    records: Vec<Vec<u8>>,
    proof_trailer: usize,
    host_key_spki: Vec<u8>,
    auth_failed: bool,
    /// Act like a Mac whose account lacks Remote Management privileges:
    /// verify the password, send the server proof, then refuse the login.
    refuse_after_proof: bool,
    /// Act like a busy Mac over a slow link: a full request is answered
    /// only after the update already in flight, and only if no incremental
    /// request replaces it first.
    busy: bool,
    /// The client replaced a full request with an incremental one before the
    /// full picture could go out.
    full_cancelled: bool,
    /// Run the short session (desktop size, full picture, then answer
    /// requests) after a type 33 login too, not only after type 36.
    short_session: bool,
}

struct FakeMac {
    port: u16,
    seen: Arc<Mutex<Seen>>,
    task: tokio::task::JoinHandle<()>,
}

async fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await.unwrap();
    b
}

async fn read_record(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await.ok()?;
    let mut c = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut c).await.ok()?;
    Some(c)
}

impl FakeMac {
    async fn start(login: Login, password: &'static str) -> Self {
        Self::start_with(login, password, false).await
    }

    async fn start_busy() -> Self {
        let mac = Self::start_with(Login::Srp36, PASSWORD, false).await;
        mac.seen.lock().busy = true;
        mac
    }

    async fn start_with(login: Login, password: &'static str, refuse_after_proof: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Seen {
            refuse_after_proof,
            ..Seen::default()
        }));
        let s2 = seen.clone();
        let key = if login == Login::Rsa33 {
            Some(
                tokio::task::spawn_blocking(|| RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap())
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            serve(&mut s, login, key, password, s2).await;
        });
        Self { port, seen, task }
    }
}

/// A fake Mac that serves one connection after another with the same host
/// key, running the short session, and drops the current connection when
/// `drop` is notified: a network blip the viewer reconnects through.
struct RedialMac {
    port: u16,
    seen: Arc<Mutex<Seen>>,
    drop: Arc<tokio::sync::Notify>,
    connections: Arc<std::sync::atomic::AtomicUsize>,
}

impl RedialMac {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Seen {
            short_session: true,
            ..Seen::default()
        }));
        let key =
            tokio::task::spawn_blocking(|| RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap())
                .await
                .unwrap();
        let drop = Arc::new(tokio::sync::Notify::new());
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (s2, d2, c2) = (seen.clone(), drop.clone(), connections.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (seen, key) = (s2.clone(), key.clone());
                tokio::select! {
                    _ = serve(&mut s, Login::Rsa33, Some(key), PASSWORD, seen) => {}
                    _ = d2.notified() => {}
                }
            }
        });
        Self {
            port,
            seen,
            drop,
            connections,
        }
    }
}

/// The busy Mac's loop after the first picture. Every request gets one
/// update. A full request is answered first with the small update that was
/// already in flight, then, if no other request replaced it within a moment,
/// with the whole screen.
async fn serve_busy(s: &mut TcpStream, tx: &mut Dir, rx: &mut Dir, seen: &Arc<Mutex<Seen>>) {
    let corner = || fbu(&[(0, 0, 3, 3, 0, raw_pixels(3, 3, [0, 0, 255, 0]))]);
    let mut next: Option<Vec<u8>> = None;
    loop {
        let body = match next.take() {
            Some(b) => b,
            None => {
                let Some(c) = read_record(s).await else {
                    return;
                };
                let Some(b) = rx.open(&c) else { return };
                seen.lock().records.push(b.clone());
                b
            }
        };
        if !(body.len() == 10 && body[0] == 3) {
            continue;
        }
        let full = body[1] == 0;
        s.write_all(&tx.seal(&corner())).await.unwrap();
        if !full {
            continue;
        }
        match tokio::time::timeout(Duration::from_millis(300), read_record(s)).await {
            Ok(Some(c)) => {
                let Some(b) = rx.open(&c) else { return };
                seen.lock().records.push(b.clone());
                if b.len() == 10 && b[0] == 3 {
                    seen.lock().full_cancelled = true;
                }
                next = Some(b);
            }
            Ok(None) => return,
            Err(_) => {
                let m = fbu(&[(
                    0,
                    0,
                    WIDTH,
                    HEIGHT,
                    0,
                    raw_pixels(WIDTH, HEIGHT, [255, 255, 255, 0]),
                )]);
                s.write_all(&tx.seal(&m)).await.unwrap();
            }
        }
    }
}

async fn serve(
    s: &mut TcpStream,
    login: Login,
    key: Option<RsaPrivateKey>,
    password: &str,
    seen: Arc<Mutex<Seen>>,
) {
    // --- version and security offer --------------------------------------
    s.write_all(b"RFB 003.889\n").await.unwrap();
    let banner: [u8; 12] = read_n(s, 12).await.try_into().unwrap();
    seen.lock().client_banner = Some(banner);
    s.write_all(&[0x04, 0x1E, 0x21, 0x24, 0x23]).await.unwrap();
    let selected = read_n(s, 1).await[0];
    seen.lock().selected = Some(selected);

    let srp = ServerSrp::new(password);

    // --- identity ----------------------------------------------------------
    match login {
        Login::Rsa33 => {
            assert_eq!(selected, 0x21);
            let key = key.unwrap();
            // Host key request: an RSA1 envelope, authtype 0.
            let req = read_waiting(s, 14);
            assert_eq!(&req[4..10], &[1, 0, b'R', b'S', b'A', b'1']);
            assert_eq!(&req[10..12], &[0, 0], "authtype 0");
            let spki = key.to_public_key().to_public_key_der().unwrap();
            let der = spki.as_bytes();
            seen.lock().host_key_spki = der.to_vec();
            let mut reply = ((der.len() + 7) as u32).to_be_bytes().to_vec();
            reply.extend_from_slice(&[0, 1, 0, 0]);
            reply.extend_from_slice(&(der.len() as u16).to_be_bytes());
            reply.extend_from_slice(der);
            reply.push(0);
            s.write_all(&reply).await.unwrap();

            // Packet 1: total 650, RSA1, authtype 2, field 256, 256 bytes of
            // ciphertext and 384 zeroes.
            let p1 = read_n(s, 654).await;
            assert_eq!(&p1[..4], &650u32.to_be_bytes());
            assert_eq!(&p1[4..14], &[1, 0, b'R', b'S', b'A', b'1', 0, 2, 1, 0]);
            assert!(p1[14 + 256..].iter().all(|b| *b == 0));
            let identity = key.decrypt(Pkcs1v15Encrypt, &p1[14..14 + 256]).unwrap();
            seen.lock().identity = Some(identity);
        }
        Login::Srp36 => {
            assert_eq!(selected, 0x24);
            // The identity record inside one more length word.
            let outer = read_waiting(s, 4);
            let outer = u32::from_be_bytes(outer[..4].try_into().unwrap()) as usize;
            let identity = read_waiting(s, outer);
            let rest = u32::from_be_bytes(identity[..4].try_into().unwrap()) as usize;
            assert_eq!(
                rest + 4,
                outer,
                "the identity record fills its outer length"
            );
            seen.lock().identity = Some(identity);
        }
    }

    // --- challenge -----------------------------------------------------------
    s.write_all(&server_frame(login, &srp.challenge()))
        .await
        .unwrap();

    // --- client proof --------------------------------------------------------
    let inner = match login {
        Login::Rsa33 => {
            let head = read_n(s, 4).await;
            let total = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
            let body = read_n(s, total).await;
            assert_eq!(&body[..8], &[1, 0, b'R', b'S', b'A', b'1', 0, 2]);
            let field = u16::from_be_bytes([body[8], body[9]]) as usize;
            assert_eq!(&body[10..12], &[0, 0]);
            let inner_len = u16::from_be_bytes([body[12], body[13]]) as usize;
            assert_eq!(field, inner_len + 4);
            seen.lock().proof_trailer = body.len() - 14 - inner_len;
            body[14..14 + inner_len].to_vec()
        }
        Login::Srp36 => {
            let head = read_n(s, 4).await;
            let total = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
            let body = read_n(s, total).await;
            assert_eq!(&body[..2], &[0, 0]);
            let inner_len = u16::from_be_bytes([body[2], body[3]]) as usize;
            assert_eq!(body.len(), 4 + inner_len);
            body[4..].to_vec()
        }
    };
    // LV16(A) LV8(M1) LV16(options) LV8(random)
    assert_eq!(&inner[..2], &512u16.to_be_bytes());
    let a_pub = inner[2..514].to_vec();
    assert_eq!(inner[514], 64);
    let m1 = inner[515..579].to_vec();
    let olen = u16::from_be_bytes([inner[579], inner[580]]) as usize;
    assert_eq!(&inner[581..581 + olen], OPTIONS, "options echoed verbatim");
    assert_eq!(inner[581 + olen], 16, "16 byte client random");
    assert_eq!(inner.len(), 581 + olen + 17);

    let Some((m2, session_key)) = srp.verify(&a_pub, &m1) else {
        // Wrong password, refused the way a real Mac does it: type 33 sends
        // an RSA1 frame with an empty message and then SecurityResult 1, type
        // 36 the SecurityResult alone. No reason string in either.
        seen.lock().auth_failed = true;
        let mut r = Vec::new();
        if login == Login::Rsa33 {
            r.extend_from_slice(&[0, 0, 0, 6, 0, 0, 0, 2, 0, 0]);
        }
        r.extend_from_slice(&1u32.to_be_bytes());
        s.write_all(&r).await.unwrap();
        return;
    };
    s.write_all(&server_frame(login, &server_proof_payload(&m2)))
        .await
        .unwrap();
    if seen.lock().refuse_after_proof {
        // The password was right (the proof above verifies), but the account
        // is not allowed in: SecurityResult 1 and macOS 26's generic reason.
        let reason = b"Authentication or authorization failure";
        s.write_all(&1u32.to_be_bytes()).await.unwrap();
        s.write_all(&(reason.len() as u32).to_be_bytes())
            .await
            .unwrap();
        s.write_all(reason).await.unwrap();
        return;
    }
    s.write_all(&0u32.to_be_bytes()).await.unwrap();

    // --- ClientInit and ServerInit ------------------------------------------
    let init = read_n(s, 1).await[0];
    seen.lock().client_init = Some(init);
    let mut si = WIDTH.to_be_bytes().to_vec();
    si.extend_from_slice(&HEIGHT.to_be_bytes());
    si.extend_from_slice(&encode_pixel_format(&PixelFormat::bgra8888()));
    let name = b"Fake Mac";
    si.extend_from_slice(&(name.len() as u32).to_be_bytes());
    si.extend_from_slice(name);
    s.write_all(&si).await.unwrap();

    // --- cleartext prelude ----------------------------------------------------
    // ViewerInfo, SetEncryption(1), SetMode(1), SetEncryption(2). Like a real
    // macOS 26 Mac, this server reads ViewerInfo's body at its fixed native
    // size of 62 bytes; one of any other size leaves it waiting for the rest,
    // and the session never starts.
    let vi_head = read_n(s, 4).await;
    assert_eq!(vi_head[0], apple_wire::client_msg::VIEWER_INFO);
    let vi_len = u16::from_be_bytes([vi_head[2], vi_head[3]]) as usize;
    if vi_len != 62 {
        seen.lock().prelude = vec![vi_head.clone()];
        std::future::pending::<()>().await;
    }
    let mut vi = vi_head;
    vi.extend_from_slice(&read_n(s, 62).await);
    let se1 = read_n(s, 12).await;
    let mode = read_n(s, 4).await;
    let se2 = read_n(s, 8).await;
    seen.lock().prelude = vec![vi, se1, mode, se2];

    let wrap: [u8; 16] = Sha256::digest(&session_key)[..16].try_into().unwrap();
    let mut key1 = [0u8; 16];
    let mut iv1 = [0u8; 16];
    rand::rng().fill_bytes(&mut key1);
    rand::rng().fill_bytes(&mut iv1);
    // The first rekey, in clear, as a one rectangle update.
    s.write_all(&fbu(&[(
        0,
        0,
        0,
        0,
        apple_wire::encoding::REKEY,
        rekey_payload(&wrap, 1, &key1, &iv1),
    )]))
    .await
    .unwrap();

    let mut tx = Dir::new(key1, iv1, 0);
    let mut rx = Dir::new(key1, iv1, 0);

    // --- encrypted opening: four records ---------------------------------------
    for _ in 0..4 {
        let c = read_record(s).await.unwrap();
        let body = rx.open(&c).expect("client record verifies");
        seen.lock().records.push(body);
    }

    if login == Login::Srp36 || seen.lock().short_session {
        // Like a real Mac: the opening's full request is dropped while the
        // display is set up. The Mac announces the desktop size, and only a
        // full non-incremental request that comes after that gets the
        // picture.
        let m = fbu(&[(0, 0, WIDTH, HEIGHT, -223, Vec::new())]);
        s.write_all(&tx.seal(&m)).await.unwrap();
        loop {
            let c = read_record(s).await.unwrap();
            let body = rx.open(&c).expect("client record verifies");
            let full_request = body.len() == 10
                && body[0] == 3
                && body[1] == 0
                && body[6..10] == [WIDTH.to_be_bytes(), HEIGHT.to_be_bytes()].concat()[..];
            seen.lock().records.push(body);
            if full_request {
                break;
            }
        }
        // Like a real Mac, the whole screen in one rectangle.
        let m = fbu(&[(
            0,
            0,
            WIDTH,
            HEIGHT,
            0,
            raw_pixels(WIDTH, HEIGHT, [0, 0, 255, 0]),
        )]);
        s.write_all(&tx.seal(&m)).await.unwrap();

        if seen.lock().busy {
            serve_busy(s, &mut tx, &mut rx, &seen).await;
            return;
        }

        // Then the screen changes at (8, 8). Like a real Mac this server
        // pushes nothing on its own and keeps only the last update request:
        // the change goes out in answer to a request that covers it, and a
        // request for a few pixels in the corner gets just that corner.
        let mut change_sent = false;
        while let Some(c) = read_record(s).await {
            let Some(body) = rx.open(&c) else { break };
            let request = body.len() == 10 && body[0] == 3;
            seen.lock().records.push(body.clone());
            if !request {
                continue;
            }
            let word = |i: usize| u16::from_be_bytes([body[i], body[i + 1]]);
            let (x, y, w, h) = (word(2), word(4), word(6), word(8));
            let covers = x <= 8 && y <= 8 && x + w >= 10 && y + h >= 10;
            let m = if covers && !change_sent {
                change_sent = true;
                fbu(&[(8, 8, 2, 2, 0, raw_pixels(2, 2, [0, 255, 0, 0]))])
            } else if !covers {
                fbu(&[(0, 0, 3, 3, 0, raw_pixels(3, 3, [0, 0, 255, 0]))])
            } else {
                continue;
            };
            s.write_all(&tx.seal(&m)).await.unwrap();
        }
        return;
    }

    // --- metadata burst: layout first, then wait for the re-arm ---------------
    let backing = (WIDTH, HEIGHT);
    let logical = (WIDTH / 2, HEIGHT / 2);
    let m = fbu(&[(
        0,
        0,
        0,
        0,
        apple_wire::encoding::DISPLAY_LAYOUT,
        layout(backing, logical),
    )]);
    s.write_all(&tx.seal(&m)).await.unwrap();
    let (mut got_fbur, mut got_auto) = (false, false);
    while !(got_fbur && got_auto) {
        let c = read_record(s).await.unwrap();
        let body = rx.open(&c).expect("client record verifies");
        got_fbur |= body.len() == 10 && body[0] == 3 && body[1] == 0;
        got_auto |= body[0] == 0x09;
        seen.lock().records.push(body);
    }

    // Keysyms, input source, device info, cursor in one update.
    let mut keysyms = vec![0x00, 0x14, 0x00, 0x01, 0x00, 0x04];
    for k in 0x1008FD00u32..=0x1008FD03 {
        keysyms.extend_from_slice(&k.to_be_bytes());
    }
    let id = b"com.apple.keylayout.ABC";
    let mut source = ((id.len() + 8) as u16).to_be_bytes().to_vec();
    source.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    source.extend_from_slice(&(id.len() as u16).to_be_bytes());
    source.extend_from_slice(id);
    let strings = b"Mac0,0\0\0\0";
    let mut device = ((16 + strings.len()) as u16).to_be_bytes().to_vec();
    device.extend_from_slice(&2u16.to_be_bytes());
    device.extend_from_slice(&1u32.to_be_bytes());
    device.extend_from_slice(&0u32.to_be_bytes());
    for l in [7u16, 1, 1] {
        device.extend_from_slice(&l.to_be_bytes());
    }
    device.extend_from_slice(strings);
    device.extend_from_slice(&0u32.to_be_bytes());
    let m = fbu(&[
        (0, 0, 0, 0, apple_wire::encoding::VENDOR_KEYSYMS, keysyms),
        (
            0,
            0,
            0,
            0,
            apple_wire::encoding::KEYBOARD_INPUT_SOURCE,
            source,
        ),
        (0, 0, 0, 0, apple_wire::encoding::DEVICE_INFO, device),
        cursor_rect(),
    ]);
    s.write_all(&tx.seal(&m)).await.unwrap();

    // A heartbeat, and a message type the client has never heard of, which
    // it must skip by its record boundary.
    s.write_all(&tx.seal(&[0x14, 0, 0, 4, 0, 1, 0, 12]))
        .await
        .unwrap();
    s.write_all(&tx.seal(&[0x7e, 1, 2, 3, 4, 5])).await.unwrap();

    // A red picture of the whole screen, whose message runs across two
    // records.
    let m = fbu(&[(
        0,
        0,
        WIDTH,
        HEIGHT,
        0,
        raw_pixels(WIDTH, HEIGHT, [0, 0, 255, 0]),
    )]);
    let (a, b) = m.split_at(20);
    s.write_all(&tx.seal(a)).await.unwrap();
    s.write_all(&tx.seal(b)).await.unwrap();

    // The clipboard, the way a real Mac hands it over: a status message says
    // it changed, and the text follows only once the viewer fetches it.
    s.write_all(&tx.seal(&[0x14, 0, 0, 4, 0, 1, 0, 2]))
        .await
        .unwrap();
    loop {
        let c = read_record(s).await.unwrap();
        let body = rx.open(&c).expect("client record verifies");
        let fetch = body[0] == apple_wire::client_msg::CLIPBOARD_FETCH;
        seen.lock().records.push(body);
        if fetch {
            break;
        }
    }
    s.write_all(&tx.seal(&clipboard_message("hello from the fake Mac")))
        .await
        .unwrap();

    // A second rekey inside the layer, then a green picture under the new key.
    let mut key2 = [0u8; 16];
    let mut iv2 = [0u8; 16];
    rand::rng().fill_bytes(&mut key2);
    rand::rng().fill_bytes(&mut iv2);
    let m = fbu(&[(
        0,
        0,
        0,
        0,
        apple_wire::encoding::REKEY,
        rekey_payload(&key1, 2, &key2, &iv2),
    )]);
    s.write_all(&tx.seal(&m)).await.unwrap();
    let old_rx = rx.clone();
    tx = Dir::new(key2, iv2, tx.seq);
    let mut new_rx = Dir::new(key2, iv2, rx.seq);
    let m = fbu(&[(4, 4, 2, 2, 0, raw_pixels(2, 2, [0, 255, 0, 0]))]);
    s.write_all(&tx.seal(&m)).await.unwrap();

    // Everything the client sends from now on, until it hangs up. A record
    // the client sealed before it saw the rekey is still under the old key.
    let mut old_rx = Some(old_rx);
    while let Some(c) = read_record(s).await {
        let body = match new_rx.clone().open(&c) {
            Some(b) => {
                new_rx.open(&c);
                old_rx = None;
                b
            }
            None => match old_rx.as_mut().and_then(|o| o.open(&c)) {
                Some(b) => {
                    new_rx.seq += 1;
                    b
                }
                None => panic!("client record did not verify under either key"),
            },
        };
        seen.lock().records.push(body);
    }
}

fn session_options(port: u16, password: &str) -> ConnectOptions {
    let mut o = options(port);
    o.credentials = Credentials::user_pass(USER, password);
    o.reconnect.enabled = false;
    o
}

async fn wait_record(seen: &Arc<Mutex<Seen>>, what: &str, f: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + DEFAULT_TIMEOUT;
    loop {
        if let Some(r) = seen.lock().records.iter().find(|r| f(r)) {
            return r.clone();
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "no client record for {what}; saw types {:?}",
                seen.lock().records.iter().map(|r| r[0]).collect::<Vec<_>>()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The whole type 33 path through the real session: login, prelude, rekey,
/// record layer, Apple metadata, picture, clipboard, a second rekey, and
/// input going back inside records with the pointer mapped to logical size.
#[tokio::test]
async fn type_33_session_end_to_end() {
    let mac = FakeMac::start(Login::Rsa33, PASSWORD).await;
    let (handle, mut events) = spawn_session(session_options(mac.port, PASSWORD));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // The host key is offered for pinning under its own scheme.
    let spki = mac.seen.lock().host_key_spki.clone();
    let expected_fp = vnc_transport::format_fingerprint(&Sha256::digest(&spki));
    assert!(events.any(|e| matches!(
        e,
        SessionEvent::CertificatePrompt { scheme: PinScheme::AppleRsa, fingerprint, .. }
            if *fingerprint == expected_fp
    )));

    // The red picture (split over two records), then the green one that
    // arrives under the second key.
    let red = events
        .wait(DEFAULT_TIMEOUT, "red update", |e| match e {
            SessionEvent::FramebufferUpdate { damage, .. } if damage.width == WIDTH => {
                Some(*damage)
            }
            _ => None,
        })
        .await;
    assert_eq!((red.x, red.y), (0, 0));
    events
        .wait(
            DEFAULT_TIMEOUT,
            "green update after the rekey",
            |e| match e {
                SessionEvent::FramebufferUpdate { damage, .. } if damage.x == 4 => Some(()),
                _ => None,
            },
        )
        .await;
    assert!(events.any(|e| matches!(
        e,
        SessionEvent::ClipboardText(t) if t == "hello from the fake Mac"
    )));
    let cursor = events
        .seen
        .iter()
        .find_map(|e| match e {
            SessionEvent::CursorUpdate(c) => Some(c.clone()),
            _ => None,
        })
        .expect("the Apple cursor was decoded");
    assert_eq!((cursor.width, cursor.height), (2, 2));
    assert_eq!((cursor.hotspot_x, cursor.hotspot_y), (1, 1));
    assert_eq!(&cursor.pixels[..4], &[255, 0, 0, 255]);
    assert_eq!(cursor.pixels[15], 0);

    // Input goes back inside records. The layout said the logical screen is
    // half the backing size, so the far corner maps to the logical one.
    send(
        &handle,
        ClientCommand::Pointer {
            x: WIDTH - 1,
            y: HEIGHT - 1,
            button_mask: 1,
        },
    )
    .await;
    send(
        &handle,
        ClientCommand::Key {
            keysym: 0x61,
            keycode: None,
            down: true,
        },
    )
    .await;
    send(
        &handle,
        ClientCommand::ClipboardText("from the viewer".into()),
    )
    .await;

    let ptr = wait_record(&mac.seen, "pointer event", |r| r[0] == 5).await;
    assert_eq!(ptr, [5, 1, 0, 31, 0, 23]);
    let key = wait_record(&mac.seen, "key event", |r| r[0] == 4).await;
    assert_eq!(key, [4, 1, 0, 0, 0, 0, 0, 0x61]);
    // The viewer's clipboard goes as a ClipboardSend in the Mac's layout.
    let send_ = wait_record(&mac.seen, "ClipboardSend", |r| r[0] == 0x1f).await;
    let un = u32::from_be_bytes(send_[8..12].try_into().unwrap()) as usize;
    let co = u32::from_be_bytes(send_[12..16].try_into().unwrap()) as usize;
    let raw = apple_wire::inflate_flushed(&send_[16..16 + co], un).unwrap();
    let items = apple_wire::parse_clipboard(&raw).unwrap();
    assert_eq!(items[0].kind, "public.utf8-plain-text");
    assert_eq!(items[0].data, b"from the viewer");
    assert!(
        !mac.seen.lock().records.iter().any(|r| r[0] == 6),
        "no ClientCutText in an Apple session"
    );

    send(&handle, ClientCommand::Disconnect).await;
    let _ = tokio::time::timeout(DEFAULT_TIMEOUT, mac.task).await;

    let seen = mac.seen.lock();
    assert_eq!(seen.client_banner, Some(*b"RFB 003.008\n"));
    assert_eq!(seen.selected, Some(33), "33 wins over 30 and 36");
    assert_eq!(
        seen.identity.as_deref(),
        Some(&[0, 0, 0, 13, 0, 0, 0, 6, b't', b'e', b's', b't', b'e', b'r', 0, 0, 0][..])
    );
    assert_eq!(seen.proof_trailer, 384);
    assert_eq!(seen.client_init, Some(0xC1));
    assert_eq!(seen.prelude[0], apple_wire::viewer_info());
    assert_eq!(seen.prelude[1], apple_wire::set_encryption_start());
    assert_eq!(seen.prelude[2], apple_wire::set_mode(true));
    assert_eq!(seen.prelude[3], apple_wire::set_encryption_finish());
    // The clipboard was fetched after the Mac said it changed.
    assert!(seen
        .records
        .iter()
        .any(|r| r[..] == apple_wire::clipboard_fetch()[..]));

    // Opening records, in the native order.
    let r = &seen.records;
    // No SetDisplayConfiguration: a real Mac adds a virtual display for it.
    assert!(
        !r.iter().any(|m| m[0] == 0x1d),
        "SetDisplayConfiguration sent; a Mac would add a virtual display"
    );
    assert_eq!(r[0][0], 2, "SetEncodings first");
    assert_eq!(&r[1][..2], &[3, 0], "a non-incremental request");
    assert_eq!(r[2][0], 0x09, "AutoFrameBufferUpdate");
    assert_eq!(r[3], apple_wire::auto_pasteboard(true));
    // A Mac sharing its real displays does not push changes, so the client
    // pulls with incremental requests once a picture is in, and never sends
    // the one pixel probe that would narrow the Mac's updates.
    assert!(
        r.iter().any(|m| m.len() == 10 && m[0] == 3 && m[1] == 1),
        "no incremental FramebufferUpdateRequest; the picture would freeze"
    );
    assert!(
        !r.iter()
            .any(|m| m.len() == 10 && m[0] == 3 && m[6..10] == [0, 1, 0, 1]),
        "a one pixel probe went to the Mac"
    );
    // SetEncodings lists only what the client decodes, zlib first.
    let encs: Vec<i32> = r[0][4..]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| i32::from_be_bytes(*c))
        .collect();
    assert_eq!(encs[0], 6);
    for bad in [7, 50, 1011, 1000, 1001, 1002, 1010] {
        assert!(!encs.contains(&bad), "advertised {bad}");
    }
    assert!(encs.contains(&apple_wire::encoding::REKEY));
}

/// The type 36 path: the identity in clear, the challenge, the proof, and a
/// picture through the record layer.
#[tokio::test]
async fn type_36_session_end_to_end() {
    let mac = FakeMac::start(Login::Srp36, PASSWORD).await;
    let mut o = session_options(mac.port, PASSWORD);
    o.vnc_mut().security_pref = Some("apple-srp".into());
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    send(&handle, ClientCommand::Disconnect).await;
    let _ = tokio::time::timeout(DEFAULT_TIMEOUT, mac.task).await;
    let seen = mac.seen.lock();
    assert_eq!(seen.selected, Some(36));
    assert_eq!(
        seen.identity.as_deref(),
        Some(&[0, 0, 0, 13, 0, 0, 0, 6, b't', b'e', b's', b't', b'e', b'r', 0, 0, 0][..])
    );
    assert_eq!(seen.records[0][0], 2, "SetEncodings opens the record layer");
    assert!(!seen.records.iter().any(|m| m[0] == 0x1d));
}

/// The picture keeps changing after the first frame. A Mac pushes nothing
/// on its own and keeps only the last update request, so the viewer must
/// pull with incremental requests once the full picture is in, and must not
/// send the one pixel round trip probe that narrowed a real Mac's updates to
/// a corner and froze the picture.
#[tokio::test]
async fn the_picture_keeps_updating_after_the_first_frame() {
    let mac = FakeMac::start(Login::Srp36, PASSWORD).await;
    let mut o = session_options(mac.port, PASSWORD);
    o.vnc_mut().security_pref = Some("apple-srp".into());
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let changed = events
        .wait(
            Duration::from_secs(5),
            "the change at (8, 8)",
            |e| match e {
                SessionEvent::FramebufferUpdate { damage, .. }
                    if damage.x == 8 && damage.y == 8 =>
                {
                    Some(*damage)
                }
                _ => None,
            },
        )
        .await;
    assert_eq!((changed.width, changed.height), (2, 2));
    send(&handle, ClientCommand::Disconnect).await;
    let seen = mac.seen.lock();
    assert!(
        !seen
            .records
            .iter()
            .any(|m| m.len() == 10 && m[0] == 3 && m[6..10] == [0, 1, 0, 1]),
        "a one pixel probe went to the Mac"
    );
}

/// "Connect once" at the host key prompt covers the whole session. The
/// prompt is raised after the login while the session goes on, and a
/// reconnect after a network blip used to raise it again, over a live
/// session, because the core never kept the answer.
#[tokio::test]
async fn an_accepted_host_key_is_not_asked_about_again_after_a_reconnect() {
    let mac = RedialMac::start().await;
    let mut o = options(mac.port);
    o.credentials = Credentials::user_pass(USER, PASSWORD);
    let (handle, mut events) = spawn_session(o);
    let fingerprint = events
        .wait(DEFAULT_TIMEOUT, "the host key prompt", |e| match e {
            SessionEvent::CertificatePrompt { fingerprint, .. } => Some(fingerprint.clone()),
            _ => None,
        })
        .await;
    events.wait_connected(DEFAULT_TIMEOUT).await;
    send(
        &handle,
        ClientCommand::TrustCertificate {
            fingerprint,
            permanent: false,
            scheme: PinScheme::AppleRsa,
        },
    )
    .await;
    // Let the run loop take the answer, then drop the connection.
    tokio::time::sleep(Duration::from_millis(300)).await;
    mac.drop.notify_one();
    events
        .wait_state(DEFAULT_TIMEOUT, "a reconnect", |s| {
            matches!(s, vnc_core::types::SessionState::Reconnecting { .. }).then_some(())
        })
        .await;
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.drain_for(Duration::from_millis(300)).await;
    assert_eq!(
        mac.connections.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "{:?}",
        events.summary()
    );
    let prompts = events
        .seen
        .iter()
        .filter(|e| matches!(e, SessionEvent::CertificatePrompt { .. }))
        .count();
    assert_eq!(
        prompts,
        1,
        "asked about the same key again: {:?}",
        events.summary()
    );
    send(&handle, ClientCommand::Disconnect).await;
    let _ = mac.seen;
}

/// An agent's clipboard read on a Mac asks the Mac for its pasteboard.
#[tokio::test]
async fn a_clipboard_request_on_a_mac_fetches_the_pasteboard() {
    let mac = FakeMac::start(Login::Srp36, PASSWORD).await;
    let mut o = session_options(mac.port, PASSWORD);
    o.vnc_mut().security_pref = Some("apple-srp".into());
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    send(&handle, ClientCommand::ClipboardRequest { formats: 1 }).await;
    wait_record(&mac.seen, "a ClipboardFetch", |r| {
        r[..] == apple_wire::clipboard_fetch()[..]
    })
    .await;
    send(&handle, ClientCommand::Disconnect).await;
}

/// A refresh on a busy Mac over a slow link gets the whole picture. The
/// small update already in flight when the refresh went out is not its
/// answer, and treating it as one sent an incremental request that cancelled
/// the refresh, so an agent's first screen read waited for a reconnect.
#[tokio::test]
async fn a_refresh_on_a_busy_mac_gets_the_whole_picture() {
    let mac = FakeMac::start_busy().await;
    let mut o = session_options(mac.port, PASSWORD);
    o.vnc_mut().security_pref = Some("apple-srp".into());
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events
        .wait(DEFAULT_TIMEOUT, "the first picture", |e| match e {
            SessionEvent::FramebufferUpdate { damage, .. } if damage.width == WIDTH => Some(()),
            _ => None,
        })
        .await;
    events.drain_for(Duration::from_millis(400)).await;
    send(&handle, ClientCommand::Refresh).await;
    events
        .wait(
            Duration::from_secs(5),
            "the refreshed picture",
            |e| match e {
                SessionEvent::FramebufferUpdate { damage, .. } if damage.width == WIDTH => Some(()),
                _ => None,
            },
        )
        .await;
    assert!(
        !mac.seen.lock().full_cancelled,
        "an incremental request replaced the refresh"
    );
    send(&handle, ClientCommand::Disconnect).await;
}

/// A quality change on a Mac sends no new SetEncodings: the encrypted
/// session keeps the encodings it opened with, and a Mac sent another list
/// mid session stopped sending updates, so an agent's mirror never filled.
#[tokio::test]
async fn a_quality_change_on_a_mac_keeps_its_encodings() {
    let mac = FakeMac::start(Login::Srp36, PASSWORD).await;
    let mut o = session_options(mac.port, PASSWORD);
    o.vnc_mut().security_pref = Some("apple-srp".into());
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    send(
        &handle,
        ClientCommand::SetQuality(vnc_core::types::QualityPreset::High),
    )
    .await;
    send(&handle, ClientCommand::Refresh).await;
    wait_record(&mac.seen, "the refresh", |r| {
        r.len() == 10 && r[0] == 3 && r[1] == 0
    })
    .await;
    events.drain_for(Duration::from_millis(300)).await;
    let set_encodings = mac.seen.lock().records.iter().filter(|r| r[0] == 2).count();
    assert_eq!(set_encodings, 1, "a second SetEncodings went to the Mac");
    send(&handle, ClientCommand::Disconnect).await;
}

/// A wrong password: the fake Mac refuses M1 with an ordinary failure result,
/// and the client reports it as rejected credentials, not a protocol error.
#[tokio::test]
async fn wrong_password_is_an_auth_failure() {
    wrong_password_with(Login::Rsa33).await;
}

#[tokio::test]
async fn wrong_password_is_an_auth_failure_36() {
    wrong_password_with(Login::Srp36).await;
}

async fn wrong_password_with(login: Login) {
    let mac = FakeMac::start(login, PASSWORD).await;
    let mut o = session_options(mac.port, "not the password");
    if login == Login::Srp36 {
        o.vnc_mut().security_pref = Some("apple-srp".into());
    }
    let (_handle, mut events) = spawn_session(o);
    let reason = events
        .wait(DEFAULT_TIMEOUT, "an authentication failure", |e| match e {
            SessionEvent::StateChanged(vnc_core::types::SessionState::Disconnected {
                reason,
                can_retry,
                ..
            }) => Some((reason.clone(), *can_retry)),
            _ => None,
        })
        .await;
    assert!(!reason.1, "a rejected password is not retried: {reason:?}");
    assert!(reason.0.contains("password was not accepted"), "{reason:?}");
    assert!(mac.seen.lock().auth_failed);
    assert!(
        !events.any(|e| matches!(
            e,
            SessionEvent::StateChanged(vnc_core::types::SessionState::Connected)
        )),
        "{:?}",
        events.summary()
    );
}

/// A Mac that verifies the password and then refuses the account (on macOS
/// 26, an account without Remote Management privileges) is reported as that,
/// not as a wrong password, and the password is not asked for again.
#[tokio::test]
async fn refused_after_a_good_password_says_why() {
    for login in [Login::Rsa33, Login::Srp36] {
        let mac = FakeMac::start_with(login, PASSWORD, true).await;
        let mut o = session_options(mac.port, PASSWORD);
        if login == Login::Srp36 {
            o.vnc_mut().security_pref = Some("apple-srp".into());
        }
        let (_handle, mut events) = spawn_session(o);
        let (reason, can_retry) = events
            .wait(DEFAULT_TIMEOUT, "a refused login", |e| match e {
                SessionEvent::StateChanged(vnc_core::types::SessionState::Disconnected {
                    reason,
                    can_retry,
                    ..
                }) => Some((reason.clone(), *can_retry)),
                _ => None,
            })
            .await;
        assert_eq!(reason, vnc_core::security::APPLE_ACCESS_DENIED, "{login:?}");
        assert!(!can_retry, "{login:?}");
        assert!(
            !mac.seen.lock().auth_failed,
            "the password itself was right"
        );
        assert!(
            !events.any(|e| matches!(e, SessionEvent::CredentialsRequired(_))),
            "{login:?}: asked for the password again"
        );
    }
}

/// A Mac that offers only type 30 (an older Mac, or one with Screen Sharing
/// set up that way) still gets a full session: the 1024-bit DH login, then
/// the ordinary cleartext RFB session with no Apple record layer.
#[tokio::test]
async fn a_mac_offering_only_30_logs_in_and_draws() {
    let server = MockServer::start(
        MockConfig::new()
            .banner(RFB_APPLE)
            .security(&[SEC_APPLE_DH])
            .username(USER)
            .password(PASSWORD)
            .size(WIDTH, HEIGHT)
            .update(vec![RectSpec::Raw {
                rect: vnc_core::types::Rect::new(0, 0, WIDTH, HEIGHT),
                colour: [200, 10, 10],
            }]),
    )
    .await;
    let (handle, mut events) = spawn_session(session_options(server.port(), PASSWORD));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (_, damage) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!((damage.width, damage.height), (WIDTH, HEIGHT));
    assert_eq!(server.selected_security(), vec![SEC_APPLE_DH]);
    assert_eq!(
        server.plain_credentials(),
        vec![(USER.to_string(), PASSWORD.to_string())]
    );
    send(&handle, ClientCommand::Disconnect).await;
}

/// A Mac that offers only Apple's type 35 and the classic VNC password (2)
/// logs in with the VNC password: 35 is not something this client speaks,
/// and offering it must not stop the login.
#[tokio::test]
async fn a_mac_offering_35_and_2_uses_the_vnc_password() {
    let server = MockServer::start(
        MockConfig::new()
            .banner(RFB_APPLE)
            .security(&[35, SEC_VNC_AUTH])
            .password("vncpw")
            .size(WIDTH, HEIGHT)
            .update(vec![RectSpec::Raw {
                rect: vnc_core::types::Rect::new(0, 0, WIDTH, HEIGHT),
                colour: [10, 200, 10],
            }]),
    )
    .await;
    let mut o = options(server.port());
    o.credentials = Credentials::password("vncpw");
    o.reconnect.enabled = false;
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(server.selected_security(), vec![SEC_VNC_AUTH]);
    send(&handle, ClientCommand::Disconnect).await;
}

/// A type 30 login the Mac refuses cannot say whether the password or the
/// account's Remote Management privileges were the problem, so the prompt
/// that asks again carries the hint, and the right password still gets in.
#[tokio::test]
async fn a_refused_type_30_login_asks_again_with_the_hint() {
    let mut config = MockConfig::new()
        .banner(RFB_APPLE)
        .security(&[SEC_APPLE_DH])
        .username(USER)
        .password(PASSWORD)
        .size(WIDTH, HEIGHT);
    // The reason macOS 26 gives for a wrong password and for an account it
    // will not let in alike.
    config.auth_failure_reason = "Authentication or authorization failure".into();
    let server = MockServer::start(config).await;
    let mut o = options(server.port());
    o.reconnect.enabled = false;
    let (handle, mut events) = spawn_session(o);
    async fn prompt(events: &mut Events) -> vnc_core::types::CredentialRequest {
        events
            .wait(DEFAULT_TIMEOUT, "a credential prompt", |e| match e {
                SessionEvent::CredentialsRequired(r) => Some(r.clone()),
                _ => None,
            })
            .await
    }
    let first = prompt(&mut events).await;
    assert_eq!(first.error, None);
    let answer = |password: &str| ClientCommand::ProvideCredentials {
        username: Some(USER.into()),
        password: password.into(),
        save: false,
    };
    send(&handle, answer("not the password")).await;
    let second = prompt(&mut events).await;
    assert_eq!(second.attempt, 2);
    assert_eq!(
        second.error.as_deref(),
        Some(vnc_core::security::APPLE_DH_REFUSED)
    );
    assert!(second
        .error
        .unwrap()
        .contains("may need this account allowed under Remote Management, Options"));
    send(&handle, answer(PASSWORD)).await;
    events.wait_connected(DEFAULT_TIMEOUT).await;
    assert_eq!(server.selected_security(), vec![SEC_APPLE_DH, SEC_APPLE_DH]);
    send(&handle, ClientCommand::Disconnect).await;
}

/// A host key that differs from the pinned one stops the login before the
/// user name is sent.
#[tokio::test]
async fn changed_host_key_is_refused_before_the_identity() {
    let mac = FakeMac::start(Login::Rsa33, PASSWORD).await;
    let mut o = session_options(mac.port, PASSWORD);
    o.cert_pins.set(PinScheme::AppleRsa, Some("ab".repeat(32)));
    let (_handle, mut events) = spawn_session(o);
    events
        .wait(DEFAULT_TIMEOUT, "the session to stop", |e| match e {
            SessionEvent::StateChanged(vnc_core::types::SessionState::Disconnected { .. }) => {
                Some(())
            }
            _ => None,
        })
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(mac.seen.lock().identity.is_none());
}

/// Selection order for the offer a Mac makes.
#[test]
fn a_mac_offer_selects_33_then_30_then_36() {
    let o = ConnectOptions::vnc("mac.local", 5900);
    assert_eq!(
        select_security_type(&[30, 33, 36, 35], &o).unwrap(),
        SecurityType::AppleRsaSrp
    );
    assert_eq!(
        select_security_type(&[30, 36, 35], &o).unwrap(),
        SecurityType::AppleDh
    );
    assert_eq!(
        select_security_type(&[36, 35, 2], &o).unwrap(),
        SecurityType::AppleSrp
    );
    for (pref, t) in [
        ("apple-dh", SecurityType::AppleDh),
        ("apple-srp", SecurityType::AppleSrp),
        ("apple-srp-rsa", SecurityType::AppleRsaSrp),
    ] {
        let mut o = o.clone();
        o.vnc_mut().security_pref = Some(pref.into());
        assert_eq!(select_security_type(&[30, 33, 36, 35], &o).unwrap(), t);
    }
}

/// Every fact below is known from one source only, or the sources disagree.
/// Each test pins the reading this client uses. A live run against a Mac
/// (`tests/apple_live.rs`) is what confirms or overturns each one; when one
/// is overturned, this is the test to change first.
mod live_must_confirm {
    use super::*;
    use vnc_core::security::apple_srp::*;

    /// The host key request is an RSA1 envelope with authtype 0 and no body,
    /// in the same write as the type byte. Confirmed on a real Mac: it logs
    /// "RSA received 10 bytes" and answers with its key.
    #[test]
    fn host_key_request_has_an_empty_body() {
        assert_eq!(
            key_request(),
            [0, 0, 0, 10, 1, 0, b'R', b'S', b'A', b'1', 0, 0, 0, 0]
        );
    }

    /// The host key reply: `u32 len, 00 01 00 00, u16 n, SPKI, 00`.
    /// Confirmed on a real Mac (`00 00 01 2d 00 01 00 00 01 26 30 82 ...`).
    #[test]
    fn host_key_reply_tag_is_little_endian() {
        let key = RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap();
        let der = key.to_public_key().to_public_key_der().unwrap();
        let mut body = vec![0, 1, 0, 0];
        body.extend_from_slice(&(der.as_bytes().len() as u16).to_be_bytes());
        body.extend_from_slice(der.as_bytes());
        body.push(0);
        assert!(parse_key_reply(&body).is_ok());
    }

    /// `x` hashes an empty identity and the PBKDF2 output as the password.
    #[test]
    fn x_uses_an_empty_identity_and_the_derived_key() {
        let salt = [1u8; 32];
        let derived = derive_password(b"pw", &salt, 2);
        let inner = h512(&[b":", &derived]);
        let want = BigUint::from_bytes_be(&h512(&[&salt, &inner]));
        assert_eq!(srp_x::<Sha512>(&salt, b"", &derived), want);
    }

    /// `K` hashes the premaster secret padded to 512 bytes, not its minimal
    /// bytes. They differ only when S has a leading zero byte.
    #[test]
    fn k_hashes_the_padded_premaster() {
        let g = SrpGroup::apple();
        let s = BigUint::from(0x1234u32);
        assert_eq!(srp_session_key::<Sha512>(&g, &s), h512(&[&pad512(&s)]));
        assert_ne!(srp_session_key::<Sha512>(&g, &s), h512(&[&s.to_bytes_be()]));
    }

    /// `M1` hashes A and B as sent (512 bytes each) and g padded to 512
    /// bytes. Confirmed against Apple's own client and a real Mac; the one
    /// byte form is refused.
    #[test]
    fn m1_uses_wire_a_b_and_padded_g() {
        let g = SrpGroup::apple();
        let a = BigUint::from(7u32);
        let b = BigUint::from(9u32);
        let k = [3u8; 64];
        let m1 = srp_client_proof::<Sha512>(&g, b"", &[2; 32], &a, &b, &k);
        let hn = h512(&[&g.n.to_bytes_be()]);
        let hg = h512(&[&pad512(&BigUint::from(5u32))]);
        let xor: Vec<u8> = hn.iter().zip(&hg).map(|(x, y)| x ^ y).collect();
        let want = h512(&[&xor, &h512(&[b""]), &[2; 32], &pad512(&a), &pad512(&b), &k]);
        assert_eq!(m1, want);
        let one_byte_g = h512(&[&[5u8]]);
        let old: Vec<u8> = hn.iter().zip(&one_byte_g).map(|(x, y)| x ^ y).collect();
        let refused = h512(&[&old, &h512(&[b""]), &[2; 32], &pad512(&a), &pad512(&b), &k]);
        assert_ne!(m1, refused, "the one byte g form is the one a Mac refuses");
    }

    /// The type 33 proof carries 384 trailing bytes after its inner block.
    /// A real Mac logs "RSA received 1076 bytes" for it and goes on to check
    /// the proof, so the framing is right; whether it needs the trailer at
    /// all is untested.
    #[test]
    fn proof_33_has_a_384_byte_trailer() {
        let p = proof_packet_33(&[0u8; 10]);
        assert_eq!(p.len(), 4 + 10 + 4 + 10 + 384);
    }

    /// Type 36: the identity record goes in clear inside one more length
    /// word, and so does the proof. Confirmed on a real Mac for the identity
    /// (without the outer word it logs "SRP Buffer isn't of the right
    /// length"); the proof follows the same shape.
    #[test]
    fn type_36_framing() {
        let p = proof_packet_36(&[9u8; 3]);
        assert_eq!(p, [0, 0, 0, 7, 0, 0, 0, 3, 9, 9, 9]);
        assert_eq!(
            identity_packet_36(&identity_record("a").unwrap()),
            [0, 0, 0, 12, 0, 0, 0, 8, 0, 0, 0, 1, b'a', 0, 0, 0]
        );
    }

    /// The wrap key after SRP is the first half of SHA-256(K).
    #[test]
    fn wrap_key_after_srp() {
        let k = [4u8; 64];
        assert_eq!(initial_wrap_key(&k)[..], Sha256::digest(k)[..16]);
    }

    /// The version reply stays `RFB 003.008` (the existing type 30 behaviour)
    /// rather than echoing `RFB 003.889` as the native viewer does. A real Mac
    /// offers the same `30, 33, 36, 35` after either reply (and after
    /// `003.007`), and refuses `003.003` with "Incompatible Version.".
    #[test]
    fn version_reply_is_3_8() {
        let parsed = vnc_core::proto::version::parse_server_banner(b"RFB 003.889\n").unwrap();
        assert_eq!(&parsed.client_reply(), b"RFB 003.008\n");
    }

    /// ClientInit is 0xC1. ViewerInfo is sent, 66 bytes in the native
    /// layout read off Apple's own client through a relay (the Mac stalls on
    /// any other size). SetEncryption uses the native bytes; SetMode(1) is
    /// sent. All confirmed by full sessions against a macOS 26 Mac.
    #[test]
    fn prelude_bytes() {
        assert_eq!(apple_wire::CLIENT_INIT_SHARED, 0xC1);
        assert!(vnc_core::apple::PreludeOptions::default().viewer_info);
        let vi = apple_wire::viewer_info();
        assert_eq!(vi.len(), 66);
        assert_eq!(&vi[..6], &[0x21, 0, 0, 0x3e, 0, 1]);
        assert_eq!(
            &vi[6..34],
            &[
                0, 0, 0, 2, 0, 0, 0, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x1a, 0, 0, 0, 7, 0, 0, 0,
                1
            ]
        );
        assert_eq!(
            &vi[34..45],
            &[0xb0, 0, 0x0c, 0x03, 0x90, 0, 0, 0, 0, 0, 0x40]
        );
        assert!(vi[45..].iter().all(|b| *b == 0));
        assert_eq!(
            apple_wire::set_encryption_start()[8..],
            [0, 0, 0, 1],
            "trailing word of SetEncryption(1)"
        );
    }

    /// The record layer: one key both ways, chains continue across records,
    /// counters from zero per direction, SHA-1 check value without HMAC.
    #[test]
    fn record_layer_shape() {
        let mut ours = vnc_core::apple::record::Direction::new(
            &vnc_core::apple::ContentKeys {
                generation: 1,
                key: [1; 16],
                iv: [2; 16],
            },
            0,
        );
        let mut theirs = Dir::new([1; 16], [2; 16], 0);
        for i in 0..3u8 {
            let rec = ours.seal(&[i; 5]).unwrap();
            assert_eq!(theirs.open(&rec[2..]).unwrap(), [i; 5]);
        }
    }

    /// The display configuration word at descriptor offset 150 is sent as 0
    /// (one reading says rotation, another says 7).
    #[test]
    fn display_configuration_offset_150_is_zero() {
        let m = apple_wire::set_display_configuration(1920, 1080, 0);
        assert_eq!(&m[12 + 150..12 + 154], &[0, 0, 0, 0]);
    }

    /// Apple's metadata encodings 1103 to 1110 and 1010 are listed in
    /// SetEncodings, in case the server needs them listed.
    #[test]
    fn apple_metadata_encodings_are_listed() {
        let e = vnc_core::apple::session_encodings();
        for v in apple_wire::encoding::ADVERTISED {
            assert!(e.contains(&v));
        }
        assert!(!e.contains(&apple_wire::encoding::MEDIA_ANNOUNCE));
    }

    /// The 0x451 layout header is 20 bytes counted without the length word.
    #[test]
    fn layout_header_is_20_bytes() {
        let body = layout((3840, 2160), (1920, 1080));
        let l = apple_wire::parse_display_layout(&body[2..]).unwrap();
        assert_eq!(l.leading, Some([1920, 1080, 3840, 2160]));
    }
}
