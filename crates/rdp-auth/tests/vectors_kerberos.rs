//! RFC 3961 appendix A and RFC 3962 appendix B, transcribed.
//!
//! The rule this file is held to is `docs/RDP_SPEC_NOTES.md` §1.7 and
//! PRDRDP/14 §9.2: a value here is either copied from a published document,
//! with the section it came from named beside it, or it is derived by an
//! identity the document itself states, with the derivation written out. No
//! value in this file was produced by running the code it tests and pasting
//! the answer back.
//!
//! What is covered, and what is not:
//!
//! * `n-fold` is covered completely. RFC 3961 appendix A.1 publishes eleven
//!   vectors and all eleven are here.
//! * `PBKDF2`, `DR`, `DK` and the single block cipher path are covered by RFC
//!   3962 appendix B's seven string-to-key vectors, which assert both the
//!   intermediate PBKDF2 output and the final key. Both halves matter: the
//!   final key alone cannot tell a wrong iteration count from a wrong `DK`
//!   constant.
//! * AES-CTS is covered by RFC 3962 appendix B's six ciphertext stealing
//!   vectors, in both directions.
//! * The single block case of RFC 3962 §5 has **no published vector**. It is
//!   derived below from appendix B's own two block vector by the identity
//!   §5 states, and the derivation is written out where it is used.
//! * `Kc`, `Ke` and `Ki` at a particular key usage number have no published
//!   vector anywhere the author could find. RFC 3961 appendix A.3 publishes
//!   `DR` and `DK` values for `des3-cbc-sha1-kd` only, and RFC 3962 publishes
//!   none. The composition is proved indirectly, because string-to-key is
//!   `DK(tkey, "kerberos")` and its vectors pass, and directly by the round
//!   trip tests in `kerberos/crypto.rs`. This is a real gap and it is stated
//!   rather than papered over.
//! * RFC 4121 publishes no test vectors at all, so the AP-REQ, the 0x8003
//!   checksum and the Wrap tokens are held by structure tests and by the live
//!   interop matrix (PRDRDP/14 §7.3).

#![cfg(feature = "kerberos")]

use rdp_auth::kerberos::crypto::{
    decrypt_raw, encrypt_raw, n_fold, string_to_key, string_to_key_intermediate, Enctype, Key,
    BLOCK_LEN,
};

/// A hex string in the layout the RFCs print, with spaces and newlines.
fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(clean).expect("the transcription is valid hex")
}

// ---------------------------------------------------------------------------
// RFC 3961 appendix A.1: n-fold
// ---------------------------------------------------------------------------

/// The seven vectors "provided by Marc Horowitz and Simon Josefsson"
/// (RFC 3961 appendix A.1).
///
/// The fold length is given in bits in the RFC and in octets here, which is
/// the same number divided by eight: 64-fold is 8 octets, 56-fold is 7, and
/// 168-fold is 21. Every one of them is a length that is not a multiple of
/// the input length, which is the case where the replication and the end
/// around carry both matter.
#[test]
fn n_fold_matches_every_vector_in_rfc_3961_appendix_a_1() {
    // 64-fold("012345") = be072631276b1955
    assert_eq!(n_fold(b"012345", 8), hex("be072631276b1955"));

    // 56-fold("password") = 78a07b6caf85fa
    assert_eq!(n_fold(b"password", 7), hex("78a07b6caf85fa"));

    // 64-fold("Rough Consensus, and Running Code") = bb6ed30870b7f0e0
    assert_eq!(
        n_fold(b"Rough Consensus, and Running Code", 8),
        hex("bb6ed30870b7f0e0")
    );

    // 168-fold("password") = 59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e
    assert_eq!(
        n_fold(b"password", 21),
        hex("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e")
    );

    // 192-fold("MASSACHVSETTS INSTITVTE OF TECHNOLOGY")
    //   = db3b0d8f0b061e603282b308a50841229ad798fab9540c1b
    assert_eq!(
        n_fold(b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 24),
        hex("db3b0d8f0b061e603282b308a50841229ad798fab9540c1b")
    );

    // 168-fold("Q") = 518a54a2 15a8452a 518a54a2 15a8452a 518a54a2 15
    assert_eq!(
        n_fold(b"Q", 21),
        hex("518a54a2 15a8452a 518a54a2 15a8452a 518a54a2 15")
    );

    // 168-fold("ba") = fb25d531 ae897449 9f52fd92 ea9857c4 ba24cf29 7e
    assert_eq!(
        n_fold(b"ba", 21),
        hex("fb25d531 ae897449 9f52fd92 ea9857c4 ba24cf29 7e")
    );
}

/// The four `"kerberos"` values of RFC 3961 appendix A.1, which the appendix
/// supplies separately because they are the ones the string-to-key functions
/// use.
///
/// The appendix's own note is the reason these are worth having on their own:
/// "the initial octets exactly match the input string when the output length
/// is a multiple of the input length". That property is what fixes the
/// question the RFC's prose leaves open, whether the first repetition is
/// rotated or not. It is not, and the 128 bit value below is the proof: its
/// first eight octets are `6b657262 65726f73`, which is `"kerberos"` itself.
#[test]
fn n_fold_matches_the_kerberos_values_of_rfc_3961_appendix_a_1() {
    assert_eq!(n_fold(b"kerberos", 8), hex("6b657262 65726f73"));
    assert_eq!(
        n_fold(b"kerberos", 16),
        hex("6b657262 65726f73 7b9b5b2b 93132b93")
    );
    assert_eq!(
        n_fold(b"kerberos", 21),
        hex("8372c236 344e5f15 50cd0747 e15d62ca 7a5a3bce a4")
    );
    assert_eq!(
        n_fold(b"kerberos", 32),
        hex("6b657262 65726f73 7b9b5b2b 93132b93 \
             5c9bdcda d95c9899 c4cae4de e6d6cae4")
    );

    // The appendix's own note, asserted rather than only quoted.
    assert_eq!(n_fold(b"kerberos", 16).get(..8), Some(&b"kerberos"[..]));
    assert_eq!(n_fold(b"kerberos", 32).get(..8), Some(&b"kerberos"[..]));
}

// ---------------------------------------------------------------------------
// RFC 3962 appendix B: string-to-key
// ---------------------------------------------------------------------------

/// One appendix B string-to-key vector, with both published intermediates.
struct StringToKeyVector {
    iterations: u32,
    passphrase: &'static str,
    salt: &'static [u8],
    pbkdf2_128: &'static str,
    key_128: &'static str,
    pbkdf2_256: &'static str,
    key_256: &'static str,
}

/// Every string-to-key vector in RFC 3962 appendix B, in the order the
/// appendix prints them.
///
/// The appendix prints, for each case, a "128-bit PBKDF2 output", a "128-bit
/// AES key", a "256-bit PBKDF2 output" and a "256-bit AES key". The PBKDF2
/// output is `tkey`, before `DK(tkey, "kerberos")`; the AES key is after it.
/// Note that the first sixteen octets of every 256 bit PBKDF2 output are the
/// same as the 128 bit one, which is PBKDF2's own structure and a useful
/// check that the transcription did not slip a line.
const STRING_TO_KEY_VECTORS: &[StringToKeyVector] = &[
    StringToKeyVector {
        iterations: 1,
        passphrase: "password",
        salt: b"ATHENA.MIT.EDUraeburn",
        pbkdf2_128: "cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15",
        key_128: "42 26 3c 6e 89 f4 fc 28 b8 df 68 ee 09 79 9f 15",
        pbkdf2_256: "cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15
                     0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37",
        key_256: "fe 69 7b 52 bc 0d 3c e1 44 32 ba 03 6a 92 e6 5b
                  bb 52 28 09 90 a2 fa 27 88 39 98 d7 2a f3 01 61",
    },
    StringToKeyVector {
        iterations: 2,
        passphrase: "password",
        salt: b"ATHENA.MIT.EDUraeburn",
        pbkdf2_128: "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d",
        key_128: "c6 51 bf 29 e2 30 0a c2 7f a4 69 d6 93 bd da 13",
        pbkdf2_256: "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d
                     a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86",
        key_256: "a2 e1 6d 16 b3 60 69 c1 35 d5 e9 d2 e2 5f 89 61
                  02 68 56 18 b9 59 14 b4 67 c6 76 22 22 58 24 ff",
    },
    StringToKeyVector {
        iterations: 1200,
        passphrase: "password",
        salt: b"ATHENA.MIT.EDUraeburn",
        pbkdf2_128: "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b",
        key_128: "4c 01 cd 46 d6 32 d0 1e 6d be 23 0a 01 ed 64 2a",
        pbkdf2_256: "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b
                     a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13",
        key_256: "55 a6 ac 74 0a d1 7b 48 46 94 10 51 e1 e8 b0 a7
                  54 8d 93 b0 ab 30 a8 bc 3f f1 62 80 38 2b 8c 2a",
    },
    // "Salt=0x1234567878563412". The only vector whose salt is binary rather
    // than text, which is why `salt` is a byte string throughout: a salt from
    // PA-ETYPE-INFO2 is an OCTET STRING and nothing guarantees it is UTF-8.
    // The appendix notes this case is based on values from RFC 3211.
    StringToKeyVector {
        iterations: 5,
        passphrase: "password",
        salt: &[0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12],
        pbkdf2_128: "d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49",
        key_128: "e9 b2 3d 52 27 37 47 dd 5c 35 cb 55 be 61 9d 8e",
        pbkdf2_256: "d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49
                     3f 98 d2 03 e6 be 49 a6 ad f4 fa 57 4b 6e 64 ee",
        key_256: "97 a4 e7 86 be 20 d8 1a 38 2d 5e bc 96 d5 90 9c
                  ab cd ad c8 7c a4 8f 57 45 04 15 9f 16 c3 6e 31",
    },
    // A pass phrase of exactly the SHA-1 block size, 64 octets. PKCS#5's HMAC
    // hashes a key longer than the block size and uses a shorter one as is,
    // so 64 and 65 are the two sides of that boundary and the appendix
    // supplies both.
    StringToKeyVector {
        iterations: 1200,
        passphrase: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        salt: b"pass phrase equals block size",
        pbkdf2_128: "13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9",
        key_128: "59 d1 bb 78 9a 82 8b 1a a5 4e f9 c2 88 3f 69 ed",
        pbkdf2_256: "13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9
                     c5 ec 59 f1 a4 52 f5 cc 9a d9 40 fe a0 59 8e d1",
        key_256: "89 ad ee 36 08 db 8b c7 1f 1b fb fe 45 94 86 b0
                  56 18 b7 0c ba e2 20 92 53 4e 56 c5 53 ba 4b 34",
    },
    StringToKeyVector {
        iterations: 1200,
        passphrase: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        salt: b"pass phrase exceeds block size",
        pbkdf2_128: "9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61",
        key_128: "cb 80 05 dc 5f 90 17 9a 7f 02 10 4c 00 18 75 1d",
        pbkdf2_256: "9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61
                     1a 8b 4d 28 26 01 db 3b 36 be 92 46 91 5e c8 2a",
        key_256: "d7 8c 5c 9c b8 72 a8 c9 da d4 69 7f 0b b5 b2 d2
                  14 96 c8 2b eb 2c ae da 21 12 fc ee a0 57 40 1b",
    },
    // "Pass phrase = g-clef (0xf09d849e)". U+1D11E MUSICAL SYMBOL G CLEF,
    // whose UTF-8 encoding is those four octets. This is the vector that
    // proves the pass phrase reaches PBKDF2 as UTF-8: encoded as UTF-16LE,
    // the way every other Windows authentication path encodes a password, it
    // would be `1e d1 34 d8` and every octet below would differ.
    StringToKeyVector {
        iterations: 50,
        passphrase: "\u{1D11E}",
        salt: b"EXAMPLE.COMpianist",
        pbkdf2_128: "6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39",
        key_128: "f1 49 c1 f2 e1 54 a7 34 52 d4 3e 7f e6 2a 56 e5",
        pbkdf2_256: "6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39
                     e7 fe 37 a0 c4 1e 02 c2 81 ff 30 69 e1 e9 4f 52",
        key_256: "4b 6d 98 39 f8 44 06 df 1f 09 cc 16 6d b4 b8 3c
                  57 18 48 b7 84 a3 d6 bd c3 46 58 9a 3e 39 3f 9e",
    },
];

/// Every string-to-key vector of RFC 3962 appendix B, for both enctypes and
/// both published intermediates.
///
/// A pass through here proves, in one go: PBKDF2-HMAC-SHA1 with the salt and
/// iteration count wired the right way round, the UTF-8 encoding of the pass
/// phrase, `n-fold("kerberos", 16)`, `DR`'s loop and its zero initial cipher
/// state, the single block cipher path that `DR` reaches, `k-truncate` at
/// both key lengths, and the identity `random-to-key`.
#[test]
fn string_to_key_matches_every_vector_in_rfc_3962_appendix_b() {
    for (n, v) in STRING_TO_KEY_VECTORS.iter().enumerate() {
        let context = format!("vector {n}, iterations {}", v.iterations);

        let tkey128 = string_to_key_intermediate(
            Enctype::Aes128CtsHmacSha1_96,
            v.passphrase,
            v.salt,
            v.iterations,
        )
        .expect("the iteration count is in range");
        assert_eq!(&*tkey128, &hex(v.pbkdf2_128), "128 bit PBKDF2, {context}");

        let key128 = string_to_key(
            Enctype::Aes128CtsHmacSha1_96,
            v.passphrase,
            v.salt,
            v.iterations,
        )
        .expect("the iteration count is in range");
        assert_eq!(key128.octets(), hex(v.key_128), "128 bit key, {context}");

        let tkey256 = string_to_key_intermediate(
            Enctype::Aes256CtsHmacSha1_96,
            v.passphrase,
            v.salt,
            v.iterations,
        )
        .expect("the iteration count is in range");
        assert_eq!(&*tkey256, &hex(v.pbkdf2_256), "256 bit PBKDF2, {context}");

        let key256 = string_to_key(
            Enctype::Aes256CtsHmacSha1_96,
            v.passphrase,
            v.salt,
            v.iterations,
        )
        .expect("the iteration count is in range");
        assert_eq!(key256.octets(), hex(v.key_256), "256 bit key, {context}");

        // PBKDF2's own structure: the first block of the 256 bit output is
        // the whole of the 128 bit one. A transcription that dropped a line
        // fails here before it fails anywhere more confusing.
        assert_eq!(tkey256.get(..16), tkey128.get(..16), "{context}");
        // And DK is not the identity: the key differs from the PBKDF2 output
        // it came from, which is the assertion that a `string_to_key` with
        // the DK step accidentally removed would fail.
        assert_ne!(key128.octets(), &*tkey128, "{context}");
        assert_ne!(key256.octets(), &*tkey256, "{context}");
    }
}

// ---------------------------------------------------------------------------
// RFC 3962 appendix B: AES-CTS
// ---------------------------------------------------------------------------

/// "AES 128-bit key: 63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69", which
/// is the ASCII of `chicken teriyaki` (RFC 3962 appendix B).
const CTS_KEY: &str = "63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69";

/// The six ciphertext stealing vectors of RFC 3962 appendix B, in order. The
/// IV is all zero for every one of them, which the appendix states once above
/// the set and repeats for each.
///
/// The input is a prefix of "I would like the General Gau's Chicken, please,
/// and wonton soup." and the lengths are 17, 31, 32, 47, 48 and 64 octets.
/// The appendix supplies nothing shorter than 17, which is the whole of the
/// reason the single block case below needs its own derivation.
const CTS_VECTORS: &[(&str, &str, &str)] = &[
    // 17 octets: one whole block and one octet.
    (
        "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
         20",
        "c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f
         97",
        "c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f",
    ),
    // 31 octets: one whole block and fifteen octets.
    (
        "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
         20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20",
        "fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22
         97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5",
        "fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22",
    ),
    // 32 octets: exactly two blocks, so the ciphertext is plain CBC with the
    // last two blocks swapped. This is the vector the single block case is
    // derived from below.
    (
        "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
         20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43",
        "39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8
         97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84",
        "39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8",
    ),
    // 47 octets: two whole blocks and fifteen octets.
    (
        "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
         20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43
         68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c",
        "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84
         b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e
         39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5",
        "b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e",
    ),
    // 48 octets: exactly three blocks.
    (
        "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
         20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43
         68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20",
        "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84
         9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8
         39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8",
        "9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8",
    ),
    // 64 octets: exactly four blocks.
    (
        "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
         20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43
         68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20
         61 6e 64 20 77 6f 6e 74 6f 6e 20 73 6f 75 70 2e",
        "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84
         39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8
         48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40
         9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8",
        "48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40",
    ),
];

/// Every ciphertext stealing vector of RFC 3962 appendix B, encrypting and
/// decrypting.
///
/// The five lengths that are not a multiple of the block size exercise the
/// ragged tail, which is the part `cts` gets right and the part a hand
/// written CS-3 gets wrong. The two that are a multiple exercise the
/// unconditional swap that distinguishes CS-3 from CS-1 and CS-2.
#[test]
fn aes_cts_matches_every_vector_in_rfc_3962_appendix_b() {
    let key = Key::new(Enctype::Aes128CtsHmacSha1_96, &hex(CTS_KEY)).expect("a 16 octet key");
    for (n, (input, output, next_iv)) in CTS_VECTORS.iter().enumerate() {
        let plain = hex(input);
        let cipher = hex(output);
        assert_eq!(plain.len(), cipher.len(), "vector {n}: CTS expands nothing");

        let mut buf = plain.clone();
        encrypt_raw(&key, &[0u8; BLOCK_LEN], &mut buf).expect("encrypt");
        assert_eq!(buf, cipher, "vector {n} encrypt, {} octets", plain.len());

        decrypt_raw(&key, &[0u8; BLOCK_LEN], &mut buf).expect("decrypt");
        assert_eq!(buf, plain, "vector {n} decrypt, {} octets", plain.len());

        // The appendix also prints a "Next IV" for each vector. Nothing in
        // this client carries a cipher state from one message to the next:
        // RFC 3961 §5.3's encryption and decryption functions both start from
        // the initial cipher state, all bits zero, so there is no carried IV
        // to get wrong and no function here that returns one. The value is
        // checked anyway, as the property RFC 3962 §5 states it has ("the
        // next-to-last block of the encryption output; ... If only one
        // ciphertext block is available ... then that one block is carried
        // out instead"), because a transcription that slipped a line would
        // pass the ciphertext assertion above only by coincidence and fails
        // here.
        // "Next-to-last block" counts the ragged tail as a block: for the 17
        // octet vector the carried IV is the first sixteen octets and not the
        // one octet tail, and for the 47 octet one it is the second block and
        // not the first. That is ceil(len / 16) - 2, and getting it wrong the
        // other way is what the first run of this assertion did.
        let blocks = cipher.len().div_ceil(BLOCK_LEN);
        let next_to_last = blocks.saturating_sub(2) * BLOCK_LEN;
        assert_eq!(
            cipher.get(next_to_last..next_to_last + BLOCK_LEN),
            Some(hex(next_iv).as_slice()),
            "vector {n} next IV"
        );
    }
}

/// The single block case of RFC 3962 §5, which the appendix does not supply.
///
/// The RFC says two things that between them fix the answer without any
/// arithmetic of ours:
///
/// 1. §5: "If exactly one block is to be encrypted, that block is simply
///    encrypted with AES (also known as ECB mode)."
/// 2. §5: "If the data length is a multiple of the block size, this is
///    equivalent to plain CBC mode with the last two ciphertext blocks
///    swapped."
///
/// Appendix B's 32 octet vector is a multiple of the block size, so by (2) its
/// output is plain CBC with the two blocks swapped, which means plain CBC's
/// first ciphertext block is the *second* half of that vector's output:
///
/// ```text
///   published output = 39312523a78662d5be7fcbcc98ebf5a8  (C2)
///                      976872 68d6eccc c0c07b25 e25ecfe584  (C1)
/// ```
///
/// With an all zero IV, plain CBC's first block is `AES(P1)`, and by (1) that
/// is exactly what a one block CTS encryption must produce for the same `P1`.
/// So the expected value below is transcribed from appendix B's own output,
/// not computed here, and it agrees with the independent measurement PRDRDP/11
/// §3.9.2 recorded when it opened the finding.
///
/// This is the case `cts` 0.6.0 answers wrongly, which the second half of this
/// test asserts directly. If `cts` ever grows the special case, that assertion
/// fails, and the right response is to delete the branch in `crypto.rs` and
/// this half of the test, not to loosen either.
#[test]
fn the_single_block_case_of_rfc_3962_section_5_is_plain_aes() {
    // "I would like the", the first block of appendix B's input.
    let plain = hex("49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65");
    // The second block of appendix B's 32 octet output, which by §5's own
    // equivalence is plain CBC's first ciphertext block.
    let expected = hex("97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84");

    let key = Key::new(Enctype::Aes128CtsHmacSha1_96, &hex(CTS_KEY)).expect("a 16 octet key");
    let mut buf = plain.clone();
    encrypt_raw(&key, &[0u8; BLOCK_LEN], &mut buf).expect("encrypt");
    assert_eq!(buf, expected, "one block AES-CTS is one block of AES");

    decrypt_raw(&key, &[0u8; BLOCK_LEN], &mut buf).expect("decrypt");
    assert_eq!(buf, plain);

    // The branch is load bearing: `cts` alone gives a different answer.
    // `CbcCs3Enc` swaps the last two ciphertext blocks only when the tail is
    // empty and there is more than one block, so a single block input falls
    // into the stealing branch and is encrypted twice
    // (`cts-0.6.0/src/cbc_cs3_enc.rs`, `RustCrypto/block-modes` issue 77,
    // PRDRDP/11 §3.9.2).
    use cts::{CbcCs3Enc, Encrypt, KeyIvInit};
    let mut through_cts = plain.clone();
    CbcCs3Enc::<aes::Aes128>::new_from_slices(&hex(CTS_KEY), &[0u8; BLOCK_LEN])
        .expect("a 16 octet key")
        .encrypt(&mut through_cts)
        .expect("one block is not shorter than one block");
    assert_ne!(
        through_cts, expected,
        "cts 0.6.0 now handles the single block case of RFC 3962 §5. Delete \
         the length dispatch in kerberos/crypto.rs and this assertion with it."
    );
}
