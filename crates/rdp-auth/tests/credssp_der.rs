//! CredSSP on the wire: MS-CSSP's own bytes, PRDRDP/14 §3.2's worked example,
//! the whole five message exchange, and the refusals.
//!
//! PRDRDP/11 §2.10's transcription rule applies to every constant here: the
//! document, the revision and the section go in a comment on the constant,
//! every time, not once per file.
//!
//! ## What MS-CSSP section 4 actually publishes
//!
//! One byte dump, and it is not the one anybody wants. Section 4 (revision
//! 21.0, 23 April 2024) is a narrative walk through the nine steps of the
//! exchange plus a single hex dump of an unencrypted `TSRequest.authInfo`
//! carrying `TSSmartCardCreds`. There is no `pubKeyAuth` example, no nonce,
//! no version 5 or 6 example, and no `TSPasswordCreds` bytes.
//!
//! That dump still earns its place, because its two outer layers are the two
//! we write: a `TSCredentials` with a `credType` and a `credentials` OCTET
//! STRING holding a re-encoded inner structure, with long form lengths on
//! both. [`ms_cssp_section_4_smart_card_credentials`] parses it, checks every
//! published field against the summary printed beside it, and re-encodes it
//! byte for byte.
//!
//! What has no vector anywhere: PRDRDP/11 §2.10 records that the version 5
//! and 6 binding cannot have one, because the nonce makes it non
//! deterministic. `credssp/binding.rs` proves that construction against the
//! specification's own pseudocode instead, deriving each value independently
//! before comparing.
//!
//! ## The test double, and what it does and does not prove
//!
//! [`EchoMech`] stands in for a real mechanism in the state machine tests. It
//! performs no cryptography at all: its `wrap` prefixes a four byte sequence
//! number and copies the plaintext. That is deliberate. What these tests are
//! about is the CredSSP layer, whose contract is with
//! [`GssMechanism`](rdp_auth::gss::GssMechanism) and not with NTLM: the field
//! layout, the order the calls happen in, the sequence numbers, the version
//! freeze, and the refusal. The NTLM half is proved against MS-NLMP 4.2.4 in
//! `nlmp_vectors.rs`, and the two together are proved only against a real
//! server.

use rdp_auth::credssp::binding::PublicKeyBinding;
use rdp_auth::credssp::ts_request::TsRequest;
use rdp_auth::credssp::{
    ts_credentials, MechanismSet, CLIENT_VERSION, MIN_SERVER_VERSION, NONCE_LEN,
};
use rdp_auth::error::AuthError;
use rdp_auth::gss::{GssMechanism, GssStep};
use rdp_auth::{Class, CredSspClient, CredSspConfig, Identity, Step};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// MS-CSSP section 4, the one published byte dump
// ---------------------------------------------------------------------------

/// MS-CSSP (revision 21.0, 23 April 2024) section 4, step 9: "A sample of an
/// unencrypted (ASN.1DER encoded) TSRequest.authInfo structure follows."
///
/// A `TSCredentials` (2.2.1.2) with `credType` 2, `TSSmartCardCreds`
/// (2.2.1.2.2), whose `credentials` OCTET STRING holds 258 bytes of inner
/// DER. Transcribed from the published dump with its hyphen separator and its
/// ASCII gutter removed, 275 bytes.
const MS_CSSP_4_AUTH_INFO: &str = concat!(
    "3082010fa003020102a1820106048201023081ffa01a04186200620062006200",
    "62006200620062006200620062006200a181e03081dda003020101a22e042c4f",
    "004d004e0049004b0045005900200043006100720064004d0061006e00200033",
    "0078003200310020003000a350044e6c0065002d004d00530053006d00610072",
    "007400630061007200640055007300650072002d003800620064006100300031",
    "00390066002d0031003200360036002d002d0035003300320036003800a45404",
    "524d006900630072006f0073006f006600740020004200610073006500200053",
    "006d00610072007400200043006100720064002000430072007900700074006f",
    "002000500072006f0076006900640065007200",
);

#[test]
fn ms_cssp_section_4_smart_card_credentials() {
    let bytes = hex::decode(MS_CSSP_4_AUTH_INFO).expect("the transcribed dump is hex");

    // The summary printed beside the dump: "Total Size: 275",
    // "tscredentials_len: 0X10F=271", "credType: 0X2=2", "creds_len:
    // 0X106=262", "csp_len: 0XE0=224", "keySpec: 0X1=1".
    assert_eq!(bytes.len(), 275);
    assert_eq!(
        &bytes[..4],
        &[0x30, 0x82, 0x01, 0x0f],
        "SEQUENCE, 271 bytes"
    );
    assert_eq!(
        &bytes[4..9],
        &[0xa0, 0x03, 0x02, 0x01, 0x02],
        "[0] INTEGER 2"
    );
    assert_eq!(
        &bytes[9..17],
        &[0xa1, 0x82, 0x01, 0x06, 0x04, 0x82, 0x01, 0x02],
        "[1] of 262 holding an OCTET STRING of 258"
    );

    let creds = ts_credentials::decode_credentials(&bytes).unwrap();
    assert_eq!(creds.cred_type, 2, "TSSmartCardCreds");
    assert_eq!(creds.credentials.len(), 262 - 4);

    // The inner TSSmartCardCreds, walked far enough to prove the OCTET STRING
    // really holds DER: SEQUENCE of 255, then `pin [0] OCTET STRING` of 24,
    // which the summary prints as "pin: [bbbbbbbbbbbb]".
    assert_eq!(&creds.credentials[..3], &[0x30, 0x81, 0xff]);
    assert_eq!(&creds.credentials[3..7], &[0xa0, 0x1a, 0x04, 0x18]);
    assert_eq!(utf16le(&creds.credentials[7..31]), "bbbbbbbbbbbb");
    // And the three strings the summary names, at the offsets the lengths
    // put them at. They are UTF-16LE, which is what footnote 15 of 2.2.1.2
    // says and what the body never states.
    assert_eq!(utf16le(&bytes[63..107]), "OMNIKEY CardMan 3x21 0");
    assert_eq!(
        utf16le(&bytes[111..189]),
        "le-MSSmartcardUser-8bda019f-1266--53268"
    );
    assert_eq!(
        utf16le(&bytes[193..275]),
        "Microsoft Base Smart Card Crypto Provider"
    );

    // Our writer produces the specification's bytes exactly, which is the
    // half that proves the long form lengths and the explicit context tags.
    let re_encoded = ts_credentials::encode_credentials(creds.cred_type, &creds.credentials);
    assert_eq!(&*re_encoded, &bytes, "re-encoding changed the bytes");
}

#[test]
fn ms_cssp_section_4_travels_inside_a_ts_request_auth_info() {
    // MS-CSSP 3.1.5 step 5 encrypts that structure and puts the result in
    // `authInfo`. Unencrypted here, so the assertion is about the nesting:
    // the OCTET STRING holds whatever `wrap` produced and the TSRequest layer
    // knows only its length.
    let bytes = hex::decode(MS_CSSP_4_AUTH_INFO).unwrap();
    let mut request = TsRequest::new(CLIENT_VERSION);
    request.auth_info = Some(bytes.clone());
    let parsed = TsRequest::decode(&request.encode()).unwrap();
    assert_eq!(parsed.auth_info.as_deref(), Some(bytes.as_slice()));
    // "During this phase of the protocol, the OPTIONAL pubKeyAuth and
    // negoTokens fields are omitted from the TSRequest structure."
    assert!(parsed.nego_tokens.is_empty());
    assert!(parsed.pub_key_auth.is_none());
    assert!(parsed.client_nonce.is_none());
}

// ---------------------------------------------------------------------------
// PRDRDP/14 §3.2's worked example
// ---------------------------------------------------------------------------

#[test]
fn ts_request_first_message_bytes() {
    // PRDRDP/14 §3.2 prints this for "an NTLM NEGOTIATE_MESSAGE of 40 bytes"
    // and then writes `04 2A`, which is 42, carrying the extra two bytes up
    // through all four enclosing lengths. The nesting is right and the
    // arithmetic belongs to a 42 byte token, so this test takes the
    // document's bytes at their word and the next test does the same
    // structure over a real 40 byte NEGOTIATE.
    let token = vec![0x41u8; 42];
    let mut request = TsRequest::new(6);
    request.nego_tokens = vec![token.clone()];

    let mut expected = vec![
        0x30, 0x39, // SEQUENCE, 57 content bytes
        0xa0, 0x03, 0x02, 0x01, 0x06, // [0] version, INTEGER 6
        0xa1, 0x32, // [1] negoTokens
        0x30, 0x30, //   SEQUENCE OF
        0x30, 0x2e, //     SEQUENCE, one NegoData item
        0xa0, 0x2c, //       [0] negoToken
        0x04, 0x2a, //         OCTET STRING, 42 bytes
    ];
    expected.extend_from_slice(&token);
    assert_eq!(request.encode(), expected);
}

#[test]
fn the_first_message_carries_a_real_negotiate_and_nothing_else() {
    // The same structure over the 40 byte NEGOTIATE_MESSAGE a real client
    // sends (MS-NLMP 2.2.1.1: 32 fixed bytes and the 8 byte Version). Every
    // enclosing length is two smaller than PRDRDP/14 §3.2's.
    let mut client = CredSspClient::new(config(MechanismSet::NtlmOnly)).unwrap();
    let Step::SendAndExpect(bytes) = client.step(&[]).unwrap() else {
        panic!("the first step must send and expect")
    };
    assert_eq!(
        &bytes[..17],
        &[
            0x30, 0x37, // SEQUENCE, 55 content bytes
            0xa0, 0x03, 0x02, 0x01, 0x06, // [0] version, INTEGER 6
            0xa1, 0x30, // [1] negoTokens
            0x30, 0x2e, //   SEQUENCE OF
            0x30, 0x2c, //     SEQUENCE
            0xa0, 0x2a, //       [0] negoToken
            0x04, 0x28, //         OCTET STRING, 40 bytes
        ]
    );
    assert_eq!(bytes.len(), 57);
    assert_eq!(&bytes[17..25], b"NTLMSSP\0");
    assert_eq!(&bytes[25..29], &1u32.to_le_bytes(), "NtLmNegotiate");

    let parsed = TsRequest::decode(&bytes).unwrap();
    assert_eq!(parsed.version, 6);
    assert_eq!(parsed.nego_tokens.len(), 1);
    // "the OPTIONAL pubKeyAuth field is omitted by the client unless the
    // client is sending the last SPNEGO token" (MS-CSSP 3.1.5 step 2).
    assert!(parsed.pub_key_auth.is_none());
    assert!(parsed.auth_info.is_none());
    assert!(parsed.client_nonce.is_none());
    assert!(parsed.error_code.is_none());
}

// ---------------------------------------------------------------------------
// The TSRequest codec
// ---------------------------------------------------------------------------

#[test]
fn every_field_round_trips() {
    let request = TsRequest {
        version: 6,
        nego_tokens: vec![vec![0x11; 300]],
        auth_info: Some(vec![0x22; 200]),
        pub_key_auth: Some(vec![0x33; 100]),
        error_code: Some(0xC000_006D),
        client_nonce: Some(vec![0x44; NONCE_LEN]),
    };
    let parsed = TsRequest::decode(&request.encode()).unwrap();
    assert_eq!(parsed, request);
}

#[test]
fn an_ntstatus_is_five_octets_with_a_leading_pad() {
    // X.690 §8.3.2: a positive value with bit 31 set needs the pad, so every
    // real error code from Windows is a five byte INTEGER. A reader that
    // requires four rejects them all, and only on the failure path, which is
    // to say only when a user has typed the wrong password (PRDRDP/14 §3.3).
    let mut request = TsRequest::new(6);
    request.error_code = Some(0xC000_006D);
    let encoded = request.encode();
    assert_eq!(
        &encoded[encoded.len() - 9..],
        &[0xa4, 0x07, 0x02, 0x05, 0x00, 0xc0, 0x00, 0x00, 0x6d]
    );
    assert_eq!(
        TsRequest::decode(&encoded).unwrap().error_code,
        Some(0xC000_006D)
    );
}

#[test]
fn a_four_octet_negative_error_code_reads_as_the_same_status() {
    // The same 32 bits as a negative ASN.1 integer, `02 04 C0 00 00 6D`,
    // which is -1073741715 and which some non Microsoft servers send.
    let encoded = [
        0x30, 0x0d, 0xa0, 0x03, 0x02, 0x01, 0x06, 0xa4, 0x06, 0x02, 0x04, 0xc0, 0x00, 0x00, 0x6d,
    ];
    assert_eq!(
        TsRequest::decode(&encoded).unwrap().error_code,
        Some(0xC000_006D)
    );
}

#[test]
fn a_list_of_two_tokens_keeps_them_in_order() {
    // Neither NTLM nor SPNEGO produces two tokens for one round, and
    // refusing a list would be an interop risk for no security gain: only the
    // first is ever fed to a mechanism (PRDRDP/14 §3.2).
    let request = TsRequest {
        nego_tokens: vec![b"first".to_vec(), b"second".to_vec()],
        ..TsRequest::new(6)
    };
    let parsed = TsRequest::decode(&request.encode()).unwrap();
    assert_eq!(parsed.nego_tokens.len(), 2);
    assert_eq!(parsed.nego_tokens[0], b"first");
}

#[test]
fn the_malformed_shapes_are_refused_and_none_panics() {
    let cases: [(&[u8], &str); 9] = [
        (&[], "empty"),
        (&[0x30], "a tag with no length"),
        (&[0x30, 0x00], "a SEQUENCE with no version"),
        (
            &[0x31, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x06],
            "a SET, not a SEQUENCE",
        ),
        // An implicitly tagged version, which is the mistake PRDRDP/14 §3.2
        // says Windows answers with silence.
        (&[0x30, 0x03, 0x80, 0x01, 0x06], "an implicit version tag"),
        // The indefinite length form, illegal in DER (X.690 §10.1).
        (
            &[0x30, 0x80, 0xa0, 0x03, 0x02, 0x01, 0x06, 0x00, 0x00],
            "an indefinite length",
        ),
        (
            &[0x30, 0x7f, 0xa0, 0x03, 0x02, 0x01, 0x06],
            "a length past the end of the buffer",
        ),
        (
            &[
                0x30, 0x09, 0xa0, 0x03, 0x02, 0x01, 0x06, 0xa1, 0x02, 0x30, 0x00,
            ],
            "an empty NegoData",
        ),
        (
            &[0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x06, 0x00],
            "a trailing byte",
        ),
    ];
    for (bytes, what) in cases {
        assert!(TsRequest::decode(bytes).is_err(), "{what} decoded");
    }
}

#[test]
fn every_truncation_of_a_full_request_is_refused() {
    let full = TsRequest {
        version: 6,
        nego_tokens: vec![vec![0x11; 400]],
        auth_info: Some(vec![0x22; 40]),
        pub_key_auth: Some(vec![0x33; 48]),
        error_code: Some(0xC000_0234),
        client_nonce: Some(vec![0x44; NONCE_LEN]),
    }
    .encode();
    for n in 0..full.len() {
        assert!(
            TsRequest::decode(&full[..n]).is_err(),
            "a {n} byte prefix decoded"
        );
    }
    assert!(TsRequest::decode(&full).is_ok());
}

#[test]
fn a_duplicate_field_is_refused() {
    // DER has no repeated field in a SEQUENCE, and a parser that takes the
    // last one where a checker took the first is a confusion primitive.
    let doubled = [
        0x30, 0x0a, 0xa0, 0x03, 0x02, 0x01, 0x06, 0xa0, 0x03, 0x02, 0x01, 0x02,
    ];
    assert_eq!(
        TsRequest::decode(&doubled).unwrap_err(),
        AuthError::MalformedMessage("version")
    );
}

#[test]
fn an_unknown_context_tag_is_ignored() {
    // A later CredSSP revision adding a `[6]` must not break a client that
    // does not need it.
    let with_six = [
        0x30, 0x0a, 0xa0, 0x03, 0x02, 0x01, 0x06, 0xa6, 0x03, 0x02, 0x01, 0x01,
    ];
    assert_eq!(TsRequest::decode(&with_six).unwrap().version, 6);
}

// ---------------------------------------------------------------------------
// The state machine, end to end
// ---------------------------------------------------------------------------

#[test]
fn the_five_message_exchange_completes() {
    let mut client = echo_client(EchoMech::new(1));
    let mut server = EchoServer::new(6);

    // 1. negoTokens only.
    let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
        panic!()
    };
    let reply = server.answer_negotiate(&msg1);

    // 3. MS-CSSP 3.1.5 step 3: "the TSRequest structure MUST have both the
    //    negoTokens and the pubKeyAuth fields filled in".
    let Step::SendAndExpect(msg3) = client.step(&reply).unwrap() else {
        panic!()
    };
    let parsed = TsRequest::decode(&msg3).unwrap();
    assert_eq!(parsed.nego_tokens.len(), 1);
    assert!(parsed.pub_key_auth.is_some());
    assert_eq!(parsed.client_nonce.as_ref().map(Vec::len), Some(NONCE_LEN));
    assert!(parsed.auth_info.is_none());
    let reply = server.answer_public_key(&msg3);

    // 5. authInfo only, and no reply.
    let Step::Send(msg5) = client.step(&reply).unwrap() else {
        panic!("message 5 has no reply")
    };
    let parsed = TsRequest::decode(&msg5).unwrap();
    assert!(parsed.auth_info.is_some());
    assert!(parsed.nego_tokens.is_empty());
    assert!(parsed.pub_key_auth.is_none());
    assert!(parsed.client_nonce.is_none(), "the nonce is sent once");
    server.check_credentials(&msg5);

    let Step::Done(outcome) = client.step(&[]).unwrap() else {
        panic!("the flush is followed by the outcome")
    };
    assert_eq!(outcome.credssp_version, 6);
    assert!(outcome.public_key_bound);
    assert_eq!(outcome.method, "echo");
}

#[test]
fn credssp_nonce_is_the_one_sent() {
    // PRDRDP/14 §8.8: a nonce generated after the hash produces a binding
    // over a value that was never sent, and the server rejects it with no
    // explanation. This pulls the nonce back out of the encoded TSRequest and
    // recomputes the hash against it.
    let mut client = echo_client(EchoMech::new(1));
    let mut server = EchoServer::new(6);
    let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
        panic!()
    };
    let reply = server.answer_negotiate(&msg1);
    let Step::SendAndExpect(msg3) = client.step(&reply).unwrap() else {
        panic!()
    };

    let parsed = TsRequest::decode(&msg3).unwrap();
    let nonce: [u8; NONCE_LEN] = parsed.client_nonce.unwrap().try_into().unwrap();
    let sent = EchoMech::unseal(parsed.pub_key_auth.as_deref().unwrap(), 0).unwrap();
    let binding = PublicKeyBinding::with_nonce(6, nonce);
    assert_eq!(
        sent,
        binding.client_value(PUBLIC_KEY),
        "the pubKeyAuth was computed over a different nonce"
    );
    assert_eq!(sent.len(), 32, "a SHA-256 digest at version 6");
}

#[test]
fn credssp_sequence_numbers() {
    // PRDRDP/14 §8.8: the sealing handle persists across messages, so
    // `pubKeyAuth` is sequence 0 and `authInfo` is sequence 1. A handle
    // rebuilt per message makes message 3 succeed and message 5 fail, which
    // looks exactly like a wrong password.
    let mut client = echo_client(EchoMech::new(1));
    let mut server = EchoServer::new(6);
    let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
        panic!()
    };
    let reply = server.answer_negotiate(&msg1);
    let Step::SendAndExpect(msg3) = client.step(&reply).unwrap() else {
        panic!()
    };
    let pub_key_auth = TsRequest::decode(&msg3).unwrap().pub_key_auth.unwrap();
    assert_eq!(EchoMech::sequence_of(&pub_key_auth), 0);

    let reply = server.answer_public_key(&msg3);
    let Step::Send(msg5) = client.step(&reply).unwrap() else {
        panic!()
    };
    let auth_info = TsRequest::decode(&msg5).unwrap().auth_info.unwrap();
    assert_eq!(EchoMech::sequence_of(&auth_info), 1);
}

#[test]
fn a_pubkeyauth_that_does_not_match_is_refused_and_no_password_is_sent() {
    // The entire point of the mechanism (MS-CSSP 3.1.5 step 5).
    for corruption in [
        Corruption::OurOwnValueReplayed,
        Corruption::OneBitFlipped,
        Corruption::AnotherCertificate,
        Corruption::TheOldConstruction,
        Corruption::Absent,
    ] {
        let mut client = echo_client(EchoMech::new(1));
        let mut server = EchoServer::new(6);
        let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
            panic!()
        };
        let reply = server.answer_negotiate(&msg1);
        let Step::SendAndExpect(msg3) = client.step(&reply).unwrap() else {
            panic!()
        };
        let reply = server.answer_public_key_corrupted(&msg3, corruption);
        let error = client.step(&reply).unwrap_err();
        let expected = if corruption == Corruption::Absent {
            // No pubKeyAuth and no errorCode is a rejection, not an
            // interception (PRDRDP/14 §3.11).
            AuthError::AuthFailed
        } else {
            AuthError::PublicKeyMismatch
        };
        assert_eq!(error, expected, "{corruption:?}");
        // The failure is sticky, so a caller that ignores the `Err` does not
        // get a second chance to send the password.
        assert_eq!(client.step(&[]).unwrap_err(), expected);
        assert_eq!(client.step(&reply).unwrap_err(), expected);
    }
}

#[test]
fn an_interception_and_a_wrong_password_are_told_apart() {
    // PRDRDP/14 §3.11: a `pubKeyAuth` that fails verification must not be
    // presented as an authentication failure.
    let mismatch = AuthError::PublicKeyMismatch;
    assert_eq!(mismatch.class(), Class::Fatal);
    assert!(mismatch.user_message().contains("intercepted"));
    let rejected = AuthError::AuthFailed;
    assert_eq!(rejected.class(), Class::User);
    assert!(!rejected.user_message().contains("intercepted"));
}

#[test]
fn an_errorcode_ends_the_exchange_immediately() {
    // MS-CSSP 3.1.5: "If the client receives a TSRequest message with the
    // errorCode present, it MUST immediately fail with the provided status
    // code and cease all further processing."
    for (code, class, symbol) in [
        (0xC000_006Du32, Class::User, Some("STATUS_LOGON_FAILURE")),
        (0xC000_0234, Class::Fatal, Some("STATUS_ACCOUNT_LOCKED_OUT")),
        (
            0xC000_005E,
            Class::Transient,
            Some("STATUS_NO_LOGON_SERVERS"),
        ),
        (0xC000_9999, Class::Fatal, None),
    ] {
        let mut client = echo_client(EchoMech::new(1));
        let _ = client.step(&[]).unwrap();
        let mut reply = TsRequest::new(6);
        reply.error_code = Some(code);
        let error = client.step(&reply.encode()).unwrap_err();
        assert_eq!(error, AuthError::ServerStatus(code));
        assert_eq!(error.class(), class, "{code:#010x}");
        assert_eq!(error.nt_status_symbol(), symbol);
        // The symbol goes in the log line and never in the sentence
        // (PRDRDP/14 §8.4).
        let message = error.user_message();
        assert!(!message.contains("STATUS_"), "{message}");
        assert!(message.ends_with('.'), "{message}");
    }
}

#[test]
fn an_errorcode_in_the_public_key_message_wins_over_the_missing_binding() {
    // PRDRDP/14 §3.11 rule 2: the error is the answer.
    let mut client = echo_client(EchoMech::new(1));
    let mut server = EchoServer::new(6);
    let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
        panic!()
    };
    let reply = server.answer_negotiate(&msg1);
    let Step::SendAndExpect(_) = client.step(&reply).unwrap() else {
        panic!()
    };
    let mut reply = TsRequest::new(6);
    reply.error_code = Some(0xC000_0071);
    assert_eq!(
        client.step(&reply.encode()).unwrap_err(),
        AuthError::ServerStatus(0xC000_0071)
    );
}

#[test]
fn a_successful_errorcode_is_ignored() {
    // A value with the top bit clear is a success indication. Windows does
    // not send one; a non Microsoft server might (PRDRDP/14 §3.10).
    let mut client = echo_client(EchoMech::new(1));
    let mut server = EchoServer::new(6);
    let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
        panic!()
    };
    let mut reply = TsRequest::decode(&server.answer_negotiate(&msg1)).unwrap();
    reply.error_code = Some(0x0000_0000);
    assert!(client.step(&reply.encode()).is_ok());
}

#[test]
fn an_empty_reply_is_a_rejection_the_user_can_act_on() {
    // A well formed TSRequest with a version and nothing else, which is what
    // a server at effective version 2 does when authentication fails, because
    // `errorCode` is only defined from version 3 (PRDRDP/14 §3.11). Class
    // `User`, so the credential prompt comes back rather than a red banner.
    let mut client = echo_client(EchoMech::new(1));
    let _ = client.step(&[]).unwrap();
    let error = client.step(&TsRequest::new(2).encode()).unwrap_err();
    assert_eq!(error, AuthError::AuthFailed);
    assert_eq!(error.class(), Class::User);
}

#[test]
fn the_version_is_frozen_from_the_first_reply() {
    // PRDRDP/14 §3.4 and §8.7: a server cannot advertise 6, watch us pick the
    // hash construction, and then re-advertise 2 to get the raw public key
    // form. The server here does exactly that, and its message 4 still has to
    // carry the version 6 answer.
    let mut client = echo_client(EchoMech::new(1));
    let mut server = EchoServer::new(6);
    let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
        panic!()
    };
    let reply = server.answer_negotiate(&msg1);
    let Step::SendAndExpect(msg3) = client.step(&reply).unwrap() else {
        panic!()
    };
    assert_eq!(client.effective_version(), Some(6));

    // Message 4 claims version 2 while still answering with the version 6
    // construction, which is what a downgrade attempt looks like.
    let mut reply = TsRequest::decode(&server.answer_public_key(&msg3)).unwrap();
    reply.version = 2;
    let Step::Send(_) = client.step(&reply.encode()).unwrap() else {
        panic!("the frozen construction still verifies")
    };
    assert_eq!(client.effective_version(), Some(6));

    // And the raw key form, which is what the server would have wanted, does
    // not verify against the frozen version.
    let mut client = echo_client(EchoMech::new(1));
    let mut server = EchoServer::new(6);
    let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
        panic!()
    };
    let reply = server.answer_negotiate(&msg1);
    let Step::SendAndExpect(msg3) = client.step(&reply).unwrap() else {
        panic!()
    };
    let reply = server.answer_public_key_corrupted(&msg3, Corruption::TheOldConstruction);
    assert_eq!(
        client.step(&reply).unwrap_err(),
        AuthError::PublicKeyMismatch
    );
}

#[test]
fn a_server_below_version_two_is_refused() {
    // MS-CSSP 2.2.1: "Valid values for this field are 2, 3, 4, 5, and 6."
    for version in [0u32, 1] {
        let mut client = echo_client(EchoMech::new(1));
        let _ = client.step(&[]).unwrap();
        let mut reply = TsRequest::new(version);
        reply.nego_tokens = vec![b"challenge".to_vec()];
        assert_eq!(
            client.step(&reply.encode()).unwrap_err(),
            AuthError::UnsupportedCredSspVersion
        );
    }
}

#[test]
fn a_version_four_server_gets_the_raw_public_key_construction() {
    // Server 2008 R2 and older predate version 5 (MS-CSSP footnote 25), and
    // PRDRDP/00 R55 makes them supported targets on the legacy TLS backend,
    // so this is a path real users take rather than dead code.
    let mut client = echo_client(EchoMech::new(1));
    let mut server = EchoServer::new(4);
    let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
        panic!()
    };
    let reply = server.answer_negotiate(&msg1);
    let Step::SendAndExpect(msg3) = client.step(&reply).unwrap() else {
        panic!()
    };
    let parsed = TsRequest::decode(&msg3).unwrap();
    assert!(
        parsed.client_nonce.is_none(),
        "clientNonce is version 5 and higher only (MS-CSSP 2.2.1)"
    );
    assert_eq!(
        EchoMech::unseal(parsed.pub_key_auth.as_deref().unwrap(), 0).unwrap(),
        PUBLIC_KEY,
        "versions 2 to 4 send the key itself (MS-CSSP 3.1.5 step 3)"
    );

    let reply = server.answer_public_key(&msg3);
    // The server's answer is the key with one added to its first byte.
    let returned = TsRequest::decode(&reply).unwrap().pub_key_auth.unwrap();
    let returned = EchoMech::unseal(&returned, 0).unwrap();
    assert_eq!(returned[0], PUBLIC_KEY[0] + 1);
    assert_eq!(&returned[1..], &PUBLIC_KEY[1..]);

    let Step::Send(msg5) = client.step(&reply).unwrap() else {
        panic!()
    };
    server.check_credentials(&msg5);
    let Step::Done(outcome) = client.step(&[]).unwrap() else {
        panic!()
    };
    assert_eq!(outcome.credssp_version, 4);
}

#[test]
fn a_server_sent_nonce_is_refused() {
    // MS-CSSP 2.2.1 makes `clientNonce` the client's field, and 3.1.5 uses it
    // only in the message carrying `pubKeyAuth`. A server sending one is
    // steering our binding computation.
    let mut client = echo_client(EchoMech::new(1));
    let _ = client.step(&[]).unwrap();
    let mut reply = TsRequest::new(6);
    reply.nego_tokens = vec![b"challenge".to_vec()];
    reply.client_nonce = Some(vec![0u8; NONCE_LEN]);
    assert_eq!(
        client.step(&reply.encode()).unwrap_err(),
        AuthError::MalformedMessage("the server sent a clientNonce")
    );
}

#[test]
fn a_server_that_never_stops_negotiating_is_cut_off() {
    // PRDRDP/14 §3.13's cap of eight rounds. A server that keeps producing
    // tokens forever is either broken or trying to make us allocate.
    let mut client = echo_client(EchoMech::new(100));
    let mut input = Vec::new();
    let mut error = None;
    for _ in 0..20 {
        match client.step(&input) {
            Ok(Step::SendAndExpect(_)) => {
                let mut reply = TsRequest::new(6);
                reply.nego_tokens = vec![b"again".to_vec()];
                input = reply.encode();
            }
            Ok(other) => panic!("unexpected {other:?}"),
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }
    assert_eq!(error, Some(AuthError::TooManyRounds));
}

#[test]
fn a_real_ntlm_client_produces_the_first_three_messages() {
    // The mechanism seam with the mechanism that ships. Message 4 cannot be
    // answered here: producing the server's `pubKeyAuth` needs the server
    // direction of the NTLM sealing handles, and `NtlmSession` exposes only
    // the client direction. PRDRDP/14 §9.3 puts that server side in
    // `rdp-core/tests/common/ntlm_server.rs`.
    let mut client = CredSspClient::new(config(MechanismSet::NtlmOnly)).unwrap();
    let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
        panic!()
    };
    let negotiate = TsRequest::decode(&msg1).unwrap().nego_tokens.remove(0);
    assert_eq!(&negotiate[..8], b"NTLMSSP\0");

    let mut reply = TsRequest::new(6);
    reply.nego_tokens = vec![ntlm_challenge()];
    let Step::SendAndExpect(msg3) = client.step(&reply.encode()).unwrap() else {
        panic!()
    };
    let parsed = TsRequest::decode(&msg3).unwrap();
    assert_eq!(&parsed.nego_tokens[0][..8], b"NTLMSSP\0");
    assert_eq!(&parsed.nego_tokens[0][8..12], &3u32.to_le_bytes());

    // The pubKeyAuth is a 16 byte MESSAGE_SIGNATURE and then the sealed 32
    // byte hash (MS-NLMP 2.2.2.9.1, MS-CSSP 3.1.5).
    let pub_key_auth = parsed.pub_key_auth.unwrap();
    assert_eq!(pub_key_auth.len(), 16 + 32, "signature plus SHA-256");
    assert_eq!(&pub_key_auth[..4], &1u32.to_le_bytes(), "signature version");
    assert_eq!(
        &pub_key_auth[12..16],
        &0u32.to_le_bytes(),
        "the first use of the sealing handle is sequence 0"
    );
    assert_eq!(parsed.client_nonce.map(|n| n.len()), Some(NONCE_LEN));
}

#[test]
fn the_credssp_client_debug_hides_the_password() {
    let mut client = CredSspClient::new(config(MechanismSet::NtlmOnly)).unwrap();
    let _ = client.step(&[]).unwrap();
    for rendered in [format!("{client:?}"), format!("{client:#?}")] {
        assert!(!rendered.contains(PASSWORD), "password leaked: {rendered}");
        assert!(rendered.contains("***"), "{rendered}");
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const PASSWORD: &str = "hunter2-correct-horse-battery-staple";

/// The `subjectPublicKey` of a 2048 bit RSA certificate begins like this
/// (PRDRDP/14 §3.6). Only the shape matters here.
const PUBLIC_KEY: &[u8] = &[
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc3, 0x2f, 0x11, 0x9a, 0x40,
];

fn config(mechanisms: MechanismSet) -> CredSspConfig {
    CredSspConfig {
        identity: Identity::from_prompt("alice", "CORP", PASSWORD).unwrap(),
        spn: "TERMSRV/server.example.com".to_owned(),
        server_public_key: PUBLIC_KEY.to_vec(),
        server_certificate: Some(b"a certificate, hashed here and parsed elsewhere".to_vec()),
        // 1.2.840.113549.1.1.11, sha256WithRSAEncryption.
        certificate_signature_algorithm: vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
        workstation: Some("laptop".to_owned()),
        client_version: CLIENT_VERSION,
        min_server_version: MIN_SERVER_VERSION,
        mechanisms,
    }
}

fn echo_client(mechanism: EchoMech) -> CredSspClient {
    CredSspClient::with_mechanism(config(MechanismSet::NtlmOnly), Box::new(mechanism)).unwrap()
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).expect("UTF-16LE")
}

/// A CHALLENGE shaped like a modern Windows one, which is what our policy
/// requires (MS-NLMP 2.2.1.2, PRDRDP/14 §8.5).
fn ntlm_challenge() -> Vec<u8> {
    use rdp_auth::ntlm::{av_pair, crypto, flags, messages, version::Version};
    let mut pairs = av_pair::AvPairs::default();
    pairs.set(av_pair::MSV_AV_NB_DOMAIN_NAME, crypto::unicode("CORP"));
    pairs.set(av_pair::MSV_AV_NB_COMPUTER_NAME, crypto::unicode("SERVER"));
    pairs.set(av_pair::MSV_AV_TIMESTAMP, vec![0x77; 8]);
    messages::encode_challenge(&messages::ChallengeMessage {
        target_name: crypto::unicode("SERVER"),
        flags: flags::CLIENT_NEGOTIATE_FLAGS,
        server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        target_info: pairs.encode(),
        version: Some(Version::CLIENT),
        raw: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// The test double
// ---------------------------------------------------------------------------

/// A `GssMechanism` that performs no cryptography.
///
/// `wrap` prefixes a four byte little endian sequence number and copies the
/// plaintext; `unwrap` checks the sequence number and strips it. That is
/// enough to prove everything the CredSSP layer owns (the field layout, the
/// call order, the sequence numbering, the version freeze and the refusal)
/// and it proves nothing at all about confidentiality, which is the
/// mechanism's job and is tested in `nlmp_vectors.rs`.
struct EchoMech {
    /// How many `Token` rounds before the `FinalToken`.
    rounds: u32,
    seen: u32,
    send_seq: u32,
    recv_seq: u32,
    complete: bool,
}

impl EchoMech {
    fn new(rounds: u32) -> Self {
        EchoMech {
            rounds,
            seen: 0,
            send_seq: 0,
            recv_seq: 0,
            complete: false,
        }
    }

    fn seal(seq: u32, plaintext: &[u8]) -> Vec<u8> {
        let mut out = seq.to_le_bytes().to_vec();
        out.extend_from_slice(plaintext);
        out
    }

    fn unseal(token: &[u8], expect_seq: u32) -> Result<Vec<u8>, AuthError> {
        if token.len() < 4 {
            return Err(AuthError::MalformedMessage("echo token"));
        }
        if Self::sequence_of(token) != expect_seq {
            return Err(AuthError::MessageOutOfSequence);
        }
        Ok(token[4..].to_vec())
    }

    fn sequence_of(token: &[u8]) -> u32 {
        u32::from_le_bytes([token[0], token[1], token[2], token[3]])
    }
}

impl GssMechanism for EchoMech {
    fn oid(&self) -> &'static [u8] {
        rdp_auth::ntlm::NTLM_MECH_OID
    }

    fn method_name(&self) -> &'static str {
        "echo"
    }

    fn step(&mut self, input: &[u8]) -> Result<GssStep, AuthError> {
        if self.complete {
            return if input.is_empty() {
                Ok(GssStep::Complete)
            } else {
                Err(AuthError::UnexpectedToken)
            };
        }
        self.seen += 1;
        if self.seen > self.rounds {
            self.complete = true;
            Ok(GssStep::FinalToken(b"echo-final".to_vec()))
        } else {
            Ok(GssStep::Token(b"echo-token".to_vec()))
        }
    }

    fn is_complete(&self) -> bool {
        self.complete
    }

    fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        if !self.complete {
            return Err(AuthError::ContextNotEstablished);
        }
        let out = Self::seal(self.send_seq, plaintext);
        self.send_seq += 1;
        Ok(out)
    }

    fn unwrap(&mut self, token: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        if !self.complete {
            return Err(AuthError::ContextNotEstablished);
        }
        let out = Self::unseal(token, self.recv_seq)?;
        self.recv_seq += 1;
        Ok(Zeroizing::new(out))
    }

    fn mic(&mut self, message: &[u8]) -> Result<Vec<u8>, AuthError> {
        self.wrap(message)
    }

    fn verify_mic(&mut self, message: &[u8], mic: &[u8]) -> Result<(), AuthError> {
        let got = self.unwrap(mic)?;
        if *got == message {
            Ok(())
        } else {
            Err(AuthError::SignatureMismatch)
        }
    }
}

/// What the server does with each message (MS-CSSP 3.1.5 steps 2, 4 and 5).
///
/// Written from the specification, like the client, so it cannot validate our
/// reading of the message order: both sides share the same assumption. What
/// it does catch is every self inconsistency, which is the caveat
/// `vnc-core/src/security/ra2.rs:984` states for its own simulated peer.
struct EchoServer {
    version: u32,
    send_seq: u32,
    recv_seq: u32,
}

impl EchoServer {
    fn new(version: u32) -> Self {
        EchoServer {
            version,
            send_seq: 0,
            recv_seq: 0,
        }
    }

    fn answer_negotiate(&mut self, message: &[u8]) -> Vec<u8> {
        let parsed = TsRequest::decode(message).unwrap();
        assert_eq!(parsed.nego_tokens.len(), 1);
        assert!(parsed.pub_key_auth.is_none());
        let mut reply = TsRequest::new(self.version);
        reply.nego_tokens = vec![b"echo-challenge".to_vec()];
        reply.encode()
    }

    /// The binding the client sent, checked, and the answer computed.
    fn verified_binding(&mut self, message: &[u8]) -> (PublicKeyBinding, TsRequest) {
        let parsed = TsRequest::decode(message).unwrap();
        let effective = self.version.min(CLIENT_VERSION);
        let binding = match &parsed.client_nonce {
            Some(nonce) => PublicKeyBinding::with_nonce(
                effective,
                <[u8; NONCE_LEN]>::try_from(nonce.as_slice()).unwrap(),
            ),
            None => PublicKeyBinding::with_nonce(effective, [0u8; NONCE_LEN]),
        };
        let sent =
            EchoMech::unseal(parsed.pub_key_auth.as_deref().unwrap(), self.recv_seq).unwrap();
        self.recv_seq += 1;
        assert_eq!(
            sent,
            binding.client_value(PUBLIC_KEY),
            "the client's pubKeyAuth did not match what the server computes"
        );
        (binding, parsed)
    }

    fn answer_public_key(&mut self, message: &[u8]) -> Vec<u8> {
        let (binding, _) = self.verified_binding(message);
        let value = binding.expected_server_value(PUBLIC_KEY);
        let mut reply = TsRequest::new(self.version);
        reply.pub_key_auth = Some(EchoMech::seal(self.send_seq, &value));
        self.send_seq += 1;
        reply.encode()
    }

    fn answer_public_key_corrupted(&mut self, message: &[u8], how: Corruption) -> Vec<u8> {
        let (binding, parsed) = self.verified_binding(message);
        let value = match how {
            Corruption::Absent => {
                // A well formed TSRequest with nothing in it.
                return TsRequest::new(self.version).encode();
            }
            Corruption::OurOwnValueReplayed => binding.client_value(PUBLIC_KEY),
            Corruption::OneBitFlipped => {
                let mut v = binding.expected_server_value(PUBLIC_KEY);
                v[0] ^= 0x01;
                v
            }
            Corruption::AnotherCertificate => {
                binding.expected_server_value(b"a different server's public key")
            }
            Corruption::TheOldConstruction => {
                let mut v = PUBLIC_KEY.to_vec();
                v[0] = v[0].wrapping_add(1);
                v
            }
        };
        let _ = parsed;
        let mut reply = TsRequest::new(self.version);
        reply.pub_key_auth = Some(EchoMech::seal(self.send_seq, &value));
        self.send_seq += 1;
        reply.encode()
    }

    fn check_credentials(&mut self, message: &[u8]) {
        let parsed = TsRequest::decode(message).unwrap();
        let plaintext =
            EchoMech::unseal(parsed.auth_info.as_deref().unwrap(), self.recv_seq).unwrap();
        self.recv_seq += 1;
        let creds = ts_credentials::decode_credentials(&plaintext).unwrap();
        assert_eq!(creds.cred_type, 1, "TSPasswordCreds");
        let inner = ts_credentials::decode_password_creds(&creds.credentials).unwrap();
        assert_eq!(&*inner.domain, "CORP");
        assert_eq!(&*inner.user, "alice");
        assert_eq!(&*inner.password, PASSWORD);
    }
}

/// The ways a server's `pubKeyAuth` can be wrong, each of which a relay or a
/// confused server can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Corruption {
    /// The value we sent, echoed back. This is the replay that MS-CSSP 3.1.5
    /// says the direction reversal exists to stop.
    OurOwnValueReplayed,
    /// One bit different.
    OneBitFlipped,
    /// The right construction over a different certificate, which is what a
    /// relay to a second host produces.
    AnotherCertificate,
    /// The version 2 to 4 answer to a version 6 exchange.
    TheOldConstruction,
    /// No `pubKeyAuth` at all, and no `errorCode`.
    Absent,
}

// ---------------------------------------------------------------------------
// The SPNEGO arm, which phase 1 does not send
// ---------------------------------------------------------------------------

#[test]
fn the_spnego_arm_wraps_the_same_ntlm_tokens() {
    // PRDRDP/14 §4.8: the switch is a single field on `MechanismSet` and
    // nothing in `credssp/mod.rs` changes. This drives the same NTLM client
    // through SPNEGO and checks that what lands in `negoTokens` is an
    // `InitialContextToken` in message 1 and a bare `NegTokenResp` in message
    // 3, which is what RFC 4178 §4.2 and PRDRDP/14 §4.2 require.
    use rdp_auth::spnego::oid;
    use rdp_auth::spnego::token::NegTokenResp;
    use rdp_auth::MechanismId;

    let mut client =
        CredSspClient::new(config(MechanismSet::Spnego(vec![MechanismId::Ntlm]))).unwrap();
    let Step::SendAndExpect(msg1) = client.step(&[]).unwrap() else {
        panic!()
    };
    let init = TsRequest::decode(&msg1).unwrap().nego_tokens.remove(0);
    assert_eq!(init[0], 0x60, "[APPLICATION 0], RFC 2743 §3.1");
    // The SPNEGO OID follows the header directly, because the SEQUENCE is
    // IMPLICIT inside [APPLICATION 0].
    assert_eq!(
        &init[2..10],
        &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]
    );
    // One mechType, NTLM, and the optimistic token is the NEGOTIATE message.
    assert!(init.windows(oid::NTLMSSP.len()).any(|w| w == oid::NTLMSSP));
    assert!(init.windows(8).any(|w| w == b"NTLMSSP\0"));

    let reply = NegTokenResp {
        neg_state: Some(rdp_auth::spnego::token::NegState::AcceptIncomplete),
        supported_mech: Some(oid::NTLMSSP.to_vec()),
        response_token: Some(ntlm_challenge()),
        mech_list_mic: None,
    }
    .encode();
    let mut wrapper = TsRequest::new(6);
    wrapper.nego_tokens = vec![reply];
    let Step::SendAndExpect(msg3) = client.step(&wrapper.encode()).unwrap() else {
        panic!()
    };
    let parsed = TsRequest::decode(&msg3).unwrap();
    let resp = NegTokenResp::decode(&parsed.nego_tokens[0]).unwrap();
    assert_eq!(parsed.nego_tokens[0][0], 0xa1, "bare, with no 0x60 wrapper");
    let authenticate = resp.response_token.unwrap();
    assert_eq!(&authenticate[..8], b"NTLMSSP\0");
    assert_eq!(&authenticate[8..12], &3u32.to_le_bytes());
    assert!(
        resp.mech_list_mic.is_none(),
        "one mechanism, so RFC 4178 §5 asks for no mechListMIC"
    );

    // The wrap that produced `pubKeyAuth` went through SPNEGO to the same
    // NTLM session, so it is still the first use of the sealing handle.
    let pub_key_auth = parsed.pub_key_auth.unwrap();
    assert_eq!(pub_key_auth.len(), 16 + 32);
    assert_eq!(&pub_key_auth[12..16], &0u32.to_le_bytes());
}

#[test]
fn an_errorcode_wins_over_an_unusable_version() {
    // MS-CSSP 3.1.5: "If the client receives a TSRequest message with the
    // errorCode present, it MUST immediately fail with the provided status
    // code and cease all further processing." A server that refuses the sign
    // in and also advertises a version we will not complete against has still
    // told us why, and that sentence is the one the user can act on.
    let mut client = echo_client(EchoMech::new(1));
    let _ = client.step(&[]).unwrap();
    let mut reply = TsRequest::new(1);
    reply.error_code = Some(0xC000_0234);
    assert_eq!(
        client.step(&reply.encode()).unwrap_err(),
        AuthError::ServerStatus(0xC000_0234)
    );
}
