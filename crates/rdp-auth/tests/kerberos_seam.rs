//! Kerberos through `SpnegoClient` through `CredSspClient`, with a hand
//! written acceptor for the AP-REQ.
//!
//! PRDRDP/14 §2.8 designed [`GssMechanism`] so that Kerberos could arrive in
//! phase 3 without CredSSP or SPNEGO changing. This file is the claim tested
//! rather than asserted: it drives a `KerberosClient` on its own, then the
//! same client inside a `SpnegoClient`, then that inside a `CredSspClient`,
//! and neither of the two outer modules was touched to make it work.
//!
//! The acceptor is written from RFC 4120 §5.5.1 and RFC 4121 §4, and it
//! checks what a real service checks: that the authenticator decrypts at key
//! usage 11, that the 0x8003 checksum carries the channel binding we agreed,
//! and that the flags ask for mutual authentication.

#![cfg(feature = "kerberos")]

use rdp_auth::bindings::ChannelBindings;
use rdp_auth::error::AuthError;
use rdp_auth::gss::{GssMechanism, GssStep};
use rdp_auth::kerberos::asn1::{
    app, application, msg_type, name_type, write_encrypted_data, write_kerberos_string,
    write_kerberos_time, write_principal_name, EncryptedData, KerberosTime, PrincipalName, Ticket,
    PVNO,
};
use rdp_auth::kerberos::crypto::{self, usage, Enctype, Key};
use rdp_auth::kerberos::gss::{authenticator_checksum, CKSUMTYPE_GSSAPI};
use rdp_auth::kerberos::kdc::ServiceTicket;
use rdp_auth::spnego::oid;
use rdp_auth::{KerberosClient, KerberosConfig, SpnegoClient};
use rdp_pdu::asn1::der::{expect_tag, read_int_i64, read_tlv, write_int, write_nested, write_tlv};
use rdp_pdu::asn1::{context, tag};

/// 2026-08-24T12:00:00Z.
const NOW: i64 = 1_787_486_400;
const REALM: &str = "CORP.EXAMPLE.COM";
const ENCTYPE: Enctype = Enctype::Aes256CtsHmacSha1_96;

fn seq_field(content: &[u8], n: u8) -> Option<&[u8]> {
    let mut rest = content;
    while let Some((tlv, next)) = read_tlv(rest) {
        if tlv.tag == context(n) {
            return Some(tlv.content);
        }
        rest = next;
    }
    None
}

fn app_body(buf: &[u8], n: u8) -> Option<&[u8]> {
    let (tlv, _) = read_tlv(buf)?;
    if tlv.tag != application(n) {
        return None;
    }
    let (body, _) = expect_tag(tlv.content, tag::SEQUENCE)?;
    Some(body)
}

/// A `Ticket` for `TERMSRV/host.corp.example.com`, opaque `enc-part` and all.
fn service_ticket_der() -> Vec<u8> {
    let mut out = Vec::new();
    write_nested(&mut out, application(app::TICKET), |outer| {
        write_nested(outer, tag::SEQUENCE, |seq| {
            write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, PVNO));
            write_nested(seq, context(1), |t| write_kerberos_string(t, REALM));
            write_nested(seq, context(2), |t| {
                write_principal_name(t, name_type::SRV_HST, &["TERMSRV", "host.corp.example.com"]);
            });
            write_nested(seq, context(3), |t| {
                write_encrypted_data(t, ENCTYPE, &[0x77u8; 128]);
            });
        });
    });
    out
}

/// The session key the KDC would have put in both the ticket and the reply.
fn session_key() -> Key {
    Key::new(ENCTYPE, &[0x3c; 32]).expect("32 octets")
}

fn service_ticket() -> Box<ServiceTicket> {
    let der = service_ticket_der();
    let (ticket, rest) = Ticket::read(&der).expect("a well formed ticket");
    assert!(rest.is_empty());
    Box::new(ServiceTicket {
        ticket,
        session_key: session_key(),
        endtime: KerberosTime::from_unix_seconds(NOW + 36_000).expect("in range"),
        client_realm: REALM.to_owned(),
        client_name: PrincipalName {
            name_type: name_type::PRINCIPAL,
            components: vec!["alice".to_owned()],
        },
    })
}

fn bindings() -> ChannelBindings {
    ChannelBindings::from_certificate_hash(&[0x9e; 32])
}

fn kerberos_client(with_bindings: bool) -> KerberosClient {
    KerberosClient::new(KerberosConfig {
        ticket: service_ticket(),
        channel_bindings: with_bindings.then(bindings),
        now_unix: NOW,
    })
}

/// What the acceptor learned from the AP-REQ.
struct Accepted {
    subkey: Key,
    seq_number: u64,
    checksum: Vec<u8>,
    mutual_required: bool,
}

/// Read an AP-REQ the way RFC 4120 §5.5.1 says a service reads one, and
/// answer with the AP-REP of §5.5.2.
fn accept_ap_req(token: &[u8], acceptor_subkey: Option<&Key>) -> (Accepted, Vec<u8>) {
    // RFC 2743 §3.1's framing: 0x60, the OID, then TOK_ID and the message,
    // with no SEQUENCE in between.
    let (outer, rest) = read_tlv(token).expect("a GSS token");
    assert!(rest.is_empty(), "nothing follows the initial context token");
    assert_eq!(outer.tag, 0x60, "[APPLICATION 0]");
    let (mech, after_oid) = read_tlv(outer.content).expect("the mechanism OID");
    assert_eq!(mech.tag, tag::OBJECT_IDENTIFIER);
    assert_eq!(mech.content, oid::KRB5, "the modern Kerberos OID");
    assert_eq!(
        after_oid.get(..2),
        Some(&[0x01, 0x00][..]),
        "TOK_ID for KRB_AP_REQ (RFC 4121 §4.1)"
    );
    let ap_req = after_oid.get(2..).expect("an AP-REQ follows");

    let seq = app_body(ap_req, app::AP_REQ).expect("AP-REQ");
    assert_eq!(
        read_int_i64(seq_field(seq, 1).expect("msg-type"))
            .expect("int")
            .0,
        msg_type::AP_REQ
    );

    // ap-options [2]: mutual-required is bit 2, which in X.690 BIT STRING
    // numbering is 0x20 in the first octet.
    let options = seq_field(seq, 2).expect("ap-options");
    let (bits, _) = expect_tag(options, tag::BIT_STRING).expect("BIT STRING");
    assert_eq!(bits.first(), Some(&0x00), "no unused bits");
    let mutual_required = bits.get(1).is_some_and(|b| b & 0x20 != 0);

    // The ticket is passed through byte for byte.
    let ticket = seq_field(seq, 3).expect("ticket");
    assert_eq!(
        ticket,
        service_ticket_der().as_slice(),
        "the ticket goes into the AP-REQ exactly as the KDC issued it"
    );

    // The authenticator is at key usage 11, not 7 (RFC 4120 §7.5.1).
    let enc =
        EncryptedData::read(seq_field(seq, 4).expect("authenticator")).expect("EncryptedData");
    let plain = crypto::decrypt(&session_key(), usage::AP_REQ_AUTHENTICATOR, &enc.cipher)
        .expect("the authenticator decrypts at key usage 11");
    let auth = app_body(&plain, app::AUTHENTICATOR).expect("Authenticator");

    assert_eq!(
        read_int_i64(seq_field(auth, 0).expect("vno"))
            .expect("int")
            .0,
        PVNO
    );
    let crealm = seq_field(auth, 1).expect("crealm");
    let (crealm, _) = read_tlv(crealm).expect("GeneralString");
    assert_eq!(
        crealm.content,
        REALM.as_bytes(),
        "the realm from the ticket"
    );
    let cname = PrincipalName::read(seq_field(auth, 2).expect("cname")).expect("PrincipalName");
    assert_eq!(cname.components, ["alice"]);

    // cksum [3]: type 0x8003, the structure of RFC 4121 §4.1.1.
    let cksum = seq_field(auth, 3).expect("the authenticator MUST carry a cksum");
    let (cksum_seq, _) = expect_tag(cksum, tag::SEQUENCE).expect("Checksum");
    assert_eq!(
        read_int_i64(seq_field(cksum_seq, 0).expect("cksumtype"))
            .expect("int")
            .0,
        CKSUMTYPE_GSSAPI
    );
    let value = seq_field(cksum_seq, 1).expect("checksum");
    let (checksum, _) = expect_tag(value, tag::OCTET_STRING).expect("OCTET STRING");

    // subkey [6] and seq-number [7] are both required by RFC 4121 §4.1.1
    // ("MUST include the optional sequence number and the checksum field").
    let subkey_field = seq_field(auth, 6).expect("the initiator asserts a subkey");
    let (subkey_seq, _) = expect_tag(subkey_field, tag::SEQUENCE).expect("EncryptionKey");
    let keytype = read_int_i64(seq_field(subkey_seq, 0).expect("keytype"))
        .expect("int")
        .0;
    assert_eq!(keytype, i64::from(ENCTYPE.etype()));
    let keyvalue = seq_field(subkey_seq, 1).expect("keyvalue");
    let (keyvalue, _) = expect_tag(keyvalue, tag::OCTET_STRING).expect("OCTET STRING");
    let subkey = Key::new(ENCTYPE, keyvalue).expect("a well formed subkey");
    let seq_number = u64::try_from(
        read_int_i64(seq_field(auth, 7).expect("seq-number"))
            .expect("int")
            .0,
    )
    .expect("non negative");

    // The AP-REP: EncAPRepPart at key usage 12 under the ticket session key
    // (RFC 4120 §5.5.2).
    let ctime = KerberosTime::from_unix_seconds(NOW).expect("in range");
    let mut part = Vec::new();
    write_nested(&mut part, application(27), |outer| {
        write_nested(outer, tag::SEQUENCE, |s| {
            write_nested(s, context(0), |t| write_kerberos_time(t, ctime));
            write_nested(s, context(1), |t| write_int(t, tag::INTEGER, 0));
            if let Some(key) = acceptor_subkey {
                write_nested(s, context(2), |t| {
                    write_nested(t, tag::SEQUENCE, |k| {
                        write_nested(k, context(0), |x| {
                            write_int(x, tag::INTEGER, i64::from(key.enctype().etype()));
                        });
                        write_nested(k, context(1), |x| {
                            write_tlv(x, tag::OCTET_STRING, key.octets());
                        });
                    });
                });
            }
            write_nested(s, context(3), |t| write_int(t, tag::INTEGER, 5000));
        });
    });
    let enc = crypto::encrypt(&session_key(), usage::AP_REP_ENC_PART, &part).expect("encrypt");

    let mut ap_rep = Vec::new();
    write_nested(&mut ap_rep, application(15), |outer| {
        write_nested(outer, tag::SEQUENCE, |s| {
            write_nested(s, context(0), |t| write_int(t, tag::INTEGER, PVNO));
            write_nested(s, context(1), |t| write_int(t, tag::INTEGER, 15));
            write_nested(s, context(2), |t| write_encrypted_data(t, ENCTYPE, &enc));
        });
    });
    // The acceptor's token is bare: RFC 2743 §3.1 frames only the
    // initiator's first token.
    let mut token = vec![0x02, 0x00];
    token.extend_from_slice(&ap_rep);

    (
        Accepted {
            subkey,
            seq_number,
            checksum: checksum.to_vec(),
            mutual_required,
        },
        token,
    )
}

/// The AP-REQ carries everything RFC 4121 §4.1 requires, and the channel
/// binding is the same value the NTLM path would have put in its AV pair.
#[test]
fn the_ap_req_carries_the_flags_the_binding_and_a_subkey() {
    let mut client = kerberos_client(true);
    let GssStep::Token(token) = client.step(&[]).expect("the AP-REQ") else {
        panic!("the first step is a Token, because an AP-REP is still owed");
    };
    let (accepted, _) = accept_ap_req(&token, None);

    assert!(
        accepted.mutual_required,
        "mutual authentication was asked for"
    );
    assert_eq!(accepted.subkey.enctype(), ENCTYPE);
    assert_ne!(
        accepted.subkey.octets(),
        session_key().octets(),
        "the subkey is fresh, not the ticket session key"
    );

    // The 0x8003 structure, and the `Bnd` field in the middle of it.
    assert_eq!(accepted.checksum, authenticator_checksum(Some(&bindings())));
    assert_eq!(accepted.checksum.len(), 24);
    assert_eq!(
        accepted.checksum.get(4..20),
        Some(&bindings().value()[..]),
        "the RFC 5929 binding is the Bnd field"
    );
    assert_eq!(
        accepted.checksum.get(20..24),
        Some(&[0x3e, 0x00, 0x00, 0x00][..]),
        "the flags, little endian"
    );

    // Two clients produce two different subkeys and two different sequence
    // numbers: neither is derived from anything fixed.
    let mut other = kerberos_client(true);
    let GssStep::Token(other_token) = other.step(&[]).expect("the AP-REQ") else {
        panic!()
    };
    let (other_accepted, _) = accept_ap_req(&other_token, None);
    assert_ne!(accepted.subkey.octets(), other_accepted.subkey.octets());
    assert_ne!(accepted.seq_number, other_accepted.seq_number);
}

/// With no certificate to bind to, `Bnd` is sixteen zeroes
/// (`GSS_C_NO_CHANNEL_BINDINGS`, RFC 4121 §4.1.1.2) and nothing else changes.
#[test]
fn an_unbound_exchange_sends_sixteen_zero_octets() {
    let mut client = kerberos_client(false);
    let GssStep::Token(token) = client.step(&[]).expect("the AP-REQ") else {
        panic!()
    };
    let (accepted, _) = accept_ap_req(&token, None);
    assert_eq!(accepted.checksum.get(4..20), Some(&[0u8; 16][..]));
    assert_eq!(accepted.checksum.get(..4), Some(&[0x10, 0, 0, 0][..]));
}

/// The whole mechanism: AP-REQ out, AP-REP in, then wrap and unwrap against
/// the acceptor, for both base key cases of RFC 4121 §2.
#[test]
fn the_context_completes_and_wraps_under_the_right_base_key() {
    for acceptor_asserts_subkey in [false, true] {
        let acceptor_subkey =
            acceptor_asserts_subkey.then(|| Key::new(ENCTYPE, &[0x5b; 32]).expect("32 octets"));

        let mut client = kerberos_client(true);
        let GssStep::Token(ap_req) = client.step(&[]).expect("the AP-REQ") else {
            panic!()
        };
        assert!(!client.is_complete(), "not until the AP-REP arrives");
        assert_eq!(
            client.wrap(b"too early").unwrap_err(),
            AuthError::ContextNotEstablished
        );

        let (accepted, ap_rep) = accept_ap_req(&ap_req, acceptor_subkey.as_ref());

        let GssStep::FinalToken(token) = client.step(&ap_rep).expect("the AP-REP") else {
            panic!("the AP-REP step is a FinalToken; the type comment says why");
        };
        assert!(token.is_empty(), "there is nothing left to send");
        assert!(client.is_complete());

        // RFC 4121 §2: the base key is the acceptor's subkey when it asserted
        // one, otherwise ours.
        let base = acceptor_subkey.clone().unwrap_or(accepted.subkey);

        // Wrap, and read it the way an acceptor does.
        let wrapped = client.wrap(b"the CredSSP pubKeyAuth").expect("wrap");
        assert_eq!(wrapped.get(..2), Some(&[0x05, 0x04][..]));
        let expected_flags = if acceptor_asserts_subkey {
            0x02 | 0x04
        } else {
            0x02
        };
        assert_eq!(wrapped.get(2), Some(&expected_flags));
        assert_eq!(
            wrapped.get(8..16),
            Some(&accepted.seq_number.to_be_bytes()[..]),
            "the first wrap uses the sequence the authenticator announced"
        );
        let ciphertext = wrapped.get(16..).expect("a body");
        let plain = crypto::decrypt(&base, usage::GSS_INITIATOR_SEAL, ciphertext)
            .expect("the acceptor decrypts at KG-USAGE-INITIATOR-SEAL");
        assert_eq!(
            plain.get(..b"the CredSSP pubKeyAuth".len()),
            Some(&b"the CredSSP pubKeyAuth"[..])
        );
        // RFC 4121 §4.2.4: the header is appended, with RRC zeroed.
        assert_eq!(
            plain.get(plain.len() - 16..),
            wrapped.get(..16),
            "the encrypted copy of the header binds the token to its sequence"
        );

        // And the acceptor's answer comes back, at the acceptor's own usage
        // and sequence.
        let header: Vec<u8> = {
            let mut h = vec![0x05, 0x04, 0x01 | expected_flags, 0xff, 0, 0, 0, 0];
            h.extend_from_slice(&5000u64.to_be_bytes());
            h
        };
        let mut to_encrypt = b"the server's answer".to_vec();
        to_encrypt.extend_from_slice(&header);
        let ct = crypto::encrypt(&base, usage::GSS_ACCEPTOR_SEAL, &to_encrypt).expect("encrypt");
        let mut token = header.clone();
        token.extend_from_slice(&ct);
        let out = client.unwrap(&token).expect("unwrap");
        assert_eq!(&*out, b"the server's answer");
    }
}

/// A server that completes without the AP-REP mutual authentication asked for
/// has proved nothing, and is refused.
#[test]
fn a_missing_ap_rep_is_refused() {
    let mut client = kerberos_client(true);
    let GssStep::Token(_) = client.step(&[]).expect("the AP-REQ") else {
        panic!()
    };
    assert_eq!(client.step(&[]).unwrap_err(), AuthError::UnexpectedToken);
    assert_eq!(client.step(&[]).unwrap_err(), AuthError::AlreadyFailed);
}

/// A `KRB-ERROR` in place of the AP-REP is the service saying why, and it
/// reaches the user as a sentence.
#[test]
fn a_krb_error_in_place_of_the_ap_rep_is_reported() {
    let mut client = kerberos_client(true);
    let GssStep::Token(_) = client.step(&[]).expect("the AP-REQ") else {
        panic!()
    };
    // KRB_AP_ERR_TKT_EXPIRED, 32.
    let stime = KerberosTime::from_unix_seconds(NOW).expect("in range");
    let mut err = Vec::new();
    write_nested(&mut err, application(app::KRB_ERROR), |outer| {
        write_nested(outer, tag::SEQUENCE, |s| {
            write_nested(s, context(0), |t| write_int(t, tag::INTEGER, PVNO));
            write_nested(s, context(1), |t| {
                write_int(t, tag::INTEGER, msg_type::KRB_ERROR);
            });
            write_nested(s, context(4), |t| write_kerberos_time(t, stime));
            write_nested(s, context(5), |t| write_int(t, tag::INTEGER, 0));
            write_nested(s, context(6), |t| write_int(t, tag::INTEGER, 32));
            write_nested(s, context(9), |t| write_kerberos_string(t, REALM));
            write_nested(s, context(10), |t| {
                write_principal_name(t, name_type::SRV_HST, &["TERMSRV", "host"]);
            });
        });
    });
    let mut token = vec![0x03, 0x00];
    token.extend_from_slice(&err);

    let e = client.step(&token).expect_err("a KRB-ERROR is a failure");
    assert_eq!(e, AuthError::KdcRefused(32));
    assert_eq!(e.kdc_error_symbol(), Some("KRB_AP_ERR_TKT_EXPIRED"));
    assert!(e.user_message().ends_with('.'));
    assert!(!e.user_message().contains("KRB_AP"));
}

/// Every truncation of the AP-REP is an error and never a panic.
#[test]
fn every_truncation_of_the_ap_rep_fails_cleanly() {
    let mut probe = kerberos_client(true);
    let GssStep::Token(ap_req) = probe.step(&[]).expect("the AP-REQ") else {
        panic!()
    };
    let (_, ap_rep) = accept_ap_req(&ap_req, None);

    for cut in 0..ap_rep.len() {
        let mut client = kerberos_client(true);
        let GssStep::Token(_) = client.step(&[]).expect("the AP-REQ") else {
            panic!()
        };
        // The subkey differs per client, so a truncated reply cannot succeed
        // by accident; what matters is that it does not panic.
        let _ = client.step(ap_rep.get(..cut).expect("in range"));
        assert!(!client.is_complete(), "cut {cut} completed a context");
    }
}

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

/// Kerberos inside `SpnegoClient`, which was written before Kerberos existed
/// and did not change to take it.
///
/// The AP-REQ comes out inside a `NegTokenInit` whose `mechTypes` names
/// Kerberos first and NTLM second, which is the list Windows sends.
#[test]
fn kerberos_drives_through_spnego_unchanged() {
    use rdp_auth::{NtlmClient, NtlmConfig};

    let ntlm = NtlmClient::new(NtlmConfig {
        identity: rdp_auth::Identity::from_prompt("alice", "CORP", "pw").expect("an identity"),
        spn: "TERMSRV/host.corp.example.com".to_owned(),
        workstation: None,
        channel_bindings: Some(bindings()),
    });
    let mut spnego = SpnegoClient::new(vec![Box::new(kerberos_client(true)), Box::new(ntlm)])
        .expect("two mechanisms");

    let GssStep::Token(init) = spnego.step(&[]).expect("the NegTokenInit") else {
        panic!("SPNEGO's first step is always a Token")
    };
    // RFC 4178 §4.2.1 inside RFC 2743 §3.1's framing, with the SPNEGO OID.
    assert_eq!(init.first(), Some(&0x60));
    assert!(
        init.windows(oid::SPNEGO.len()).any(|w| w == oid::SPNEGO),
        "the outer OID is SPNEGO"
    );
    assert!(
        init.windows(oid::KRB5.len()).any(|w| w == oid::KRB5),
        "Kerberos is offered"
    );
    assert!(
        init.windows(oid::NTLMSSP.len()).any(|w| w == oid::NTLMSSP),
        "NTLM is offered as well"
    );
    // And the optimistic mechToken is the Kerberos AP-REQ: find the inner
    // [APPLICATION 0] that carries the krb5 OID.
    let krb_at = init
        .windows(oid::KRB5.len())
        .position(|w| w == oid::KRB5)
        .expect("the krb5 OID appears");
    // It appears twice: once in mechTypes, once in the inner token. The
    // second is preceded by an OID header inside a 0x60 wrapper.
    let second = init
        .get(krb_at + 1..)
        .and_then(|rest| rest.windows(oid::KRB5.len()).position(|w| w == oid::KRB5))
        .expect("the krb5 OID appears twice: mechTypes and the mechToken");
    let inner_at = krb_at + 1 + second;
    assert_eq!(
        init.get(inner_at + oid::KRB5.len()..inner_at + oid::KRB5.len() + 2),
        Some(&[0x01, 0x00][..]),
        "TOK_ID for KRB_AP_REQ follows the OID in the mechToken"
    );
}

/// The whole stack: `CredSspClient` over `SpnegoClient` over
/// `KerberosClient`. Neither of the two outer types knows which mechanism it
/// is driving, which is the property PRDRDP/14 §2.8 exists to give.
#[test]
fn kerberos_plugs_into_credssp_through_spnego() {
    use rdp_auth::credssp::{CredSspClient, CredSspConfig};
    use rdp_auth::Step;

    // A certificate is not needed for this: the CredSSP config takes the
    // public key and the signature algorithm, and message 1 carries neither.
    let mut config = CredSspConfig::new(
        rdp_auth::Identity::from_prompt("alice", "CORP", "pw").expect("an identity"),
        "TERMSRV/host.corp.example.com".to_owned(),
        vec![0x04; 65],
        vec![0x30, 0x03, 0x02, 0x01, 0x00],
        vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
    );
    config.server_certificate = None;

    let spnego = SpnegoClient::new(vec![Box::new(kerberos_client(true))])
        .expect("one mechanism is enough to negotiate");
    let mut credssp = CredSspClient::with_mechanism(config, Box::new(spnego))
        .expect("CredSSP takes any GssMechanism");

    let Step::SendAndExpect(message) = credssp.step(&[]).expect("CredSSP message 1") else {
        panic!("message 1 is sent and answered")
    };
    // A TSRequest is a SEQUENCE, and the Kerberos AP-REQ is inside its
    // negoTokens.
    assert_eq!(message.first(), Some(&0x30), "TSRequest is a SEQUENCE");
    assert!(
        message.windows(oid::KRB5.len()).any(|w| w == oid::KRB5),
        "the Kerberos AP-REQ reached CredSSP message 1 with no change to \
         CredSspClient or SpnegoClient"
    );
    assert!(
        message.windows(oid::SPNEGO.len()).any(|w| w == oid::SPNEGO),
        "wrapped in SPNEGO"
    );
}

/// Kerberos on its own as the CredSSP mechanism, with no SPNEGO. This is the
/// shape that does **not** work end to end, and it is asserted so the
/// limitation is recorded rather than discovered.
///
/// Message 1 is fine. The AP-REP step returns a `FinalToken` with an empty
/// token, so CredSSP would put an empty `negoTokens` entry in message 3.
/// Kerberos is meant to be offered through SPNEGO (PRDRDP/14 §4.8), which is
/// what Windows does and what the test above exercises.
#[test]
fn raw_kerberos_in_credssp_produces_message_one_and_is_not_the_supported_shape() {
    use rdp_auth::credssp::{CredSspClient, CredSspConfig};
    use rdp_auth::Step;

    let mut config = CredSspConfig::new(
        rdp_auth::Identity::from_prompt("alice", "CORP", "pw").expect("an identity"),
        "TERMSRV/host.corp.example.com".to_owned(),
        vec![0x04; 65],
        vec![0x30, 0x03, 0x02, 0x01, 0x00],
        vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
    );
    config.server_certificate = None;

    let mut credssp = CredSspClient::with_mechanism(config, Box::new(kerberos_client(true)))
        .expect("CredSSP takes any GssMechanism");
    let Step::SendAndExpect(message) = credssp.step(&[]).expect("message 1") else {
        panic!()
    };
    assert!(message.windows(oid::KRB5.len()).any(|w| w == oid::KRB5));
    // No SPNEGO wrapper on this path.
    assert!(!message.windows(oid::SPNEGO.len()).any(|w| w == oid::SPNEGO));
}

/// PRDRDP/14 §8.3: no secret in any `Debug`, on every type this lane added.
#[test]
fn no_kerberos_type_prints_a_secret() {
    let mut client = kerberos_client(true);
    let GssStep::Token(ap_req) = client.step(&[]).expect("the AP-REQ") else {
        panic!()
    };
    let (_, ap_rep) = accept_ap_req(&ap_req, None);
    let GssStep::FinalToken(_) = client.step(&ap_rep).expect("the AP-REP") else {
        panic!()
    };

    let shown = format!("{client:?}");
    // The ticket session key is 0x3c repeated; the subkey is random. Neither
    // may appear, in either rendering a Debug could produce.
    assert!(!shown.contains("3c3c"), "{shown}");
    assert!(!shown.contains("60, 60"), "{shown}");
    assert!(shown.contains("redacted"), "{shown}");
    assert!(!shown.to_lowercase().contains("keyvalue: ["), "{shown}");
}
