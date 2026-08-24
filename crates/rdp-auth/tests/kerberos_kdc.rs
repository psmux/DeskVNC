//! The AS and TGS exchanges driven against a hand written KDC.
//!
//! PRDRDP/14 §9.3 wrote an NTLM server side into the test suite for the same
//! reason this writes a KDC: a client state machine tested only against
//! recorded bytes is tested against one KDC's habits, and a client tested
//! against nothing but itself is tested against nothing. The mock below is
//! written from RFC 4120 §5, independently of the client, and it checks what
//! a real KDC checks: that the pre-authentication timestamp decrypts under
//! the key the salt and iteration count derive, that the nonce comes back,
//! that the TGS-REQ's authenticator decrypts at key usage 7, and that its
//! checksum verifies at key usage 6 over the request body.
//!
//! What it cannot prove, stated plainly: both sides share this crate's
//! reading of RFC 4120, so a misreading common to both passes here. The
//! things that would catch that are RFC 3962 appendix B, which
//! `vectors_kerberos.rs` asserts and which pins every key this file derives,
//! and the live interop matrix (PRDRDP/14 §7.3 and §9.4).

#![cfg(feature = "kerberos")]

use rdp_auth::error::AuthError;
use rdp_auth::identity::Identity;
use rdp_auth::kerberos::asn1::{
    app, application, kerberos_flags, msg_type, name_type, padata_type, write_encrypted_data,
    write_kerberos_string, write_kerberos_time, write_padata, write_principal_name, EncryptedData,
    KerberosTime, PrincipalName, PVNO,
};
use rdp_auth::kerberos::crypto::{self, usage, Enctype, Key};
use rdp_auth::kerberos::kdc::{KdcClient, KdcConfig, KdcStep, DEFAULT_TICKET_LIFETIME_SECS};
use rdp_pdu::asn1::der::{expect_tag, read_int_i64, read_tlv, write_int, write_nested, write_tlv};
use rdp_pdu::asn1::{context, tag};

/// A fixed instant, so nothing here depends on the machine's clock:
/// 2026-08-24T12:00:00Z.
const NOW: i64 = 1_787_486_400;

/// The `[n]` field of a SEQUENCE's content, found by scanning rather than by
/// walking in order, because a test that has to know the order of the fields
/// it is checking is a test that fails for the wrong reason.
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

/// The content of an `[APPLICATION n] SEQUENCE`.
fn app_body(buf: &[u8], n: u8) -> Option<&[u8]> {
    let (tlv, _) = read_tlv(buf)?;
    if tlv.tag != application(n) {
        return None;
    }
    let (body, _) = expect_tag(tlv.content, tag::SEQUENCE)?;
    Some(body)
}

/// Strip the RFC 4120 §7.2.2 length prefix, checking it.
fn unframe(buf: &[u8]) -> &[u8] {
    let declared = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    assert_eq!(declared, buf.len() - 4, "the framed length must match");
    &buf[4..]
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// A KDC that answers one client, written from RFC 4120 §5.
struct MockKdc {
    realm: String,
    client_components: Vec<String>,
    client_name_type: i64,
    password: String,
    salt: Vec<u8>,
    iterations: u32,
    enctype: Enctype,
    spn: Vec<String>,
    tgt_session_key: Key,
    service_session_key: Key,
    /// The KDC's own clock, which the skew tests move.
    now: i64,
    /// Refuse an AS-REQ that arrives with no `PA-ENC-TIMESTAMP`.
    demand_preauth: bool,
    /// Answer the next AS-REQ with `KRB_AP_ERR_SKEW` whatever else is true.
    skew_once: bool,
    /// What the client actually sent, for the assertions.
    pub saw_preauth: bool,
    pub saw_authenticator_checksum: bool,
}

impl MockKdc {
    fn new(enctype: Enctype) -> Self {
        MockKdc {
            realm: "CORP.EXAMPLE.COM".to_owned(),
            client_components: vec!["alice".to_owned()],
            client_name_type: name_type::PRINCIPAL,
            password: "Pa55w0rd!".to_owned(),
            salt: b"CORP.EXAMPLE.COMalice".to_vec(),
            iterations: 4096,
            enctype,
            spn: vec!["TERMSRV".to_owned(), "host.corp.example.com".to_owned()],
            tgt_session_key: Key::new(enctype, &vec![0x5au8; enctype.key_len()]).unwrap(),
            service_session_key: Key::new(enctype, &vec![0xa5u8; enctype.key_len()]).unwrap(),
            now: NOW,
            demand_preauth: true,
            skew_once: false,
            saw_preauth: false,
            saw_authenticator_checksum: false,
        }
    }

    /// The client's long term key, derived exactly as the client must.
    fn client_key(&self) -> Key {
        crypto::string_to_key(self.enctype, &self.password, &self.salt, self.iterations)
            .expect("the iteration count is in range")
    }

    /// `SEQUENCE OF PA-DATA` holding one `PA-ETYPE-INFO2` for our enctype.
    fn etype_info2_padata(&self) -> Vec<u8> {
        let mut info = Vec::new();
        write_nested(&mut info, tag::SEQUENCE, |list| {
            write_nested(list, tag::SEQUENCE, |entry| {
                write_nested(entry, context(0), |t| {
                    write_int(t, tag::INTEGER, i64::from(self.enctype.etype()));
                });
                write_nested(entry, context(1), |t| {
                    // salt [1] KerberosString.
                    write_tlv(t, 0x1b, &self.salt);
                });
                write_nested(entry, context(2), |t| {
                    // s2kparams [2] OCTET STRING: RFC 3962 §4's four octets.
                    write_tlv(t, tag::OCTET_STRING, &self.iterations.to_be_bytes());
                });
            });
        });
        let mut padata = Vec::new();
        write_nested(&mut padata, tag::SEQUENCE, |list| {
            write_padata(list, padata_type::ETYPE_INFO2, &info);
        });
        padata
    }

    /// `KRB-ERROR`, RFC 4120 §5.9.1.
    fn krb_error(&self, code: i64, e_data: &[u8]) -> Vec<u8> {
        let stime = KerberosTime::from_unix_seconds(self.now).expect("in range");
        let mut out = Vec::new();
        write_nested(&mut out, application(app::KRB_ERROR), |outer| {
            write_nested(outer, tag::SEQUENCE, |seq| {
                write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, PVNO));
                write_nested(seq, context(1), |t| {
                    write_int(t, tag::INTEGER, msg_type::KRB_ERROR);
                });
                write_nested(seq, context(4), |t| write_kerberos_time(t, stime));
                write_nested(seq, context(5), |t| write_int(t, tag::INTEGER, 0));
                write_nested(seq, context(6), |t| write_int(t, tag::INTEGER, code));
                write_nested(seq, context(9), |t| write_kerberos_string(t, &self.realm));
                write_nested(seq, context(10), |t| {
                    write_principal_name(t, name_type::SRV_INST, &["krbtgt", &self.realm]);
                });
                if !e_data.is_empty() {
                    write_nested(seq, context(12), |t| {
                        write_tlv(t, tag::OCTET_STRING, e_data);
                    });
                }
            });
        });
        out
    }

    /// A `Ticket`, RFC 4120 §5.3. Its `enc-part` is opaque to a client, so
    /// the contents are a plausible ciphertext and nothing more.
    fn ticket(&self, sname: &[&str], sname_type: i64) -> Vec<u8> {
        let mut out = Vec::new();
        write_nested(&mut out, application(app::TICKET), |outer| {
            write_nested(outer, tag::SEQUENCE, |seq| {
                write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, PVNO));
                write_nested(seq, context(1), |t| write_kerberos_string(t, &self.realm));
                write_nested(seq, context(2), |t| {
                    write_principal_name(t, sname_type, sname);
                });
                write_nested(seq, context(3), |t| {
                    write_encrypted_data(t, self.enctype, &[0x11u8; 96]);
                });
            });
        });
        out
    }

    /// `EncKDCRepPart`, RFC 4120 §5.4.2, under the given application tag.
    fn enc_kdc_rep_part(
        &self,
        app_tag: u8,
        key: &Key,
        nonce: i64,
        sname: &[&str],
        sname_type: i64,
    ) -> Vec<u8> {
        let authtime = KerberosTime::from_unix_seconds(self.now).expect("in range");
        let endtime = KerberosTime::from_unix_seconds(self.now + DEFAULT_TICKET_LIFETIME_SECS)
            .expect("in range");
        let mut out = Vec::new();
        write_nested(&mut out, application(app_tag), |outer| {
            write_nested(outer, tag::SEQUENCE, |seq| {
                // key [0] EncryptionKey
                write_nested(seq, context(0), |t| {
                    write_nested(t, tag::SEQUENCE, |k| {
                        write_nested(k, context(0), |x| {
                            write_int(x, tag::INTEGER, i64::from(key.enctype().etype()));
                        });
                        write_nested(k, context(1), |x| {
                            write_tlv(x, tag::OCTET_STRING, key.octets());
                        });
                    });
                });
                // last-req [1] LastReq
                write_nested(seq, context(1), |t| {
                    write_nested(t, tag::SEQUENCE, |list| {
                        write_nested(list, tag::SEQUENCE, |item| {
                            write_nested(item, context(0), |x| write_int(x, tag::INTEGER, 0));
                            write_nested(item, context(1), |x| write_kerberos_time(x, authtime));
                        });
                    });
                });
                write_nested(seq, context(2), |t| write_int(t, tag::INTEGER, nonce));
                // flags [4] TicketFlags
                write_nested(seq, context(4), |t| {
                    let mut bits = vec![0x00];
                    bits.extend_from_slice(&kerberos_flags(&[1, 8]));
                    write_tlv(t, tag::BIT_STRING, &bits);
                });
                write_nested(seq, context(5), |t| write_kerberos_time(t, authtime));
                write_nested(seq, context(7), |t| write_kerberos_time(t, endtime));
                write_nested(seq, context(9), |t| write_kerberos_string(t, &self.realm));
                write_nested(seq, context(10), |t| {
                    write_principal_name(t, sname_type, sname);
                });
            });
        });
        out
    }

    /// A `KDC-REP`, RFC 4120 §5.4.2.
    fn kdc_rep(
        &self,
        app_tag: u8,
        message_type: i64,
        ticket: &[u8],
        enc_part: &[u8],
        padata: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        write_nested(&mut out, application(app_tag), |outer| {
            write_nested(outer, tag::SEQUENCE, |seq| {
                write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, PVNO));
                write_nested(seq, context(1), |t| {
                    write_int(t, tag::INTEGER, message_type)
                });
                if let Some(padata) = padata {
                    write_nested(seq, context(2), |t| t.extend_from_slice(padata));
                }
                write_nested(seq, context(3), |t| write_kerberos_string(t, &self.realm));
                write_nested(seq, context(4), |t| {
                    let parts: Vec<&str> =
                        self.client_components.iter().map(String::as_str).collect();
                    write_principal_name(t, self.client_name_type, &parts);
                });
                write_nested(seq, context(5), |t| t.extend_from_slice(ticket));
                write_nested(seq, context(6), |t| {
                    write_encrypted_data(t, self.enctype, enc_part);
                });
            });
        });
        out
    }

    /// Answer one framed request with one framed reply.
    fn answer(&mut self, request: &[u8]) -> Vec<u8> {
        let body = unframe(request);
        let (tlv, _) = read_tlv(body).expect("a well formed request");
        let reply = if tlv.tag == application(app::AS_REQ) {
            self.answer_as_req(body)
        } else if tlv.tag == application(app::TGS_REQ) {
            self.answer_tgs_req(body)
        } else {
            panic!("the client sent something that is neither an AS-REQ nor a TGS-REQ");
        };
        frame(&reply)
    }

    fn answer_as_req(&mut self, body: &[u8]) -> Vec<u8> {
        let seq = app_body(body, app::AS_REQ).expect("AS-REQ");
        assert_eq!(
            read_int_i64(seq_field(seq, 1).expect("pvno"))
                .expect("int")
                .0,
            PVNO,
            "KDC-REQ.pvno"
        );
        assert_eq!(
            read_int_i64(seq_field(seq, 2).expect("msg-type"))
                .expect("int")
                .0,
            msg_type::AS_REQ,
            "KDC-REQ.msg-type"
        );
        let req_body = seq_field(seq, 4).expect("req-body");
        let (req_body_seq, _) = expect_tag(req_body, tag::SEQUENCE).expect("KDC-REQ-BODY");
        let nonce = read_int_i64(seq_field(req_body_seq, 7).expect("nonce"))
            .expect("int")
            .0;

        // The client must name itself in an AS-REQ and must ask for
        // `krbtgt/REALM` (RFC 4120 §5.4.1).
        let cname =
            PrincipalName::read(seq_field(req_body_seq, 1).expect("cname")).expect("PrincipalName");
        assert_eq!(cname.components, self.client_components, "AS-REQ cname");
        let sname =
            PrincipalName::read(seq_field(req_body_seq, 3).expect("sname")).expect("PrincipalName");
        assert_eq!(sname.components, ["krbtgt", self.realm.as_str()]);

        if self.skew_once {
            self.skew_once = false;
            return self.krb_error(37, &[]);
        }

        let padata = seq_field(seq, 3);
        let preauth = padata.and_then(|p| {
            let (mut items, _) = expect_tag(p, tag::SEQUENCE)?;
            while let Some((tlv, next)) = read_tlv(items) {
                items = next;
                let ty = read_int_i64(seq_field(tlv.content, 1)?)?.0;
                if ty == padata_type::ENC_TIMESTAMP {
                    let value = seq_field(tlv.content, 2)?;
                    let (octets, _) = expect_tag(value, tag::OCTET_STRING)?;
                    return Some(octets.to_vec());
                }
            }
            None
        });

        let Some(preauth) = preauth else {
            if self.demand_preauth {
                return self.krb_error(25, &self.etype_info2_padata());
            }
            return self.issue_tgt(nonce, None);
        };

        // A real KDC decrypts the timestamp under the client's long term key
        // at key usage 1 and refuses if it does not verify. That check is the
        // whole of what "the password is right" means here.
        self.saw_preauth = true;
        let encrypted = EncryptedData::read(&preauth).expect("PA-ENC-TIMESTAMP is EncryptedData");
        assert_eq!(
            encrypted.etype,
            i64::from(self.enctype.etype()),
            "the timestamp is encrypted at the enctype the client announced"
        );
        match crypto::decrypt(
            &self.client_key(),
            usage::AS_REQ_PA_ENC_TIMESTAMP,
            &encrypted.cipher,
        ) {
            Ok(plain) => {
                // PA-ENC-TS-ENC ::= SEQUENCE { patimestamp [0] KerberosTime }
                let (ts_seq, _) = expect_tag(&plain, tag::SEQUENCE).expect("PA-ENC-TS-ENC");
                let stamp = seq_field(ts_seq, 0).expect("patimestamp");
                let (tlv, _) = read_tlv(stamp).expect("GeneralizedTime");
                let stamp = KerberosTime::parse(tlv.content).expect("a KerberosTime");
                let skew = (stamp.to_unix_seconds() - self.now).abs();
                if skew > 300 {
                    // RFC 4120 §5.4.1's five minutes, which Windows enforces.
                    return self.krb_error(37, &[]);
                }
                self.issue_tgt(nonce, Some(&self.etype_info2_padata()))
            }
            // A wrong password looks exactly like this to a KDC.
            Err(_) => self.krb_error(24, &[]),
        }
    }

    fn issue_tgt(&self, nonce: i64, padata: Option<&[u8]>) -> Vec<u8> {
        let ticket = self.ticket(&["krbtgt", &self.realm], name_type::SRV_INST);
        let part = self.enc_kdc_rep_part(
            app::ENC_AS_REP_PART,
            &self.tgt_session_key,
            nonce,
            &["krbtgt", &self.realm],
            name_type::SRV_INST,
        );
        let enc =
            crypto::encrypt(&self.client_key(), usage::AS_REP_ENC_PART, &part).expect("encrypt");
        self.kdc_rep(app::AS_REP, msg_type::AS_REP, &ticket, &enc, padata)
    }

    fn answer_tgs_req(&mut self, body: &[u8]) -> Vec<u8> {
        let seq = app_body(body, app::TGS_REQ).expect("TGS-REQ");
        let req_body = seq_field(seq, 4).expect("req-body");
        let (req_body_seq, _) = expect_tag(req_body, tag::SEQUENCE).expect("KDC-REQ-BODY");
        let nonce = read_int_i64(seq_field(req_body_seq, 7).expect("nonce"))
            .expect("int")
            .0;

        // A TGS-REQ names no client (RFC 4120 §5.4.1: cname is "Used only in
        // AS-REQ") and asks for the service.
        assert!(
            seq_field(req_body_seq, 1).is_none(),
            "a TGS-REQ must not carry a cname"
        );
        let sname =
            PrincipalName::read(seq_field(req_body_seq, 3).expect("sname")).expect("PrincipalName");
        assert_eq!(sname.components, self.spn, "TGS-REQ sname");

        // The PA-TGS-REQ carries an AP-REQ against the TGT.
        let padata = seq_field(seq, 3).expect("a TGS-REQ carries padata");
        let (padata_seq, _) = expect_tag(padata, tag::SEQUENCE).expect("SEQUENCE OF PA-DATA");
        let (first, _) = read_tlv(padata_seq).expect("one PA-DATA");
        assert_eq!(
            read_int_i64(seq_field(first.content, 1).expect("padata-type"))
                .expect("int")
                .0,
            padata_type::TGS_REQ
        );
        let ap_req = seq_field(first.content, 2).expect("padata-value");
        let (ap_req, _) = expect_tag(ap_req, tag::OCTET_STRING).expect("OCTET STRING");
        let ap_seq = app_body(ap_req, app::AP_REQ).expect("AP-REQ");
        assert_eq!(
            read_int_i64(seq_field(ap_seq, 1).expect("msg-type"))
                .expect("int")
                .0,
            msg_type::AP_REQ
        );

        // The authenticator is encrypted under the TGT session key at key
        // usage 7 (RFC 4120 §7.5.1). Getting this number wrong is the single
        // most likely Kerberos bug and it is invisible without a check here.
        let enc = EncryptedData::read(seq_field(ap_seq, 4).expect("authenticator"))
            .expect("EncryptedData");
        let plain = crypto::decrypt(
            &self.tgt_session_key,
            usage::TGS_REQ_AUTHENTICATOR,
            &enc.cipher,
        )
        .expect("the authenticator decrypts at key usage 7");
        let auth = app_body(&plain, app::AUTHENTICATOR).expect("Authenticator");

        // And its checksum is keyed at usage 6 over the KDC-REQ-BODY, which
        // is a different number again (RFC 4120 §5.5.1).
        let cksum = seq_field(auth, 3).expect("the authenticator must carry a cksum");
        let (cksum_seq, _) = expect_tag(cksum, tag::SEQUENCE).expect("Checksum");
        let cksum_type = read_int_i64(seq_field(cksum_seq, 0).expect("cksumtype"))
            .expect("int")
            .0;
        assert_eq!(
            cksum_type,
            i64::from(self.enctype.checksum_type()),
            "the checksum type is the one paired with the enctype (RFC 3962 §7)"
        );
        let value = seq_field(cksum_seq, 1).expect("checksum");
        let (value, _) = expect_tag(value, tag::OCTET_STRING).expect("OCTET STRING");
        crypto::verify_checksum(
            &self.tgt_session_key,
            usage::TGS_REQ_AUTHENTICATOR_CKSUM,
            req_body,
            value,
        )
        .expect("the authenticator checksum verifies at key usage 6 over the request body");
        self.saw_authenticator_checksum = true;

        let spn: Vec<&str> = self.spn.iter().map(String::as_str).collect();
        let ticket = self.ticket(&spn, name_type::SRV_HST);
        let part = self.enc_kdc_rep_part(
            app::ENC_TGS_REP_PART,
            &self.service_session_key,
            nonce,
            &spn,
            name_type::SRV_HST,
        );
        let enc = crypto::encrypt(&self.tgt_session_key, usage::TGS_REP_ENC_PART, &part)
            .expect("encrypt");
        self.kdc_rep(app::TGS_REP, msg_type::TGS_REP, &ticket, &enc, None)
    }
}

fn client_for(kdc: &MockKdc, now: i64) -> KdcClient {
    let identity = Identity::from_prompt("alice", "corp.example.com", &kdc.password)
        .expect("a user name and a domain");
    KdcClient::new(KdcConfig {
        identity,
        spn: "TERMSRV/host.corp.example.com".to_owned(),
        now_unix: now,
        ticket_lifetime_secs: DEFAULT_TICKET_LIFETIME_SECS,
    })
    .expect("a domain qualified account can use Kerberos")
}

/// Drive the client against the KDC until it produces a ticket or fails,
/// returning the number of round trips.
fn run(
    client: &mut KdcClient,
    kdc: &mut MockKdc,
) -> Result<(usize, Box<rdp_auth::kerberos::kdc::ServiceTicket>), AuthError> {
    let mut input = Vec::new();
    for round in 1..=8 {
        match client.step(&input)? {
            KdcStep::SendAndExpect(request) => {
                input = kdc.answer(&request);
            }
            KdcStep::Done(ticket) => return Ok((round, ticket)),
        }
    }
    panic!("the exchange did not finish in eight rounds");
}

/// The whole exchange, for both enctypes.
///
/// Three round trips: the AS-REQ that gets the salt, the AS-REQ that gets the
/// TGT, and the TGS-REQ that gets the service ticket.
#[test]
fn the_as_and_tgs_exchanges_produce_a_service_ticket() {
    for enctype in Enctype::offered() {
        let mut kdc = MockKdc::new(enctype);
        let mut client = client_for(&kdc, NOW);
        let (rounds, ticket) = run(&mut client, &mut kdc).expect("the exchange succeeds");

        assert_eq!(rounds, 4, "three requests, then Done on the fourth call");
        assert!(kdc.saw_preauth, "the client pre-authenticated");
        assert!(
            kdc.saw_authenticator_checksum,
            "the client's authenticator checksum verified"
        );
        assert_eq!(
            ticket.session_key.octets(),
            kdc.service_session_key.octets(),
            "the client took the service session key out of the TGS-REP"
        );
        assert_eq!(ticket.client_realm, "CORP.EXAMPLE.COM");
        assert_eq!(ticket.client_name.components, ["alice"]);
        assert_eq!(
            ticket.ticket.sname.display(),
            "TERMSRV/host.corp.example.com"
        );
    }
}

/// A wrong password reaches the user as a wrong password and not as a parse
/// failure or a generic refusal.
#[test]
fn a_wrong_password_is_reported_as_a_wrong_password() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    let identity = Identity::from_prompt("alice", "corp.example.com", "not-the-password")
        .expect("a user name");
    let mut client = KdcClient::new(KdcConfig {
        identity,
        spn: "TERMSRV/host.corp.example.com".to_owned(),
        now_unix: NOW,
        ticket_lifetime_secs: DEFAULT_TICKET_LIFETIME_SECS,
    })
    .expect("Kerberos applies");

    let err = run(&mut client, &mut kdc).expect_err("a wrong password fails");
    assert_eq!(err, AuthError::KdcRefused(24));
    assert_eq!(err.kdc_error_symbol(), Some("KDC_ERR_PREAUTH_FAILED"));
    assert_eq!(err.class(), rdp_auth::error::Class::User);
    assert_eq!(
        err.user_message(),
        "The user name or password is incorrect."
    );
    // The message never names the code, the symbol, or anything from the wire
    // (PRDRDP/14 §8.4).
    assert!(!err.user_message().contains("24"));
    assert!(!err.user_message().contains("KDC_ERR"));
}

/// The salt the KDC names is the salt used, not one we computed.
///
/// This KDC salts with something that is not `REALM || principal`, which is
/// exactly the case a client that guesses the salt gets wrong and reports as
/// a wrong password (PRDRDP/14 §7.2).
#[test]
fn the_salt_from_pa_etype_info2_is_the_one_used() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    kdc.salt = b"a-salt-no-client-would-guess".to_vec();
    kdc.iterations = 1200;
    let mut client = client_for(&kdc, NOW);
    let (_, ticket) = run(&mut client, &mut kdc).expect("the exchange succeeds");
    assert_eq!(
        ticket.session_key.octets(),
        kdc.service_session_key.octets()
    );
}

/// A KDC that omits the salt gets the RFC 3961 §4 default,
/// `REALM || principal`, which is the same construction RFC 3962 appendix B's
/// own `ATHENA.MIT.EDUraeburn` uses.
#[test]
fn an_omitted_salt_falls_back_to_the_default_for_the_principal() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    // The mock always sends a salt, so prove the fallback by making the salt
    // it sends equal to the default and then dropping it from the reply.
    kdc.salt = b"CORP.EXAMPLE.COMalice".to_vec();
    kdc.demand_preauth = true;

    // Answer the first AS-REQ with a preauth demand carrying no ETYPE-INFO2
    // at all, which is the shape a KDC with nothing to say sends.
    let mut client = client_for(&kdc, NOW);
    let KdcStep::SendAndExpect(_first) = client.step(&[]).expect("first AS-REQ") else {
        panic!("expected a request");
    };
    let error = frame(&kdc.krb_error(25, &[]));
    let KdcStep::SendAndExpect(second) = client.step(&error).expect("second AS-REQ") else {
        panic!("expected a request");
    };
    // The KDC now checks that second request against the default salt.
    let reply = kdc.answer(&second);
    assert!(kdc.saw_preauth, "the second request carried a timestamp");
    // A KDC_ERR_PREAUTH_FAILED here would mean the fallback salt was wrong.
    let body = unframe(&reply);
    assert_ne!(
        read_tlv(body).expect("a reply").0.tag,
        application(app::KRB_ERROR),
        "the default salt derived the right key"
    );
}

/// RFC 4120 §5.4.1's clock skew, and PRDRDP/14 §7.1 item 11's one retry.
///
/// The client's clock is twenty minutes behind the KDC's, which is four times
/// the five minutes Windows allows. The KDC refuses once with the truth about
/// its own clock in `stime`, and the retry carries a timestamp the KDC
/// accepts. Nothing changes this computer's clock.
#[test]
fn a_clock_skew_is_measured_from_stime_and_retried_once() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    let twenty_minutes = 20 * 60;
    let mut client = client_for(&kdc, NOW - twenty_minutes);

    // First AS-REQ: the KDC sees a timestamp twenty minutes old. It has no
    // timestamp to check yet, so it answers the preauth demand; the skew
    // shows up on the second request.
    let KdcStep::SendAndExpect(first) = client.step(&[]).expect("first AS-REQ") else {
        panic!("expected a request");
    };
    let reply = kdc.answer(&first);
    let KdcStep::SendAndExpect(second) = client.step(&reply).expect("second AS-REQ") else {
        panic!("expected a request");
    };
    // The KDC refuses this one for skew, because the timestamp is twenty
    // minutes out.
    let reply = kdc.answer(&second);
    let body = unframe(&reply);
    assert_eq!(
        read_tlv(body).expect("a reply").0.tag,
        application(app::KRB_ERROR),
        "a twenty minute skew is refused"
    );

    // The client measures the offset from `stime` and retries once.
    let KdcStep::SendAndExpect(third) = client.step(&reply).expect("the skew retry") else {
        panic!("expected a retry");
    };
    let reply = kdc.answer(&third);
    let body = unframe(&reply);
    assert_ne!(
        read_tlv(body).expect("a reply").0.tag,
        application(app::KRB_ERROR),
        "the corrected timestamp is accepted"
    );

    // And the exchange finishes from there.
    let KdcStep::SendAndExpect(tgs) = client.step(&reply).expect("TGS-REQ") else {
        panic!("expected the TGS-REQ");
    };
    let reply = kdc.answer(&tgs);
    let KdcStep::Done(ticket) = client.step(&reply).expect("done") else {
        panic!("expected a ticket");
    };
    assert_eq!(
        ticket.session_key.octets(),
        kdc.service_session_key.octets()
    );
}

/// A skew that does not go away after the one retry is reported with the
/// measured difference, because "the clocks are too far apart" without a
/// number leaves the user nothing to check.
#[test]
fn a_persistent_skew_reports_the_measured_difference() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    kdc.now = NOW + 3600;
    let mut client = client_for(&kdc, NOW);

    // The KDC answers KRB_AP_ERR_SKEW to every AS-REQ.
    kdc.skew_once = true;
    let KdcStep::SendAndExpect(first) = client.step(&[]).expect("first AS-REQ") else {
        panic!("expected a request");
    };
    let reply = kdc.answer(&first);
    // The retry, which this KDC also refuses for skew.
    let KdcStep::SendAndExpect(_retry) = client.step(&reply).expect("the skew retry") else {
        panic!("expected a retry");
    };
    let again = frame(&kdc.krb_error(37, &[]));
    let err = client.step(&again).expect_err("the second skew is fatal");
    match err {
        AuthError::ClockSkew(seconds) => {
            assert_eq!(seconds, 3600, "the offset measured from stime");
            assert!(err.user_message().contains("3600"));
            assert!(err.user_message().ends_with('.'));
        }
        other => panic!("expected ClockSkew, got {other:?}"),
    }
    assert_eq!(err.class(), rdp_auth::error::Class::Fatal);
}

/// A ticket for a service other than the one asked for is refused
/// (RFC 4120 §3.3.3). A KDC whose answer an attacker controls would like us
/// to accept one.
#[test]
fn a_ticket_for_the_wrong_service_is_refused() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    let mut client = client_for(&kdc, NOW);

    let KdcStep::SendAndExpect(first) = client.step(&[]).expect("first") else {
        panic!()
    };
    let reply = kdc.answer(&first);
    let KdcStep::SendAndExpect(second) = client.step(&reply).expect("second") else {
        panic!()
    };
    let reply = kdc.answer(&second);
    let KdcStep::SendAndExpect(tgs) = client.step(&reply).expect("tgs") else {
        panic!()
    };
    // The KDC now answers with a ticket for a different host.
    kdc.spn = vec![
        "TERMSRV".to_owned(),
        "elsewhere.corp.example.com".to_owned(),
    ];
    let mut permissive = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    permissive.spn = kdc.spn.clone();
    permissive.tgt_session_key =
        Key::new(Enctype::Aes256CtsHmacSha1_96, kdc.tgt_session_key.octets()).unwrap();
    permissive.service_session_key = Key::new(
        Enctype::Aes256CtsHmacSha1_96,
        kdc.service_session_key.octets(),
    )
    .unwrap();
    // Build the TGS-REP by hand so the mock's own sname assertion does not
    // fire first: this is a hostile KDC, not a well behaved one.
    let seq = app_body(unframe(&tgs), app::TGS_REQ).expect("TGS-REQ");
    let req_body = seq_field(seq, 4).expect("req-body");
    let (req_body_seq, _) = expect_tag(req_body, tag::SEQUENCE).expect("body");
    let nonce = read_int_i64(seq_field(req_body_seq, 7).expect("nonce"))
        .expect("int")
        .0;
    let wrong: Vec<&str> = permissive.spn.iter().map(String::as_str).collect();
    let ticket = permissive.ticket(&wrong, name_type::SRV_HST);
    let part = permissive.enc_kdc_rep_part(
        app::ENC_TGS_REP_PART,
        &permissive.service_session_key,
        nonce,
        &wrong,
        name_type::SRV_HST,
    );
    let enc = crypto::encrypt(&permissive.tgt_session_key, usage::TGS_REP_ENC_PART, &part)
        .expect("encrypt");
    let rep = permissive.kdc_rep(app::TGS_REP, msg_type::TGS_REP, &ticket, &enc, None);

    let err = client
        .step(&frame(&rep))
        .expect_err("the wrong service is refused");
    assert_eq!(err, AuthError::MalformedMessage("TGS-REP sname"));
}

/// A reply whose nonce is not the one we sent is a reply to somebody else's
/// request (RFC 4120 §5.4.2).
#[test]
fn a_reply_with_the_wrong_nonce_is_refused() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    let mut client = client_for(&kdc, NOW);
    let KdcStep::SendAndExpect(first) = client.step(&[]).expect("first") else {
        panic!()
    };
    let reply = kdc.answer(&first);
    let KdcStep::SendAndExpect(_second) = client.step(&reply).expect("second") else {
        panic!()
    };
    // Issue a TGT whose EncASRepPart carries a nonce nobody asked for.
    let rep = kdc.issue_tgt(0x0bad_0bad, None);
    let err = client.step(&frame(&rep)).expect_err("the nonce is checked");
    assert_eq!(err, AuthError::MessageOutOfSequence);
}

/// Every truncation of every message the KDC sends is an error and never a
/// panic. These are bytes a remote peer chose.
#[test]
fn every_truncation_of_every_reply_fails_cleanly() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    let mut replies = Vec::new();

    let mut client = client_for(&kdc, NOW);
    let KdcStep::SendAndExpect(first) = client.step(&[]).expect("first") else {
        panic!()
    };
    let reply = kdc.answer(&first);
    replies.push(reply.clone());
    let KdcStep::SendAndExpect(second) = client.step(&reply).expect("second") else {
        panic!()
    };
    let reply = kdc.answer(&second);
    replies.push(reply.clone());
    let KdcStep::SendAndExpect(tgs) = client.step(&reply).expect("tgs") else {
        panic!()
    };
    replies.push(kdc.answer(&tgs));
    replies.push(frame(&kdc.krb_error(37, &kdc.etype_info2_padata())));
    replies.push(frame(&kdc.krb_error(25, &kdc.etype_info2_padata())));

    for (n, reply) in replies.iter().enumerate() {
        for cut in 0..reply.len() {
            // A fresh client for every cut, because a failed one stays
            // failed and would answer AlreadyFailed to everything after.
            let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
            let mut client = client_for(&kdc, NOW);
            let KdcStep::SendAndExpect(first) = client.step(&[]).expect("first") else {
                panic!()
            };
            let _ = kdc.answer(&first);
            // Whatever it makes of the prefix, it must not panic.
            let _ = client.step(reply.get(..cut).expect("in range"));
            assert!(
                client.step(&[]).is_err(),
                "reply {n} cut at {cut} left the client usable"
            );
        }
    }
}

/// Rubbish in place of a reply is an error, not a panic, at every state.
#[test]
fn rubbish_in_place_of_a_reply_is_refused() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    for junk in [
        &b""[..],
        &[0x00][..],
        &[0xff, 0xff, 0xff, 0xff][..],
        &[0x80, 0x00, 0x00, 0x01, 0x41][..],
        &[0x00, 0x00, 0x00, 0x01, 0x41][..],
        &[0x00, 0x00, 0x00, 0x02, 0x30, 0x00][..],
        &[0x00, 0x00, 0x00, 0x05, 0x6b, 0x03, 0x30, 0x01, 0x00][..],
    ] {
        let mut client = client_for(&kdc, NOW);
        let KdcStep::SendAndExpect(_) = client.step(&[]).expect("first") else {
            panic!()
        };
        assert!(client.step(junk).is_err(), "junk {junk:?} was accepted");
    }
    // And the same at the TGS state.
    let mut client = client_for(&kdc, NOW);
    let KdcStep::SendAndExpect(first) = client.step(&[]).expect("first") else {
        panic!()
    };
    let reply = kdc.answer(&first);
    let KdcStep::SendAndExpect(second) = client.step(&reply).expect("second") else {
        panic!()
    };
    let reply = kdc.answer(&second);
    let KdcStep::SendAndExpect(_tgs) = client.step(&reply).expect("tgs") else {
        panic!()
    };
    assert!(client.step(&[0x00, 0x00, 0x00, 0x01, 0x41]).is_err());
}

/// A failed client stays failed rather than restarting (the same rule
/// `NtlmClient` follows).
#[test]
fn a_failed_client_stays_failed() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    let mut client = client_for(&kdc, NOW);
    let KdcStep::SendAndExpect(first) = client.step(&[]).expect("first") else {
        panic!()
    };
    let _ = kdc.answer(&first);
    assert!(client.step(&[0x41]).is_err());
    assert_eq!(client.step(&[]).unwrap_err(), AuthError::AlreadyFailed);
    assert_eq!(client.step(&[0x41]).unwrap_err(), AuthError::AlreadyFailed);
}

/// PRDRDP/14 §8.3: nothing here prints a secret.
#[test]
fn no_kerberos_type_prints_a_secret() {
    let mut kdc = MockKdc::new(Enctype::Aes256CtsHmacSha1_96);
    let mut client = client_for(&kdc, NOW);
    let shown = format!("{client:?}");
    assert!(!shown.contains("Pa55w0rd"), "{shown}");
    assert!(
        shown.contains("***"),
        "the identity redacts itself: {shown}"
    );

    let (_, ticket) = run(&mut client, &mut kdc).expect("the exchange succeeds");
    let shown = format!("{ticket:?}");
    assert!(!shown.contains("Pa55w0rd"), "{shown}");
    assert!(shown.contains("redacted"), "{shown}");
    // The session key's octets are 0xa5 repeated; check the hex does not
    // leak either way it might be rendered.
    assert!(!shown.contains("a5a5"), "{shown}");
    assert!(!shown.contains("165, 165"), "{shown}");

    let shown = format!("{client:?}");
    assert!(!shown.contains("Pa55w0rd"), "{shown}");
}

/// A bare local account name cannot use Kerberos, and the constructor says so
/// rather than failing three round trips later.
#[test]
fn an_account_with_no_domain_is_refused_at_construction() {
    let identity = Identity::from_prompt("localuser", "", "pw").expect("a user name");
    let err = KdcClient::new(KdcConfig {
        identity,
        spn: "TERMSRV/host".to_owned(),
        now_unix: NOW,
        ticket_lifetime_secs: DEFAULT_TICKET_LIFETIME_SECS,
    })
    .expect_err("a local account has no realm");
    assert_eq!(err, AuthError::NoCommonMechanism);
}

/// A user principal name goes whole into an `NT-ENTERPRISE` principal, in the
/// realm after the last `@`.
#[test]
fn a_user_principal_name_becomes_an_enterprise_principal() {
    let identity = Identity::from_prompt("alice@corp.example.com", "", "pw").expect("a user name");
    let client = KdcClient::new(KdcConfig {
        identity,
        spn: "TERMSRV/host".to_owned(),
        now_unix: NOW,
        ticket_lifetime_secs: DEFAULT_TICKET_LIFETIME_SECS,
    })
    .expect("a UPN carries its own realm");
    assert_eq!(client.realm(), "CORP.EXAMPLE.COM");
}
