//! Phase 7: the client side of the licensing exchange (MS-RDPELE, MS-RDPBCGR
//! 2.2.1.12).
//!
//! A Windows host without Remote Desktop licensing says "no licence needed"
//! in one PDU and this module has nothing to do. An RD Session Host with a
//! licence server sends a `LICENSE_REQUEST`, and until this module existed
//! the client declined it with an `ERROR_ALERT`. The server let the session
//! through anyway, recorded no licence for the device, and once the grace
//! period was over told the user the session would end in sixty minutes
//! (issue #25). Now the client asks for a licence, answers the platform
//! challenge, stores what it is given, and presents it next time:
//!
//! ```text
//! server                               client
//! LICENSE_REQUEST            ------>
//!                            <------   NEW_LICENSE_REQUEST, or LICENSE_INFO
//!                                      when a licence for this server is stored
//! PLATFORM_CHALLENGE         ------>
//!                            <------   PLATFORM_CHALLENGE_RESPONSE
//! NEW_LICENSE, UPGRADE_LICENSE,
//! or STATUS_VALID_CLIENT     ------>   (store the licence, carry on)
//! ```
//!
//! The byte layouts are `rdp-pdu`'s and the cryptography is
//! `rdp-auth::licensing`'s. What this module owns is the order, the hardware
//! id, and the files.
//!
//! # Where licences live
//!
//! In [`ResolvedOptions::license_dir`], which the viewer points at a folder
//! under its own data directory. One file per server name holds the licence
//! exactly as the server issued it, and one file holds the sixteen random
//! bytes of this installation's hardware id, because a licence is bound to
//! the hardware id it was issued against. Without a folder the exchange still
//! runs; the licence is simply asked for again next time, which a licence
//! server answers with the same device's licence or a temporary one.
//!
//! # Failing safe
//!
//! Anything this client cannot do with a `LICENSE_REQUEST` (no certificate,
//! a key it cannot use) falls back to what the client did before: an
//! `ERROR_ALERT` declining the exchange, which a host in its grace period
//! answers with `STATUS_VALID_CLIENT`. Nothing that worked before this module
//! stops working because of it.

use std::path::{Path, PathBuf};

use rdp_auth::licensing::{ClientSecrets, LicensingKeys, LicensingPublicKey};
use rdp_pdu::gcc::{parse_server_certificate, RsaKeyBytes};
use rdp_pdu::io::{Encode, Reader, Writer};
use rdp_pdu::rdp::license::{
    self, message_type, ClientLicenseInfo, ClientNewLicenseRequest,
    ClientPlatformChallengeResponse, NewLicenseInfo, PlatformChallengeResponseData,
    ServerLicenseRequest, HARDWARE_ID_LEN, PLATFORM_ID, SERVER_RANDOM_LEN,
};
use rdp_pdu::rdp::{LicenseMessage, LicensePdu};
use zeroize::Zeroizing;

use crate::error::{RdpError, Result};

/// The file holding this installation's hardware id.
const HARDWARE_ID_FILE: &str = "hardware-id";

/// The extension of a stored licence.
const LICENCE_EXTENSION: &str = "licence";

/// What the activation loop should do after one licensing PDU.
#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    /// A licensing PDU to send back, security header included.
    pub reply: Option<Vec<u8>>,
    /// True when licensing is over and the next I/O channel PDU is the
    /// Demand Active.
    pub done: bool,
}

/// Where we are in the exchange.
enum State {
    /// Nothing received yet.
    Start,
    /// A request or licence info went out; the keys are agreed.
    Requested {
        keys: LicensingKeys,
        /// True when it was a stored licence that went out, so a refusal
        /// can say so.
        presented_stored: bool,
    },
    /// The challenge was answered.
    Answered { keys: LicensingKeys },
    /// Declined with an `ERROR_ALERT`, the fallback.
    Declined,
}

/// The client's licensing state for one connection.
pub struct Licensing {
    state: State,
    store: Option<LicenceStore>,
    server: String,
    hardware_id: Zeroizing<[u8; HARDWARE_ID_LEN]>,
    user_name: Vec<u8>,
    machine_name: Vec<u8>,
}

impl std::fmt::Debug for Licensing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Licensing")
            .field("server", &self.server)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

/// A NUL terminated ANSI string for `ClientUserName` and `ClientMachineName`
/// (MS-RDPELE 2.2.2.3). Non ASCII characters become `?`, as an ANSI code
/// page without them would render them.
fn ansi_z(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s
        .chars()
        .map(|c| {
            if c.is_ascii() && c != '\0' {
                c as u8
            } else {
                b'?'
            }
        })
        .collect();
    out.push(0);
    out
}

impl Licensing {
    /// State for a connection to `server`, as user `user`, from the machine
    /// called `machine`, storing licences in `dir` when there is one.
    #[must_use]
    pub fn new(server: &str, user: &str, machine: &str, dir: Option<&Path>) -> Self {
        let store = dir.map(|d| LicenceStore::new(d.to_path_buf()));
        let data = store
            .as_ref()
            .and_then(|s| {
                s.hardware_id()
                    .inspect_err(|e| {
                        tracing::warn!(error = %e, "the licence folder's hardware id is unusable");
                    })
                    .ok()
            })
            .unwrap_or_else(rdp_auth::licensing::random_hardware_id);
        let mut hardware_id = Zeroizing::new([0u8; HARDWARE_ID_LEN]);
        hardware_id[..4].copy_from_slice(&PLATFORM_ID.to_le_bytes());
        hardware_id[4..].copy_from_slice(&data);
        Self {
            state: State::Start,
            store,
            server: server.to_owned(),
            hardware_id,
            user_name: ansi_z(user),
            machine_name: ansi_z(machine),
        }
    }

    /// Act on one licensing PDU.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] for an `ERROR_ALERT` that is not
    /// `STATUS_VALID_CLIENT`, a message out of order, a MAC that does not
    /// verify, and a message type MS-RDPELE does not send to a client.
    pub fn step(&mut self, pdu: &LicensePdu<'_>) -> Result<Step> {
        match (&pdu.message, &self.state) {
            (LicenseMessage::ErrorAlert(error), _) => {
                if error.is_valid_client() {
                    if matches!(self.state, State::Requested { .. } | State::Answered { .. }) {
                        tracing::info!("the licence server accepted this client");
                    }
                    return Ok(Step {
                        reply: None,
                        done: true,
                    });
                }
                let stored = matches!(
                    self.state,
                    State::Requested {
                        presented_stored: true,
                        ..
                    }
                );
                Err(RdpError::Protocol(format!(
                    "the server refused the licensing exchange{}: {} ({})",
                    if stored {
                        " when this client presented its stored licence"
                    } else {
                        ""
                    },
                    error.error_code.describe(),
                    error.state_transition.symbol()
                )))
            }
            (LicenseMessage::LicenseRequest(request), State::Start) => {
                Ok(self.answer_request(request))
            }
            (LicenseMessage::PlatformChallenge(challenge), State::Requested { keys, .. }) => {
                let plain = keys
                    .decrypt_verified(
                        challenge.encrypted_challenge.data.as_slice(),
                        &challenge.mac,
                    )
                    .map_err(|e| licensing_error("PLATFORM_CHALLENGE", &e))?;
                let reply = self.challenge_response(keys, &plain)?;
                let State::Requested { keys, .. } =
                    std::mem::replace(&mut self.state, State::Declined)
                else {
                    unreachable!("matched above");
                };
                self.state = State::Answered { keys };
                tracing::debug!("answered the licence server's platform challenge");
                Ok(Step {
                    reply: Some(reply),
                    done: false,
                })
            }
            (LicenseMessage::NewLicense { upgrade, license }, State::Answered { keys }) => {
                let plain = keys
                    .decrypt_verified(license.encrypted_license_info.data.as_slice(), &license.mac)
                    .map_err(|e| licensing_error("NEW_LICENSE", &e))?;
                let info = NewLicenseInfo::read(&mut Reader::new(&plain))?;
                tracing::info!(
                    upgrade = *upgrade,
                    version = format_args!("{:#010x}", info.version),
                    len = info.license_info.len(),
                    "the licence server issued a client access licence"
                );
                if let Some(store) = &self.store {
                    match store.save(&self.server, info.license_info) {
                        Ok(path) => tracing::info!(path = %path.display(), "stored the licence"),
                        Err(e) => tracing::warn!(error = %e, "the licence could not be stored"),
                    }
                }
                Ok(Step {
                    reply: None,
                    done: true,
                })
            }
            (LicenseMessage::Unimplemented { msg_type, .. }, _) => {
                Err(RdpError::Protocol(format!(
                    "the server sent licensing message 0x{msg_type:02x}, which MS-RDPELE never \
                     sends to a client"
                )))
            }
            (message, _) => Err(RdpError::Protocol(format!(
                "the server sent {} at a point in the licensing exchange where it makes no sense",
                name_of(message)
            ))),
        }
    }

    /// Answer a `LICENSE_REQUEST` with the stored licence when there is one
    /// and a new request when there is not, or decline it when neither can
    /// be built.
    fn answer_request(&mut self, request: &ServerLicenseRequest<'_>) -> Step {
        match self.build_answer(request) {
            Ok((reply, keys, presented_stored)) => {
                self.state = State::Requested {
                    keys,
                    presented_stored,
                };
                Step {
                    reply: Some(reply),
                    done: false,
                }
            }
            Err(reason) => {
                tracing::warn!(
                    reason = %reason,
                    "declining the licence exchange: the request cannot be answered"
                );
                self.state = State::Declined;
                Step {
                    reply: decline().ok(),
                    done: false,
                }
            }
        }
    }

    fn build_answer(
        &self,
        request: &ServerLicenseRequest<'_>,
    ) -> std::result::Result<(Vec<u8>, LicensingKeys, bool), String> {
        let key = server_key(request)?;
        let mut server_random = [0u8; SERVER_RANDOM_LEN];
        server_random.copy_from_slice(request.server_random.as_slice());
        let secrets = ClientSecrets::generate();
        let keys = secrets.derive_keys(&server_random);
        let premaster = secrets
            .encrypted_premaster_secret(&key)
            .map_err(|e| e.to_string())?;

        let stored = self.store.as_ref().and_then(|s| s.load(&self.server));
        if let Some(licence) = stored.as_deref() {
            let info = ClientLicenseInfo {
                client_random: *secrets.client_random(),
                encrypted_premaster_secret: &premaster,
                license_info: licence,
                encrypted_hwid: &keys.rc4(&self.hardware_id[..]),
                mac: keys.mac(&self.hardware_id[..]),
            };
            let bytes = license::encode_client_message(message_type::LICENSE_INFO, &info)
                .map_err(|e| e.to_string())?;
            tracing::info!(
                server = %self.server,
                "presenting the stored client access licence (MS-RDPELE 2.2.2.2)"
            );
            return Ok((bytes, keys, true));
        }
        let new = ClientNewLicenseRequest {
            client_random: *secrets.client_random(),
            encrypted_premaster_secret: &premaster,
            user_name: &self.user_name,
            machine_name: &self.machine_name,
        };
        let bytes = license::encode_client_message(message_type::NEW_LICENSE_REQUEST, &new)
            .map_err(|e| e.to_string())?;
        tracing::info!(
            server = %self.server,
            "asking the licence server for a client access licence (MS-RDPELE 2.2.2.3)"
        );
        Ok((bytes, keys, false))
    }

    /// `CLIENT_PLATFORM_CHALLENGE_RESPONSE`: the challenge echoed in a
    /// `PLATFORM_CHALLENGE_RESPONSE_DATA`, the hardware id, both encrypted,
    /// and a MAC over the two plaintexts (MS-RDPELE 3.2.5.4).
    fn challenge_response(&self, keys: &LicensingKeys, challenge: &[u8]) -> Result<Vec<u8>> {
        let data = PlatformChallengeResponseData { challenge };
        let mut plain = Zeroizing::new(Vec::with_capacity(data.size() + HARDWARE_ID_LEN));
        data.encode_checked(&mut Writer::new(&mut plain))?;
        let response_len = plain.len();
        plain.extend_from_slice(&self.hardware_id[..]);
        let response = ClientPlatformChallengeResponse {
            encrypted_response: &keys.rc4(&plain[..response_len]),
            encrypted_hwid: &keys.rc4(&self.hardware_id[..]),
            mac: keys.mac(&plain),
        };
        Ok(license::encode_client_message(
            message_type::PLATFORM_CHALLENGE_RESPONSE,
            &response,
        )?)
    }
}

fn licensing_error(message: &str, e: &rdp_auth::licensing::LicensingError) -> RdpError {
    RdpError::Protocol(format!("the licence server's {message} {e}"))
}

fn name_of(message: &LicenseMessage<'_>) -> &'static str {
    match message {
        LicenseMessage::ErrorAlert(_) => "ERROR_ALERT",
        LicenseMessage::LicenseRequest(_) => "LICENSE_REQUEST",
        LicenseMessage::PlatformChallenge(_) => "PLATFORM_CHALLENGE",
        LicenseMessage::NewLicense { upgrade: false, .. } => "NEW_LICENSE",
        LicenseMessage::NewLicense { upgrade: true, .. } => "UPGRADE_LICENSE",
        LicenseMessage::Unimplemented { .. } => "an unknown licensing message",
    }
}

/// The `ERROR_ALERT` that declines the exchange, the fallback this client
/// used for every `LICENSE_REQUEST` before it could answer one.
fn decline() -> Result<Vec<u8>> {
    let alert = LicensePdu::client_error_alert();
    let mut out = Vec::with_capacity(alert.size());
    alert.encode_checked(&mut Writer::new(&mut out))?;
    Ok(out)
}

/// The key the premaster secret goes under: the request's own certificate,
/// which under TLS and CredSSP is the only one there is (MS-RDPELE 3.1.5.1).
fn server_key(
    request: &ServerLicenseRequest<'_>,
) -> std::result::Result<LicensingPublicKey, String> {
    let blob = request.server_certificate.data.as_slice();
    if blob.is_empty() {
        return Err("the request carries no server certificate".into());
    }
    let cert = parse_server_certificate(blob).map_err(|e| e.to_string())?;
    let key = cert.rsa_public_key().map_err(|e| e.to_string())?;
    match key {
        RsaKeyBytes::LittleEndian { modulus, exponent } => {
            LicensingPublicKey::from_le(modulus, &exponent)
        }
        RsaKeyBytes::BigEndian { modulus, exponent } => {
            LicensingPublicKey::from_be(modulus, exponent)
        }
    }
    .map_err(|e| e.to_string())
}

/// The licence folder.
#[derive(Debug, Clone)]
pub struct LicenceStore {
    dir: PathBuf,
}

impl LicenceStore {
    /// A store in `dir`, which is created on first write.
    #[must_use]
    pub const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The file a server's licence lives in. The server name is the one the
    /// user typed (never the dial address of a tunnel), lower cased, with
    /// anything that is not a letter, digit, dot or hyphen replaced, so it
    /// is a file name on every platform and cannot climb out of the folder.
    #[must_use]
    pub fn path_for(&self, server: &str) -> PathBuf {
        let name: String = server
            .trim()
            .to_ascii_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else if c == '.' {
                    '.'
                } else {
                    '_'
                }
            })
            .collect();
        let name = name.trim_matches('.');
        let name = if name.is_empty() { "_" } else { name };
        self.dir.join(format!("{name}.{LICENCE_EXTENSION}"))
    }

    /// The stored licence for `server`, if there is one.
    #[must_use]
    pub fn load(&self, server: &str) -> Option<Vec<u8>> {
        let bytes = std::fs::read(self.path_for(server)).ok()?;
        // A licence has to fit `wBlobLen`; anything else is not one of ours.
        (!bytes.is_empty() && bytes.len() <= usize::from(u16::MAX)).then_some(bytes)
    }

    /// Store `licence` for `server`, replacing what was there, through a
    /// temporary file so a crash leaves the old licence or the new one and
    /// never half of either.
    ///
    /// # Errors
    ///
    /// The I/O error that stopped it.
    pub fn save(&self, server: &str, licence: &[u8]) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.path_for(server);
        let tmp = path.with_extension(format!("{LICENCE_EXTENSION}.tmp"));
        std::fs::write(&tmp, licence)?;
        std::fs::rename(&tmp, &path)?;
        Ok(path)
    }

    /// This installation's sixteen hardware id bytes, created on first use.
    ///
    /// # Errors
    ///
    /// The I/O error when the file can neither be read nor written.
    pub fn hardware_id(&self) -> std::io::Result<[u8; 16]> {
        let path = self.dir.join(HARDWARE_ID_FILE);
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(id) = <[u8; 16]>::try_from(bytes.as_slice()) {
                return Ok(id);
            }
            tracing::warn!(path = %path.display(), "replacing a hardware id file of the wrong size");
        }
        let id = rdp_auth::licensing::random_hardware_id();
        std::fs::create_dir_all(&self.dir)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, id)?;
        std::fs::rename(&tmp, &path)?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;
    use num_bigint_dig::{BigUint, ModInverse};
    use rdp_pdu::codes::{LicenseError, LicenseStateTransition};
    use rdp_pdu::io::{Decode, Payload};
    use rdp_pdu::rdp::license::{
        blob_type, preamble_flags, LicenseBinaryBlob, LicenseErrorMessage, LicensePreamble,
        ProductInfo, ServerNewLicense, ServerPlatformChallenge, LICENSE_PREAMBLE_LEN,
    };

    /// A licence server for the tests: a 512 bit RSA key whose private half
    /// it knows, so it can recover the premaster secret exactly as Windows
    /// does and derive the same keys from it. It is built from MS-RDPELE
    /// 5.1 and nothing in it is shared with the client code above except the
    /// `rdp-auth` key derivation, which has its own vectors.
    struct Server {
        n: BigUint,
        d: BigUint,
        cert: Vec<u8>,
        server_random: [u8; 32],
    }

    impl Server {
        fn new() -> Self {
            let one = BigUint::from(1u32);
            let p = (BigUint::from(1u32) << 256) - BigUint::from(189u32);
            let q = (BigUint::from(1u32) << 256) - BigUint::from(357u32);
            let n = &p * &q;
            let e = BigUint::from(65537u32);
            let phi = (&p - &one) * (&q - &one);
            let d = e.mod_inverse(&phi).unwrap().to_biguint().unwrap();
            // A proprietary certificate (MS-RDPBCGR 2.2.1.4.3.1.1).
            let mut modulus = n.to_bytes_le();
            modulus.resize(64 + 8, 0);
            let mut cert = Vec::new();
            cert.extend_from_slice(&1u32.to_le_bytes());
            cert.extend_from_slice(&1u32.to_le_bytes());
            cert.extend_from_slice(&1u32.to_le_bytes());
            cert.extend_from_slice(&0x0006u16.to_le_bytes());
            cert.extend_from_slice(&(20u16 + 72).to_le_bytes());
            cert.extend_from_slice(b"RSA1");
            cert.extend_from_slice(&72u32.to_le_bytes());
            cert.extend_from_slice(&512u32.to_le_bytes());
            cert.extend_from_slice(&63u32.to_le_bytes());
            cert.extend_from_slice(&65537u32.to_le_bytes());
            cert.extend_from_slice(&modulus);
            cert.extend_from_slice(&0x0008u16.to_le_bytes());
            cert.extend_from_slice(&72u16.to_le_bytes());
            cert.extend_from_slice(&[0u8; 72]);
            Self {
                n,
                d,
                cert,
                server_random: [0x5e; 32],
            }
        }

        fn request(&self) -> LicensePdu<'_> {
            LicensePdu {
                preamble: LicensePreamble {
                    msg_type: message_type::LICENSE_REQUEST,
                    flags: preamble_flags::VERSION_3_0,
                    msg_size: 0,
                },
                message: LicenseMessage::LicenseRequest(Box::new(ServerLicenseRequest {
                    server_random: Payload::new(&self.server_random),
                    product_info: ProductInfo {
                        version: 0x0006_0000,
                        company_name: Payload::new(b"A\0\0\0"),
                        product_id: Payload::new(b"B\0\0\0"),
                    },
                    key_exchange_list: LicenseBinaryBlob {
                        blob_type: blob_type::KEY_EXCHG_ALG,
                        data: Payload::new(&[1, 0, 0, 0]),
                    },
                    server_certificate: LicenseBinaryBlob {
                        blob_type: blob_type::CERTIFICATE,
                        data: Payload::new(&self.cert),
                    },
                    scopes: vec![],
                })),
            }
        }

        /// Read the client's first message: recover the premaster secret,
        /// derive the keys, and return them with the message type and body.
        fn receive(&self, bytes: &[u8]) -> (u8, Vec<u8>, LicensingKeys) {
            assert_eq!(bytes[..4], [0x80, 0x00, 0x00, 0x00]);
            assert_eq!(
                bytes[5],
                preamble_flags::VERSION_3_0 | preamble_flags::EXTENDED_ERROR_MSG_SUPPORTED
            );
            let msg_type = bytes[4];
            let body = bytes[4 + LICENSE_PREAMBLE_LEN..].to_vec();
            assert_eq!(&body[..4], &1u32.to_le_bytes());
            assert_eq!(&body[4..8], &PLATFORM_ID.to_le_bytes());
            let mut client_random = [0u8; 32];
            client_random.copy_from_slice(&body[8..40]);
            assert_eq!(&body[40..42], &blob_type::RANDOM.to_le_bytes());
            let len = u16::from_le_bytes([body[42], body[43]]) as usize;
            assert_eq!(len, 64 + 8, "the modulus length plus eight");
            let sealed = &body[44..44 + len];
            assert_eq!(&sealed[64..], &[0u8; 8]);
            let mut pm = BigUint::from_bytes_le(&sealed[..64])
                .modpow(&self.d, &self.n)
                .to_bytes_le();
            pm.resize(48, 0);
            let pm: [u8; 48] = pm.try_into().unwrap();
            let keys = LicensingKeys::derive(&pm, &client_random, &self.server_random);
            (msg_type, body[44 + len..].to_vec(), keys)
        }
    }

    fn challenge_pdu<'a>(sealed: &'a [u8], mac: [u8; 16]) -> LicensePdu<'a> {
        LicensePdu {
            preamble: LicensePreamble {
                msg_type: message_type::PLATFORM_CHALLENGE,
                flags: 3,
                msg_size: 0,
            },
            message: LicenseMessage::PlatformChallenge(ServerPlatformChallenge {
                connect_flags: 0,
                encrypted_challenge: LicenseBinaryBlob {
                    blob_type: blob_type::ANY,
                    data: Payload::new(sealed),
                },
                mac,
            }),
        }
    }

    fn new_license_pdu<'a>(sealed: &'a [u8], mac: [u8; 16]) -> LicensePdu<'a> {
        LicensePdu {
            preamble: LicensePreamble {
                msg_type: message_type::NEW_LICENSE,
                flags: 3,
                msg_size: 0,
            },
            message: LicenseMessage::NewLicense {
                upgrade: false,
                license: ServerNewLicense {
                    encrypted_license_info: LicenseBinaryBlob {
                        blob_type: blob_type::ENCRYPTED_DATA,
                        data: Payload::new(sealed),
                    },
                    mac,
                },
            },
        }
    }

    fn valid_client() -> LicensePdu<'static> {
        LicensePdu {
            preamble: LicensePreamble {
                msg_type: message_type::ERROR_ALERT,
                flags: 3,
                msg_size: 16,
            },
            message: LicenseMessage::ErrorAlert(LicenseErrorMessage {
                error_code: LicenseError::StatusValidClient,
                state_transition: LicenseStateTransition::NoTransition,
                error_info: LicenseBinaryBlob::empty(blob_type::ERROR),
            }),
        }
    }

    /// Run the whole exchange against the test server, returning the type
    /// of the client's first message and the hardware id the server saw.
    fn exchange(client: &mut Licensing, server: &Server, licence: &[u8]) -> (u8, Vec<u8>) {
        let step = client.step(&server.request()).unwrap();
        assert!(!step.done);
        let (first, rest, keys) = server.receive(&step.reply.unwrap());

        let challenge = b"T\0E\0S\0T\0\0\0";
        let sealed = keys.rc4(challenge);
        let step = client
            .step(&challenge_pdu(&sealed, keys.mac(challenge)))
            .unwrap();
        assert!(!step.done);
        let reply = step.reply.unwrap();
        assert_eq!(reply[4], message_type::PLATFORM_CHALLENGE_RESPONSE);
        let body = &reply[4 + LICENSE_PREAMBLE_LEN..];
        let mut r = Reader::new(body);
        let response = LicenseBinaryBlob::read(&mut r, "test").unwrap();
        let hwid = LicenseBinaryBlob::read(&mut r, "test").unwrap();
        let mac: [u8; 16] = r.array("test").unwrap();
        assert!(r.is_empty());
        assert_eq!(response.blob_type, blob_type::ENCRYPTED_DATA);
        let response = keys.rc4(response.data.as_slice());
        let hwid = keys.rc4(hwid.data.as_slice());
        // MS-RDPELE 2.2.2.5.1, and the challenge echoed.
        assert_eq!(
            response[..8],
            [0x00, 0x01, 0x00, 0xff, 0x03, 0x00, 0x0a, 0x00]
        );
        assert_eq!(&response[8..], challenge);
        let mut both = response.clone();
        both.extend_from_slice(&hwid);
        assert_eq!(keys.mac(&both), mac, "the MAC covers response then hwid");
        assert_eq!(&hwid[..4], &PLATFORM_ID.to_le_bytes());

        if first == message_type::LICENSE_INFO {
            // The stored licence and the encrypted hardware id, MAC'd.
            let mut r = Reader::new(&rest);
            let presented = LicenseBinaryBlob::read(&mut r, "test").unwrap();
            assert_eq!(presented.blob_type, blob_type::DATA);
            assert_eq!(presented.data.as_slice(), licence);
            let sealed = LicenseBinaryBlob::read(&mut r, "test").unwrap();
            let mac: [u8; 16] = r.array("test").unwrap();
            assert_eq!(keys.rc4(sealed.data.as_slice()), hwid);
            assert_eq!(keys.mac(&hwid), mac);
        }

        let info = NewLicenseInfo {
            version: 0x0006_0000,
            scope: b"example.test\0",
            company_name: b"A\0\0\0",
            product_id: b"B\0\0\0",
            license_info: licence,
        };
        let mut plain = Vec::new();
        info.encode_checked(&mut Writer::new(&mut plain)).unwrap();
        let sealed = keys.rc4(&plain);
        let step = client
            .step(&new_license_pdu(&sealed, keys.mac(&plain)))
            .unwrap();
        assert_eq!(
            step,
            Step {
                reply: None,
                done: true
            }
        );
        (first, hwid)
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rdp-licensing-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The first connection asks for a licence and stores it; the second
    /// presents it, with the same hardware id, and stores the upgrade.
    #[test]
    fn a_licence_is_requested_stored_and_presented_next_time() {
        let dir = scratch("roundtrip");
        let server = Server::new();

        let mut first = Licensing::new("RDS.example.test", "someone", "client-1", Some(&dir));
        let (kind, hwid_1) = exchange(&mut first, &server, b"licence one");
        assert_eq!(kind, message_type::NEW_LICENSE_REQUEST);
        let store = LicenceStore::new(dir.clone());
        assert_eq!(
            store.load("rds.example.test").as_deref(),
            Some(&b"licence one"[..])
        );

        let mut second = Licensing::new("rds.example.test", "someone", "client-1", Some(&dir));
        let (kind, hwid_2) = exchange(&mut second, &server, b"licence one");
        assert_eq!(kind, message_type::LICENSE_INFO);
        assert_eq!(hwid_1, hwid_2, "a licence is bound to the hardware id");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Without a folder the exchange still runs to the end, and the user and
    /// machine names travel NUL terminated.
    #[test]
    fn without_a_folder_the_exchange_still_completes() {
        let server = Server::new();
        let mut client = Licensing::new("host", "someone", "client-1", None);
        let step = client.step(&server.request()).unwrap();
        let (kind, rest, _) = server.receive(step.reply.as_ref().unwrap());
        assert_eq!(kind, message_type::NEW_LICENSE_REQUEST);
        let mut r = Reader::new(&rest);
        let user = LicenseBinaryBlob::read(&mut r, "test").unwrap();
        let machine = LicenseBinaryBlob::read(&mut r, "test").unwrap();
        assert_eq!(user.blob_type, blob_type::CLIENT_USER_NAME);
        assert_eq!(user.data.as_slice(), b"someone\0");
        assert_eq!(machine.blob_type, blob_type::CLIENT_MACHINE_NAME);
        assert_eq!(machine.data.as_slice(), b"client-1\0");

        let mut client = Licensing::new("host", "someone", "client-1", None);
        exchange(&mut client, &server, b"x");
    }

    /// A server that issues nothing and says "valid client" after the
    /// challenge ends licensing too, which is what a host in its grace
    /// period does.
    #[test]
    fn valid_client_after_the_challenge_ends_licensing() {
        let server = Server::new();
        let mut client = Licensing::new("host", "u", "m", None);
        let step = client.step(&server.request()).unwrap();
        server.receive(&step.reply.unwrap());
        assert_eq!(
            client.step(&valid_client()).unwrap(),
            Step {
                reply: None,
                done: true
            }
        );
    }

    /// A challenge whose MAC does not verify ends the connection rather than
    /// being answered.
    #[test]
    fn a_challenge_with_a_bad_mac_is_refused() {
        let server = Server::new();
        let mut client = Licensing::new("host", "u", "m", None);
        let step = client.step(&server.request()).unwrap();
        let (_, _, keys) = server.receive(&step.reply.unwrap());
        let sealed = keys.rc4(b"challenge");
        let mut mac = keys.mac(b"challenge");
        mac[0] ^= 1;
        let err = client.step(&challenge_pdu(&sealed, mac)).unwrap_err();
        assert!(err.to_string().contains("integrity"), "{err}");
    }

    /// A request this client cannot answer is declined the way every request
    /// was before the exchange existed, so a host in its grace period still
    /// lets the session through.
    #[test]
    fn a_request_without_a_certificate_is_declined_as_before() {
        let server = Server::new();
        let mut pdu = server.request();
        let LicenseMessage::LicenseRequest(request) = &mut pdu.message else {
            unreachable!();
        };
        request.server_certificate.data = Payload::new(&[]);
        let mut client = Licensing::new("host", "u", "m", None);
        let step = client.step(&pdu).unwrap();
        assert_eq!(step.reply, Some(decline().unwrap()));
        assert!(!step.done);
        let declined = LicensePdu::decode(&mut Reader::new(step.reply.as_ref().unwrap())).unwrap();
        assert!(matches!(declined.message, LicenseMessage::ErrorAlert(_)));
        assert!(client.step(&valid_client()).unwrap().done);
    }

    #[test]
    fn messages_out_of_order_are_refused() {
        let server = Server::new();
        let mut client = Licensing::new("host", "u", "m", None);
        let err = client
            .step(&challenge_pdu(&[1, 2, 3], [0; 16]))
            .unwrap_err();
        assert!(err.to_string().contains("PLATFORM_CHALLENGE"), "{err}");
        let mut client = Licensing::new("host", "u", "m", None);
        let err = client.step(&new_license_pdu(&[1], [0; 16])).unwrap_err();
        assert!(err.to_string().contains("NEW_LICENSE"), "{err}");
        let mut client = Licensing::new("host", "u", "m", None);
        client.step(&server.request()).unwrap();
        let err = client.step(&server.request()).unwrap_err();
        assert!(err.to_string().contains("LICENSE_REQUEST"), "{err}");
    }

    #[test]
    fn a_refusal_names_the_error_and_whether_a_stored_licence_was_shown() {
        let dir = scratch("refusal");
        LicenceStore::new(dir.clone()).save("host", b"old").unwrap();
        let server = Server::new();
        let mut client = Licensing::new("host", "u", "m", Some(&dir));
        client.step(&server.request()).unwrap();
        let refused = LicensePdu {
            preamble: valid_client().preamble,
            message: LicenseMessage::ErrorAlert(LicenseErrorMessage {
                error_code: LicenseError::InvalidClient,
                state_transition: LicenseStateTransition::TotalAbort,
                error_info: LicenseBinaryBlob::empty(blob_type::ERROR),
            }),
        };
        let err = client.step(&refused).unwrap_err().to_string();
        assert!(err.contains("stored licence"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn server_names_become_safe_file_names() {
        let store = LicenceStore::new(PathBuf::from("base"));
        let name = |s: &str| {
            store
                .path_for(s)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        };
        assert_eq!(name("RDS01.Example.Test"), "rds01.example.test.licence");
        assert_eq!(name("../../etc/passwd"), "_.._etc_passwd.licence");
        assert_eq!(name("10.0.0.5"), "10.0.0.5.licence");
        assert_eq!(name("fe80::1%eth0"), "fe80__1_eth0.licence");
        assert_eq!(name(""), "_.licence");
        assert_eq!(store.path_for("..").parent(), Some(Path::new("base")));
    }

    #[test]
    fn the_hardware_id_is_created_once_and_kept() {
        let dir = scratch("hwid");
        let store = LicenceStore::new(dir.clone());
        let a = store.hardware_id().unwrap();
        let b = store.hardware_id().unwrap();
        assert_eq!(a, b);
        std::fs::write(dir.join(HARDWARE_ID_FILE), b"short").unwrap();
        let c = store.hardware_id().unwrap();
        assert_ne!(c, a);
        assert_eq!(store.hardware_id().unwrap(), c);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ansi_names_are_nul_terminated_and_ascii() {
        assert_eq!(ansi_z("pc-1"), b"pc-1\0");
        assert_eq!(ansi_z("caf\u{e9}"), b"caf?\0");
    }
}
