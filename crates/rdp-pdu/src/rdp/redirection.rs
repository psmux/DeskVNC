//! Server Redirection, standard and enhanced.
//!
//! MS-RDPBCGR 2.2.13, PRDRDP/13 §4.10.4.
//!
//! One structure, [`ServerRedirectionPacket`], inside two wrappers. The
//! **Standard Redirection PDU** (2.2.13.2) arrives as a Share Control PDU with
//! `PDUTYPE_SERVER_REDIR_PKT`, which
//! [`SharePdu::ServerRedirection`](super::SharePdu::ServerRedirection) already
//! carries whole; read it with [`ServerRedirectionPacket::read_standard`]. The
//! **Enhanced Security Server Redirection PDU** (2.2.13.3) arrives behind a
//! basic security header with `SEC_REDIRECTION_PKT`, which
//! [`SlowPathClass::EnhancedRedirection`](super::SlowPathClass::EnhancedRedirection)
//! already answers for and
//! [`decode_io_pdu`](super::decode_io_pdu) already reads; decode its body with
//! the plain [`Decode`] implementation. That form is the one a TLS or CredSSP
//! session actually sees.
//!
//! Both readings of where the packet starts are on one line each, which is
//! deliberate: `Flags` must be `SEC_REDIRECTION_PKT` (2.2.13.1), and it is
//! checked, so a wrapper that turns out to have one more field or one fewer
//! fails as a single `InvalidField` on `Flags` at offset zero or two rather
//! than as a host name assembled out of the middle of a password. If a real
//! Windows redirection ever fails that way, swap the two entry points and the
//! next byte is right.
//!
//! # Why this decoder is written defensively even by this crate's standards
//!
//! Three properties, all of them PRDRDP/13 §4.10.4's:
//!
//! It is the only PDU in the protocol that carries a **password from server
//! to client**, either in the clear (a broker redirecting over a channel that
//! is already authenticated) or public key encrypted when
//! `LB_PASSWORD_IS_PK_ENCRYPTED` is set. That field is a [`SecretBytes`],
//! which redacts itself in `Debug` and zeroizes on drop, so a `tracing` line
//! that formats a redirection cannot print a credential.
//!
//! It is variable in a way where **one length field lying by a few bytes
//! silently shifts every later field**, and the fields that follow are a host
//! name and a password. So every field is `take`n into a sub reader whose
//! bound is the outer one, and [`MAX_REDIRECTION_FIELD`] caps each.
//!
//! And it **points us at a host the user did not choose**. Nothing here acts
//! on that; deciding whether to follow a redirection is PRDRDP/06's, and this
//! module's job is to make sure the bytes it hands over are the bytes that
//! arrived.
//!
//! # Where the specification is unreliable, and what this file does about it
//!
//! * `TargetCertificate` was documented wrong twice (PRDRDP/11 §5.3 item 7):
//!   a raw X.509 byte array, corrected 2018-05-07 to a Base64 encoded Target
//!   Certificate Container, corrected again 2018-06-04 to add "in Unicode
//!   format". The real wire form is UTF-16LE text of a Base64 string. This
//!   module carries the bytes and interprets none of them, so the erratum
//!   costs it nothing and the session decodes what it needs.
//! * The `Pad` is documented "optional" with no rule for when it is present,
//!   and some Windows versions omit it (PRDRDP/11 §5.3, the unnumbered
//!   redirection note). `Length` bounds the structure, so whatever is left
//!   inside that bound after the last present field is the pad, however long
//!   it turns out to be, and it is discarded rather than required.
//! * The specification gives **no length limits** for the variable length
//!   fields, so every implementation invents its own. Ours is
//!   [`MAX_REDIRECTION_FIELD`] per field and
//!   [`MAX_REDIRECTION_ADDRESSES`] on the address list, and saying so here is
//!   half the requirement.
//! * **The field order after `TsvUrl` is not certain.** PRDRDP/13 §4.10.4's
//!   table puts `TargetNetAddresses` last, after `RedirectionGuid` and
//!   `TargetCertificate`. This module puts it directly after `TsvUrl`,
//!   because the fields of 2.2.13.1 run in ascending `RedirFlags` order
//!   everywhere else in the structure and `LB_TARGET_NET_ADDRESSES` (0x800)
//!   is below `LB_CLIENT_TSV_URL` (0x1000) as well as below the two flags
//!   that were appended later, `LB_REDIRECTION_GUID` (0x8000) and
//!   `LB_TARGET_CERTIFICATE` (0x10000). Only a captured redirection from a
//!   connection broker settles it, and until one exists the two readings
//!   differ solely for a server that sets `LB_TARGET_NET_ADDRESSES` together
//!   with one of the two later flags.

use core::fmt;

use zeroize::Zeroize;

use crate::io::limits::{MAX_REDIRECTION_ADDRESSES, MAX_REDIRECTION_FIELD};
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

use super::security::security_flags;

/// `RDP_SERVER_REDIRECTION_PACKET.RedirFlags` (MS-RDPBCGR 2.2.13.1).
///
/// Eleven of these say a field is present and five say something about the
/// fields that are; [`DATA_FLAGS`] is the first group, which is what the
/// encoder recomputes.
pub mod redir_flags {
    /// `LB_TARGET_NET_ADDRESS`.
    pub const TARGET_NET_ADDRESS: u32 = 0x0000_0001;
    /// `LB_LOAD_BALANCE_INFO`.
    pub const LOAD_BALANCE_INFO: u32 = 0x0000_0002;
    /// `LB_USERNAME`.
    pub const USERNAME: u32 = 0x0000_0004;
    /// `LB_DOMAIN`.
    pub const DOMAIN: u32 = 0x0000_0008;
    /// `LB_PASSWORD`.
    pub const PASSWORD: u32 = 0x0000_0010;
    /// `LB_DONTSTOREUSERNAME`, which carries no field: the user name in this
    /// packet is for this reconnection and must not be saved.
    pub const DONTSTOREUSERNAME: u32 = 0x0000_0020;
    /// `LB_SMARTCARD_LOGON`, no field.
    pub const SMARTCARD_LOGON: u32 = 0x0000_0040;
    /// `LB_NOREDIRECT`, no field: the packet is informational and the client
    /// stays where it is.
    pub const NOREDIRECT: u32 = 0x0000_0080;
    /// `LB_TARGET_FQDN`.
    pub const TARGET_FQDN: u32 = 0x0000_0100;
    /// `LB_TARGET_NETBIOS_NAME`.
    pub const TARGET_NETBIOS_NAME: u32 = 0x0000_0200;
    /// `LB_TARGET_NET_ADDRESSES`.
    pub const TARGET_NET_ADDRESSES: u32 = 0x0000_0800;
    /// `LB_CLIENT_TSV_URL`.
    pub const CLIENT_TSV_URL: u32 = 0x0000_1000;
    /// `LB_SERVER_TSV_CAPABLE`, no field.
    pub const SERVER_TSV_CAPABLE: u32 = 0x0000_2000;
    /// `LB_PASSWORD_IS_PK_ENCRYPTED`, no field: it says how to read the
    /// `Password` that `LB_PASSWORD` brought.
    pub const PASSWORD_IS_PK_ENCRYPTED: u32 = 0x0000_4000;
    /// `LB_REDIRECTION_GUID`.
    pub const REDIRECTION_GUID: u32 = 0x0000_8000;
    /// `LB_TARGET_CERTIFICATE`.
    pub const TARGET_CERTIFICATE: u32 = 0x0001_0000;
}

/// Every flag of [`redir_flags`] that brings a length prefixed field with it.
///
/// The encoder clears these and sets them again from the fields that are
/// actually present, so a packet cannot go out claiming a field it does not
/// carry. The five flags outside this mask are properties of the packet
/// rather than presence bits and are written through unchanged.
pub const DATA_FLAGS: u32 = redir_flags::TARGET_NET_ADDRESS
    | redir_flags::LOAD_BALANCE_INFO
    | redir_flags::USERNAME
    | redir_flags::DOMAIN
    | redir_flags::PASSWORD
    | redir_flags::TARGET_FQDN
    | redir_flags::TARGET_NETBIOS_NAME
    | redir_flags::TARGET_NET_ADDRESSES
    | redir_flags::CLIENT_TSV_URL
    | redir_flags::REDIRECTION_GUID
    | redir_flags::TARGET_CERTIFICATE;

/// `Flags`, `Length`, `SessionID` and `RedirFlags`: the fixed head of the
/// packet, and the smallest a `Length` may legally state.
pub const REDIRECTION_HEADER_LEN: usize = 2 + 2 + 4 + 4;

/// `pad2Octets`, between the Share Control header and the packet in the
/// standard form (MS-RDPBCGR 2.2.13.2).
pub const STANDARD_PAD_LEN: usize = 2;

/// A secret that arrived from a server: redacted in `Debug`, zeroized on
/// drop.
///
/// The byte twin of
/// [`SecretString`](super::client_info::SecretString), which cannot be reused
/// here: a `Password` with `LB_PASSWORD_IS_PK_ENCRYPTED` set is ciphertext
/// and is not text in any encoding, so wrapping a `String` around it would
/// mangle it (PRDRDP/12 §6.4 is the rule, and its two mistakes are a `Debug`
/// format of a PDU and a credential sitting in freed memory for the life of
/// the process).
///
/// This is the one field in the module that is owned rather than borrowed.
/// Zeroizing needs ownership, and a redirection carries one password of a few
/// hundred bytes at most once per session, so the copy is not on any path
/// that matters (D9).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap owned bytes.
    #[must_use]
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self(value.into())
    }

    /// The bytes themselves, for the session that has to use them and for
    /// nothing else.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The length, which is diagnostic where the bytes are not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True for an empty password, which a server may legitimately send.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(redacted, {} bytes)", self.0.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `RDP_SERVER_REDIRECTION_PACKET` (MS-RDPBCGR 2.2.13.1).
///
/// Every optional field is an [`Option`] rather than an empty value, because
/// "the server did not send a domain" and "the server sent an empty domain"
/// mean different things to the reconnection that follows.
///
/// The binary fields are [`Payload`] views into the receive buffer and the
/// text fields are owned `String`s, which is not an inconsistency: a UTF-16LE
/// field has to be transcoded to be a Rust string at all, so there is no
/// borrow to keep, while `LoadBalanceInfo`, `TsvUrl`, `RedirectionGuid` and
/// `TargetCertificate` are handed on as they arrived and are never copied
/// (D9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRedirectionPacket<'a> {
    /// `Flags`, always `SEC_REDIRECTION_PKT`.
    pub flags: u16,
    /// `SessionID`, the session on the target host to reconnect to.
    pub session_id: u32,
    /// The `RedirFlags` bits that are **not** presence bits:
    /// `LB_DONTSTOREUSERNAME`, `LB_SMARTCARD_LOGON`, `LB_NOREDIRECT`,
    /// `LB_SERVER_TSV_CAPABLE` and `LB_PASSWORD_IS_PK_ENCRYPTED`.
    ///
    /// The other eleven bits say which fields are present, and the fields
    /// themselves already say that, so storing them here too would be two
    /// statements of one fact that can disagree. [`Self::redir_flags`] puts
    /// them back together, and it is what goes on the wire.
    pub redir_options: u32,
    /// `TargetNetAddress`, an IP address or host name.
    pub target_net_address: Option<String>,
    /// `LoadBalanceInfo`, opaque bytes echoed back in the `TS_INFO_PACKET` of
    /// the reconnection (MS-RDPBCGR 2.2.1.11.1.1).
    pub load_balance_info: Option<Payload<'a>>,
    /// `UserName`.
    pub username: Option<String>,
    /// `Domain`.
    pub domain: Option<String>,
    /// `Password`, cleartext unless
    /// [`redir_flags::PASSWORD_IS_PK_ENCRYPTED`] is set.
    pub password: Option<SecretBytes>,
    /// `TargetFQDN`.
    pub target_fqdn: Option<String>,
    /// `TargetNetBiosName`.
    pub target_netbios_name: Option<String>,
    /// `TsvUrl`, echoed to a connection broker.
    pub tsv_url: Option<Payload<'a>>,
    /// `TargetNetAddresses` (2.2.13.1.1), one entry per network the target is
    /// reachable on. Empty when the flag was not set.
    pub target_net_addresses: Vec<String>,
    /// `RedirectionGuid`.
    pub redirection_guid: Option<Payload<'a>>,
    /// `TargetCertificate`, UTF-16LE text of a Base64 Target Certificate
    /// Container, carried unread for the reason this module's comment gives.
    pub target_certificate: Option<Payload<'a>>,
}

impl<'a> ServerRedirectionPacket<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDP_SERVER_REDIRECTION_PACKET";

    /// An empty packet for the target host, with no credential and no
    /// session.
    ///
    /// The starting point for the mock server of PRDRDP/09 §3 and for a test
    /// that wants one field set; a real client never builds one.
    #[must_use]
    pub fn new(session_id: u32) -> Self {
        Self {
            flags: security_flags::REDIRECTION_PKT,
            session_id,
            redir_options: 0,
            target_net_address: None,
            load_balance_info: None,
            username: None,
            domain: None,
            password: None,
            target_fqdn: None,
            target_netbios_name: None,
            tsv_url: None,
            target_net_addresses: Vec::new(),
            redirection_guid: None,
            target_certificate: None,
        }
    }

    /// True when `LB_NOREDIRECT` says to stay put (MS-RDPBCGR 2.2.13.1).
    ///
    /// A packet with this bit set still carries its fields, and following it
    /// anyway is how a client ends up connecting somewhere it was told not
    /// to.
    #[must_use]
    pub const fn is_no_redirect(&self) -> bool {
        self.redir_options & redir_flags::NOREDIRECT != 0
    }

    /// True when the `Password` is public key encrypted rather than
    /// cleartext (`LB_PASSWORD_IS_PK_ENCRYPTED`).
    #[must_use]
    pub const fn password_is_encrypted(&self) -> bool {
        self.redir_options & redir_flags::PASSWORD_IS_PK_ENCRYPTED != 0
    }

    /// `RedirFlags` as the wire carries it: [`Self::redir_options`] with a
    /// presence bit set for every field that is actually there.
    ///
    /// Derived rather than stored, so a packet cannot claim a field it does
    /// not carry, which is the mistake that shifts every later field by four
    /// bytes on the far side.
    #[must_use]
    pub fn redir_flags(&self) -> u32 {
        let mut flags = self.redir_options & !DATA_FLAGS;
        let present = [
            (
                self.target_net_address.is_some(),
                redir_flags::TARGET_NET_ADDRESS,
            ),
            (
                self.load_balance_info.is_some(),
                redir_flags::LOAD_BALANCE_INFO,
            ),
            (self.username.is_some(), redir_flags::USERNAME),
            (self.domain.is_some(), redir_flags::DOMAIN),
            (self.password.is_some(), redir_flags::PASSWORD),
            (self.target_fqdn.is_some(), redir_flags::TARGET_FQDN),
            (
                self.target_netbios_name.is_some(),
                redir_flags::TARGET_NETBIOS_NAME,
            ),
            (self.tsv_url.is_some(), redir_flags::CLIENT_TSV_URL),
            (
                !self.target_net_addresses.is_empty(),
                redir_flags::TARGET_NET_ADDRESSES,
            ),
            (
                self.redirection_guid.is_some(),
                redir_flags::REDIRECTION_GUID,
            ),
            (
                self.target_certificate.is_some(),
                redir_flags::TARGET_CERTIFICATE,
            ),
        ];
        for (is_present, flag) in present {
            if is_present {
                flags |= flag;
            }
        }
        flags
    }

    /// Read the packet out of a Standard Redirection PDU's body
    /// (MS-RDPBCGR 2.2.13.2).
    ///
    /// The body is what
    /// [`SharePdu::ServerRedirection`](super::SharePdu::ServerRedirection)
    /// carries, and 2.2.13.2 puts `pad2Octets` between the Share Control
    /// header and the packet, so those two bytes are skipped first.
    ///
    /// If a real Windows redirection ever fails here, this is the line to
    /// suspect: the failure is an `InvalidField` on `Flags` at offset two,
    /// which is exactly what a `pad2Octets` that is not there would produce.
    pub fn read_standard(r: &mut Reader<'a>) -> PduResult<Self> {
        r.skip(STANDARD_PAD_LEN, Self::NAME)?;
        Self::decode(r)
    }
}

/// Read one `u32` length prefixed field into a sub reader, capped.
fn take_field<'a>(r: &mut Reader<'a>, field: &'static str) -> PduResult<Reader<'a>> {
    // A `u32` that does not fit a `usize` is a target narrower than the
    // field, and saturating is right there: the value is certainly past the
    // cap, so `ensure_cap` reports it by name on the next line.
    let declared = usize::try_from(r.u32(ServerRedirectionPacket::NAME)?).unwrap_or(usize::MAX);
    r.ensure_cap(
        declared,
        MAX_REDIRECTION_FIELD,
        "MAX_REDIRECTION_FIELD",
        field,
    )?;
    r.take(declared, field)
}

/// Read a length prefixed UTF-16LE field, present only when `flag` is set.
fn read_text(
    r: &mut Reader<'_>,
    flags: u32,
    flag: u32,
    field: &'static str,
) -> PduResult<Option<String>> {
    if flags & flag == 0 {
        return Ok(None);
    }
    let mut body = take_field(r, field)?;
    let len = body.remaining();
    Ok(Some(body.utf16_len(len, field)?))
}

/// Read a length prefixed binary field, present only when `flag` is set.
fn read_blob<'a>(
    r: &mut Reader<'a>,
    flags: u32,
    flag: u32,
    field: &'static str,
) -> PduResult<Option<Payload<'a>>> {
    if flags & flag == 0 {
        return Ok(None);
    }
    let mut body = take_field(r, field)?;
    Ok(Some(Payload::new(body.rest())))
}

/// The encoded length of a UTF-16LE field: the string, its mandatory
/// terminator, and the `u32` that counts them.
fn text_field_size(value: &str) -> usize {
    4 + value.encode_utf16().count() * 2 + 2
}

/// Write a length prefixed UTF-16LE field, terminator included in the length,
/// which is how every string in this packet is laid out.
fn write_text(w: &mut Writer<'_>, value: &str) -> PduResult<()> {
    let bytes = value.encode_utf16().count() * 2 + 2;
    let bytes = u32::try_from(bytes).map_err(|_| PduError::Encode {
        context: ServerRedirectionPacket::NAME,
        reason: "string longer than its u32 length prefix",
    })?;
    w.u32(bytes);
    for unit in value.encode_utf16() {
        w.u16(unit);
    }
    w.u16(0);
    Ok(())
}

/// Write a length prefixed binary field.
fn write_blob(w: &mut Writer<'_>, value: &[u8]) -> PduResult<()> {
    let len = u32::try_from(value.len()).map_err(|_| PduError::Encode {
        context: ServerRedirectionPacket::NAME,
        reason: "field longer than its u32 length prefix",
    })?;
    w.u32(len);
    w.bytes(value);
    Ok(())
}

/// The encoded length of the `TARGET_NET_ADDRESSES` structure alone, without
/// the `u32` that prefixes it (MS-RDPBCGR 2.2.13.1.1).
fn addresses_body_size(addresses: &[String]) -> usize {
    4 + addresses.iter().map(|a| text_field_size(a)).sum::<usize>()
}

impl Encode for ServerRedirectionPacket<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        let mut size = REDIRECTION_HEADER_LEN;
        for text in [
            self.target_net_address.as_ref(),
            self.username.as_ref(),
            self.domain.as_ref(),
            self.target_fqdn.as_ref(),
            self.target_netbios_name.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            size += text_field_size(text);
        }
        for blob in [
            self.load_balance_info.as_ref(),
            self.tsv_url.as_ref(),
            self.redirection_guid.as_ref(),
            self.target_certificate.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            size += 4 + blob.len();
        }
        if let Some(password) = self.password.as_ref() {
            size += 4 + password.len();
        }
        if !self.target_net_addresses.is_empty() {
            size += 4 + addresses_body_size(&self.target_net_addresses);
        }
        size
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let length = u16::try_from(self.size()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "packet longer than its u16 Length field",
        })?;
        w.u16(self.flags);
        w.u16(length);
        w.u32(self.session_id);
        w.u32(self.redir_flags());

        if let Some(value) = &self.target_net_address {
            write_text(w, value)?;
        }
        if let Some(value) = &self.load_balance_info {
            write_blob(w, value.as_slice())?;
        }
        if let Some(value) = &self.username {
            write_text(w, value)?;
        }
        if let Some(value) = &self.domain {
            write_text(w, value)?;
        }
        if let Some(value) = &self.password {
            write_blob(w, value.expose())?;
        }
        if let Some(value) = &self.target_fqdn {
            write_text(w, value)?;
        }
        if let Some(value) = &self.target_netbios_name {
            write_text(w, value)?;
        }
        if let Some(value) = &self.tsv_url {
            write_blob(w, value.as_slice())?;
        }
        if !self.target_net_addresses.is_empty() {
            let body =
                u32::try_from(addresses_body_size(&self.target_net_addresses)).map_err(|_| {
                    PduError::Encode {
                        context: Self::NAME,
                        reason: "address list longer than its u32 length prefix",
                    }
                })?;
            w.u32(body);
            let count =
                u32::try_from(self.target_net_addresses.len()).map_err(|_| PduError::Encode {
                    context: Self::NAME,
                    reason: "more addresses than addressCount can hold",
                })?;
            w.u32(count);
            for address in &self.target_net_addresses {
                write_text(w, address)?;
            }
        }
        if let Some(value) = &self.redirection_guid {
            write_blob(w, value.as_slice())?;
        }
        if let Some(value) = &self.target_certificate {
            write_blob(w, value.as_slice())?;
        }
        // No `Pad`: it is optional and the length already ended the
        // structure.
        Ok(())
    }
}

impl<'a> Decode<'a> for ServerRedirectionPacket<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let flags = r.u16(Self::NAME)?;
        if flags != security_flags::REDIRECTION_PKT {
            // 2.2.13.1 requires `SEC_REDIRECTION_PKT` here in both forms.
            // Checking it is what turns a packet read at the wrong offset
            // into one error naming one field, instead of a host name
            // assembled out of the middle of a password.
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "Flags",
                value: u64::from(flags),
                offset: at,
            });
        }
        let at = r.offset();
        let length = usize::from(r.u16(Self::NAME)?);
        if length < REDIRECTION_HEADER_LEN {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "Length",
                value: length as u64,
                offset: at,
            });
        }
        // `Length` covers the whole structure, this four byte head included,
        // so the sub reader bounds every field that follows to what the
        // server declared, and the outer reader advances past all of it
        // whatever the field lengths inside claim (PRDRDP/13 §2.5).
        let mut body = r.take(length - 4, Self::NAME)?;

        let session_id = body.u32(Self::NAME)?;
        let f = body.u32(Self::NAME)?;

        let packet = Self {
            flags,
            session_id,
            // Only the bits that are not presence bits; the eleven that are
            // become the `Option`s below.
            redir_options: f & !DATA_FLAGS,
            target_net_address: read_text(
                &mut body,
                f,
                redir_flags::TARGET_NET_ADDRESS,
                "TargetNetAddress",
            )?,
            load_balance_info: read_blob(
                &mut body,
                f,
                redir_flags::LOAD_BALANCE_INFO,
                "LoadBalanceInfo",
            )?,
            username: read_text(&mut body, f, redir_flags::USERNAME, "UserName")?,
            domain: read_text(&mut body, f, redir_flags::DOMAIN, "Domain")?,
            password: read_password(&mut body, f)?,
            target_fqdn: read_text(&mut body, f, redir_flags::TARGET_FQDN, "TargetFQDN")?,
            target_netbios_name: read_text(
                &mut body,
                f,
                redir_flags::TARGET_NETBIOS_NAME,
                "TargetNetBiosName",
            )?,
            tsv_url: read_blob(&mut body, f, redir_flags::CLIENT_TSV_URL, "TsvUrl")?,
            target_net_addresses: read_addresses(&mut body, f)?,
            redirection_guid: read_blob(
                &mut body,
                f,
                redir_flags::REDIRECTION_GUID,
                "RedirectionGuid",
            )?,
            target_certificate: read_blob(
                &mut body,
                f,
                redir_flags::TARGET_CERTIFICATE,
                "TargetCertificate",
            )?,
        };

        if !body.is_empty() {
            // The `Pad`, whose presence the specification does not state a
            // rule for. Discarded rather than required or rejected.
            tracing::trace!(
                pad = body.remaining(),
                "trailing bytes in a server redirection, taken as the Pad"
            );
        }
        Ok(packet)
    }
}

/// Read the `Password`, which is the one field that is copied, because
/// zeroizing needs ownership.
fn read_password(r: &mut Reader<'_>, flags: u32) -> PduResult<Option<SecretBytes>> {
    if flags & redir_flags::PASSWORD == 0 {
        return Ok(None);
    }
    let mut body = take_field(r, "Password")?;
    Ok(Some(SecretBytes::new(body.rest().to_vec())))
}

/// Read `TARGET_NET_ADDRESSES` (MS-RDPBCGR 2.2.13.1.1): a count, then that
/// many length prefixed UTF-16LE addresses.
fn read_addresses(r: &mut Reader<'_>, flags: u32) -> PduResult<Vec<String>> {
    if flags & redir_flags::TARGET_NET_ADDRESSES == 0 {
        return Ok(Vec::new());
    }
    let mut body = take_field(r, "TargetNetAddresses")?;
    let count = usize::try_from(body.u32("TARGET_NET_ADDRESSES")?).unwrap_or(usize::MAX);
    body.ensure_cap(
        count,
        MAX_REDIRECTION_ADDRESSES,
        "MAX_REDIRECTION_ADDRESSES",
        "TARGET_NET_ADDRESSES",
    )?;
    // `count` is past the cap check, so this reserves at most
    // `MAX_REDIRECTION_ADDRESSES` entries whatever the server claimed.
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        let mut address = take_field(&mut body, "TARGET_NET_ADDRESS")?;
        let len = address.remaining();
        addresses.push(address.utf16_len(len, "TARGET_NET_ADDRESS")?);
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    fn full_packet() -> ServerRedirectionPacket<'static> {
        ServerRedirectionPacket {
            flags: security_flags::REDIRECTION_PKT,
            session_id: 0x0000_0003,
            redir_options: redir_flags::DONTSTOREUSERNAME
                | redir_flags::PASSWORD_IS_PK_ENCRYPTED
                | redir_flags::SERVER_TSV_CAPABLE,
            target_net_address: Some("10.0.0.7".to_owned()),
            load_balance_info: Some(Payload::new(b"tsv://MS Terminal Services Plugin.1.farm")),
            username: Some("alice".to_owned()),
            domain: Some("EXAMPLE".to_owned()),
            password: Some(SecretBytes::new(vec![0xde, 0xad, 0xbe, 0xef])),
            target_fqdn: Some("host.example.test".to_owned()),
            target_netbios_name: Some("HOST".to_owned()),
            tsv_url: Some(Payload::new(b"/tsv/url")),
            target_net_addresses: vec!["10.0.0.7".to_owned(), "fe80::1".to_owned()],
            redirection_guid: Some(Payload::new(&[0x11; 16])),
            target_certificate: Some(Payload::new(b"MIIB")),
        }
    }

    /// Every field present, out and back.
    #[test]
    fn a_packet_with_every_field_round_trips() {
        let packet = full_packet();
        let bytes = encode(&packet);
        let back = ServerRedirectionPacket::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back, packet);
        assert!(back.password_is_encrypted());
        assert!(!back.is_no_redirect());
        assert_eq!(
            back.password.as_ref().unwrap().expose(),
            &[0xde, 0xad, 0xbe, 0xef]
        );
    }

    /// The empty packet, which is the other end of the range: no flags, no
    /// fields, twelve bytes.
    ///
    /// `Flags` is `SEC_REDIRECTION_PKT` 0x0400, little endian `00 04`.
    /// `Length` is 2 + 2 + 4 + 4 = 12, so `0c 00`. `SessionID` 3 is
    /// `03 00 00 00` and `RedirFlags` is `00 00 00 00`.
    #[test]
    fn an_empty_packet_is_the_twelve_bytes_the_header_states() {
        let packet = ServerRedirectionPacket::new(3);
        let bytes = encode(&packet);
        assert_eq!(bytes.len(), REDIRECTION_HEADER_LEN);
        assert_eq!(
            bytes,
            [0x00, 0x04, 0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            ServerRedirectionPacket::decode(&mut Reader::new(&bytes)).unwrap(),
            packet
        );
    }

    /// One field, computed by hand, so the length prefix convention is
    /// pinned rather than merely self consistent.
    ///
    /// `TargetNetAddress` is "A", one UTF-16 unit plus the mandatory
    /// terminator, so the field is four bytes and
    /// `TargetNetAddressLength` is `04 00 00 00`. `Length` is the twelve byte
    /// head plus four for that prefix plus four of string, which is twenty.
    /// `RedirFlags` is `LB_TARGET_NET_ADDRESS` 0x00000001.
    #[test]
    fn one_text_field_is_the_bytes_the_arithmetic_predicts() {
        let mut packet = ServerRedirectionPacket::new(0);
        packet.target_net_address = Some("A".to_owned());
        let bytes = encode(&packet);
        assert_eq!(bytes.len(), 12 + 4 + 4);
        assert_eq!(bytes.len(), 20);
        assert_eq!(
            bytes,
            [
                0x00, 0x04, // Flags
                0x14, 0x00, // Length = 20
                0x00, 0x00, 0x00, 0x00, // SessionID
                0x01, 0x00, 0x00, 0x00, // RedirFlags = LB_TARGET_NET_ADDRESS
                0x04, 0x00, 0x00, 0x00, // TargetNetAddressLength = 4
                b'A', 0x00, 0x00, 0x00, // "A\0" in UTF-16LE
            ]
        );
        assert_eq!(
            ServerRedirectionPacket::decode(&mut Reader::new(&bytes)).unwrap(),
            packet
        );
    }

    /// The presence bits are the fields, so a packet cannot claim one it does
    /// not carry.
    #[test]
    fn the_presence_flags_are_recomputed_from_the_fields() {
        let mut packet = ServerRedirectionPacket::new(0);
        // A caller sets every data flag by hand and supplies nothing.
        packet.redir_options = DATA_FLAGS | redir_flags::NOREDIRECT;
        assert_eq!(packet.redir_flags(), redir_flags::NOREDIRECT);
        let bytes = encode(&packet);
        let back = ServerRedirectionPacket::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back.redir_options, redir_flags::NOREDIRECT);
        assert!(back.is_no_redirect());
        assert_eq!(back.target_net_address, None);

        // And a field whose flag nobody set still goes out flagged.
        let mut packet = ServerRedirectionPacket::new(0);
        packet.username = Some("bob".to_owned());
        assert_eq!(packet.redir_flags(), redir_flags::USERNAME);
        assert_eq!(packet.redir_options, 0);
    }

    /// The three properties PRDRDP/13 §4.10.4 asks for, on the one field that
    /// is a credential.
    #[test]
    fn the_password_is_redacted_zeroized_and_never_borrowed() {
        let secret = SecretBytes::new(vec![b's', b'e', b'c', b'r', b'e', b't']);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretBytes(redacted, 6 bytes)");
        assert!(!rendered.contains("secret"));
        assert_eq!(secret.len(), 6);
        assert!(!secret.is_empty());
        assert!(SecretBytes::default().is_empty());

        // A whole packet formats without leaking it either, which is the
        // mistake that actually happens.
        let rendered = format!("{:?}", full_packet());
        assert!(rendered.contains("SecretBytes(redacted"));
        // 0xde 0xad 0xbe 0xef is how a `Vec<u8>` would have printed it.
        assert!(!rendered.contains("222, 173, 190, 239"));

        // Zeroizing needs ownership, so the field is a `Vec` where every
        // other blob is a borrowed view.
        let mut owned = SecretBytes::new(vec![1, 2, 3]);
        owned.0.zeroize();
        assert!(owned.expose().is_empty(), "the buffer survived zeroizing");
    }

    /// The address list of 2.2.13.1.1, and the cap that bounds its `Vec`.
    #[test]
    fn the_address_list_round_trips_and_is_capped() {
        let mut packet = ServerRedirectionPacket::new(0);
        packet.target_net_addresses = vec!["a".to_owned(), "bb".to_owned(), String::new()];
        let bytes = encode(&packet);
        let back = ServerRedirectionPacket::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back.target_net_addresses, packet.target_net_addresses);
        assert_eq!(
            back.redir_flags() & redir_flags::TARGET_NET_ADDRESSES,
            redir_flags::TARGET_NET_ADDRESSES
        );

        // A count larger than the cap is refused by name, and never
        // allocated. Twelve bytes of head, then `TargetNetAddressesLength`,
        // then `addressCount` at offset sixteen.
        let mut hostile = bytes.clone();
        let count_at = 16;
        hostile[count_at..count_at + 4].copy_from_slice(&0xffff_ffff_u32.to_le_bytes());
        assert!(matches!(
            ServerRedirectionPacket::decode(&mut Reader::new(&hostile)).unwrap_err(),
            PduError::CapExceeded {
                limit_name: "MAX_REDIRECTION_ADDRESSES",
                ..
            }
        ));
    }

    /// A length that lies is the failure this decoder is written against: it
    /// must be an error, never a field assembled out of the next one.
    #[test]
    fn a_field_length_that_lies_is_refused_rather_than_believed() {
        let mut packet = ServerRedirectionPacket::new(0);
        packet.username = Some("alice".to_owned());
        packet.password = Some(SecretBytes::new(vec![0xaa; 8]));
        let bytes = encode(&packet);

        // `UserNameLength` claims the rest of the packet and more.
        let mut hostile = bytes.clone();
        hostile[12..16].copy_from_slice(&0xffff_u32.to_le_bytes());
        assert!(matches!(
            ServerRedirectionPacket::decode(&mut Reader::new(&hostile)).unwrap_err(),
            PduError::Truncated { .. }
        ));

        // And one past the cap names the constant rather than the number.
        let mut hostile = bytes.clone();
        hostile[12..16].copy_from_slice(&(MAX_REDIRECTION_FIELD as u32 + 1).to_le_bytes());
        assert!(matches!(
            ServerRedirectionPacket::decode(&mut Reader::new(&hostile)).unwrap_err(),
            PduError::CapExceeded {
                limit_name: "MAX_REDIRECTION_FIELD",
                ..
            }
        ));
    }

    /// `Length` bounds the structure, so a field cannot reach past it into
    /// whatever followed the PDU in the frame.
    #[test]
    fn a_field_cannot_read_past_the_declared_length() {
        let mut packet = ServerRedirectionPacket::new(0);
        packet.username = Some("alice".to_owned());
        let mut bytes = encode(&packet);
        let declared = u16::from_le_bytes([bytes[2], bytes[3]]);
        // Shrink `Length` by two: the user name field now runs past the end
        // of the structure the server declared.
        bytes[2..4].copy_from_slice(&(declared - 2).to_le_bytes());
        // Trailing bytes that a decoder ignoring `Length` would swallow.
        bytes.extend_from_slice(&[0xff; 16]);
        assert!(matches!(
            ServerRedirectionPacket::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::Truncated { .. }
        ));
    }

    /// The `Pad` is optional and its rule is unstated, so trailing bytes
    /// inside `Length` are discarded rather than rejected (PRDRDP/11 §5.3).
    #[test]
    fn a_trailing_pad_is_discarded_rather_than_rejected() {
        let packet = ServerRedirectionPacket::new(9);
        let mut bytes = encode(&packet);
        for pad in 1..=8usize {
            let mut padded = bytes.clone();
            padded.extend(std::iter::repeat_n(0u8, pad));
            let length = u16::try_from(padded.len()).unwrap();
            padded[2..4].copy_from_slice(&length.to_le_bytes());
            let back = ServerRedirectionPacket::decode(&mut Reader::new(&padded)).unwrap();
            assert_eq!(back.session_id, 9);
        }
        // And a packet with no pad at all decodes the same way, which is the
        // half of the rule Windows sometimes takes.
        bytes.truncate(REDIRECTION_HEADER_LEN);
        assert_eq!(
            ServerRedirectionPacket::decode(&mut Reader::new(&bytes))
                .unwrap()
                .session_id,
            9
        );
    }

    #[test]
    fn a_packet_without_sec_redirection_pkt_is_refused() {
        let mut bytes = encode(&ServerRedirectionPacket::new(0));
        bytes[0] = 0x00;
        bytes[1] = 0x00;
        assert!(matches!(
            ServerRedirectionPacket::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::InvalidField { field: "Flags", .. }
        ));
    }

    #[test]
    fn a_length_below_its_own_header_is_refused() {
        let mut bytes = encode(&ServerRedirectionPacket::new(0));
        bytes[2] = 0x0b;
        assert!(matches!(
            ServerRedirectionPacket::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::InvalidField {
                field: "Length",
                ..
            }
        ));
    }

    /// The standard form's two byte `pad2Octets` (MS-RDPBCGR 2.2.13.2).
    #[test]
    fn the_standard_form_skips_its_pad_and_the_enhanced_form_does_not() {
        let packet = full_packet();
        let mut body = vec![0x00, 0x00];
        body.extend_from_slice(&encode(&packet));
        assert_eq!(
            ServerRedirectionPacket::read_standard(&mut Reader::new(&body)).unwrap(),
            packet
        );
        // The enhanced form starts at `Flags`, so reading it as the standard
        // form fails on the field the pad displaced, which is the diagnostic
        // the doc comment promises.
        assert!(matches!(
            ServerRedirectionPacket::read_standard(&mut Reader::new(&encode(&packet))).unwrap_err(),
            PduError::InvalidField { field: "Flags", .. }
        ));
    }

    #[test]
    fn every_prefix_errors_rather_than_panicking() {
        let bytes = encode(&full_packet());
        for cut in 0..bytes.len() {
            assert!(
                ServerRedirectionPacket::decode(&mut Reader::new(&bytes[..cut])).is_err(),
                "a {cut} byte prefix decoded"
            );
        }
        let mut standard = vec![0x00, 0x00];
        standard.extend_from_slice(&bytes);
        for cut in 0..standard.len() {
            let _ = ServerRedirectionPacket::read_standard(&mut Reader::new(&standard[..cut]));
        }
    }

    /// Every single flag on its own, so no field's presence depends on
    /// another's.
    #[test]
    fn each_field_can_be_the_only_one_present() {
        let template = full_packet();
        let cases: Vec<ServerRedirectionPacket<'_>> = vec![
            ServerRedirectionPacket {
                target_net_address: template.target_net_address.clone(),
                ..ServerRedirectionPacket::new(1)
            },
            ServerRedirectionPacket {
                load_balance_info: template.load_balance_info,
                ..ServerRedirectionPacket::new(1)
            },
            ServerRedirectionPacket {
                username: template.username.clone(),
                ..ServerRedirectionPacket::new(1)
            },
            ServerRedirectionPacket {
                domain: template.domain.clone(),
                ..ServerRedirectionPacket::new(1)
            },
            ServerRedirectionPacket {
                password: Some(SecretBytes::new(vec![0xde, 0xad, 0xbe, 0xef])),
                ..ServerRedirectionPacket::new(1)
            },
            ServerRedirectionPacket {
                target_fqdn: template.target_fqdn.clone(),
                ..ServerRedirectionPacket::new(1)
            },
            ServerRedirectionPacket {
                target_netbios_name: template.target_netbios_name.clone(),
                ..ServerRedirectionPacket::new(1)
            },
            ServerRedirectionPacket {
                tsv_url: template.tsv_url,
                ..ServerRedirectionPacket::new(1)
            },
            ServerRedirectionPacket {
                target_net_addresses: template.target_net_addresses.clone(),
                ..ServerRedirectionPacket::new(1)
            },
            ServerRedirectionPacket {
                redirection_guid: template.redirection_guid,
                ..ServerRedirectionPacket::new(1)
            },
            ServerRedirectionPacket {
                target_certificate: template.target_certificate,
                ..ServerRedirectionPacket::new(1)
            },
        ];
        assert_eq!(cases.len(), DATA_FLAGS.count_ones() as usize);
        for case in &cases {
            let bytes = encode(case);
            assert_eq!(
                &ServerRedirectionPacket::decode(&mut Reader::new(&bytes)).unwrap(),
                case
            );
            assert_eq!(case.redir_flags().count_ones(), 1);
        }
    }
}
