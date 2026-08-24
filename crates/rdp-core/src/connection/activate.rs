//! Phases 6 to 10: Client Info, licensing, capability exchange and connection
//! finalisation (MS-RDPBCGR 2.2.1.11 to 2.2.1.22, PRDRDP/03 §2.7 to §2.11).
//!
//! Everything here travels inside an MCS Send Data Request or Indication on
//! the I/O channel, which is what [`send_data_request`] and [`ServerData`]
//! wrap and unwrap. The bodies are `rdp-pdu`'s; the sequencing is this file's.
//!
//! # Which security header a PDU carries, and how we know
//!
//! MS-RDPBCGR 2.2.8.1.1.2 puts a four byte basic security header on six
//! classes of slow path PDU and on nothing else, and PRDRDP/13 §5.2 tabulates
//! it. `rdp_pdu::rdp::decode_io_pdu` therefore takes the class as a parameter
//! rather than working it out, because it cannot be worked out by looking: the
//! first two bytes of a Share Control PDU are a `totalLength` and the first
//! two bytes of a Client Info PDU are a flag word, and a Demand Active of 128
//! bytes begins with the same two bytes as `SEC_INFO_PKT`.
//!
//! So the class comes from two things we know and the server does not choose:
//!
//! * **The channel.** Connect time auto detect (2.2.14.1.1), the heartbeat
//!   (2.2.16.1) and the Server Initiate Multitransport Request (2.2.15.1) all
//!   arrive on the MCS message channel when one was allocated. Anything on the
//!   message channel therefore has a security header, and its flags word says
//!   which class it is, unambiguously.
//! * **The phase.** On the I/O channel, everything between the Client Info PDU
//!   and the Demand Active is a licensing PDU (2.2.1.12) and carries
//!   `SEC_LICENSE_PKT`; everything from the Demand Active onwards is a Share
//!   Control PDU and carries no header at all. During the licensing phase a
//!   Share Control header is recognised rather than assumed away, by
//!   [`looks_like_share_control`], so a server that skips licensing entirely
//!   and goes straight to the Demand Active is read correctly instead of
//!   losing four bytes to a header that is not there.
//!
//! The phase half of that is the rule FreeRDP's connection state machine
//! applies, and it is the reason `decode_io_pdu` is shaped the way it is.

use std::time::Duration;

use bytes::Bytes;
use rdp_pdu::io::{Decode, Encode, Payload, Writer};
use rdp_pdu::mcs::DomainMcsPdu;
use rdp_pdu::rdp::capabilities::{
    capability_set_type, ClientCapabilitySupport, InputCapabilitySet,
};
use rdp_pdu::rdp::client_info::{address_family, ExtendedInfoPacket, InfoPacket, SecretString};
use rdp_pdu::rdp::security::security_flags;
use rdp_pdu::rdp::{
    decode_io_pdu, CapabilitySet, CapabilitySets, ClientInfoPdu, ConfirmActivePdu, ControlPdu,
    FontListPdu, IoPdu, IoPduContext, LicenseMessage, LicensePdu, SharePdu, SlowPathClass,
    SynchronizePdu,
};
use rdp_pdu::{codes, x224, Reader};
use remote_core::{Credentials, SessionEvent};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::connection::mcs::ChannelMap;
use crate::error::{ConnectStage, RdpError, Result};
use crate::options::ResolvedOptions;
use crate::transport::framer::{Framed, FramedKind, Framer};
use crate::transport::with_timeout;

/// How long the whole of phases 6 to 10 may take (PRDRDP/03 §3.3).
///
/// Deliberately longer than the dial budget: a cold domain logon spends twenty
/// to thirty seconds between the Client Info PDU and the Font Map with nothing
/// wrong, because the server is building a user profile while we wait.
pub const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(90);

/// `TS_EXTENDED_INFO_PACKET.clientDir`, the path every Windows client sends
/// (MS-RDPBCGR 2.2.1.11.1.1.1). Servers log it and nothing reads it.
const CLIENT_DIR: &str = r"C:\Windows\System32\mstscax.dll";

/// What the capability exchange and the finalisation settled on.
///
/// Everything the connected pump needs from the connection sequence and
/// nothing it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activated {
    /// `shareId` from the Demand Active, echoed by every Share Data PDU
    /// afterwards. A server that sees a different value answers
    /// `ERRINFO_CONFIRMACTIVEWRONGSHAREID` (MS-RDPBCGR 2.2.1.13.1.1).
    pub share_id: u32,
    /// The Demand Active's `PDUSource`, which is what a Synchronize PDU's
    /// `targetUser` has to name (MS-RDPBCGR 2.2.1.14.1).
    pub server_pdu_source: u16,
    /// The desktop size the server chose, from its Bitmap capability set
    /// (MS-RDPBCGR 2.2.7.1.2). Not necessarily the size we asked for.
    pub desktop: (u16, u16),
    /// The server's `TS_INPUT_CAPABILITYSET.inputFlags`
    /// (MS-RDPBCGR 2.2.7.1.6), which gates the horizontal wheel and the
    /// extended pointer buttons on the input path (PRDRDP/05 §3.3, §3.4).
    pub server_input_flags: u16,
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

/// Wrap one already encoded slow path PDU in an MCS Send Data Request, an
/// X.224 Data TPDU and a TPKT header (MS-RDPBCGR 2.2.1.13.2.1).
///
/// Public because the connected pump sends the same shape: this is the one
/// place that decides how a client PDU is addressed, so a Refresh Rect and a
/// Client Info PDU cannot disagree about it.
///
/// # Errors
///
/// [`RdpError::Pdu`] when the body is longer than the MCS length field can
/// carry.
pub fn send_data_request(user_channel_id: u16, channel_id: u16, body: &[u8]) -> Result<Bytes> {
    let pdu = DomainMcsPdu::SendDataRequest {
        initiator: user_channel_id,
        channel_id,
        payload: Payload::new(body),
    };
    let mut out = Vec::with_capacity(pdu.size() + x224::TPKT_HEADER_LEN + 3);
    x224::write_data_tpdu_with(&mut Writer::new(&mut out), pdu.size(), |w| pdu.encode(w))?;
    Ok(Bytes::from(out))
}

/// One Send Data Indication, unwrapped.
///
/// The payload is an owned view of the same buffer rather than a copy:
/// `Payload::to_bytes` is `Bytes::slice_ref`, which is a refcount bump
/// (PRDRDP/12 §4.2).
#[derive(Debug, Clone)]
pub struct ServerData {
    /// The channel it arrived on.
    pub channel_id: u16,
    /// The slow path PDU, still wrapped in whatever security header its class
    /// carries.
    pub payload: Bytes,
}

/// Unwrap one TPKT frame into the Send Data Indication it carries.
///
/// # Errors
///
/// [`RdpError::ServerDisconnect`] for an MCS Disconnect Provider Ultimatum,
/// which means the session is over rather than that the server sent the wrong
/// PDU, and [`RdpError::Protocol`] for any other domain PDU, which a server
/// has no business sending here.
pub fn read_send_data_indication(frame: &Bytes) -> Result<ServerData> {
    let mut r = Reader::new(frame);
    let mut body = x224::read_data_tpdu(&mut r)?;
    match DomainMcsPdu::decode(&mut body)? {
        DomainMcsPdu::SendDataIndication {
            channel_id,
            payload,
            ..
        } => Ok(ServerData {
            channel_id,
            payload: payload.to_bytes(frame),
        }),
        DomainMcsPdu::DisconnectProviderUltimatum { reason } => Err(RdpError::ServerDisconnect {
            user_requested: reason == rdp_pdu::mcs::disconnect_reason::USER_REQUESTED,
        }),
        other => Err(RdpError::Protocol(format!(
            "the server sent MCS choice {} during the connection sequence \
             (MS-RDPBCGR 2.2.1.13.3.1)",
            other.choice_index()
        ))),
    }
}

/// Which phase of the sequence we are in, which is half of what decides
/// whether a PDU on the I/O channel carries a security header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Between the Client Info PDU and the Demand Active.
    Licensing,
    /// From the Demand Active onwards.
    Sharing,
}

/// The first two bytes read as `TS_SECURITY_HEADER.flags`, or `None` when the
/// PDU is too short to have one.
fn peek_security_flags(payload: &[u8]) -> Option<u16> {
    let two = payload.get(..2)?;
    Some(u16::from_le_bytes([two[0], two[1]]))
}

/// True when the payload begins with a `TS_SHARECONTROLHEADER` and therefore
/// carries no security header (MS-RDPBCGR 2.2.8.1.1.1.1).
///
/// Two fields have to agree for this to be true, and together they cannot be
/// mistaken for a security header. `totalLength` describes the PDU exactly,
/// including its own six bytes, so it equals the whole Send Data payload. And
/// the twelve high bits of `pduType` are `TS_PROTOCOL_VERSION`, `0x0010`,
/// while the same two bytes of a security header are `flagsHi`, which
/// MS-RDPBCGR 2.2.8.1.1.2.1 reserves and requires to be zero. So a licensing
/// PDU can never satisfy the second condition however long it is, which is
/// what makes this safe to use as the discriminator during the licensing phase
/// rather than only the `SEC_LICENSE_PKT` flag that FreeRDP checks.
fn looks_like_share_control(payload: &[u8]) -> bool {
    use rdp_pdu::rdp::share::TS_PROTOCOL_VERSION;
    let Some(total_length) = peek_security_flags(payload) else {
        return false;
    };
    let Some(two) = payload.get(2..4) else {
        return false;
    };
    let pdu_type = u16::from_le_bytes([two[0], two[1]]);
    usize::from(total_length) == payload.len() && pdu_type & 0xfff0 == TS_PROTOCOL_VERSION
}

/// Which [`SlowPathClass`] a PDU belongs to, decided from the channel it
/// arrived on and the phase we are in. See this module's documentation for why
/// it is decided that way and not by looking at the bytes.
fn classify(channel_id: u16, channels: &ChannelMap, phase: Phase, payload: &[u8]) -> SlowPathClass {
    let flags = peek_security_flags(payload).unwrap_or(0);
    let has = |flag: u16| flags & flag != 0;

    if channels.message_channel_id == Some(channel_id) {
        // Everything the message channel carries has a basic security header,
        // so its flags word is the class and there is nothing to guess at
        // (MS-RDPBCGR 2.2.1.4.5).
        if has(security_flags::AUTODETECT_REQ) {
            return SlowPathClass::AutoDetectRequest;
        }
        if has(security_flags::HEARTBEAT) {
            return SlowPathClass::Heartbeat;
        }
        if has(security_flags::TRANSPORT_REQ) {
            return SlowPathClass::MultitransportRequest;
        }
        if has(security_flags::LICENSE_PKT) {
            return SlowPathClass::Licensing;
        }
        return SlowPathClass::Other;
    }

    match phase {
        // A Share Control PDU is recognised rather than assumed away, so a
        // server that sends no licensing PDU at all and goes straight to the
        // Demand Active does not lose four bytes to a header that is not
        // there. Anything else in this phase is licensing, and a licensing PDU
        // without `SEC_LICENSE_PKT` fails to decode naming the flags, which is
        // a much clearer report than the truncation it would otherwise be.
        Phase::Licensing if !looks_like_share_control(payload) => SlowPathClass::Licensing,
        _ => SlowPathClass::Other,
    }
}

/// Read one TPKT frame, parking any fast path update that overtakes the
/// sequence.
///
/// A server is allowed to start drawing before the Font Map arrives, and a
/// pointer or bitmap update that reaches us here belongs to the connected pump
/// rather than to the bin. `pending` carries them across.
async fn next_tpkt<S: AsyncRead + Unpin>(
    framer: &mut Framer<S>,
    stage: ConnectStage,
    pending: &mut Vec<Framed>,
) -> Result<Bytes> {
    loop {
        let framed = with_timeout(stage, ACTIVATION_TIMEOUT, framer.read()).await?;
        match framed.kind {
            FramedKind::Tpkt => return Ok(framed.frame),
            FramedKind::FastPath => {
                tracing::debug!(
                    %stage,
                    len = framed.frame.len(),
                    "a fast path update arrived before the sequence finished; keeping it"
                );
                pending.push(framed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 6: the Client Info PDU
// ---------------------------------------------------------------------------

/// Build the Client Info PDU (MS-RDPBCGR 2.2.1.11, PRDRDP/03 §2.7).
///
/// Under CredSSP the credentials here are redundant with the ones already
/// sent, and they are still sent: Windows uses them for single sign on into
/// the session, and without `INFO_AUTOLOGON` the session lands on a
/// "press Ctrl+Alt+Del" screen rather than on the desktop.
///
/// Three fields are honestly wrong and say so here rather than in a bug
/// report. `clientAddress` is `0.0.0.0` because nothing in this crate's
/// dependency set reads the local address of a socket we have already given
/// away to the framer, and the field is a diagnostic a server logs.
/// `clientTimeZone` is UTC with no daylight rule, because reading the host's
/// zone needs a dependency this crate does not have; the consequence is that
/// the remote session's clock is UTC unless the server overrides it.
/// `clientDir` is the fixed string every client sends.
#[must_use]
pub fn client_info(
    opts: &ResolvedOptions,
    creds: &Credentials,
    arc: Option<rdp_pdu::rdp::client_info::ArcClientPrivatePacket>,
) -> ClientInfoPdu {
    use rdp_pdu::rdp::client_info::info_flags;

    let username = creds
        .username
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .unwrap_or_default();
    let (user, domain) = crate::connection::nla::logon_identity(username, creds, opts);
    let password = creds.password.clone().unwrap_or_default();

    // `INFO_AUTOLOGON` belongs on a PDU that carries a full credential and on
    // no other, which is why `InfoPacket::DEFAULT_FLAGS` leaves it out: a
    // server told to log the user on automatically with an empty password
    // answers with a logon failure rather than with its own logon screen.
    let mut flags = InfoPacket::DEFAULT_FLAGS;
    if !user.is_empty() && !password.is_empty() {
        flags |= info_flags::AUTOLOGON;
    }

    ClientInfoPdu {
        info: InfoPacket {
            code_page: 0,
            flags,
            domain,
            user_name: user,
            password: SecretString::new(password),
            alternate_shell: String::new(),
            working_dir: String::new(),
            extra_info: Some(ExtendedInfoPacket {
                client_address_family: address_family::INET,
                client_address: "0.0.0.0".to_owned(),
                client_dir: CLIENT_DIR.to_owned(),
                client_time_zone: rdp_pdu::rdp::client_info::TimeZoneInfo::default(),
                client_session_id: 0,
                performance_flags: opts.performance_flags(),
                // MS-RDPBCGR 2.2.1.11.1.1.1: `cbAutoReconnectCookie` is zero
                // or 0x1C, and the cookie sits immediately after
                // `performanceFlags`, which is why the encoder writes the two
                // together or neither.
                auto_reconnect_cookie: arc,
                dynamic_dst_time_zone_key_name: None,
                dynamic_daylight_time_disabled: None,
            }),
        },
    }
}

// ---------------------------------------------------------------------------
// Phase 9: what we confirm
// ---------------------------------------------------------------------------

/// The capability sets this client confirms (MS-RDPBCGR 2.2.1.13.2.1,
/// PRDRDP/04 §8.2 chooses them and PRDRDP/13 §4.8 encodes them).
///
/// `nodeId` in the Share capability set is zero, which is what
/// MS-RDPBCGR 2.2.7.2.4 asks a client for; the server puts its own channel id
/// there.
///
/// **The Surface Commands set is left out, and wiring up EGFX did not change
/// that.** The two are easy to confuse and they are different negotiations.
/// `CAPSETTYPE_SURFACE_COMMANDS` (MS-RDPBCGR 2.2.7.2.9) governs the *legacy*
/// Surface Bits command on the fast path, `TS_SURFCMD_SET_SURF_BITS`
/// (MS-RDPBCGR 2.2.9.2.1), which this build still does not decode: the pump's
/// `FastPathUpdate::SurfaceCommands` arm refuses one
/// (`crate::session::run_loop`). The graphics pipeline is negotiated
/// somewhere else entirely, on the `drdynvc` channel with its own capability
/// advertisement (MS-RDPEGFX 2.2.2.18, [`crate::channels::egfx`]), and having
/// it does not make a Surface Bits command decodable.
///
/// So the rule PRDRDP/04 §9.3 states is unchanged: the codec allow list is
/// enforced at negotiation and not only at dispatch, and asking for pixels we
/// would then throw away is the thing it forbids. Absence is the
/// specification's way of saying "not supported"; a set with `cmdFlags = 0` is
/// read by some servers as a client that supports the frame marker, which is
/// why [`ClientCapabilitySupport::surface_commands`] removes the set rather
/// than zeroing it.
#[must_use]
pub fn client_capabilities(opts: &ResolvedOptions, desktop: (u16, u16)) -> CapabilitySets<'static> {
    let (width, height) = desktop;
    CapabilitySets::client(
        width,
        height,
        0,
        // The keyboard fields echo `TS_UD_CS_CORE` exactly. A server that sees
        // two different layouts uses the Client Core Data one and logs the
        // disagreement, which is a support call nobody can explain.
        // 4 is `IBM_101_102_KEYS` and 12 function keys is the usual pair.
        InputCapabilitySet::client(opts.keyboard_layout, 4, 0, 12),
        ClientCapabilitySupport::minimal()
            // Desktop composition is an aero glass effect, and enabling it
            // costs bandwidth for a translucency the user cannot interact
            // with (PRDRDP/04 §9.2 turns it on only for the High preset).
            .with_desktop_composition(matches!(opts.quality, remote_core::QualityPreset::High)),
    )
}

// ---------------------------------------------------------------------------
// The sequence
// ---------------------------------------------------------------------------

/// What the Demand Active settled, read out of the PDU
/// (MS-RDPBCGR 2.2.1.13.1.1).
#[must_use]
pub fn activated_from(
    demand: &rdp_pdu::rdp::DemandActivePdu<'_>,
    pdu_source: u16,
    fallback_desktop: (u16, u16),
) -> Activated {
    let desktop = demand
        .capabilities
        .bitmap()
        .map(|b| (b.desktop_width, b.desktop_height))
        .filter(|(w, h)| *w != 0 && *h != 0)
        .unwrap_or(fallback_desktop);
    let server_input_flags = match demand.capabilities.find(capability_set_type::INPUT) {
        Some(CapabilitySet::Input(set)) => set.input_flags,
        _ => 0,
    };
    Activated {
        share_id: demand.share_id,
        server_pdu_source: pdu_source,
        desktop,
        server_input_flags,
    }
}

/// Everything the client sends in answer to a Demand Active, in one write: the
/// Confirm Active PDU and then the four finalisation PDUs
/// (MS-RDPBCGR 2.2.1.13.2, 2.2.1.14 to 2.2.1.18).
///
/// One write and not five, because MS-RDPBCGR 1.3.1.1 lets the client send all
/// of them without waiting for any of the server's four and every real client
/// does: it saves four round trips, which on a link with 100 ms of latency is
/// most of the time between the Demand Active and the first frame.
///
/// Public because the capability exchange can recur. MS-RDPBCGR 1.3.1.3 lets a
/// server send a Deactivate All at any time and restart it, typically after a
/// resolution change, so the connected pump answers the next Demand Active
/// with exactly these bytes rather than with a second implementation
/// (PRDRDP/03 §2.10, PRDRDP/06 §6.1).
///
/// # Errors
///
/// [`RdpError::Pdu`] when a capability set or the MCS wrapper cannot be
/// encoded, which the sizes above make impossible.
pub fn activation_reply(
    opts: &ResolvedOptions,
    channels: &ChannelMap,
    activated: &Activated,
) -> Result<Bytes> {
    use rdp_pdu::rdp::ShareDataPdu;

    let mut out = Vec::new();
    let confirm = SharePdu::ConfirmActive {
        pdu_source: channels.user_channel_id,
        pdu: Box::new(ConfirmActivePdu::new(
            activated.share_id,
            client_capabilities(opts, activated.desktop),
        )),
    };
    push_share(&mut out, channels, &confirm)?;

    for pdu in [
        // `targetUser` is the server's own `PDUSource` from the Demand Active,
        // which is what MS-RDPBCGR 2.2.1.14.1 means by "the MCS channel of the
        // peer being synchronised with".
        ShareDataPdu::Synchronize(SynchronizePdu::client(activated.server_pdu_source)),
        ShareDataPdu::Control(ControlPdu::cooperate()),
        ShareDataPdu::Control(ControlPdu::request_control()),
        // The Persistent Key List (2.2.1.17) is optional and we keep no
        // persistent bitmap cache, so there is nothing to list.
        ShareDataPdu::FontList(FontListPdu::client()),
    ] {
        push_share(
            &mut out,
            channels,
            &SharePdu::data(channels.user_channel_id, activated.share_id, pdu),
        )?;
    }
    Ok(Bytes::from(out))
}

/// Encode one Share Control PDU, wrap it for the I/O channel and append it.
fn push_share(out: &mut Vec<u8>, channels: &ChannelMap, share: &SharePdu<'_>) -> Result<()> {
    let mut body = Vec::with_capacity(share.size());
    share.encode_checked(&mut Writer::new(&mut body))?;
    out.extend_from_slice(&send_data_request(
        channels.user_channel_id,
        channels.io_channel_id,
        &body,
    )?);
    Ok(())
}

/// Phases 6 to 10, from the Client Info PDU to the Font Map.
///
/// The connection is up when the Font Map arrives (MS-RDPBCGR 2.2.1.22).
///
/// # Errors
///
/// [`RdpError::Protocol`] when the server refused the licensing exchange or
/// sent a PDU no phase of the sequence allows, [`RdpError::ServerError`] when
/// it sent a Set Error Info PDU, [`RdpError::Pdu`] when anything did not
/// parse, and [`RdpError::Timeout`] against the stage that was waiting.
#[allow(clippy::too_many_arguments)]
pub async fn activate<S: AsyncRead + AsyncWrite + Unpin>(
    framer: &mut Framer<S>,
    opts: &ResolvedOptions,
    creds: &Credentials,
    channels: &ChannelMap,
    arc: Option<rdp_pdu::rdp::client_info::ArcClientPrivatePacket>,
    events: &mpsc::Sender<SessionEvent>,
    pending: &mut Vec<Framed>,
) -> Result<Activated> {
    // Phase 6. The credentials go out here even under CredSSP, because that is
    // what single sign on into the session is (PRDRDP/03 §2.7).
    let info = client_info(opts, creds, arc);
    let mut body = Vec::with_capacity(info.size());
    info.encode_checked(&mut Writer::new(&mut body))?;
    tracing::debug!(stage = %ConnectStage::SendClientInfo, "sending the client info pdu");
    let frame = send_data_request(channels.user_channel_id, channels.io_channel_id, &body)?;
    framer.write_pdu(&frame).await?;
    // The password is out of our hands the moment it is on the wire. The copy
    // in the encode buffer is not, so it does not outlive this statement.
    body.clear();
    drop(info);

    // Phases 7 to 10 in one loop, because the specification lets licensing,
    // connect time auto detect and the multitransport request interleave, the
    // Demand Active ends all three, and the finalisation PDUs come back in
    // whatever order the server likes (MS-RDPBCGR 1.3.1.1).
    let context = IoPduContext::external_security();
    let mut phase = Phase::Licensing;
    let mut activated: Option<Activated> = None;
    let started = std::time::Instant::now();

    loop {
        if started.elapsed() > ACTIVATION_TIMEOUT {
            return Err(RdpError::Timeout {
                stage: stage_of(phase, activated.is_some()),
            });
        }
        let frame = next_tpkt(framer, stage_of(phase, activated.is_some()), pending).await?;
        let data = read_send_data_indication(&frame)?;
        if !channels.knows(data.channel_id) {
            return Err(RdpError::Protocol(format!(
                "data arrived on channel {}, which we never joined \
                 (MS-RDPBCGR 2.2.1.13.3.1)",
                data.channel_id
            )));
        }

        let class = classify(data.channel_id, channels, phase, &data.payload);
        let mut r = Reader::new(&data.payload);
        // Nothing is written from inside this match, so a decode that borrows
        // the frame cannot be alive across an await.
        let mut reply: Option<Bytes> = None;
        let mut done = false;

        let decoded = decode_io_pdu(&mut r, context, class).inspect_err(|e| {
            tracing::error!(
                error = %e,
                body = %crate::connection::mcs::hex_dump(&data.payload),
                "an i/o channel pdu did not parse during activation"
            );
        })?;
        match decoded {
            IoPdu::License(license) => {
                if let Some(bytes) = licensing_step(&license)? {
                    reply = Some(send_data_request(
                        channels.user_channel_id,
                        channels.io_channel_id,
                        &bytes,
                    )?);
                }
                // Licensing is over the moment the server says the client is
                // valid; anything after that on the I/O channel is a Share
                // Control PDU, which is what the Demand Active is.
                if license.is_valid_client() {
                    tracing::debug!("licensing complete: no licence required");
                    phase = Phase::Sharing;
                }
            }
            IoPdu::AutoDetect(_) => {
                // MS-RDPBCGR 2.2.14 is optional and best effort: a server that
                // gets no response uses its own default for the connection
                // type hint. Answering needs the round trip measurement of
                // PRDRDP/05 §6.1, which is not written, so the phase is named
                // in the trace rather than answered wrongly.
                tracing::debug!(
                    stage = %ConnectStage::ConnectTimeAutoDetect,
                    "connect time auto detect is not answered in this build"
                );
            }
            IoPdu::Heartbeat(_) => {
                tracing::trace!("a heartbeat arrived during the connection sequence");
            }
            IoPdu::Other { header, body }
                if header.basic().flags & security_flags::REDIRECTION_PKT != 0 =>
            {
                // The Enhanced Security Server Redirection PDU
                // (MS-RDPBCGR 2.2.13.3): the same packet as the standard form
                // with a basic security header in front of it instead of a
                // Share Control header, which is why the plain `Decode` is
                // the right one here and `read_standard` is not
                // (`docs/RDP_SPEC_NOTES.md` §1.5 records that both offsets
                // are inferred).
                return Err(redirection(body.as_slice()));
            }
            IoPdu::Other { header, .. } => {
                // The Server Initiate Multitransport Request is the only class
                // that reaches here in practice. We sent a Client Multitransport
                // Channel Data block with `flags = 0`, which says we want
                // neither UDP transport (PRDRDP/03 §2.9), so a conforming
                // server does not send one and an unconforming one is refused
                // by silence: the TCP connection is unaffected either way.
                tracing::debug!(
                    stage = %ConnectStage::MultitransportBootstrap,
                    flags = header.basic().flags,
                    "a multitransport request is refused by silence"
                );
            }
            IoPdu::Share(share) => {
                phase = Phase::Sharing;
                match share.as_ref() {
                    SharePdu::DemandActive { pdu_source, pdu } => {
                        let settled = activated_from(pdu, *pdu_source, opts.desktop);
                        tracing::info!(
                            share_id = settled.share_id,
                            source = %pdu.source_descriptor_lossy(),
                            width = settled.desktop.0,
                            height = settled.desktop.1,
                            sets = pdu.capabilities.sets.len(),
                            "demand active"
                        );
                        reply = Some(activation_reply(opts, channels, &settled)?);
                        activated = Some(settled);
                    }
                    // A Deactivate All before the first Demand Active is a
                    // server that changed its mind about the session; the next
                    // Demand Active restarts the exchange and this loop is
                    // already waiting for it.
                    SharePdu::DeactivateAll { .. } => {
                        tracing::debug!("a deactivate all arrived during the capability exchange");
                        activated = None;
                    }
                    SharePdu::Data { pdu, .. } => {
                        error_info(pdu)?;
                        if matches!(pdu, rdp_pdu::rdp::ShareDataPdu::FontMap(_)) {
                            done = activated.is_some();
                        } else {
                            tracing::trace!(pdu_type2 = pdu.pdu_type2(), "finalisation pdu");
                        }
                    }
                    // A broker redirects immediately after licensing, before
                    // the share exists (MS-RDPBCGR 1.3.8). The attempt is
                    // over and the session dials the target instead.
                    SharePdu::ServerRedirection { body, .. } => {
                        return Err(redirection_standard(body.as_slice()));
                    }
                    SharePdu::FlowControl => {}
                    other => {
                        return Err(RdpError::Protocol(format!(
                            "the server sent {other:?} during the capability exchange \
                             (MS-RDPBCGR 2.2.1.13)"
                        )))
                    }
                }
            }
        }

        if let Some(bytes) = reply {
            framer.write_pdu(&bytes).await?;
        }
        if done {
            let settled = activated.expect("`done` is only set once the demand active arrived");
            tracing::info!("font map received: the connection is up");
            // The size the server chose, not the size we asked for. The UI
            // sizes its canvas from this and the graphics path clips to it.
            remote_core::emit(
                events,
                SessionEvent::DesktopResize {
                    width: settled.desktop.0,
                    height: settled.desktop.1,
                },
            )
            .await?;
            return Ok(settled);
        }
    }
}

/// Turn an Enhanced Security Server Redirection PDU body into the error the
/// session acts on (MS-RDPBCGR 2.2.13.3).
///
/// The redirection travels as an error because the connection sequence is
/// straight line `await` code: there is no share, no pump and nothing for
/// this function to return. `crate::session::connect` catches it and the next
/// attempt dials the target. A packet we will not follow (`LB_NOREDIRECT`, or
/// a target that is not a plausible host) becomes a `Protocol` error naming
/// the phase rather than a silent stall, because the sequence has nowhere to
/// carry on to either way.
fn redirection(body: &[u8]) -> RdpError {
    match rdp_pdu::rdp::ServerRedirectionPacket::decode(&mut Reader::new(body)) {
        Ok(packet) => redirection_from(&packet),
        Err(e) => RdpError::from(e),
    }
}

/// The same for the Standard Redirection PDU (MS-RDPBCGR 2.2.13.2), whose
/// body begins with the `pad2Octets` [`ServerRedirectionPacket::read_standard`]
/// skips.
fn redirection_standard(body: &[u8]) -> RdpError {
    match rdp_pdu::rdp::ServerRedirectionPacket::read_standard(&mut Reader::new(body)) {
        Ok(packet) => redirection_from(&packet),
        Err(e) => RdpError::from(e),
    }
}

fn redirection_from(packet: &rdp_pdu::rdp::ServerRedirectionPacket<'_>) -> RdpError {
    match crate::session::redirect::Redirection::from_packet(packet) {
        Some(redirect) => RdpError::Redirected(Box::new(redirect)),
        None => RdpError::Protocol(
            "the server ended the connection sequence with a redirection this client will \
             not follow (MS-RDPBCGR 2.2.13.1)"
                .to_owned(),
        ),
    }
}

/// The stage a timeout or a log line is reported against.
const fn stage_of(phase: Phase, activated: bool) -> ConnectStage {
    match (phase, activated) {
        (Phase::Licensing, _) => ConnectStage::Licensing,
        (Phase::Sharing, false) => ConnectStage::CapabilitiesExchange,
        (Phase::Sharing, true) => ConnectStage::ConnectionFinalization,
    }
}

/// What to do about one licensing PDU (MS-RDPBCGR 2.2.1.12, MS-RDPELE 2.2.2,
/// PRDRDP/03 §2.8).
///
/// Returns the body to send back, or `None` when there is nothing to say.
///
/// # Errors
///
/// [`RdpError::Protocol`] naming licensing for a message this build cannot
/// complete, and for an error alert that is not `STATUS_VALID_CLIENT`.
fn licensing_step(license: &LicensePdu<'_>) -> Result<Option<Vec<u8>>> {
    match &license.message {
        LicenseMessage::ErrorAlert(error) => {
            if error.is_valid_client() {
                return Ok(None);
            }
            Err(RdpError::Protocol(format!(
                "the server refused the licensing exchange: {} ({})",
                error.error_code.describe(),
                error.state_transition.symbol()
            )))
        }
        // MS-RDPELE 2.2.2.1. Completing a real licence exchange needs the
        // platform challenge, the hardware id, and somewhere to store the
        // granted licence so it is not requested again on every connect, none
        // of which exists yet (PRDRDP/03 §2.8). Declining cleanly with an
        // `ERROR_ALERT` is what gets us past a Windows host in per user
        // licensing mode whose licence server is unreachable, which answers
        // `STATUS_VALID_CLIENT` next.
        LicenseMessage::LicenseRequest(_) => {
            tracing::info!("declining the licence exchange (MS-RDPELE 2.2.2.3 is not implemented)");
            let alert = LicensePdu::client_error_alert();
            let mut out = Vec::with_capacity(alert.size());
            alert.encode_checked(&mut Writer::new(&mut out))?;
            Ok(Some(out))
        }
        LicenseMessage::Unimplemented { msg_type, .. } => Err(RdpError::Protocol(format!(
            "that computer requires a Remote Desktop Services client access licence, \
             which this client cannot obtain yet (licensing message 0x{msg_type:02x}, \
             MS-RDPELE 2.2.2)"
        ))),
    }
}

/// Turn a Set Error Info PDU into the error it announces
/// (MS-RDPBCGR 2.2.5.1.1).
///
/// `ERRINFO_NONE` is not an error: a server sends it to clear a previous code.
pub fn error_info(pdu: &rdp_pdu::rdp::ShareDataPdu<'_>) -> Result<()> {
    let rdp_pdu::rdp::ShareDataPdu::SetErrorInfo(info) = pdu else {
        return Ok(());
    };
    if info.error_info == codes::ErrInfo::None {
        return Ok(());
    }
    Err(RdpError::ServerError {
        code: info.error_info.to_u32(),
        symbol: info.error_info.symbol().to_owned(),
        message: info.error_info.describe().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_core::{ConnectOptions, QualityPreset};

    fn resolved() -> ResolvedOptions {
        let c = ConnectOptions::rdp("host.example", 3389);
        let rdp = c.rdp_options().expect("rdp").clone();
        ResolvedOptions::resolve(&c, &rdp, &mut Vec::new()).expect("valid")
    }

    fn channels() -> ChannelMap {
        ChannelMap {
            io_channel_id: 1003,
            user_channel_id: 1007,
            message_channel_id: Some(1005),
            statics: vec![("drdynvc", 1010)],
        }
    }

    /// `INFO_AUTOLOGON` is the difference between landing on the desktop and
    /// landing on a "press Ctrl+Alt+Del" screen, and it must go out only with
    /// a credential behind it: a server told to log a user on automatically
    /// with an empty password answers with a logon failure rather than with
    /// its own logon screen.
    #[test]
    fn autologon_is_set_only_when_there_is_a_full_credential() {
        use rdp_pdu::rdp::client_info::info_flags;
        let opts = resolved();

        let anonymous = client_info(&opts, &Credentials::default(), None);
        assert_eq!(anonymous.info.flags & info_flags::AUTOLOGON, 0);
        assert_ne!(anonymous.info.flags & info_flags::UNICODE, 0);

        let full = client_info(&opts, &Credentials::user_pass("CORP\\alice", "pw"), None);
        assert_ne!(full.info.flags & info_flags::AUTOLOGON, 0);
        assert_eq!(full.info.user_name, "alice");
        assert_eq!(full.info.domain, "CORP");
        assert_eq!(full.info.password.expose(), "pw");
    }

    /// The Client Info PDU and the CredSSP identity have to name the same
    /// logon, or the credentials the server checks are not the ones we proved
    /// possession of. One function decides for both.
    #[test]
    fn the_client_info_logon_matches_the_credssp_one() {
        let mut opts = resolved();
        opts.domain = Some("PROFILE".into());
        let creds = Credentials::user_pass("alice", "pw");
        let info = client_info(&opts, &creds, None);
        assert_eq!(info.info.user_name, "alice");
        assert_eq!(
            (info.info.user_name.clone(), info.info.domain.clone()),
            crate::connection::nla::logon_identity("alice", &creds, &opts)
        );
    }

    /// The performance flags are the whole of the quality preset on the legacy
    /// path, so a preset that changes nothing on the wire is not a preset.
    #[test]
    fn the_quality_preset_reaches_the_extended_info_packet() {
        use rdp_pdu::rdp::client_info::performance_flags as p;
        let mut opts = resolved();
        opts.quality = QualityPreset::Low;
        let info = client_info(&opts, &Credentials::default(), None);
        let extra = info.info.extra_info.expect("an extended info packet");
        assert_ne!(extra.performance_flags & p::DISABLE_WALLPAPER, 0);
        assert_eq!(extra.client_address_family, address_family::INET);
        assert!(extra.client_dir.contains("mstscax"));
    }

    /// The class of a slow path PDU is decided by the channel and the phase,
    /// never by the shape of the bytes. This is the table in this module's
    /// documentation, stated as a test, because getting it wrong reads four
    /// bytes of a Demand Active as a security header and produces a session
    /// that dies two seconds in with an unintelligible error.
    #[test]
    fn the_security_header_rule_follows_the_channel_and_the_phase() {
        let channels = channels();
        // `SEC_LICENSE_PKT` is 0x0080, so its two little endian bytes are
        // 80 00, and `flagsHi` after it is the reserved zero word.
        let licensing = [0x80u8, 0x00, 0x00, 0x00, 0xff, 0x03, 0x04, 0x00];
        // A Demand Active of eight bytes: `totalLength` 8, then `pduType`
        // 0x0011, which is `TS_PROTOCOL_VERSION | PDUTYPE_DEMANDACTIVEPDU`.
        let demand = [0x08u8, 0x00, 0x11, 0x00, 0xea, 0x03, 0x00, 0x00];
        // The collision the length alone cannot resolve: 0x0080 is both
        // `SEC_LICENSE_PKT` and a plausible `totalLength` of 128. The version
        // bits are what tells them apart.
        let mut awkward = vec![0x80u8, 0x00, 0x00, 0x00];
        awkward.resize(128, 0);

        assert_eq!(
            classify(1003, &channels, Phase::Licensing, &licensing),
            SlowPathClass::Licensing
        );
        assert_eq!(
            classify(1003, &channels, Phase::Licensing, &demand),
            SlowPathClass::Other,
            "a server that skips licensing must not lose four bytes to a header"
        );
        assert_eq!(
            classify(1003, &channels, Phase::Licensing, &awkward),
            SlowPathClass::Licensing,
            "flagsHi is a reserved zero, so this is a security header and not a share control one"
        );
        assert_eq!(
            classify(1003, &channels, Phase::Sharing, &licensing),
            SlowPathClass::Other,
            "after the demand active the I/O channel carries share pdus only"
        );

        // `SEC_AUTODETECT_REQ` is 0x1000 and `SEC_HEARTBEAT` is 0x4000.
        assert_eq!(
            classify(1005, &channels, Phase::Sharing, &[0x00, 0x10, 0, 0]),
            SlowPathClass::AutoDetectRequest
        );
        assert_eq!(
            classify(1005, &channels, Phase::Sharing, &[0x00, 0x40, 0, 0]),
            SlowPathClass::Heartbeat
        );
        assert_eq!(
            classify(1005, &channels, Phase::Sharing, &[0x02, 0x00, 0, 0]),
            SlowPathClass::MultitransportRequest
        );
        // A truncated payload has no flags to read and must not panic.
        assert_eq!(
            classify(1005, &channels, Phase::Sharing, &[0x00]),
            SlowPathClass::Other
        );
        assert_eq!(
            classify(1003, &channels, Phase::Licensing, &[]),
            SlowPathClass::Licensing
        );
    }

    /// The only licensing answer phase 1 completes on, and the two it refuses
    /// with a sentence rather than with a number (PRDRDP/03 §2.8).
    #[test]
    fn licensing_accepts_a_valid_client_and_declines_a_real_exchange() {
        use rdp_pdu::rdp::license::{blob_type, LicenseBinaryBlob, LicenseErrorMessage};
        use rdp_pdu::rdp::LicensePreamble;

        let valid = LicensePdu {
            preamble: LicensePreamble {
                msg_type: rdp_pdu::rdp::license::message_type::ERROR_ALERT,
                flags: rdp_pdu::rdp::license::preamble_flags::VERSION_3_0,
                msg_size: 20,
            },
            message: LicenseMessage::ErrorAlert(LicenseErrorMessage {
                error_code: codes::LicenseError::StatusValidClient,
                state_transition: codes::LicenseStateTransition::NoTransition,
                error_info: LicenseBinaryBlob::empty(blob_type::ANY),
            }),
        };
        assert!(licensing_step(&valid).expect("valid client").is_none());

        let refused = LicensePdu {
            preamble: valid.preamble,
            message: LicenseMessage::ErrorAlert(LicenseErrorMessage {
                error_code: codes::LicenseError::NoLicenseServer,
                state_transition: codes::LicenseStateTransition::TotalAbort,
                error_info: LicenseBinaryBlob::empty(blob_type::ANY),
            }),
        };
        let err = licensing_step(&refused).expect_err("no licence server");
        assert!(err.to_string().contains("licence server"), "{err}");

        let unimplemented = LicensePdu {
            preamble: valid.preamble,
            message: LicenseMessage::Unimplemented {
                msg_type: rdp_pdu::rdp::license::message_type::PLATFORM_CHALLENGE,
                body: Payload::new(&[]),
            },
        };
        let err = licensing_step(&unimplemented).expect_err("platform challenge");
        assert!(err.to_string().contains("licence"), "{err}");
    }

    /// A Set Error Info PDU is the server saying why the session is about to
    /// end, and it has to reach the user as a sentence with the code beside
    /// it. `ERRINFO_NONE` is a server clearing a previous code and is not an
    /// error.
    #[test]
    fn a_set_error_info_pdu_becomes_a_named_server_error() {
        use rdp_pdu::rdp::control::SetErrorInfoPdu;
        use rdp_pdu::rdp::ShareDataPdu;

        assert!(error_info(&ShareDataPdu::SetErrorInfo(SetErrorInfoPdu {
            error_info: codes::ErrInfo::None,
        }))
        .is_ok());

        let err = error_info(&ShareDataPdu::SetErrorInfo(SetErrorInfoPdu {
            error_info: codes::ErrInfo::LogoffByUser,
        }))
        .expect_err("a logoff");
        match err {
            RdpError::ServerError { code, symbol, .. } => {
                assert_eq!(code, codes::ErrInfo::LogoffByUser.to_u32());
                assert_eq!(symbol, "ERRINFO_LOGOFF_BY_USER");
            }
            other => panic!("expected a server error, got {other:?}"),
        }
    }

    /// A client PDU is addressed from our user channel to the I/O channel, and
    /// it comes back off the wire as the same thing. One function decides how,
    /// so a Refresh Rect and a Client Info PDU cannot disagree.
    #[test]
    fn a_client_pdu_round_trips_through_the_mcs_wrapper() {
        let frame = send_data_request(1007, 1003, b"body").expect("encodes");
        // The wrapper is symmetric enough to read back with the server side
        // reader, which is what the mock does with what we send.
        let mut r = Reader::new(&frame);
        let mut body = x224::read_data_tpdu(&mut r).expect("a data tpdu");
        match DomainMcsPdu::decode(&mut body).expect("parses") {
            DomainMcsPdu::SendDataRequest {
                initiator,
                channel_id,
                payload,
            } => {
                assert_eq!(initiator, 1007);
                assert_eq!(channel_id, 1003);
                assert_eq!(payload.as_slice(), b"body");
            }
            other => panic!("expected a send data request, got {other:?}"),
        }
    }

    /// An ultimatum during the sequence means the session is over, not that
    /// the server sent the wrong PDU. Reporting it as a protocol violation
    /// would put a red banner on a server that is merely busy.
    #[test]
    fn an_ultimatum_during_the_sequence_is_a_disconnect() {
        let pdu = DomainMcsPdu::DisconnectProviderUltimatum {
            reason: rdp_pdu::mcs::disconnect_reason::USER_REQUESTED,
        };
        let mut out = Vec::new();
        x224::write_data_tpdu_with(&mut Writer::new(&mut out), pdu.size(), |w| pdu.encode(w))
            .expect("encodes");
        let err = read_send_data_indication(&Bytes::from(out)).expect_err("a disconnect");
        assert!(matches!(
            err,
            RdpError::ServerDisconnect {
                user_requested: true
            }
        ));
    }

    /// Every set we confirm has to be one the server can parse, and the
    /// keyboard layout has to match what `TS_UD_CS_CORE` already said.
    #[test]
    fn the_confirmed_capabilities_echo_the_client_core_data() {
        let opts = resolved();
        let sets = client_capabilities(&opts, (1920, 1080));
        let Some(CapabilitySet::Input(input)) = sets.find(capability_set_type::INPUT) else {
            panic!("an input capability set");
        };
        assert_eq!(input.keyboard_layout, opts.keyboard_layout);
        let bitmap = sets.bitmap().expect("a bitmap capability set");
        assert_eq!((bitmap.desktop_width, bitmap.desktop_height), (1920, 1080));

        let mut out = Vec::new();
        sets.encode(&mut Writer::new(&mut out)).expect("encodes");
        assert_eq!(out.len(), sets.size(), "size() disagrees with encode()");
    }

    /// A capability we advertise is a capability the server will use, and a
    /// server drawing with Surface Bits commands into a client that decodes
    /// Bitmap Updates paints nothing at all (PRDRDP/04 §9.3).
    #[test]
    fn the_surface_commands_set_is_not_advertised() {
        let sets = client_capabilities(&resolved(), (1024, 768));
        assert!(sets.find(capability_set_type::SURFACE_COMMANDS).is_none());
        // And what is left is still a set a server can read: the general and
        // bitmap sets are the two it acts on first.
        assert!(sets.general().is_some());
        assert!(sets.bitmap().is_some());
    }
}
