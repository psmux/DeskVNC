//! A configurable in-process RDP server for end to end tests
//! (PRDRDP/12 §8.4, PRDRDP/09 §3).
//!
//! It speaks the real wire protocol over a real TCP socket bound to
//! `127.0.0.1:0`, so the client under test exercises `vnc-transport`,
//! `rdp-core`'s framer and its connection sequence exactly as it would
//! against a Windows host. That is the argument
//! `crates/vnc-core/tests/common/mock_server.rs:3` makes for the RFB mock and
//! it holds here: a `DuplexStream` would skip the transport layer and prove
//! less.
//!
//! **The one rule that makes this affordable is in `rdp-pdu`: every PDU type
//! implements both `Decode` and `Encode`.** The mock is a state machine over
//! the same type definitions the client uses, writing where the client reads
//! and reading where the client writes. Its size comes from scenario
//! plumbing, not from wire formats.
//!
//! Everything the client sends is recorded (see [`Recorded`]) so tests can
//! make assertions about what reached the wire, and the mock can be told to
//! misbehave in the specific ways the connection sequence has to survive.
//!
//! # What it does not do
//!
//! No TLS and no CredSSP. The mock has no certificate, so it answers the
//! X.224 negotiation with `PROTOCOL_SSL` and the test drives the phases
//! either side of the upgrade separately: `negotiate_security` over the
//! socket, then `after_upgrade` over the same socket. Both are the production
//! functions; what is skipped is the handshake between them, which needs a
//! committed test key pair (PRDRDP/12 §3.14 `tests/common/certs.rs`) that
//! does not exist yet.
//!
//! # What it does after the joins
//!
//! Phases 6 to 10 and then a live session: it reads the Client Info PDU,
//! answers licensing, sends a Demand Active, reads the Confirm Active and the
//! four finalisation PDUs, sends its own four, and then draws one bitmap
//! update on the fast path and reads whatever input comes back. That is what
//! makes `tests/connect.rs` able to assert a decoded pixel and an input event
//! round trip rather than only the shape of the handshake.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rdp_pdu::gcc::server::{
    ServerCoreData, ServerMessageChannelData, ServerNetworkData, ServerSecurityData,
};
use rdp_pdu::io::{Decode, Encode, Payload, Writer};
use rdp_pdu::mcs::{result_code, DomainMcsPdu};
use rdp_pdu::rdp::capabilities::{ClientCapabilitySupport, InputCapabilitySet};
use rdp_pdu::rdp::license::{
    blob_type, message_type, preamble_flags, LicenseBinaryBlob, LicenseErrorMessage,
    LicenseMessage, LicensePdu, LicensePreamble, LICENSE_PREAMBLE_LEN,
};
use rdp_pdu::rdp::{
    CapabilitySets, ClientInfoPdu, ControlPdu, DemandActivePdu, FontMapPdu, ShareDataPdu, SharePdu,
    SynchronizePdu,
};
use rdp_pdu::update::fastpath::{encode_fastpath_update, update_code, FpUpdate, FpUpdateHeader};
use rdp_pdu::update::slowpath::GraphicsUpdate;
use rdp_pdu::update::{BitmapData, BitmapUpdate, RectExclusive, RectInclusive};
use rdp_pdu::vc::dvc::{cmd as dvc_cmd, dvc_version, read_channel_id, DvcHeader, DvcPdu};
use rdp_pdu::vc::egfx::{caps_version, codec_id, pixel_format, Capset, EgfxPdu};
use rdp_pdu::vc::segment::Segmented;
use rdp_pdu::vc::static_vc::{channel_flags, ChannelPduHeader};
use rdp_pdu::x224::{
    self, security_protocol, NegotiationFailure, NegotiationResponse, X224ConnectionConfirm,
    X224ConnectionRequest, X224Negotiation,
};
use rdp_pdu::{
    ClientGccBlocks, ConferenceCreateRequest, ConferenceCreateResponse, ConnectInitial,
    ConnectResponse, DomainParameters, Reader, ServerGccBlocks,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The first channel id the mock allocates. Real servers start the I/O
/// channel at 1003, above the user channel range's base of 1001
/// (T.125 §7, `rdp_pdu::mcs::MCS_USER_ID_BASE`).
pub const IO_CHANNEL_ID: u16 = 1003;
/// The user channel the Attach User Confirm hands back.
pub const USER_CHANNEL_ID: u16 = 1007;
/// The message channel, where connect time auto detect would arrive.
pub const MESSAGE_CHANNEL_ID: u16 = 1005;
/// The first static virtual channel id, incremented per requested channel.
pub const FIRST_VIRTUAL_CHANNEL_ID: u16 = 1010;

/// The `PDUSource` the mock puts on every Share Control PDU it sends, which is
/// what the client's Synchronize PDU has to name back
/// (MS-RDPBCGR 2.2.1.14.1).
pub const SERVER_PDU_SOURCE: u16 = 0x03ea;

/// The `shareId` the Demand Active hands out. Every Share Data PDU the client
/// sends afterwards has to echo it.
pub const SHARE_ID: u32 = 0x0010_3ea9;

/// The desktop size the mock's Bitmap capability set announces.
///
/// Deliberately not the 1024 by 768 the client asks for in `TS_UD_CS_CORE`, so
/// a test can prove the client adopts the server's answer rather than its own
/// request (MS-RDPBCGR 2.2.7.1.2).
pub const SERVER_DESKTOP: (u16, u16) = (800, 600);

/// Where the mock draws its one bitmap.
pub const BITMAP_AT: (u16, u16) = (10, 20);

/// Two rows of two pixels at 24 bits per pixel, bottom row first, which is
/// what a Windows DIB body is: the first wire row is the BOTTOM row of the
/// picture. Blue underneath and red on top, so a client that forgets the flip
/// fails rather than passing on a symmetric fixture (PRDRDP/04 §2.3).
pub const BITMAP_ROWS: &[u8] = &[
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, // bottom row: blue
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, // top row: red
];

/// The dynamic channel id the mock hands the graphics channel
/// (MS-RDPEDYC 2.2.2.1). Any non zero value; three is arbitrary and is only
/// here so the client's Create Response can be checked against it.
pub const EGFX_DVC_CHANNEL_ID: u32 = 3;

/// The surface the mock creates on the graphics channel.
pub const EGFX_SURFACE_ID: u16 = 1;

/// Where that surface is mapped on the output
/// (`RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU`, MS-RDPEGFX 2.2.2.15).
///
/// Deliberately not the origin, so a client that ignores the mapping and
/// emits surface coordinates fails rather than passing by accident.
pub const EGFX_SURFACE_AT: (u32, u32) = (10, 20);

/// The surface's geometry.
pub const EGFX_SURFACE_SIZE: (u16, u16) = (64, 64);

/// The `frameId` of the one frame the mock draws (MS-RDPEGFX 2.2.2.11).
pub const EGFX_FRAME_ID: u32 = 42;

/// Two pixels of `RDPGFX_CODECID_UNCOMPRESSED`: B, G, R, X per pixel, top
/// down, rows packed to `width * 4` (MS-RDPEGFX 2.2.2.1).
///
/// Red then blue, so a client that swapped the channels or read the row
/// backwards fails rather than passing on a symmetric fixture.
pub const EGFX_PIXELS: &[u8] = &[
    0x00, 0x00, 0xff, 0x00, // red
    0xff, 0x00, 0x00, 0x00, // blue
];

/// Where the mock draws inside the surface.
pub const EGFX_DRAW_AT: (u16, u16) = (2, 3);

/// The text the mock puts on its clipboard for the client to fetch.
///
/// CRLF on the wire, because that is what Windows puts on a clipboard
/// (MS-RDPECLIP 2.2.5.2). The client has to hand the shell the LF form.
pub const CLIPBOARD_FROM_SERVER: &str = "server side\r\nsecond line";

/// `CF_UNICODETEXT` (MS-RDPECLIP 1.3.1.2).
pub const CF_UNICODETEXT: u32 = 13;

/// `CLIPRDR_HEADER.msgType` values the mock uses (MS-RDPECLIP 2.2.1).
pub mod clip_msg {
    /// `CB_MONITOR_READY`.
    pub const MONITOR_READY: u16 = 0x0001;
    /// `CB_FORMAT_LIST`.
    pub const FORMAT_LIST: u16 = 0x0002;
    /// `CB_FORMAT_LIST_RESPONSE`.
    pub const FORMAT_LIST_RESPONSE: u16 = 0x0003;
    /// `CB_FORMAT_DATA_REQUEST`.
    pub const FORMAT_DATA_REQUEST: u16 = 0x0004;
    /// `CB_FORMAT_DATA_RESPONSE`.
    pub const FORMAT_DATA_RESPONSE: u16 = 0x0005;
    /// `CB_CLIP_CAPS`.
    pub const CLIP_CAPS: u16 = 0x0007;
    /// `CB_RESPONSE_OK`.
    pub const RESPONSE_OK: u16 = 0x0001;
}

/// How the mock answers the X.224 Connection Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negotiation {
    /// `RDP_NEG_RSP` selecting this protocol.
    Select(u32),
    /// `RDP_NEG_FAILURE` with this code (MS-RDPBCGR 2.2.1.2.2).
    Fail(u32),
    /// A Connection Confirm with no negotiation structure at all, which means
    /// the server does not understand negotiation and has chosen standard RDP
    /// security. A real case, not a theoretical one.
    NoStructure,
}

/// What the mock does after the channel joins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBehaviour {
    /// Nothing. The old behaviour, for the tests that only care about the MCS
    /// phases.
    StopAfterJoins,
    /// The whole of phases 6 to 10, then one bitmap update and an input read.
    Serve,
    /// The same, but with no licensing PDU at all: straight from the Client
    /// Info PDU to the Demand Active. A real case on some non Microsoft
    /// servers, and the one that catches a client which assumes a security
    /// header is there.
    ServeWithoutLicensing,
    /// Answer licensing with `ERR_NO_LICENSE_SERVER`, which is a refusal the
    /// client must report as a sentence rather than carry on through.
    RefuseLicence,
    /// The whole of phases 6 to 10, and then a virtual channel session
    /// instead of a legacy bitmap: the drdynvc version handshake, the
    /// graphics channel with one frame on it, and a clipboard exchange in
    /// both directions.
    ServeChannels,
    /// The same, but the graphics frame is an EGFX message that decompresses
    /// into bytes that are not EGFX commands.
    ///
    /// That is the shape a wrong row in the ZGFX literal token table produces
    /// (`docs/RDP_SPEC_NOTES.md` §1.1), and the client has to report it
    /// rather than draw whatever fell out.
    ServeMalformedEgfx,
}

/// How the mock answers the MCS Connect Initial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McsBehaviour {
    /// A well formed Connect Response and every join confirmed.
    Normal,
    /// A Connect Response that asks for standard RDP security, which the
    /// client must refuse before sending a credential.
    DemandStandardSecurity,
    /// Refuse the join for the I/O channel, which is a connect failure.
    RefuseIoChannelJoin,
    /// Refuse the join for the last virtual channel, which is survivable.
    RefuseLastVirtualChannelJoin,
    /// Answer the Connect Initial with a channel id array of the wrong
    /// length, which the client must refuse rather than pairing up by
    /// position.
    WrongChannelCount,
    /// Answer the Attach User Request with a refusal.
    RefuseAttachUser,
    /// Send an MCS Disconnect Provider Ultimatum instead of the Connect
    /// Response.
    DisconnectDuringConnect,
}

/// What the mock should do.
#[derive(Debug, Clone)]
pub struct MockConfig {
    /// How to answer the X.224 Connection Request.
    pub negotiation: Negotiation,
    /// How to run the MCS phases.
    pub mcs: McsBehaviour,
    /// Whether to advertise `RNS_UD_SC_SKIP_CHANNELJOIN_SUPPORTED`.
    pub skip_channel_join: bool,
    /// Whether to offer a message channel.
    pub message_channel: bool,
    /// What to do after the joins.
    pub session: SessionBehaviour,
}

impl Default for MockConfig {
    /// A server that does what a Windows host with NLA turned off does: TLS
    /// only, every channel allocated, every join confirmed, licensing answered
    /// with "no licence required", and then a live session.
    fn default() -> Self {
        Self {
            negotiation: Negotiation::Select(security_protocol::SSL),
            mcs: McsBehaviour::Normal,
            skip_channel_join: false,
            message_channel: true,
            session: SessionBehaviour::Serve,
        }
    }
}

/// What the client sent, for byte level assertions.
#[derive(Debug, Default, Clone)]
pub struct Recorded {
    /// The X.224 Connection Request, decoded.
    pub connection_request: Option<X224ConnectionRequest>,
    /// The `TS_UD_CS_*` blocks from the Connect Initial, decoded.
    pub client_blocks: Option<ClientGccBlocks>,
    /// The whole `Connect-Initial`, so a test can assert on the domain
    /// parameters as well as on the user data.
    pub domain_parameters: Option<DomainParameters>,
    /// Every Erect Domain Request the client sent.
    pub erect_domains: usize,
    /// Every Attach User Request.
    pub attach_users: usize,
    /// The channel ids the client asked to join, in the order it asked.
    pub joins: Vec<u16>,
    /// The reason code of a Disconnect Provider Ultimatum from the client.
    pub client_disconnect: Option<u8>,
    /// The `TS_INFO_PACKET` from the Client Info PDU, decoded.
    pub client_info: Option<ClientInfoPdu>,
    /// The `shareId` the client echoed in its Confirm Active.
    pub confirmed_share_id: Option<u32>,
    /// The `capabilitySetType` of every set the client confirmed, in order.
    pub confirmed_capabilities: Vec<u16>,
    /// The `pduType2` of every Share Data PDU the client sent after the
    /// Confirm Active, in order.
    pub finalization: Vec<u8>,
    /// Every fast path input event the client sent, in order.
    pub input_events: Vec<rdp_pdu::input::fastpath::FastPathInputEvent>,

    // -- The virtual channels (MS-RDPEDYC, MS-RDPEGFX, MS-RDPECLIP) -------
    /// The `Version` in the client's drdynvc Capabilities Response
    /// (MS-RDPEDYC 2.2.1.2).
    pub dvc_version: Option<u16>,
    /// Every Create Response the client sent, as `(ChannelId,
    /// CreationStatus)` (MS-RDPEDYC 2.2.2.2).
    pub dvc_creations: Vec<(u32, i32)>,
    /// The capability set versions in the client's
    /// `RDPGFX_CAPS_ADVERTISE_PDU` (MS-RDPEGFX 2.2.2.18).
    pub egfx_advertised: Vec<u32>,
    /// Entries in the client's `RDPGFX_CACHE_IMPORT_OFFER_PDU`
    /// (MS-RDPEGFX 2.2.2.16), and `None` until one arrives.
    pub egfx_cache_offer: Option<usize>,
    /// Every `RDPGFX_FRAME_ACKNOWLEDGE_PDU` the client sent
    /// (MS-RDPEGFX 2.2.2.13).
    pub frame_acks: Vec<FrameAck>,
    /// True once the client has sent `CB_CLIP_CAPS` (MS-RDPECLIP 2.2.2.1).
    pub clipboard_caps: bool,
    /// The format ids of every `CB_FORMAT_LIST` the client sent, in order
    /// (MS-RDPECLIP 2.2.3.1).
    pub clipboard_formats: Vec<Vec<u32>>,
    /// The text the client handed back in a `CB_FORMAT_DATA_RESPONSE`,
    /// decoded from UTF-16LE with its terminator stripped
    /// (MS-RDPECLIP 2.2.5.2).
    pub clipboard_from_client: Option<String>,
}

/// One `RDPGFX_FRAME_ACKNOWLEDGE_PDU` (MS-RDPEGFX 2.2.2.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameAck {
    /// `queueDepth`: how many frames the client says are waiting to be shown.
    pub queue_depth: u32,
    /// `frameId`, the frame being acknowledged.
    pub frame_id: u32,
    /// `totalFramesDecoded`, a running count over the life of the channel.
    pub total_frames_decoded: u32,
}

/// A running mock. Dropping it leaves the accept task to finish on its own.
pub struct MockRdpServer {
    /// Where to dial.
    pub addr: SocketAddr,
    recorded: Arc<Mutex<Recorded>>,
}

impl MockRdpServer {
    /// Bind and start serving one connection.
    pub async fn start(config: MockConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding the loopback");
        let addr = listener.local_addr().expect("a bound address");
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let shared = recorded.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                if let Err(e) = serve(stream, config, shared).await {
                    // A test that stops reading part way through is normal:
                    // the client got the error it was looking for and hung up.
                    eprintln!("mock rdp server finished: {e}");
                }
            }
        });
        Self { addr, recorded }
    }

    /// What the client has sent so far.
    pub fn recorded(&self) -> Recorded {
        self.recorded.lock().expect("not poisoned").clone()
    }

    /// Wait until `ready` says the mock has seen what a test is about to
    /// assert on.
    ///
    /// The mock runs in its own task, so bytes the client has finished writing
    /// have not necessarily been read yet: asserting straight after the client
    /// hangs up is a race that passes on a quiet machine and fails on a loaded
    /// CI box. This is the same wait the RFB integration tests use, with the
    /// same budget.
    pub async fn wait_until(&self, ready: impl Fn(&Recorded) -> bool) -> Recorded {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let recorded = self.recorded();
            if ready(&recorded) || std::time::Instant::now() > deadline {
                return recorded;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }
}

/// Read one whole TPKT from `stream`.
///
/// The mock's own framer, deliberately the naive one: read the four byte
/// header, ask how many more bytes, read exactly those. The client's framer
/// is the one under test and it must not share code with this.
async fn read_tpkt(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; x224::TPKT_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let total = x224::peek_tpkt_length(&header)
        .map_err(std::io::Error::other)?
        .ok_or_else(|| std::io::Error::other("short TPKT header"))?;
    let mut frame = header.to_vec();
    frame.resize(total, 0);
    stream
        .read_exact(&mut frame[x224::TPKT_HEADER_LEN..])
        .await?;
    Ok(frame)
}

fn encoded(value: &impl Encode) -> Vec<u8> {
    let mut buf = Vec::new();
    value
        .encode_checked(&mut Writer::new(&mut buf))
        .expect("the mock encodes what the client parses");
    buf
}

fn domain_frame(pdu: &DomainMcsPdu<'_>) -> Vec<u8> {
    let mut frame = Vec::new();
    x224::write_data_tpdu_with(&mut Writer::new(&mut frame), pdu.size(), |w| pdu.encode(w))
        .expect("the mock encodes what the client parses");
    frame
}

async fn serve(
    mut stream: TcpStream,
    config: MockConfig,
    recorded: Arc<Mutex<Recorded>>,
) -> std::io::Result<()> {
    // ---- Phase 1: X.224 -------------------------------------------------
    let frame = read_tpkt(&mut stream).await?;
    let request =
        X224ConnectionRequest::decode(&mut Reader::new(&frame)).map_err(std::io::Error::other)?;
    recorded.lock().expect("not poisoned").connection_request = Some(request);

    let confirm = X224ConnectionConfirm {
        dst_ref: 0,
        // Non zero, as MS-RDPBCGR 4.1.2's example is, so a client that
        // accidentally requires zero fails here rather than in the field.
        src_ref: 0x1234,
        class_options: 0,
        nego: match config.negotiation {
            Negotiation::Select(p) => Some(X224Negotiation::Response(NegotiationResponse {
                flags: 0,
                selected_protocol: p,
            })),
            Negotiation::Fail(code) => Some(X224Negotiation::Failure(NegotiationFailure {
                failure_code: code,
            })),
            Negotiation::NoStructure => None,
        },
    };
    stream.write_all(&encoded(&confirm)).await?;
    stream.flush().await?;
    if !matches!(config.negotiation, Negotiation::Select(_)) {
        return Ok(());
    }

    // ---- Phase 3: the Basic Settings Exchange ---------------------------
    let frame = read_tpkt(&mut stream).await?;
    let mut r = Reader::new(&frame);
    let mut body = x224::read_data_tpdu(&mut r).map_err(std::io::Error::other)?;
    let initial = ConnectInitial::decode(&mut body).map_err(std::io::Error::other)?;
    let ccr = ConferenceCreateRequest::decode(&mut Reader::new(initial.user_data))
        .map_err(std::io::Error::other)?;
    let blocks =
        ClientGccBlocks::decode(&mut Reader::new(ccr.user_data)).map_err(std::io::Error::other)?;
    let requested = blocks
        .network
        .as_ref()
        .map(|n| n.channels.len())
        .unwrap_or(0);
    {
        let mut rec = recorded.lock().expect("not poisoned");
        rec.domain_parameters = Some(initial.target_parameters);
        rec.client_blocks = Some(blocks);
    }

    if config.mcs == McsBehaviour::DisconnectDuringConnect {
        let bye = domain_frame(&DomainMcsPdu::DisconnectProviderUltimatum {
            reason: rdp_pdu::mcs::disconnect_reason::PROVIDER_INITIATED,
        });
        stream.write_all(&bye).await?;
        return Ok(());
    }

    let allocated = if config.mcs == McsBehaviour::WrongChannelCount {
        requested.saturating_sub(1)
    } else {
        requested
    };
    let channel_ids: Vec<u16> = (0..allocated as u16)
        .map(|i| FIRST_VIRTUAL_CHANNEL_ID + i)
        .collect();

    let security = if config.mcs == McsBehaviour::DemandStandardSecurity {
        // ENCRYPTION_METHOD_128BIT with ENCRYPTION_LEVEL_CLIENT_COMPATIBLE:
        // a server asking for standard RDP security (MS-RDPBCGR 2.2.1.4.3).
        ServerSecurityData {
            encryption_method: 0x0000_0002,
            encryption_level: 0x0000_0002,
            server_random: None,
            server_certificate: None,
        }
    } else {
        ServerSecurityData::default()
    };

    let server_blocks = ServerGccBlocks {
        core: Some(ServerCoreData {
            version: rdp_pdu::gcc::client::RDP_VERSION_5_PLUS,
            client_requested_protocols: Some(security_protocol::SSL | security_protocol::HYBRID),
            early_capability_flags: Some(if config.skip_channel_join {
                rdp_pdu::gcc::server::server_early_capability_flags::SKIP_CHANNELJOIN_SUPPORTED
            } else {
                0
            }),
        }),
        security: Some(security),
        network: Some(ServerNetworkData {
            io_channel_id: IO_CHANNEL_ID,
            channel_ids: channel_ids.clone(),
        }),
        message_channel: config.message_channel.then_some(ServerMessageChannelData {
            channel_id: MESSAGE_CHANNEL_ID,
        }),
        multitransport: None,
    };
    let user_data = encoded(&server_blocks);
    let gcc = encoded(&ConferenceCreateResponse {
        node_id: 1002,
        tag: 1,
        result: result_code::RT_SUCCESSFUL,
        user_data: &user_data,
    });
    let response = ConnectResponse {
        result: u32::from(result_code::RT_SUCCESSFUL),
        called_connect_id: 0,
        domain_parameters: DomainParameters::TARGET,
        user_data: &gcc,
    };
    let mut frame = Vec::new();
    x224::write_data_tpdu_with(&mut Writer::new(&mut frame), response.size(), |w| {
        response.encode(w)
    })
    .expect("the mock encodes what the client parses");
    stream.write_all(&frame).await?;
    stream.flush().await?;

    // ---- Phase 4: Channel Connection ------------------------------------
    // The client pipelines Erect Domain and Attach User in one write, so both
    // may arrive in one read. Reading TPKT by TPKT is what makes that work
    // without the mock caring.
    let frame = read_tpkt(&mut stream).await?;
    expect_domain(&frame, &recorded)?;
    let frame = read_tpkt(&mut stream).await?;
    expect_domain(&frame, &recorded)?;

    let confirm = domain_frame(&DomainMcsPdu::AttachUserConfirm {
        result: if config.mcs == McsBehaviour::RefuseAttachUser {
            result_code::RT_USER_REJECTED
        } else {
            result_code::RT_SUCCESSFUL
        },
        initiator: (config.mcs != McsBehaviour::RefuseAttachUser).then_some(USER_CHANNEL_ID),
    });
    stream.write_all(&confirm).await?;
    stream.flush().await?;
    if config.mcs == McsBehaviour::RefuseAttachUser {
        return Ok(());
    }

    // One confirm per request. The client pipelines the requests and accepts
    // the confirms in any order, so answering them in reverse is a legal
    // server and a real test of that.
    let expected_joins = 2 + usize::from(config.message_channel) + allocated;
    let mut wanted = Vec::new();
    for _ in 0..expected_joins {
        let frame = read_tpkt(&mut stream).await?;
        let mut r = Reader::new(&frame);
        let mut body = x224::read_data_tpdu(&mut r).map_err(std::io::Error::other)?;
        match DomainMcsPdu::decode(&mut body).map_err(std::io::Error::other)? {
            DomainMcsPdu::ChannelJoinRequest { channel_id, .. } => {
                recorded
                    .lock()
                    .expect("not poisoned")
                    .joins
                    .push(channel_id);
                wanted.push(channel_id);
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "expected a channel join request, got choice {}",
                    other.choice_index()
                )));
            }
        }
    }

    let last_virtual = channel_ids.last().copied();
    for channel_id in wanted.into_iter().rev() {
        let refuse = match config.mcs {
            McsBehaviour::RefuseIoChannelJoin => channel_id == IO_CHANNEL_ID,
            McsBehaviour::RefuseLastVirtualChannelJoin => Some(channel_id) == last_virtual,
            _ => false,
        };
        let confirm = domain_frame(&DomainMcsPdu::ChannelJoinConfirm {
            result: if refuse {
                result_code::RT_USER_REJECTED
            } else {
                result_code::RT_SUCCESSFUL
            },
            initiator: USER_CHANNEL_ID,
            requested: channel_id,
            channel_id: (!refuse).then_some(channel_id),
        });
        stream.write_all(&confirm).await?;
    }
    stream.flush().await?;

    if config.session == SessionBehaviour::StopAfterJoins {
        // The client's next PDU is the Client Info (MS-RDPBCGR 2.2.1.11) and
        // this scenario does not answer it, so the client hangs up. Whatever
        // arrives is recorded so a test can assert the teardown was ordered.
        return drain(&mut stream, &recorded, None).await;
    }

    // ---- Phase 6: the Client Info PDU -----------------------------------
    let frame = read_tpkt(&mut stream).await?;
    let payload = expect_io_payload(&frame)?;
    let info = ClientInfoPdu::decode(&mut Reader::new(&payload)).map_err(std::io::Error::other)?;
    recorded.lock().expect("not poisoned").client_info = Some(info);

    // ---- Phase 7: licensing ---------------------------------------------
    match config.session {
        SessionBehaviour::ServeWithoutLicensing => {}
        SessionBehaviour::RefuseLicence => {
            let bye = license_alert(
                rdp_pdu::codes::LicenseError::NoLicenseServer,
                rdp_pdu::codes::LicenseStateTransition::TotalAbort,
            );
            stream.write_all(&io_frame(&bye)).await?;
            stream.flush().await?;
            return drain(&mut stream, &recorded, None).await;
        }
        _ => {
            // The one licensing answer a TLS session actually sees: "no
            // licence is required, carry on" (MS-RDPBCGR 2.2.1.12.1.3).
            let ok = license_alert(
                rdp_pdu::codes::LicenseError::StatusValidClient,
                rdp_pdu::codes::LicenseStateTransition::NoTransition,
            );
            stream.write_all(&io_frame(&ok)).await?;
            stream.flush().await?;
        }
    }

    // ---- Phase 9: the capability exchange -------------------------------
    // The server's own advertisement. `ClientCapabilitySupport` names the two
    // optional sets from the client's side, and a server offering both is the
    // case that proves the client removes what it cannot decode rather than
    // relying on the server not to offer it.
    let capabilities = CapabilitySets::client(
        SERVER_DESKTOP.0,
        SERVER_DESKTOP.1,
        SERVER_PDU_SOURCE,
        InputCapabilitySet::client(0x0409, 4, 0, 12),
        ClientCapabilitySupport::minimal().with_surface_commands(true),
    );
    let demand = SharePdu::DemandActive {
        pdu_source: SERVER_PDU_SOURCE,
        pdu: Box::new(DemandActivePdu {
            share_id: SHARE_ID,
            source_descriptor: b"RDP\0".to_vec(),
            capabilities,
            session_id: Some(1),
        }),
    };
    stream.write_all(&io_frame(&encoded(&demand))).await?;
    stream.flush().await?;

    // The client answers with the Confirm Active and its four finalisation
    // PDUs in one write, which may arrive in one read or in five.
    for _ in 0..5 {
        let frame = read_tpkt(&mut stream).await?;
        let payload = expect_io_payload(&frame)?;
        let share = SharePdu::decode(&mut Reader::new(&payload)).map_err(std::io::Error::other)?;
        let mut rec = recorded.lock().expect("not poisoned");
        match share {
            SharePdu::ConfirmActive { pdu, .. } => {
                rec.confirmed_share_id = Some(pdu.share_id);
                rec.confirmed_capabilities = pdu
                    .capabilities
                    .sets
                    .iter()
                    .map(|set| set.capability_set_type())
                    .collect();
            }
            SharePdu::Data { pdu, .. } => rec.finalization.push(pdu.pdu_type2()),
            other => {
                return Err(std::io::Error::other(format!(
                    "expected a confirm active or a share data pdu, got {other:?}"
                )))
            }
        }
    }

    // ---- Phase 10: the server's four, the Font Map last -----------------
    for pdu in [
        ShareDataPdu::Synchronize(SynchronizePdu::client(USER_CHANNEL_ID)),
        ShareDataPdu::Control(ControlPdu::cooperate()),
        ShareDataPdu::Control(ControlPdu {
            action: rdp_pdu::rdp::finalize::control_action::GRANTED_CONTROL,
            grant_id: USER_CHANNEL_ID,
            control_id: u32::from(SERVER_PDU_SOURCE),
        }),
        ShareDataPdu::FontMap(FontMapPdu::server()),
    ] {
        let share = SharePdu::data(SERVER_PDU_SOURCE, SHARE_ID, pdu);
        stream.write_all(&io_frame(&encoded(&share))).await?;
    }
    stream.flush().await?;

    // ---- The live session ------------------------------------------------
    //
    // Two shapes. The legacy one draws a bitmap on the fast path, which is
    // what every scenario before the virtual channels used. The other opens
    // drdynvc, runs the graphics channel and the clipboard, and never sends a
    // legacy bitmap at all, which is what a Windows host with the graphics
    // pipeline on actually does.
    if matches!(
        config.session,
        SessionBehaviour::ServeChannels | SessionBehaviour::ServeMalformedEgfx
    ) {
        let mut script = ChannelScript::new(
            &recorded,
            config.session == SessionBehaviour::ServeMalformedEgfx,
        )?;
        script.open(&mut stream).await?;
        return drain(&mut stream, &recorded, Some(&mut script)).await;
    }

    // ---- The legacy live session: one bitmap update on the fast path ----
    let bitmap = BitmapUpdate {
        rectangles: vec![BitmapData {
            dest: RectInclusive {
                left: BITMAP_AT.0,
                top: BITMAP_AT.1,
                right: BITMAP_AT.0 + 1,
                bottom: BITMAP_AT.1 + 1,
            },
            width: 2,
            height: 2,
            bits_per_pixel: 24,
            flags: 0,
            compression_header: None,
            data: Payload::new(BITMAP_ROWS),
        }],
    };
    let mut body = Vec::new();
    GraphicsUpdate::Bitmap(bitmap)
        .encode_body(&mut Writer::new(&mut body))
        .expect("the mock encodes what the client parses");
    let mut wire = Vec::new();
    encode_fastpath_update(
        &mut Writer::new(&mut wire),
        &[FpUpdate {
            header: FpUpdateHeader::single(update_code::BITMAP),
            data: Payload::new(&body),
        }],
    )
    .expect("the mock encodes what the client parses");
    stream.write_all(&wire).await?;
    stream.flush().await?;

    drain(&mut stream, &recorded, None).await
}

/// Read until the client hangs up, recording the input events and the
/// disconnect ultimatum.
///
/// The mock's own framer for the two framings, deliberately naive and
/// deliberately not shared with the client's: TPKT's first byte is version 3
/// and a fast path header's low two bits are the action code, which is how
/// MS-RDPBCGR 2.2.9.1.2 arranges for them to be told apart.
async fn drain(
    stream: &mut TcpStream,
    recorded: &Arc<Mutex<Recorded>>,
    mut script: Option<&mut ChannelScript>,
) -> std::io::Result<()> {
    use rdp_pdu::input::fastpath::FastPathInputPdu;

    loop {
        let mut first = [0u8; 1];
        if stream.read_exact(&mut first).await.is_err() {
            return Ok(());
        }
        if first[0] & 0x03 == 0x03 {
            let mut rest = [0u8; 3];
            stream.read_exact(&mut rest).await?;
            let header = [first[0], rest[0], rest[1], rest[2]];
            let total = x224::peek_tpkt_length(&header)
                .map_err(std::io::Error::other)?
                .ok_or_else(|| std::io::Error::other("short TPKT header"))?;
            let mut frame = header.to_vec();
            frame.resize(total, 0);
            stream
                .read_exact(&mut frame[x224::TPKT_HEADER_LEN..])
                .await?;
            let mut r = Reader::new(&frame);
            if let Ok(mut body) = x224::read_data_tpdu(&mut r) {
                match DomainMcsPdu::decode(&mut body) {
                    Ok(DomainMcsPdu::DisconnectProviderUltimatum { reason }) => {
                        recorded.lock().expect("not poisoned").client_disconnect = Some(reason);
                    }
                    // A virtual channel PDU. Without a script this is a
                    // scenario that does not run the channels, and the PDU is
                    // length prefixed so ignoring it cannot desynchronise the
                    // mock's own framing.
                    Ok(DomainMcsPdu::SendDataRequest {
                        channel_id,
                        payload,
                        ..
                    }) => {
                        if let Some(script) = script.as_deref_mut() {
                            script
                                .channel_pdu(channel_id, payload.as_slice(), stream, recorded)
                                .await?;
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }

        // A fast path input PDU. Its length field is one or two bytes and the
        // top bit of the first says which (MS-RDPBCGR 2.2.8.1.2).
        let mut len1 = [0u8; 1];
        stream.read_exact(&mut len1).await?;
        let total = if len1[0] & 0x80 == 0 {
            usize::from(len1[0])
        } else {
            let mut len2 = [0u8; 1];
            stream.read_exact(&mut len2).await?;
            (usize::from(len1[0] & 0x7f) << 8) | usize::from(len2[0])
        };
        let header_len = if len1[0] & 0x80 == 0 { 2 } else { 3 };
        let mut frame = vec![0u8; total];
        frame[0] = first[0];
        frame[1] = len1[0];
        if header_len == 3 {
            // The second length byte was already consumed above.
            frame[2] = (total & 0xff) as u8;
        }
        stream.read_exact(&mut frame[header_len..]).await?;
        let pdu =
            FastPathInputPdu::decode(&mut Reader::new(&frame)).map_err(std::io::Error::other)?;
        recorded
            .lock()
            .expect("not poisoned")
            .input_events
            .extend(pdu.events);
    }
}

/// A server licensing `ERROR_ALERT` (MS-RDPBCGR 2.2.1.12.1.3).
fn license_alert(
    error_code: rdp_pdu::codes::LicenseError,
    state_transition: rdp_pdu::codes::LicenseStateTransition,
) -> Vec<u8> {
    let message = LicenseErrorMessage {
        error_code,
        state_transition,
        error_info: LicenseBinaryBlob::empty(blob_type::ANY),
    };
    let pdu = LicensePdu {
        preamble: LicensePreamble {
            msg_type: message_type::ERROR_ALERT,
            flags: preamble_flags::VERSION_3_0,
            msg_size: (LICENSE_PREAMBLE_LEN + message.size()) as u16,
        },
        message: LicenseMessage::ErrorAlert(message),
    };
    encoded(&pdu)
}

/// Wrap an encoded slow path PDU for the I/O channel, the way a server does.
fn io_frame(body: &[u8]) -> Vec<u8> {
    domain_frame(&DomainMcsPdu::SendDataIndication {
        initiator: SERVER_PDU_SOURCE,
        channel_id: IO_CHANNEL_ID,
        payload: Payload::new(body),
    })
}

/// The payload of a client Send Data Request on the I/O channel.
fn expect_io_payload(frame: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut r = Reader::new(frame);
    let mut body = x224::read_data_tpdu(&mut r).map_err(std::io::Error::other)?;
    match DomainMcsPdu::decode(&mut body).map_err(std::io::Error::other)? {
        DomainMcsPdu::SendDataRequest {
            channel_id,
            payload,
            ..
        } if channel_id == IO_CHANNEL_ID => Ok(payload.as_slice().to_vec()),
        other => Err(std::io::Error::other(format!(
            "expected a send data request on the I/O channel, got choice {}",
            other.choice_index()
        ))),
    }
}

/// Record an Erect Domain Request or an Attach User Request.
fn expect_domain(frame: &[u8], recorded: &Arc<Mutex<Recorded>>) -> std::io::Result<()> {
    let mut r = Reader::new(frame);
    let mut body = x224::read_data_tpdu(&mut r).map_err(std::io::Error::other)?;
    let pdu = DomainMcsPdu::decode(&mut body).map_err(std::io::Error::other)?;
    let mut rec = recorded.lock().expect("not poisoned");
    match pdu {
        DomainMcsPdu::ErectDomainRequest { .. } => rec.erect_domains += 1,
        DomainMcsPdu::AttachUserRequest => rec.attach_users += 1,
        other => {
            return Err(std::io::Error::other(format!(
                "expected erect domain or attach user, got choice {}",
                other.choice_index()
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The virtual channel scenario (MS-RDPEDYC, MS-RDPEGFX, MS-RDPECLIP)
// ---------------------------------------------------------------------------

/// The server half of a virtual channel session, driven by what the client
/// says.
///
/// Reactive rather than scripted in a straight line, and that is the point: a
/// real server answers what arrives, and a mock that wrote its side in a fixed
/// order would deadlock the moment the client's ordering differed by one PDU.
/// Each arm of [`ChannelScript::channel_pdu`] is one "when the client says X,
/// answer Y", which is also how MS-RDPEDYC 1.3.1 and MS-RDPECLIP 1.3.2.1
/// describe the two sequences.
pub struct ChannelScript {
    drdynvc_id: u16,
    cliprdr_id: u16,
    /// Send an EGFX message that decompresses into nonsense instead of a
    /// frame, for the ZGFX failure mode (`docs/RDP_SPEC_NOTES.md` §1.1).
    malformed_egfx: bool,
    /// Partial static channel messages, per channel id. Everything the client
    /// sends here fits one 1600 byte chunk, but reassembling anyway is what
    /// makes the mock's framing independent of that assumption.
    partial: std::collections::HashMap<u16, Vec<u8>>,
    /// Whether the mock has already offered its own clipboard formats, so a
    /// second format list from the client does not start the exchange again.
    offered_clipboard: bool,
}

impl ChannelScript {
    /// Work out which MCS channel ids the joins gave `drdynvc` and `cliprdr`.
    ///
    /// The mock allocated them in the order the client asked for them
    /// (see `read_connect_initial`), so the name's position in
    /// `TS_UD_CS_NET` is the offset from [`FIRST_VIRTUAL_CHANNEL_ID`].
    fn new(recorded: &Arc<Mutex<Recorded>>, malformed_egfx: bool) -> std::io::Result<Self> {
        let id = |name: &str| -> std::io::Result<u16> {
            let rec = recorded.lock().expect("not poisoned");
            let index = rec
                .client_blocks
                .as_ref()
                .and_then(|b| b.network.as_ref())
                .and_then(|n| n.channels.iter().position(|c| c.name == name))
                .ok_or_else(|| {
                    std::io::Error::other(format!("the client did not ask for {name}"))
                })?;
            Ok(FIRST_VIRTUAL_CHANNEL_ID + index as u16)
        };
        Ok(Self {
            drdynvc_id: id("drdynvc")?,
            cliprdr_id: id("cliprdr")?,
            malformed_egfx,
            partial: std::collections::HashMap::new(),
            offered_clipboard: false,
        })
    }

    /// Open both channels: the drdynvc version handshake and the clipboard's
    /// `CB_MONITOR_READY`.
    ///
    /// Both are the server's first word on their channel
    /// (MS-RDPEDYC 1.3.1, MS-RDPECLIP 1.3.2.1).
    async fn open(&mut self, stream: &mut TcpStream) -> std::io::Result<()> {
        self.send_dvc(
            stream,
            &DvcPdu::Capabilities {
                version: dvc_version::V3,
                priority_charges: Some([0, 0, 0, 0]),
            },
        )
        .await?;
        self.send_clip(stream, clip_msg::MONITOR_READY, 0, &[])
            .await
    }

    /// One MCS Send Data Request on a virtual channel.
    async fn channel_pdu(
        &mut self,
        channel_id: u16,
        payload: &[u8],
        stream: &mut TcpStream,
        recorded: &Arc<Mutex<Recorded>>,
    ) -> std::io::Result<()> {
        let Some(message) = self.reassemble(channel_id, payload)? else {
            return Ok(());
        };
        if channel_id == self.drdynvc_id {
            self.drdynvc(&message, stream, recorded).await
        } else if channel_id == self.cliprdr_id {
            self.cliprdr(&message, stream, recorded).await
        } else {
            Ok(())
        }
    }

    /// The static channel layer: `CHANNEL_PDU_HEADER` and its chunks
    /// (MS-RDPBCGR 2.2.6.1).
    fn reassemble(&mut self, channel_id: u16, payload: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
        let mut r = Reader::new(payload);
        let header = ChannelPduHeader::decode(&mut r).map_err(std::io::Error::other)?;
        let chunk = r.rest();
        if header.is_first() && header.is_last() {
            return Ok(Some(chunk.to_vec()));
        }
        let buf = self.partial.entry(channel_id).or_default();
        if header.is_first() {
            buf.clear();
        }
        buf.extend_from_slice(chunk);
        if header.is_last() {
            return Ok(Some(std::mem::take(buf)));
        }
        Ok(None)
    }

    /// One drdynvc PDU from the client (MS-RDPEDYC 2.2).
    async fn drdynvc(
        &mut self,
        message: &[u8],
        stream: &mut TcpStream,
        recorded: &Arc<Mutex<Recorded>>,
    ) -> std::io::Result<()> {
        // `DYNVC_CREATE` is the one PDU whose two directions share a `Cmd`:
        // a Create Request is a NUL terminated name and a Create Response is
        // four bytes of `CreationStatus`, and nothing on the wire tells them
        // apart (MS-RDPEDYC 2.2.2.1, 2.2.2.2). `DvcPdu::decode` is written for
        // the client, which only ever receives requests, and says so
        // (`crates/rdp-pdu/src/vc/dvc.rs:407`). The mock is the other end, so
        // it reads this one by hand rather than being handed a
        // `CreateRequest` with an empty name.
        if let Some(response) = read_create_response(message) {
            recorded
                .lock()
                .expect("not poisoned")
                .dvc_creations
                .push(response);
            return Ok(());
        }
        match DvcPdu::decode(&mut Reader::new(message)).map_err(std::io::Error::other)? {
            DvcPdu::Capabilities { version, .. } => {
                recorded.lock().expect("not poisoned").dvc_version = Some(version);
                // The version is settled, so the graphics channel can be
                // opened (MS-RDPEDYC 1.3.1).
                self.send_dvc(
                    stream,
                    &DvcPdu::CreateRequest {
                        channel_id: EGFX_DVC_CHANNEL_ID,
                        channel_name: "Microsoft::Windows::RDS::Graphics".to_owned(),
                    },
                )
                .await
            }
            DvcPdu::Data {
                channel_id, data, ..
            } if channel_id == EGFX_DVC_CHANNEL_ID => {
                self.egfx(data.as_slice(), stream, recorded).await
            }
            _ => Ok(()),
        }
    }

    /// One EGFX message from the client: the envelope, then its commands
    /// (MS-RDPEGFX 2.2.5.1, 2.2.1.5).
    async fn egfx(
        &mut self,
        message: &[u8],
        stream: &mut TcpStream,
        recorded: &Arc<Mutex<Recorded>>,
    ) -> std::io::Result<()> {
        // The client sends the literal form, so the mock reads the envelope
        // rather than decompressing: there is no ZGFX compressor in the tree
        // and a client to server message is never compressed.
        let segmented =
            Segmented::decode(&mut Reader::new(message)).map_err(std::io::Error::other)?;
        let Segmented::Literal { data, .. } = segmented else {
            return Err(std::io::Error::other(
                "the client compressed an EGFX message, which it never should",
            ));
        };
        for item in EgfxPdu::iter(data.as_slice()) {
            match item.map_err(std::io::Error::other)? {
                EgfxPdu::CapsAdvertise { capsets } => {
                    recorded.lock().expect("not poisoned").egfx_advertised =
                        capsets.iter().map(|c| c.version).collect();
                    // Confirm the highest set the client offered, which is
                    // what a server does (MS-RDPEGFX 3.3.5.2).
                    let confirmed = capsets
                        .iter()
                        .map(|c| c.version)
                        .max()
                        .unwrap_or(caps_version::V8);
                    self.send_egfx(
                        stream,
                        &[EgfxPdu::CapsConfirm {
                            capset: Capset::new(confirmed, &[0, 0, 0, 0]),
                        }],
                    )
                    .await?;
                }
                EgfxPdu::CacheImportOffer { entries } => {
                    recorded.lock().expect("not poisoned").egfx_cache_offer = Some(entries.len());
                    // The offer is the last thing in the opening exchange, so
                    // this is where the picture starts.
                    self.send_egfx(
                        stream,
                        &[EgfxPdu::CacheImportReply {
                            cache_slots: Vec::new(),
                        }],
                    )
                    .await?;
                    if self.malformed_egfx {
                        self.send_malformed_egfx(stream).await?;
                    } else {
                        self.send_frame(stream).await?;
                    }
                }
                EgfxPdu::FrameAcknowledge {
                    queue_depth,
                    frame_id,
                    total_frames_decoded,
                } => {
                    recorded
                        .lock()
                        .expect("not poisoned")
                        .frame_acks
                        .push(FrameAck {
                            queue_depth,
                            frame_id,
                            total_frames_decoded,
                        });
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// One whole frame: a surface, its output mapping, and one rectangle
    /// between a `START_FRAME` and an `END_FRAME` (MS-RDPEGFX 3.3.5.6).
    async fn send_frame(&mut self, stream: &mut TcpStream) -> std::io::Result<()> {
        let dest = RectExclusive {
            left: EGFX_DRAW_AT.0,
            top: EGFX_DRAW_AT.1,
            right: EGFX_DRAW_AT.0 + 2,
            bottom: EGFX_DRAW_AT.1 + 1,
        };
        self.send_egfx(
            stream,
            &[
                EgfxPdu::CreateSurface {
                    surface_id: EGFX_SURFACE_ID,
                    width: EGFX_SURFACE_SIZE.0,
                    height: EGFX_SURFACE_SIZE.1,
                    pixel_format: pixel_format::XRGB_8888,
                },
                EgfxPdu::MapSurfaceToOutput {
                    surface_id: EGFX_SURFACE_ID,
                    reserved: 0,
                    output_origin_x: EGFX_SURFACE_AT.0,
                    output_origin_y: EGFX_SURFACE_AT.1,
                },
                EgfxPdu::StartFrame {
                    timestamp: 0x0001_0203,
                    frame_id: EGFX_FRAME_ID,
                },
                EgfxPdu::WireToSurface1 {
                    surface_id: EGFX_SURFACE_ID,
                    codec_id: codec_id::UNCOMPRESSED,
                    pixel_format: pixel_format::XRGB_8888,
                    dest_rect: dest,
                    bitmap_data: Payload::new(EGFX_PIXELS),
                },
                EgfxPdu::EndFrame {
                    frame_id: EGFX_FRAME_ID,
                },
            ],
        )
        .await
    }

    /// A well formed envelope holding bytes that are not EGFX commands.
    ///
    /// This is what a wrong row in the ZGFX literal token table produces: the
    /// decompression succeeds and what falls out has a `cmdId` or a
    /// `pduLength` that does not parse (`docs/RDP_SPEC_NOTES.md` §1.1). The
    /// `pduLength` here claims 65,535 bytes and eight are present.
    async fn send_malformed_egfx(&mut self, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut body = vec![0xE0, 0x04];
        body.extend_from_slice(&0x000B_u16.to_le_bytes()); // RDPGFX_CMDID_STARTFRAME
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0xFFFF_u32.to_le_bytes());
        self.send_dvc(
            stream,
            &DvcPdu::Data {
                channel_id: EGFX_DVC_CHANNEL_ID,
                data: Payload::new(&body),
                compressed: false,
            },
        )
        .await
    }

    /// One `cliprdr` PDU from the client (MS-RDPECLIP 2.2.1).
    async fn cliprdr(
        &mut self,
        message: &[u8],
        stream: &mut TcpStream,
        recorded: &Arc<Mutex<Recorded>>,
    ) -> std::io::Result<()> {
        let mut r = Reader::new(message);
        let msg_type = r.u16("msgType").map_err(std::io::Error::other)?;
        let _flags = r.u16("msgFlags").map_err(std::io::Error::other)?;
        let len = r.u32("dataLen").map_err(std::io::Error::other)? as usize;
        let body = r.rest().get(..len).unwrap_or(&[]).to_vec();

        match msg_type {
            clip_msg::CLIP_CAPS => {
                recorded.lock().expect("not poisoned").clipboard_caps = true;
                self.send_clip(stream, clip_msg::CLIP_CAPS, 0, &general_capability())
                    .await
            }
            clip_msg::FORMAT_LIST => {
                let ids = long_format_ids(&body);
                let has_text = ids.contains(&CF_UNICODETEXT);
                recorded
                    .lock()
                    .expect("not poisoned")
                    .clipboard_formats
                    .push(ids);
                // The response is mandatory: a server thread waiting on it
                // hangs copy and paste for every application on the desktop
                // (MS-RDPECLIP 3.1.5.2.4).
                self.send_clip(
                    stream,
                    clip_msg::FORMAT_LIST_RESPONSE,
                    clip_msg::RESPONSE_OK,
                    &[],
                )
                .await?;
                if !self.offered_clipboard {
                    // Our own formats, so the client can raise a notify.
                    self.offered_clipboard = true;
                    self.send_clip(
                        stream,
                        clip_msg::FORMAT_LIST,
                        0,
                        &unicode_text_format_list(),
                    )
                    .await?;
                }
                if has_text {
                    // The client has text: pull it, which is what a paste on
                    // the server side does (MS-RDPECLIP 1.3.2.2).
                    self.send_clip(
                        stream,
                        clip_msg::FORMAT_DATA_REQUEST,
                        0,
                        &CF_UNICODETEXT.to_le_bytes(),
                    )
                    .await?;
                }
                Ok(())
            }
            clip_msg::FORMAT_DATA_REQUEST => {
                self.send_clip(
                    stream,
                    clip_msg::FORMAT_DATA_RESPONSE,
                    clip_msg::RESPONSE_OK,
                    &utf16_nul(CLIPBOARD_FROM_SERVER),
                )
                .await
            }
            clip_msg::FORMAT_DATA_RESPONSE => {
                recorded.lock().expect("not poisoned").clipboard_from_client =
                    Some(from_utf16_nul(&body));
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Wrap one drdynvc PDU and put it on the wire.
    async fn send_dvc(&self, stream: &mut TcpStream, pdu: &DvcPdu<'_>) -> std::io::Result<()> {
        let body = encoded(pdu);
        stream
            .write_all(&channel_frame(self.drdynvc_id, &body))
            .await?;
        stream.flush().await
    }

    /// Wrap a sequence of EGFX commands in an uncompressed `RDP_SEGMENTED_DATA`
    /// envelope, then in a `DYNVC_DATA`, and put it on the wire.
    ///
    /// The envelope is descriptor `SINGLE` (0xE0) then a flags byte of
    /// `PACKET_COMPR_TYPE_RDP8` with `PACKET_COMPRESSED` clear (0x04). That is
    /// a real envelope and the client's `rdp_codecs::zgfx` entry point walks
    /// it; what it does not exercise is the token table, because there is no
    /// ZGFX compressor in the tree to build a compressed fixture with.
    async fn send_egfx(&self, stream: &mut TcpStream, pdus: &[EgfxPdu<'_>]) -> std::io::Result<()> {
        let mut body = vec![0xE0, 0x04];
        for pdu in pdus {
            body.extend_from_slice(&encoded(pdu));
        }
        self.send_dvc(
            stream,
            &DvcPdu::Data {
                channel_id: EGFX_DVC_CHANNEL_ID,
                data: Payload::new(&body),
                compressed: false,
            },
        )
        .await
    }

    /// Frame one `cliprdr` message and put it on the wire
    /// (MS-RDPECLIP 2.2.1).
    async fn send_clip(
        &self,
        stream: &mut TcpStream,
        msg_type: u16,
        flags: u16,
        body: &[u8],
    ) -> std::io::Result<()> {
        let mut pdu = Vec::with_capacity(8 + body.len());
        let mut w = Writer::new(&mut pdu);
        w.u16(msg_type);
        w.u16(flags);
        w.u32(body.len() as u32);
        w.bytes(body);
        stream
            .write_all(&channel_frame(self.cliprdr_id, &pdu))
            .await?;
        stream.flush().await
    }
}

/// A client `DYNVC_CREATE` read as a Create Response: the header, the channel
/// id at the width `cbId` names, then a four byte `CreationStatus`
/// (MS-RDPEDYC 2.2.2.2).
///
/// Returns `None` for anything that is not a `DYNVC_CREATE` or that does not
/// have exactly a status behind the channel id, which is what a Create
/// Request looks like.
fn read_create_response(message: &[u8]) -> Option<(u32, i32)> {
    let mut r = Reader::new(message);
    let header = DvcHeader::from_u8(r.u8("DYNVC header").ok()?);
    if header.cmd != dvc_cmd::CREATE {
        return None;
    }
    let channel_id = read_channel_id(&mut r, header.cb_id, "DYNVC_CREATE ChannelId").ok()?;
    let status = r.u32("DYNVC_CREATE CreationStatus").ok()?;
    r.is_empty().then_some((channel_id, status as i32))
}

/// One whole channel PDU in a single `CHANNEL_PDU_HEADER` chunk, inside an MCS
/// Send Data Indication (MS-RDPBCGR 2.2.6.1).
///
/// Everything the mock sends fits one chunk. A client that only handled the
/// single chunk case would still pass here, which is why
/// `crate::channels::tests` drives the multi chunk path separately.
fn channel_frame(channel_id: u16, body: &[u8]) -> Vec<u8> {
    let header = ChannelPduHeader {
        length: body.len() as u32,
        flags: channel_flags::FIRST | channel_flags::LAST,
    };
    let mut payload = Vec::with_capacity(ChannelPduHeader::LEN + body.len());
    header
        .encode(&mut Writer::new(&mut payload))
        .expect("the mock encodes what the client parses");
    payload.extend_from_slice(body);
    domain_frame(&DomainMcsPdu::SendDataIndication {
        initiator: SERVER_PDU_SOURCE,
        channel_id,
        payload: Payload::new(&payload),
    })
}

/// `CLIPRDR_CAPS` holding one `CLIPRDR_GENERAL_CAPABILITY` that agrees long
/// format names (MS-RDPECLIP 2.2.2.1.1.1).
fn general_capability() -> Vec<u8> {
    let mut body = Vec::new();
    let mut w = Writer::new(&mut body);
    w.u16(1); // cCapabilitiesSets
    w.u16(0); // pad1
    w.u16(0x0001); // CB_CAPSTYPE_GENERAL
    w.u16(12); // lengthCapability
    w.u32(0x0000_0002); // CB_CAPS_VERSION_2
    w.u32(0x0000_0002); // CB_USE_LONG_FORMAT_NAMES
    body
}

/// A long form `CLIPRDR_FORMAT_LIST` offering `CF_UNICODETEXT` and nothing
/// else (MS-RDPECLIP 2.2.3.1.2). A standard format has no name, so the name is
/// the two byte UTF-16 terminator.
fn unicode_text_format_list() -> Vec<u8> {
    let mut body = Vec::new();
    let mut w = Writer::new(&mut body);
    w.u32(CF_UNICODETEXT);
    w.u16(0);
    body
}

/// The format ids in a long form `CLIPRDR_FORMAT_LIST`
/// (MS-RDPECLIP 2.2.3.1.2).
fn long_format_ids(body: &[u8]) -> Vec<u32> {
    let mut ids = Vec::new();
    let mut r = Reader::new(body);
    while r.remaining() >= 4 {
        let Ok(id) = r.u32("formatId") else { break };
        ids.push(id);
        loop {
            match r.u16("formatName") {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => return ids,
            }
        }
    }
    ids
}

/// UTF-16LE with a NUL terminator, which is what `CF_UNICODETEXT` is
/// (MS-RDPECLIP 2.2.5.2).
fn utf16_nul(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2 + 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// The inverse of [`utf16_nul`].
fn from_utf16_nul(body: &[u8]) -> String {
    let units: Vec<u16> = body
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}
