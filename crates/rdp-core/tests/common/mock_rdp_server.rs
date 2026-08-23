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
use rdp_pdu::rdp::capabilities::InputCapabilitySet;
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
use rdp_pdu::update::{BitmapData, BitmapUpdate, RectInclusive};
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
        return drain(&mut stream, &recorded).await;
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
            return drain(&mut stream, &recorded).await;
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
    let capabilities = CapabilitySets::client_defaults(
        SERVER_DESKTOP.0,
        SERVER_DESKTOP.1,
        SERVER_PDU_SOURCE,
        InputCapabilitySet::client(0x0409, 4, 0, 12),
        false,
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

    // ---- The live session: one bitmap update on the fast path -----------
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

    drain(&mut stream, &recorded).await
}

/// Read until the client hangs up, recording the input events and the
/// disconnect ultimatum.
///
/// The mock's own framer for the two framings, deliberately naive and
/// deliberately not shared with the client's: TPKT's first byte is version 3
/// and a fast path header's low two bits are the action code, which is how
/// MS-RDPBCGR 2.2.9.1.2 arranges for them to be told apart.
async fn drain(stream: &mut TcpStream, recorded: &Arc<Mutex<Recorded>>) -> std::io::Result<()> {
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
                if let Ok(DomainMcsPdu::DisconnectProviderUltimatum { reason }) =
                    DomainMcsPdu::decode(&mut body)
                {
                    recorded.lock().expect("not poisoned").client_disconnect = Some(reason);
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
