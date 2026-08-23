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

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rdp_pdu::gcc::server::{
    ServerCoreData, ServerMessageChannelData, ServerNetworkData, ServerSecurityData,
};
use rdp_pdu::io::{Decode, Encode, Writer};
use rdp_pdu::mcs::{result_code, DomainMcsPdu};
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
}

impl Default for MockConfig {
    /// A server that does what a Windows host with NLA turned off does: TLS
    /// only, every channel allocated, every join confirmed.
    fn default() -> Self {
        Self {
            negotiation: Negotiation::Select(security_protocol::SSL),
            mcs: McsBehaviour::Normal,
            skip_channel_join: false,
            message_channel: true,
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

    // The client's next PDU would be the Client Info (MS-RDPBCGR 2.2.1.11).
    // It has none, so it hangs up, and whatever arrives here is recorded so a
    // test can assert the teardown was ordered.
    while let Ok(frame) = read_tpkt(&mut stream).await {
        let mut r = Reader::new(&frame);
        if let Ok(mut body) = x224::read_data_tpdu(&mut r) {
            if let Ok(DomainMcsPdu::DisconnectProviderUltimatum { reason }) =
                DomainMcsPdu::decode(&mut body)
            {
                recorded.lock().expect("not poisoned").client_disconnect = Some(reason);
            }
        }
    }
    Ok(())
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
