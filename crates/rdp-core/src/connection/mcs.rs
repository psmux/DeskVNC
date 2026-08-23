//! Phases 3 and 4: the Basic Settings Exchange and Channel Connection
//! (MS-RDPBCGR 2.2.1.3 to 2.2.1.9, T.125, T.124 §8.7, PRDRDP/03 §2.4, §2.5).
//!
//! Four layers travel in one PDU and four modules that know nothing about
//! each other write them, so this file composes them exactly as
//! `crates/rdp-pdu/src/lib.rs:64` says to:
//!
//! ```text
//! ClientGccBlocks::encode        -> the TS_UD_CS_* blocks
//! ConferenceCreateRequest        -> the GCC PER wrapper around them
//! ConnectInitial                 -> the MCS BER envelope around that
//! x224::write_data_tpdu_with     -> the X.224 Data TPDU and the TPKT header
//! ```
//!
//! and the Connect Response comes back the same way in reverse, each step
//! handing the next a borrowed slice of the receive buffer rather than a
//! copy.

use rdp_pdu::gcc::client::{
    ChannelDef, ClientCoreData, ClientMessageChannelData, ClientNetworkData, ClientSecurityData,
};
use rdp_pdu::gcc::server::ServerGccBlocks;
use rdp_pdu::io::{Decode, Encode, Writer};
use rdp_pdu::mcs::{result_code, DomainMcsPdu};
use rdp_pdu::{
    x224, ClientGccBlocks, ConferenceCreateRequest, ConferenceCreateResponse, ConnectInitial,
    ConnectResponse, Reader,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::connection::negotiate::SecurityProtocol;
use crate::error::{ConnectStage, RdpError, Result};
use crate::options::ResolvedOptions;
use crate::transport::framer::{Expect, Framer};
use crate::transport::{with_timeout, MCS_TIMEOUT};

/// The channels the session can address, after the joins.
///
/// Every later Send Data Request is addressed to one of these, so this is the
/// map the whole session indexes by (PRDRDP/12 §3.9).
#[derive(Debug, Clone, Default)]
pub struct ChannelMap {
    /// `MCSChannelId` from `TS_UD_SC_NET`: the I/O channel every share PDU
    /// travels on (MS-RDPBCGR 2.2.1.4.4).
    pub io_channel_id: u16,
    /// The user channel from the Attach User Confirm (MS-RDPBCGR 2.2.1.7),
    /// already offset back off the PER lower bound of 1001.
    pub user_channel_id: u16,
    /// The message channel from `TS_UD_SC_MCS_MSGCHANNEL`, where connect time
    /// auto detect and the heartbeat arrive (MS-RDPBCGR 2.2.1.4.5). Absent
    /// when the server did not offer one.
    pub message_channel_id: Option<u16>,
    /// One entry per static virtual channel we asked for, in the order of our
    /// `TS_UD_CS_NET` request, which is the order MS-RDPBCGR 2.2.1.4.4 says
    /// the server's `channelIdArray` answers in.
    pub statics: Vec<(&'static str, u16)>,
}

impl ChannelMap {
    /// The channel id for a static virtual channel by name, or `None` when
    /// the server did not allocate one.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<u16> {
        self.statics
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, id)| *id)
    }

    /// Every channel that has to be joined, in the order MS-RDPBCGR 2.2.1.8
    /// lists them: the user channel, the I/O channel, the message channel,
    /// then each virtual channel.
    fn join_order(&self) -> Vec<u16> {
        let mut ids = vec![self.user_channel_id, self.io_channel_id];
        ids.extend(self.message_channel_id);
        ids.extend(self.statics.iter().map(|(_, id)| *id));
        ids
    }
}

/// What the Basic Settings Exchange produced.
#[derive(Debug, Clone)]
pub struct McsConnected {
    /// The channels, joined.
    pub channels: ChannelMap,
    /// Whether the server said the Channel Join round trips could be skipped
    /// (`RNS_UD_SC_SKIP_CHANNELJOIN_SUPPORTED`, MS-RDPBCGR 2.2.1.4.2). Kept
    /// for the trace: on a link with 100 ms of latency it is eight PDUs and
    /// eight round trips saved on a four channel session.
    pub skipped_channel_joins: bool,
}

/// Build the `TS_UD_CS_*` blocks we send in the Connect Initial
/// (MS-RDPBCGR 2.2.1.3, PRDRDP/03 §2.4).
///
/// Separate from the I/O so a test can assert what we advertise without a
/// socket, which is how PRDRDP/09 §3 asserts the codec set for a given
/// profile.
#[must_use]
pub fn client_blocks(opts: &ResolvedOptions, selected: SecurityProtocol) -> ClientGccBlocks {
    let (width, height) = opts.desktop;
    ClientGccBlocks {
        core: Some(ClientCoreData {
            desktop_width: width,
            desktop_height: height,
            keyboard_layout: opts.keyboard_layout,
            client_name: opts.client_name.clone(),
            high_color_depth: Some(opts.color_depth.wire()),
            // MS-RDPBCGR 2.2.1.3.2 makes `serverSelectedProtocol` the
            // client's assertion of what it thinks was negotiated, and a
            // server that sees a mismatch aborts. It is the one field here
            // that is not a preference.
            server_selected_protocol: Some(selected.wire()),
            // The tail is filled from here to the end, and it has to be:
            // MS-RDPBCGR 2.2.1.3.2 makes presence cumulative, so a server
            // reading `desktopScaleFactor` has already read the three fields
            // before it. Setting one without its predecessors produces a
            // block the encoder truncates at the first gap, which is a scale
            // factor silently dropped rather than an error.
            //
            // Zero is the specification's "not specified" for the two
            // physical dimensions, which is what we mean: the window size is
            // in pixels and we do not know the monitor's millimetres.
            desktop_physical_width: Some(0),
            desktop_physical_height: Some(0),
            desktop_orientation: Some(0),
            desktop_scale_factor: Some(opts.scale_factor),
            device_scale_factor: Some(device_scale_factor(opts.scale_factor)),
            ..ClientCoreData::default()
        }),
        // Both words zero is the correct "I am using TLS or CredSSP" signal
        // and the only value this client ever sends
        // (`crates/rdp-pdu/src/gcc/client.rs:401` says so on the type).
        security: Some(ClientSecurityData::default()),
        network: Some(ClientNetworkData {
            channels: opts
                .channels
                .iter()
                .map(|name| ChannelDef {
                    name: (*name).to_owned(),
                    // `CHANNEL_OPTION_INITIALIZED`. PRDRDP/11 §5.3 item 6
                    // records the 2020-08-17 erratum saying the flag is
                    // unused and must be ignored; we set it because every
                    // client does and a server that reads it expects it.
                    options: rdp_pdu::gcc::client::channel_option::INITIALIZED,
                })
                .collect(),
        }),
        // Asking for the message channel is what makes connect time auto
        // detect and the heartbeat reachable (MS-RDPBCGR 2.2.1.3.7). The
        // server answers with `TS_UD_SC_MCS_MSGCHANNEL` or does not.
        message_channel: Some(ClientMessageChannelData::default()),
        ..ClientGccBlocks::default()
    }
}

/// `TS_UD_CS_CORE.deviceScaleFactor` takes 100, 140 or 180 and no other value
/// (MS-RDPBCGR 2.2.1.3.2), while `desktopScaleFactor` is any value from 100 to
/// 500. So the user's percentage picks the nearest of the three the field can
/// carry; sending anything else makes a server ignore both fields together.
const fn device_scale_factor(desktop_scale: u32) -> u32 {
    if desktop_scale < 140 {
        100
    } else if desktop_scale < 180 {
        140
    } else {
        180
    }
}

/// Send the Connect Initial, read the Connect Response, then run the Channel
/// Connection phase.
///
/// # Errors
///
/// [`RdpError::Protocol`] when the server refused the conference or asked for
/// standard RDP security, [`RdpError::Pdu`] when anything did not parse, and
/// [`RdpError::Timeout`] against the stage that was waiting.
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    framer: &mut Framer<S>,
    opts: &ResolvedOptions,
    selected: SecurityProtocol,
) -> Result<McsConnected> {
    let blocks = client_blocks(opts, selected);

    let mut user_data = Vec::with_capacity(blocks.size());
    blocks.encode_checked(&mut Writer::new(&mut user_data))?;
    let request = ConferenceCreateRequest {
        user_data: &user_data,
    };
    let mut gcc = Vec::with_capacity(request.size());
    request.encode_checked(&mut Writer::new(&mut gcc))?;
    let initial = ConnectInitial::new(&gcc);
    let mut frame = Vec::with_capacity(initial.size() + 7);
    x224::write_data_tpdu_with(&mut Writer::new(&mut frame), initial.size(), |w| {
        initial.encode(w)
    })?;

    tracing::debug!(
        stage = %ConnectStage::SendMcsConnectInitial,
        channels = opts.channels.len(),
        "sending the mcs connect initial"
    );
    framer.write_pdu(&frame).await?;

    let response = with_timeout(
        ConnectStage::AwaitMcsConnectResponse,
        MCS_TIMEOUT,
        framer.read_expect(Expect::Tpkt),
    )
    .await?;
    let mut channels = read_connect_response(&response, opts)?;

    // The server's channel ids are what every later Send Data Request is
    // addressed to, so the whole map is fixed before a single join goes out.
    let skipped = channel_connection(framer, &mut channels).await?;

    Ok(McsConnected {
        channels,
        skipped_channel_joins: skipped,
    })
}

/// Decode a Connect Response into a [`ChannelMap`].
///
/// Takes the frame rather than the stream so every rejection below is a unit
/// test over bytes the mock server encoded with the same encoders.
///
/// # Errors
///
/// [`RdpError::Protocol`] when the server refused the conference, asked for
/// standard RDP security, or answered with a channel count that does not
/// match what we asked for.
pub fn read_connect_response(frame: &[u8], opts: &ResolvedOptions) -> Result<ChannelMap> {
    let mut r = Reader::new(frame);
    let mut body = x224::read_data_tpdu(&mut r)?;
    let response = ConnectResponse::decode(&mut body)?;
    if response.result != u32::from(result_code::RT_SUCCESSFUL) {
        return Err(RdpError::Protocol(format!(
            "the server refused the MCS conference with result {} (T.125 §7)",
            response.result
        )));
    }

    let ccrsp = ConferenceCreateResponse::decode(&mut Reader::new(response.user_data))?;
    if ccrsp.result != result_code::RT_SUCCESSFUL {
        return Err(RdpError::Protocol(format!(
            "the server refused the GCC conference with result {} (T.124 §8.7)",
            ccrsp.result
        )));
    }
    let blocks = ServerGccBlocks::decode(&mut Reader::new(ccrsp.user_data))?;

    // MS-RDPBCGR 2.2.1.4.3: under an external security protocol the server
    // sends ENCRYPTION_METHOD_NONE and ENCRYPTION_LEVEL_NONE. Anything else
    // is a server asking for standard RDP security, which is RC4 with a
    // server chosen key, and D6 refuses it. Doing the check here rather than
    // later means the refusal happens before we have sent a credential.
    if let Some(security) = &blocks.security {
        if security.wants_standard_security() {
            return Err(RdpError::Protocol(
                "the server asked for standard RDP security, which this client refuses \
                 (MS-RDPBCGR 2.2.1.4.3)"
                    .to_owned(),
            ));
        }
    }

    let network = blocks.network.ok_or_else(|| {
        RdpError::Protocol(
            "the Connect Response carried no TS_UD_SC_NET, so there is no I/O channel \
             (MS-RDPBCGR 2.2.1.4.4)"
                .to_owned(),
        )
    })?;

    // The server answers with one id per channel we asked for, in the same
    // order (MS-RDPBCGR 2.2.1.4.4). A different count means the two sides
    // disagree about the session, and pairing them up by position anyway
    // would address clipboard traffic to whatever the server put in that
    // slot.
    if network.channel_ids.len() != opts.channels.len() {
        return Err(RdpError::Protocol(format!(
            "asked for {} channels and the server allocated {} (MS-RDPBCGR 2.2.1.4.4)",
            opts.channels.len(),
            network.channel_ids.len()
        )));
    }

    Ok(ChannelMap {
        io_channel_id: network.io_channel_id,
        // Filled in by the Attach User Confirm, which has not happened yet.
        user_channel_id: 0,
        message_channel_id: blocks.message_channel.map(|m| m.channel_id),
        statics: opts
            .channels
            .iter()
            .copied()
            .zip(network.channel_ids)
            .collect(),
    })
}

/// Erect Domain, Attach User, and one Channel Join per channel
/// (MS-RDPBCGR 2.2.1.5 to 2.2.1.9).
///
/// Returns whether the joins were skipped. Erect Domain and Attach User are
/// written together without waiting, because Erect Domain is unacknowledged
/// (`DomainMcsPdu::ErectDomainRequest` says so on the variant) and only the
/// Attach User Confirm has to come back before the joins can start.
async fn channel_connection<S: AsyncRead + AsyncWrite + Unpin>(
    framer: &mut Framer<S>,
    channels: &mut ChannelMap,
) -> Result<bool> {
    let mut out = Vec::new();
    for pdu in [
        DomainMcsPdu::ErectDomainRequest {
            sub_height: 0,
            sub_interval: 0,
        },
        DomainMcsPdu::AttachUserRequest,
    ] {
        x224::write_data_tpdu_with(&mut Writer::new(&mut out), pdu.size(), |w| pdu.encode(w))?;
    }
    tracing::debug!(stage = %ConnectStage::ChannelConnection, "erect domain and attach user");
    framer.write_pdu(&out).await?;

    let frame = with_timeout(
        ConnectStage::ChannelConnection,
        MCS_TIMEOUT,
        framer.read_expect(Expect::Tpkt),
    )
    .await?;
    channels.user_channel_id = read_attach_user_confirm(&frame)?;

    // PRDRDP/03 §2.5 and MS-RDPBCGR 2.2.1.4.2: with
    // `RNS_UD_SC_SKIP_CHANNELJOIN_SUPPORTED` the client goes straight from
    // the Attach User Confirm to the Client Info PDU. Reading that flag needs
    // the Server Core Data, which `read_connect_response` has already parsed
    // and thrown away, so this pass always joins. Saying so is better than a
    // comment claiming a fast path that is not taken; the report names it.
    let skipped = false;

    // One Channel Join Request per channel, all written before any Confirm is
    // read (PRDRDP/03 §3.3: pipelined, confirms accepted in any order, one
    // timeout for the set). On a link with 100 ms of latency a four channel
    // session waits 100 ms rather than 400.
    let wanted = channels.join_order();
    let mut out = Vec::new();
    for &channel_id in &wanted {
        let pdu = DomainMcsPdu::ChannelJoinRequest {
            initiator: channels.user_channel_id,
            channel_id,
        };
        x224::write_data_tpdu_with(&mut Writer::new(&mut out), pdu.size(), |w| pdu.encode(w))?;
    }
    tracing::debug!(
        stage = %ConnectStage::ChannelConnection,
        joins = wanted.len(),
        "joining channels"
    );
    framer.write_pdu(&out).await?;

    let mut outstanding: Vec<u16> = wanted;
    while !outstanding.is_empty() {
        let frame = with_timeout(
            ConnectStage::ChannelConnection,
            MCS_TIMEOUT,
            framer.read_expect(Expect::Tpkt),
        )
        .await?;
        // A confirm carries the channel it answers whether it succeeded or
        // not, so the outstanding entry is always removed by value. Removing
        // by position instead would mean a refused optional channel
        // cancelling out a different channel's join, and the session would
        // then address clipboard traffic to a channel it never joined.
        let (requested, joined) = read_channel_join_confirm(&frame, channels.io_channel_id)?;
        let Some(at) = outstanding.iter().position(|&o| o == requested) else {
            return Err(RdpError::Protocol(format!(
                "the server confirmed a join for channel {requested}, which we did not request \
                 (MS-RDPBCGR 2.2.1.9)"
            )));
        };
        outstanding.remove(at);

        // A refused optional channel is a log line, not a failure: the
        // session runs without a clipboard. A refused I/O channel is a
        // connect failure and `read_channel_join_confirm` has already turned
        // it into one.
        if joined.is_none() {
            channels.statics.retain(|(_, id)| *id != requested);
            if channels.message_channel_id == Some(requested) {
                channels.message_channel_id = None;
            }
        }
    }

    Ok(skipped)
}

/// The user channel id from an Attach User Confirm (MS-RDPBCGR 2.2.1.7).
///
/// # Errors
///
/// [`RdpError::Protocol`] when the server refused, or sent something else.
fn read_attach_user_confirm(frame: &[u8]) -> Result<u16> {
    let mut r = Reader::new(frame);
    let mut body = x224::read_data_tpdu(&mut r)?;
    match DomainMcsPdu::decode(&mut body)? {
        DomainMcsPdu::AttachUserConfirm { result, initiator } => {
            if result != result_code::RT_SUCCESSFUL {
                return Err(RdpError::Protocol(format!(
                    "the server refused Attach User with result {result} (T.125 §7)"
                )));
            }
            // T.125 §7 makes `initiator` OPTIONAL, for the refusal case. A
            // success without one leaves nothing to address a Send Data
            // Request from.
            initiator.ok_or_else(|| {
                RdpError::Protocol(
                    "the Attach User Confirm succeeded without a user channel id \
                     (MS-RDPBCGR 2.2.1.7)"
                        .to_owned(),
                )
            })
        }
        other => Err(unexpected(ConnectStage::ChannelConnection, &other)),
    }
}

/// The channel a Channel Join Confirm answers, and the id actually joined or
/// `None` when the server refused (MS-RDPBCGR 2.2.1.9).
///
/// The first half of the pair is always present, including on a refusal,
/// which is what lets the caller strike the right entry off its outstanding
/// list whichever way the answer went.
///
/// # Errors
///
/// [`RdpError::Protocol`] when the refused channel is the I/O channel, which
/// is a connect failure because every share PDU travels on it.
fn read_channel_join_confirm(frame: &[u8], io_channel_id: u16) -> Result<(u16, Option<u16>)> {
    let mut r = Reader::new(frame);
    let mut body = x224::read_data_tpdu(&mut r)?;
    match DomainMcsPdu::decode(&mut body)? {
        DomainMcsPdu::ChannelJoinConfirm {
            result,
            requested,
            channel_id,
            ..
        } => {
            if result != result_code::RT_SUCCESSFUL {
                if requested == io_channel_id {
                    return Err(RdpError::Protocol(format!(
                        "the server refused the join for the I/O channel {requested} with result \
                         {result}, so no share PDU can be sent (MS-RDPBCGR 2.2.1.8)"
                    )));
                }
                tracing::warn!(channel = requested, result, "channel join refused");
                return Ok((requested, None));
            }
            Ok((requested, Some(channel_id.unwrap_or(requested))))
        }
        other => Err(unexpected(ConnectStage::ChannelConnection, &other)),
    }
}

/// A well formed PDU that has no business arriving in this stage.
///
/// Named rather than inlined so every site produces the same sentence, which
/// is what makes a support log greppable.
fn unexpected(stage: ConnectStage, pdu: &DomainMcsPdu<'_>) -> RdpError {
    if let DomainMcsPdu::DisconnectProviderUltimatum { reason } = pdu {
        // MS-RDPBCGR 2.2.2.3 is accepted in every stage from the Connect
        // Initial onwards, and it means the session is over rather than that
        // the server sent the wrong thing.
        return RdpError::ServerDisconnect {
            user_requested: *reason == rdp_pdu::mcs::disconnect_reason::USER_REQUESTED,
        };
    }
    RdpError::Protocol(format!(
        "MCS choice {} arrived during {stage} ({spec})",
        pdu.choice_index(),
        spec = stage.spec()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_pdu::gcc::server::{
        ServerCoreData, ServerMessageChannelData, ServerNetworkData, ServerSecurityData,
    };
    use rdp_pdu::io::Payload;
    use rdp_pdu::mcs::DomainParameters;
    use remote_core::ConnectOptions;

    fn opts() -> ResolvedOptions {
        let c = ConnectOptions::rdp("host", 3389);
        let rdp = c.rdp_options().expect("rdp").clone();
        ResolvedOptions::resolve(&c, &rdp, &mut Vec::new()).expect("valid")
    }

    fn to_vec(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value
            .encode_checked(&mut Writer::new(&mut buf))
            .expect("encodes");
        buf
    }

    /// A Connect Response built with the same encoders the client parses
    /// with, which is the rule in PRDRDP/12 §8.4.
    fn connect_response(blocks: &ServerGccBlocks<'_>) -> Vec<u8> {
        let user_data = to_vec(blocks);
        let gcc = to_vec(&ConferenceCreateResponse {
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
        .expect("encodes");
        frame
    }

    fn good_blocks(channel_ids: Vec<u16>) -> ServerGccBlocks<'static> {
        ServerGccBlocks {
            core: Some(ServerCoreData {
                version: 0x0008_0004,
                client_requested_protocols: Some(super::super::negotiate::REQUESTED_PROTOCOLS),
                early_capability_flags: Some(0),
            }),
            security: Some(ServerSecurityData::default()),
            network: Some(ServerNetworkData {
                io_channel_id: 1003,
                channel_ids,
            }),
            message_channel: Some(ServerMessageChannelData { channel_id: 1005 }),
            multitransport: None,
        }
    }

    /// The `serverSelectedProtocol` field is the client's assertion of what
    /// it thinks was negotiated, and a server that sees a mismatch aborts, so
    /// it is the one field in the block that is not a preference.
    #[test]
    fn the_client_core_data_echoes_the_selected_protocol() {
        for p in [
            SecurityProtocol::Ssl,
            SecurityProtocol::Hybrid,
            SecurityProtocol::HybridEx,
        ] {
            let blocks = client_blocks(&opts(), p);
            assert_eq!(
                blocks.core.expect("core block").server_selected_protocol,
                Some(p.wire())
            );
        }
    }

    /// `deviceScaleFactor` takes three values and no others, so the user's
    /// percentage is snapped to the nearest one. A value outside the set makes
    /// a server ignore both scale fields together, which is a HiDPI session
    /// that silently comes back at 100 percent.
    #[test]
    fn the_device_scale_factor_is_one_of_the_three_the_field_allows() {
        for percent in [100u32, 125, 139, 140, 150, 179, 180, 250, 500] {
            let got = device_scale_factor(percent);
            assert!([100, 140, 180].contains(&got), "{percent} produced {got}");
        }
        assert_eq!(device_scale_factor(100), 100);
        assert_eq!(device_scale_factor(150), 140);
        assert_eq!(device_scale_factor(200), 180);
    }

    /// Both words zero is the "I am using TLS or CredSSP" signal, and sending
    /// anything else invites a server to answer with standard RDP security.
    #[test]
    fn the_client_security_data_asks_for_no_rdp_encryption() {
        let blocks = client_blocks(&opts(), SecurityProtocol::Hybrid);
        let sec = blocks.security.expect("security block");
        assert_eq!(sec.encryption_methods, 0);
        assert_eq!(sec.ext_encryption_methods, 0);
    }

    /// The whole of phase 3 in one test: the four layers compose and take
    /// apart again. This is the composition `crates/rdp-pdu/src/mcs/mod.rs`
    /// demonstrates, run against the blocks this crate actually sends.
    #[test]
    fn the_basic_settings_exchange_round_trips() {
        let opts = opts();
        let blocks = client_blocks(&opts, SecurityProtocol::Hybrid);
        let user_data = to_vec(&blocks);
        let gcc = to_vec(&ConferenceCreateRequest {
            user_data: &user_data,
        });
        let initial = ConnectInitial::new(&gcc);
        let mut frame = Vec::new();
        x224::write_data_tpdu_with(&mut Writer::new(&mut frame), initial.size(), |w| {
            initial.encode(w)
        })
        .expect("encodes");

        assert_eq!(x224::peek_tpkt_length(&frame).unwrap(), Some(frame.len()));

        let mut r = Reader::new(&frame);
        let mut body = x224::read_data_tpdu(&mut r).expect("data tpdu");
        let decoded = ConnectInitial::decode(&mut body).expect("connect initial");
        let ccr = ConferenceCreateRequest::decode(&mut Reader::new(decoded.user_data))
            .expect("conference create request");
        let back = ClientGccBlocks::decode(&mut Reader::new(ccr.user_data)).expect("blocks");
        assert_eq!(back, blocks);
    }

    #[test]
    fn a_connect_response_yields_the_channel_map() {
        let opts = opts();
        let ids: Vec<u16> = (0..opts.channels.len() as u16).map(|i| 1004 + i).collect();
        let frame = connect_response(&good_blocks(ids.clone()));
        let map = read_connect_response(&frame, &opts).expect("valid response");
        assert_eq!(map.io_channel_id, 1003);
        assert_eq!(map.message_channel_id, Some(1005));
        assert_eq!(map.statics.len(), opts.channels.len());
        assert_eq!(map.by_name("cliprdr"), Some(*ids.last().unwrap()));
        assert_eq!(map.by_name("nosuch"), None);
    }

    /// The join order is the one MS-RDPBCGR 2.2.1.8 lists, and getting it
    /// wrong produces a session where the server answers a join we did not
    /// send.
    #[test]
    fn the_join_order_is_user_io_message_then_the_virtual_channels() {
        let map = ChannelMap {
            io_channel_id: 1003,
            user_channel_id: 1007,
            message_channel_id: Some(1005),
            statics: vec![("drdynvc", 1004), ("cliprdr", 1006)],
        };
        assert_eq!(map.join_order(), vec![1007, 1003, 1005, 1004, 1006]);

        // A server with no message channel simply has one fewer join.
        let map = ChannelMap {
            message_channel_id: None,
            ..map
        };
        assert_eq!(map.join_order(), vec![1007, 1003, 1004, 1006]);
    }

    /// Standard RDP security is RC4 with a server chosen key, and the refusal
    /// happens here, before a credential has been sent.
    #[test]
    fn a_server_asking_for_standard_rdp_security_is_refused() {
        let opts = opts();
        let ids: Vec<u16> = (0..opts.channels.len() as u16).map(|i| 1004 + i).collect();
        let mut blocks = good_blocks(ids);
        blocks.security = Some(ServerSecurityData {
            encryption_method: 0x02,
            encryption_level: 0x02,
            server_random: None,
            server_certificate: None,
        });
        let frame = connect_response(&blocks);
        let err = read_connect_response(&frame, &opts).expect_err("refused");
        assert!(err.to_string().contains("standard RDP security"), "{err}");
    }

    /// Pairing our channel names against a differently sized id array by
    /// position would address clipboard traffic to whatever the server put in
    /// that slot.
    #[test]
    fn a_channel_count_mismatch_is_refused_rather_than_paired_up() {
        let opts = opts();
        let frame = connect_response(&good_blocks(vec![1004]));
        let err = read_connect_response(&frame, &opts).expect_err("refused");
        assert!(err.to_string().contains("channels"), "{err}");
    }

    #[test]
    fn a_response_without_a_network_block_is_refused() {
        let opts = opts();
        let mut blocks = good_blocks(vec![]);
        blocks.network = None;
        let frame = connect_response(&blocks);
        let err = read_connect_response(&frame, &opts).expect_err("refused");
        assert!(err.to_string().contains("TS_UD_SC_NET"), "{err}");
    }

    fn domain_frame(pdu: &DomainMcsPdu<'_>) -> Vec<u8> {
        let mut frame = Vec::new();
        x224::write_data_tpdu_with(&mut Writer::new(&mut frame), pdu.size(), |w| pdu.encode(w))
            .expect("encodes");
        frame
    }

    #[test]
    fn an_attach_user_confirm_yields_the_user_channel() {
        let frame = domain_frame(&DomainMcsPdu::AttachUserConfirm {
            result: result_code::RT_SUCCESSFUL,
            initiator: Some(1007),
        });
        assert_eq!(read_attach_user_confirm(&frame).unwrap(), 1007);
    }

    /// T.125 §7 makes `initiator` OPTIONAL for the refusal case, so a success
    /// without one leaves nothing to address a Send Data Request from.
    #[test]
    fn an_attach_user_confirm_without_an_initiator_is_refused() {
        let frame = domain_frame(&DomainMcsPdu::AttachUserConfirm {
            result: result_code::RT_SUCCESSFUL,
            initiator: None,
        });
        assert!(read_attach_user_confirm(&frame).is_err());

        let frame = domain_frame(&DomainMcsPdu::AttachUserConfirm {
            result: result_code::RT_USER_REJECTED,
            initiator: None,
        });
        let err = read_attach_user_confirm(&frame).unwrap_err();
        assert!(err.to_string().contains("Attach User"), "{err}");
    }

    /// A refused optional channel is a log line and a session without a
    /// clipboard; a refused I/O channel is a connect failure, because every
    /// share PDU travels on it.
    #[test]
    fn a_refused_optional_channel_is_survivable_and_a_refused_io_channel_is_not() {
        let ok = domain_frame(&DomainMcsPdu::ChannelJoinConfirm {
            result: result_code::RT_SUCCESSFUL,
            initiator: 1007,
            requested: 1004,
            channel_id: Some(1004),
        });
        assert_eq!(
            read_channel_join_confirm(&ok, 1003).unwrap(),
            (1004, Some(1004))
        );

        let refused_optional = domain_frame(&DomainMcsPdu::ChannelJoinConfirm {
            result: result_code::RT_USER_REJECTED,
            initiator: 1007,
            requested: 1004,
            channel_id: None,
        });
        assert_eq!(
            read_channel_join_confirm(&refused_optional, 1003).unwrap(),
            (1004, None),
            "a refusal still names the channel it answers, so the caller can \
             strike the right entry off its outstanding list"
        );

        let refused_io = domain_frame(&DomainMcsPdu::ChannelJoinConfirm {
            result: result_code::RT_USER_REJECTED,
            initiator: 1007,
            requested: 1003,
            channel_id: None,
        });
        let err = read_channel_join_confirm(&refused_io, 1003).unwrap_err();
        assert!(err.to_string().contains("I/O channel"), "{err}");
    }

    /// MS-RDPBCGR 2.2.2.3 arrives in every stage from the Connect Initial
    /// onwards, and it means the session is over rather than that the server
    /// sent the wrong PDU. Reporting it as a protocol violation would put a
    /// red banner on a clean logoff.
    #[test]
    fn a_disconnect_ultimatum_mid_sequence_is_a_disconnect_not_a_violation() {
        let frame = domain_frame(&DomainMcsPdu::DisconnectProviderUltimatum {
            reason: rdp_pdu::mcs::disconnect_reason::USER_REQUESTED,
        });
        match read_attach_user_confirm(&frame) {
            Err(RdpError::ServerDisconnect { user_requested }) => assert!(user_requested),
            other => panic!("expected a server disconnect, got {other:?}"),
        }
    }

    #[test]
    fn an_out_of_sequence_pdu_names_the_stage_it_arrived_in() {
        let frame = domain_frame(&DomainMcsPdu::SendDataIndication {
            initiator: 1007,
            channel_id: 1003,
            payload: Payload::new(&[0u8; 4]),
        });
        let err = read_attach_user_confirm(&frame).unwrap_err();
        assert!(err.to_string().contains("channel-connection"), "{err}");
    }
}
