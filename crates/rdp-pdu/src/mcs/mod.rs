//! MCS: the BER connect envelope and the PER domain PDUs
//! (PRDRDP/13 §4.2, T.125 §7, MS-RDPBCGR 2.2.1.3 to 2.2.1.9 and 2.2.2).
//!
//! T.125 uses two encodings in one protocol and the split falls exactly on
//! the connect exchange. `Connect-Initial` and `Connect-Response` are BER
//! (T.125 §11.1 to §11.4), and everything after them is the `DomainMCSPDU`
//! CHOICE in aligned PER (T.125 §7). [`connect`] holds the first,
//! [`domain`] the second.
//!
//! Nothing in this module writes a TPKT header or an X.224 Data TPDU. Every
//! MCS PDU travels inside one, and the session wraps them with
//! [`x224::write_data_tpdu_with`](crate::x224::write_data_tpdu_with), so a
//! caller that wants the bytes for a fuzz corpus or a golden vector gets the
//! MCS PDU alone.

pub mod connect;
pub mod domain;

pub use connect::{ConnectInitial, ConnectResponse, DomainParameters};
pub use domain::DomainMcsPdu;

/// The `DomainMCSPDU` CHOICE indices this crate meets (T.125 §7).
///
/// The CHOICE has fewer than 64 alternatives and no extension marker, so PER
/// encodes the index in the top six bits of the first octet and the chosen
/// alternative's own bits follow in the low two (X.691 §23). Every constant
/// here is the index, not the octet: the octet is `index << 2` plus whatever
/// the alternative puts in the two bits below it.
pub mod choice {
    /// `erectDomainRequest` (MS-RDPBCGR 2.2.1.5).
    pub const ERECT_DOMAIN_REQUEST: u8 = 1;
    /// `disconnectProviderUltimatum` (MS-RDPBCGR 2.2.2.3).
    pub const DISCONNECT_PROVIDER_ULTIMATUM: u8 = 8;
    /// `attachUserRequest` (MS-RDPBCGR 2.2.1.6).
    pub const ATTACH_USER_REQUEST: u8 = 10;
    /// `attachUserConfirm` (MS-RDPBCGR 2.2.1.7).
    pub const ATTACH_USER_CONFIRM: u8 = 11;
    /// `channelJoinRequest` (MS-RDPBCGR 2.2.1.8).
    pub const CHANNEL_JOIN_REQUEST: u8 = 14;
    /// `channelJoinConfirm` (MS-RDPBCGR 2.2.1.9).
    pub const CHANNEL_JOIN_CONFIRM: u8 = 15;
    /// `sendDataRequest` (MS-RDPBCGR 2.2.1.13.2.1).
    pub const SEND_DATA_REQUEST: u8 = 25;
    /// `sendDataIndication` (MS-RDPBCGR 2.2.1.13.3.1).
    pub const SEND_DATA_INDICATION: u8 = 26;
}

/// `Result ::= ENUMERATED` (T.125 §7), carried by the Connect Response, the
/// Attach User Confirm and the Channel Join Confirm.
///
/// Sixteen values, which is why PER gives the field four bits. Only the first
/// matters to the connection sequence: anything else is a refusal that
/// PRDRDP/03 turns into a message. The full enum with its display strings
/// belongs to `codes/` (PRDRDP/13 §8); these constants are here so this
/// module can name the one value it checks without waiting for it.
pub mod result_code {
    /// `rt-successful`, and the only value a connection proceeds from.
    pub const RT_SUCCESSFUL: u8 = 0;
    /// `rt-user-rejected`.
    pub const RT_USER_REJECTED: u8 = 15;
    /// The number of values the ENUMERATED has, which is what fixes the
    /// field at four bits.
    pub const COUNT: u8 = 16;
}

/// `Reason ::= ENUMERATED` of a Disconnect Provider Ultimatum (T.125 §7,
/// surfaced by MS-RDPBCGR 2.2.2.3).
///
/// Five values, so PER gives the field three bits. PRDRDP/06 maps them onto
/// the session's teardown paths and `codes/` will own the enum.
pub mod disconnect_reason {
    /// `rn-domain-disconnected`.
    pub const DOMAIN_DISCONNECTED: u8 = 0;
    /// `rn-provider-initiated`.
    pub const PROVIDER_INITIATED: u8 = 1;
    /// `rn-token-purged`.
    pub const TOKEN_PURGED: u8 = 2;
    /// `rn-user-requested`, which is what a client sends when it hangs up.
    pub const USER_REQUESTED: u8 = 3;
    /// `rn-channel-purged`.
    pub const CHANNEL_PURGED: u8 = 4;
    /// The number of values the ENUMERATED has, which fixes the field at
    /// three bits.
    pub const COUNT: u8 = 5;
}

/// The lower bound of `UserId ::= DynamicChannelId ::= INTEGER (1001..65535)`
/// (T.125 §7).
///
/// PER encodes a constrained integer as its offset from the lower bound, so
/// the two octets on the wire are `userId - 1001`. Decoding adds it back, and
/// every user id this crate hands to the session is the real channel id: a
/// wire layer that leaves an offset in place produces a Channel Join Request
/// for a channel that does not exist and a debugging session.
pub const MCS_USER_ID_BASE: u32 = 1001;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;
    use crate::gcc::client::{
        ChannelDef, ClientCoreData, ClientMessageChannelData, ClientNetworkData, ClientSecurityData,
    };
    use crate::gcc::server::{
        ServerCoreData, ServerMessageChannelData, ServerNetworkData, ServerSecurityData,
    };
    use crate::gcc::{
        ClientGccBlocks, ConferenceCreateRequest, ConferenceCreateResponse, ServerGccBlocks,
    };
    use crate::io::{Decode, Encode, Payload, Reader, Writer};
    use crate::x224;

    fn to_vec(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        buf
    }

    /// The whole of phase 3 in both directions, composed the way PRDRDP/03
    /// §2.4 composes it and taken apart again: X.224 Data TPDU, BER connect
    /// envelope, PER conference PDU, user data blocks.
    ///
    /// The four layers are written by four modules that know nothing about
    /// each other, so this is the test that catches a length field counted
    /// from the wrong place.
    #[test]
    fn the_basic_settings_exchange_composes_and_decodes_back() {
        let blocks = ClientGccBlocks {
            core: Some(ClientCoreData {
                client_name: "RUSTCLIENT".to_owned(),
                server_selected_protocol: Some(crate::x224::security_protocol::HYBRID),
                ..ClientCoreData::default()
            }),
            security: Some(ClientSecurityData::default()),
            network: Some(ClientNetworkData {
                channels: vec![ChannelDef {
                    name: "cliprdr".to_owned(),
                    options: 0x8000_0000,
                }],
            }),
            message_channel: Some(ClientMessageChannelData::default()),
            ..ClientGccBlocks::default()
        };

        let user_data = to_vec(&blocks);
        let gcc = to_vec(&ConferenceCreateRequest {
            user_data: &user_data,
        });
        let initial = ConnectInitial::new(&gcc);
        let mut frame = Vec::new();
        x224::write_data_tpdu_with(&mut Writer::new(&mut frame), initial.size(), |w| {
            initial.encode(w)
        })
        .unwrap();
        assert_eq!(frame.len(), 7 + initial.size());
        assert_eq!(x224::peek_tpkt_length(&frame).unwrap(), Some(frame.len()));

        let mut r = Reader::new(&frame);
        let mut body = x224::read_data_tpdu(&mut r).unwrap();
        let decoded = ConnectInitial::decode(&mut body).unwrap();
        assert_eq!(decoded, initial);
        let ccr = ConferenceCreateRequest::decode(&mut Reader::new(decoded.user_data)).unwrap();
        assert_eq!(
            ClientGccBlocks::decode(&mut Reader::new(ccr.user_data)).unwrap(),
            blocks
        );

        // And the answer.
        let server_blocks = ServerGccBlocks {
            core: Some(ServerCoreData {
                version: 0x0008_0004,
                client_requested_protocols: Some(crate::x224::security_protocol::HYBRID),
                early_capability_flags: Some(0),
            }),
            security: Some(ServerSecurityData::default()),
            network: Some(ServerNetworkData {
                io_channel_id: 1003,
                channel_ids: vec![1004],
            }),
            message_channel: Some(ServerMessageChannelData { channel_id: 1005 }),
            multitransport: None,
        };
        let server_user_data = to_vec(&server_blocks);
        let gcc = to_vec(&ConferenceCreateResponse {
            node_id: 1002,
            tag: 1,
            result: 0,
            user_data: &server_user_data,
        });
        let response = ConnectResponse {
            result: result_code::RT_SUCCESSFUL.into(),
            called_connect_id: 0,
            domain_parameters: DomainParameters::TARGET,
            user_data: &gcc,
        };
        let mut frame = Vec::new();
        x224::write_data_tpdu_with(&mut Writer::new(&mut frame), response.size(), |w| {
            response.encode(w)
        })
        .unwrap();

        let mut r = Reader::new(&frame);
        let mut body = x224::read_data_tpdu(&mut r).unwrap();
        let decoded = ConnectResponse::decode(&mut body).unwrap();
        assert_eq!(decoded.result, 0);
        let ccrsp = ConferenceCreateResponse::decode(&mut Reader::new(decoded.user_data)).unwrap();
        assert_eq!(ccrsp.node_id, 1002);
        let back = ServerGccBlocks::decode(&mut Reader::new(ccrsp.user_data)).unwrap();
        assert_eq!(back, server_blocks);
        assert_eq!(back.network.unwrap().io_channel_id, 1003);
    }

    /// Phase 4, the same way: every domain PDU inside a Data TPDU.
    #[test]
    fn the_channel_connection_phase_composes_and_decodes_back() {
        let pdus = [
            DomainMcsPdu::ErectDomainRequest {
                sub_height: 0,
                sub_interval: 0,
            },
            DomainMcsPdu::AttachUserRequest,
            DomainMcsPdu::ChannelJoinRequest {
                initiator: 1007,
                channel_id: 1003,
            },
            DomainMcsPdu::SendDataRequest {
                initiator: 1007,
                channel_id: 1003,
                payload: Payload::new(&[0x41; 200]),
            },
        ];
        let mut stream = Vec::new();
        for pdu in &pdus {
            x224::write_data_tpdu_with(&mut Writer::new(&mut stream), pdu.size(), |w| {
                pdu.encode(w)
            })
            .unwrap();
        }

        let mut r = Reader::new(&stream);
        for expected in &pdus {
            let mut body = x224::read_data_tpdu(&mut r).unwrap();
            assert_eq!(&DomainMcsPdu::decode(&mut body).unwrap(), expected);
            body.expect_empty("DomainMCSPDU").unwrap();
        }
        assert!(r.is_empty());
    }
}
