//! RDP wire formats: parsing and serialising the PDUs of MS-RDPBCGR and the
//! extension protocols the client speaks, with no I/O and no session state.
//!
//! Everything here is a pure function over bytes. A decoder takes a [`Reader`]
//! positioned at the first byte of a structure and returns either a typed
//! value or a [`PduError`] naming the offset and what was expected. An encoder
//! appends to a [`Writer`]. Nothing awaits, nothing allocates more than the
//! structure it returns, and nothing indexes remote data (D11).
//!
//! # Layering
//!
//! Each layer uses the one above it in this list and nothing below it
//! (PRDRDP/13 §2.9):
//!
//! * [`io`], the reader, writer, error and caps every other module is built
//!   on.
//! * [`asn1`], the three encoding rules RDP needs: BER for MCS, aligned PER
//!   for GCC, DER for CredSSP and certificates.
//! * `x224`, TPKT and X.224 framing.
//! * `mcs` and `gcc`, the connect PDUs and the user data blocks.
//! * `rdp`, share headers, capability sets and the connection PDUs.
//! * `input` and `update`, the per frame traffic.
//! * `vc`, static channel chunking, drdynvc and EGFX.
//! * `codes`, the ERRINFO table and the other code enums.
//!
//! # What is here today
//!
//! The foundation, [`io`] and [`asn1`], and the whole connection sequence up
//! to the Client Info PDU: [`x224`], [`mcs`] and [`gcc`]. Together those
//! three carry a client from the first byte on the socket to the end of MCS
//! channel connection (PRDRDP/03 §2.1 to §2.5).
//!
//! The modules above them are written per PRDRDP/13 §4.6 onwards and land in
//! this order, each declared here as it arrives so the crate compiles at
//! every commit:
//!
//! ```text
//! x224.rs       TPKT, CR/CC/DT, RDP_NEG_*                    §4.1  done
//! mcs/          Connect Initial and Response, domain PDUs    §4.2  done
//! gcc/          the TS_UD_CS_* and TS_UD_SC_* blocks         §4.3 to §4.5  done
//! rdp/          client info, licensing, capabilities, share  §4.6 onwards
//! input/        slow and fast path input                     §5.3, §5.4
//! update/       bitmap, palette, pointer, surface commands   §5.5 to §5.7
//! vc/           channel chunking, drdynvc, EGFX, segments    §6
//! codes/        ERRINFO, negotiation, licensing, logon       §7, §8
//! ```
//!
//! # Composing the connection sequence
//!
//! Each layer encodes itself and nothing else, and the session composes
//! them. A Connect Initial goes out like this (PRDRDP/03 §2.4):
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
//!
//! # What is deliberately absent
//!
//! No sockets, no `tokio`, no `async fn`, no state that outlives a single
//! PDU. No decompression, no pixel decoding, no cryptography. No policy: this
//! crate will encode a Client Info PDU with an empty password, because
//! deciding what to send is the session's job (PRDRDP/13 §1.2).

#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod asn1;
pub mod codes;
pub mod gcc;
pub mod input;
pub mod io;
pub mod mcs;
pub mod rdp;
pub mod update;
pub mod vc;
pub mod x224;

pub use gcc::{
    parse_server_certificate, ClientGccBlocks, ConferenceCreateRequest, ConferenceCreateResponse,
    ServerCertificate, ServerGccBlocks,
};
pub use io::error::{PduError, PduResult};
pub use io::reader::Reader;
pub use io::writer::Writer;
pub use io::{Decode, Encode, Payload};
pub use mcs::{ConnectInitial, ConnectResponse, DomainMcsPdu, DomainParameters};
pub use x224::{X224ConnectionConfirm, X224ConnectionRequest, X224Negotiation};

// The session PDUs, at the crate root so `rdp-core` does not have to spell the
// module path for the types it touches on every connection.
pub use codes::{ErrInfo, MultitransportProtocol};
// The virtual channel layer, at the crate root for the same reason: the
// session touches these on every EGFX frame.
pub use vc::dvc::{DvcPdu, DvcReassembler};
pub use vc::egfx::{Capset, EgfxPdu};
pub use vc::segment::{CompressedSegment, Segmented};
pub use vc::static_vc::{chunk_channel_pdu, ChannelPduHeader, ChannelReassembler};

pub use rdp::{
    decode_io_pdu, CapabilitySets, ClientInfoPdu, ConfirmActivePdu, DemandActivePdu, IoPdu,
    IoPduContext, LicensePdu, ShareDataPdu, SharePdu, SlowPathClass,
};
pub use rdp::{
    AutoDetectResponse, ClientCapabilitySupport, ClientInitiateMultitransportResponse,
    ClientSecurityExchange, SecretBytes, ServerInitiateMultitransportRequest,
    ServerRedirectionPacket,
};
