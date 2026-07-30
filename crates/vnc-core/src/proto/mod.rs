//! RFB protocol engine: version negotiation, message framing, the
//! ClientInit/ServerInit handshake, and pseudo-encoding rectangles.
//!
//! The session module drives these pieces; the security and encodings modules
//! plug in for authentication and rect payload decoding respectively.

pub mod handshake;
pub mod messages;
pub mod pseudo;
pub mod version;

pub use handshake::{
    build_capabilities, read_server_init, read_tight_server_capabilities, write_client_init,
    ServerInit, TightCapability, TightServerCapabilities,
};
pub use messages::{CutTextPayload, Screen};
pub use pseudo::{is_pseudo, PseudoRect};
pub use version::{negotiate, parse_server_banner, NegotiatedVersion, ProtocolVersion};
