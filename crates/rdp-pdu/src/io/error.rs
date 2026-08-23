//! The one error type this crate returns (PRDRDP/13 §2.3).

/// Everything that can go wrong turning bytes into a PDU.
///
/// Every variant carries enough to write one log line that identifies the
/// exact byte. `offset` is measured from the start of the buffer the
/// [`Reader`](crate::Reader) was created over, which the session sets to the
/// start of the PDU, so offsets in logs line up with a hex dump of the PDU.
/// A sub reader keeps the outer buffer's numbering, so a field inside a
/// nested structure still reports its absolute position.
///
/// `context` is a `&'static str` naming the structure being parsed, set by
/// the decoder that is running, for example `"TS_UD_CS_CORE"` or
/// `"RDPGFX_WIRE_TO_SURFACE_PDU_1"`. It is static rather than a `String` so
/// building an error costs nothing. `crates/vnc-core/src/proto/messages.rs`
/// line 112 uses `VncError::Protocol(format!(...))` at every site, which is
/// fine at RFB's message rate and wrong here: a fast path update PDU arrives
/// sixty times a second and a hostile server can otherwise make us format a
/// string per PDU.
///
/// The error owns no data, so it is `'static` and crosses into `rdp-core`
/// without a lifetime. `rdp-core` converts it with `#[from]` into
/// `RdpError::Pdu { structure, message }` (PRDRDP/12 §3.7), where `structure`
/// is this error's `context`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PduError {
    /// Ran out of bytes. `needed` is what the read wanted, `available` is
    /// what was left.
    #[error("{context}: need {needed} bytes at offset {offset}, {available} available")]
    Truncated {
        /// The structure being parsed.
        context: &'static str,
        /// Absolute offset of the read that failed.
        offset: usize,
        /// Bytes the read wanted.
        needed: usize,
        /// Bytes that were left.
        available: usize,
    },

    /// A field held a value the protocol does not define, or one we refuse.
    #[error("{context}: invalid {field} = {value:#x} at offset {offset}")]
    InvalidField {
        /// The structure being parsed.
        context: &'static str,
        /// The field's name, in the specification's own spelling.
        field: &'static str,
        /// The value that was rejected.
        value: u64,
        /// Absolute offset of the field.
        offset: usize,
    },

    /// A length field disagrees with the bytes that follow it.
    #[error("{context}: declared length {declared} but {actual} bytes remain at offset {offset}")]
    LengthMismatch {
        /// The structure being parsed.
        context: &'static str,
        /// What the length field said.
        declared: usize,
        /// What was actually there.
        actual: usize,
        /// Absolute offset of the length field or of the trailing bytes.
        offset: usize,
    },

    /// A declared length is legal per the specification but larger than we
    /// will accept. Always cites the constant that rejected it, so a log line
    /// names the knob (PRDRDP/13 §2.8, [`crate::io::limits`]).
    #[error("{context}: length {declared} exceeds cap {cap} ({limit_name}) at offset {offset}")]
    CapExceeded {
        /// The structure being parsed.
        context: &'static str,
        /// What the length field said.
        declared: usize,
        /// The cap that rejected it.
        cap: usize,
        /// The name of the constant holding `cap`.
        limit_name: &'static str,
        /// Absolute offset of the length field.
        offset: usize,
    },

    /// A type code, PDU type, command id or codec id we do not implement and
    /// cannot skip, because we do not know the length of what follows.
    ///
    /// This is the same rule `crates/vnc-core/src/encodings/mod.rs` arrived at
    /// for RFB encodings: its test `unknown_negative_encoding_is_unsupported`
    /// records that silently returning `Ok(None)` consumed zero bytes and
    /// desynced every rect that followed. An unknown enumerant whose length we
    /// do know is preserved rather than rejected (PRDRDP/13 §2.7 rule 3).
    #[error("{context}: unsupported {kind} {value:#x} at offset {offset}")]
    Unsupported {
        /// The structure being parsed.
        context: &'static str,
        /// What kind of code it was, for example `"pduType2"` or `"codecId"`.
        kind: &'static str,
        /// The code we do not implement.
        value: u64,
        /// Absolute offset of the code.
        offset: usize,
    },

    /// ASN.1 specific: a tag that is not the one the grammar requires.
    #[error("{context}: expected ASN.1 tag {expected:#x}, found {found:#x} at offset {offset}")]
    Asn1Tag {
        /// The structure being parsed.
        context: &'static str,
        /// The identifier octet the grammar requires.
        expected: u8,
        /// The identifier octet that was there.
        found: u8,
        /// Absolute offset of the identifier octet.
        offset: usize,
    },

    /// The encoder was asked to write something that cannot be represented,
    /// for example a virtual channel name longer than seven characters
    /// (MS-RDPBCGR 2.2.1.3.4.1) or a body longer than its length prefix.
    #[error("encode {context}: {reason}")]
    Encode {
        /// The structure being encoded.
        context: &'static str,
        /// Why it cannot be represented.
        reason: &'static str,
    },
}

/// The result of every read and every write in this crate.
pub type PduResult<T> = Result<T, PduError>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    #[test]
    fn truncated_names_the_structure_and_the_offset() {
        let e = PduError::Truncated {
            context: "TS_UD_CS_CORE",
            offset: 42,
            needed: 4,
            available: 1,
        };
        assert_eq!(
            e.to_string(),
            "TS_UD_CS_CORE: need 4 bytes at offset 42, 1 available"
        );
    }

    #[test]
    fn cap_exceeded_names_the_constant() {
        let e = PduError::CapExceeded {
            context: "CHANNEL_PDU_HEADER",
            declared: 1 << 30,
            cap: crate::io::limits::MAX_VC_REASSEMBLED,
            limit_name: "MAX_VC_REASSEMBLED",
            offset: 8,
        };
        assert!(e.to_string().contains("MAX_VC_REASSEMBLED"));
    }

    /// The error owns nothing, so it clones without allocating and can be
    /// stored in a session field that outlives the receive buffer.
    #[test]
    fn error_is_static_and_cheap_to_clone() {
        fn assert_static<T: 'static>(_: &T) {}
        let e = PduError::Encode {
            context: "CHANNEL_DEF",
            reason: "channel name longer than seven characters",
        };
        assert_static(&e);
        assert_eq!(e.clone(), e);
    }
}
