//! The primitives every other module is built on: the cursor, the appender,
//! the error, the caps, and the two traits a PDU implements.
//!
//! Nothing here knows what RDP is. Everything above it does.

pub mod error;
pub mod limits;
pub mod reader;
pub mod writer;

pub use error::{PduError, PduResult};
pub use reader::Reader;
pub use writer::Writer;

/// A structure that can be read from the wire.
///
/// The lifetime is the receive buffer's: a decoded structure may borrow from
/// it, which is how a payload is carried without a copy (see [`Payload`]).
pub trait Decode<'a>: Sized {
    /// The structure's name in the specification, used as the `context` of
    /// every error this decoder raises.
    const NAME: &'static str;

    /// Read one structure, leaving the reader positioned after it.
    ///
    /// A decoder rejects bytes it cannot parse and values the protocol
    /// forbids. It does not reject values the client dislikes: that is
    /// `rdp-core`'s decision (PRDRDP/13 §2.7 rule 3). An unknown enumerant
    /// whose length is known is preserved rather than rejected.
    fn decode(r: &mut Reader<'a>) -> PduResult<Self>;
}

/// A structure that can be written to the wire.
pub trait Encode {
    /// The structure's name in the specification.
    const NAME: &'static str;

    /// The exact encoded size in bytes.
    ///
    /// Used to pre-size a buffer, and checked against the bytes actually
    /// written by [`Encode::encode_checked`] in debug builds. A wrong
    /// `size()` is otherwise invisible until a length prefix somewhere is one
    /// byte short.
    fn size(&self) -> usize;

    /// Append the structure.
    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()>;

    /// [`Encode::encode`] with the debug build size check of PRDRDP/13 §2.7
    /// rule 2. Call this from tests and from the session; the plain `encode`
    /// stays free of the check so a release build pays nothing.
    fn encode_checked(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let before = w.len();
        self.encode(w)?;
        debug_assert_eq!(
            w.len() - before,
            self.size(),
            "{}: size() disagrees with encode()",
            Self::NAME
        );
        Ok(())
    }
}

/// A payload view that outlives the decode call.
///
/// D9 makes zero copy a design invariant, and PRDRDP/13 §2.6 draws the line:
/// [`Reader`] borrows `&'a [u8]` because it is `Copy` and a nested `take` is
/// two words on the stack, where a `Bytes` reader would pay an atomic
/// increment per sub structure and a Confirm Active with twenty capability
/// sets would pay forty of them for nothing.
///
/// The payloads that genuinely outlive the decode are the handful this type
/// marks: a bitmap's compressed data, an EGFX bitstream, a virtual channel
/// chunk. The session parses a PDU with `Reader::new(&frame[..])` where
/// `frame: Bytes`, and turns the borrowed field back into an owned `Bytes`
/// with [`Payload::to_bytes`]. `Bytes::slice_ref` is O(1) and checks that the
/// view points inside `frame`, which it does because the reader never leaves
/// the buffer it was created over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload<'a>(&'a [u8]);

impl<'a> Payload<'a> {
    /// Wrap a borrowed view. The only way to get one, so a payload always
    /// points into the buffer that was decoded.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The borrowed view, for a caller that decodes and drops within one
    /// call.
    #[must_use]
    pub const fn as_slice(self) -> &'a [u8] {
        self.0
    }

    /// The payload's length, which a caller usually wants before deciding to
    /// keep it.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.len()
    }

    /// True for a zero length payload, which several PDUs allow.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }

    /// An owned view over the same bytes, refcounted rather than copied.
    ///
    /// `frame` must be the buffer this payload was decoded from. `slice_ref`
    /// panics otherwise, which is why [`Payload`] exists as a distinct type:
    /// it marks the places where the pairing has to hold, and there are only
    /// a handful of them.
    #[must_use]
    pub fn to_bytes(self, frame: &bytes::Bytes) -> bytes::Bytes {
        frame.slice_ref(self.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// A structure small enough to state the whole round trip in one test,
    /// standing in for the real PDUs the later modules add.
    #[derive(Debug, PartialEq, Eq)]
    struct Pair {
        a: u16,
        b: u32,
    }

    impl Pair {
        /// An inherent constant of the same name, which is how a type that
        /// implements both traits refers to `Self::NAME` without the two
        /// trait constants being ambiguous. An inherent associated constant
        /// wins over a trait one, so the later lanes write this line once per
        /// type and use `Self::NAME` everywhere.
        const NAME: &'static str = "TEST_PAIR";
    }

    impl Decode<'_> for Pair {
        const NAME: &'static str = Self::NAME;
        fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
            Ok(Self {
                a: r.u16(Self::NAME)?,
                b: r.u32(Self::NAME)?,
            })
        }
    }

    impl Encode for Pair {
        const NAME: &'static str = Self::NAME;
        fn size(&self) -> usize {
            6
        }
        fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
            w.u16(self.a);
            w.u32(self.b);
            Ok(())
        }
    }

    #[test]
    fn encode_then_decode_is_the_identity() {
        let value = Pair {
            a: 0x1234,
            b: 0xdead_beef,
        };
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size());
        assert_eq!(Pair::decode(&mut Reader::new(&buf)).unwrap(), value);
    }

    #[test]
    fn a_truncated_structure_errors_rather_than_decoding_short() {
        let full = [0x34, 0x12, 0xef, 0xbe, 0xad, 0xde];
        for cut in 0..full.len() {
            assert!(Pair::decode(&mut Reader::new(&full[..cut])).is_err());
        }
    }

    /// The zero copy invariant, asserted structurally: an owned payload points
    /// inside the frame it was decoded from rather than at a copy of it.
    #[test]
    fn a_payload_becomes_bytes_without_copying() {
        let frame = bytes::Bytes::from_static(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let mut r = Reader::new(&frame);
        r.skip(2, "header").unwrap();
        let payload = Payload::new(r.rest());
        assert_eq!(payload.len(), 6);

        let owned = payload.to_bytes(&frame);
        assert_eq!(&owned[..], &[2, 3, 4, 5, 6, 7]);
        let frame_start = frame.as_ptr() as usize;
        let owned_start = owned.as_ptr() as usize;
        assert_eq!(owned_start - frame_start, 2, "payload was copied");
    }
}
