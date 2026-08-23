//! The `VERSION` structure, MS-NLMP 2.2.2.10.
//!
//! ```text
//! offset size field
//!   0     1    ProductMajorVersion
//!   1     1    ProductMinorVersion
//!   2     2    ProductBuild
//!   4     3    Reserved (zero)
//!   7     1    NTLMRevisionCurrent
//! ```

/// `NTLMSSP_REVISION_W2K3`, the only value MS-NLMP 2.2.2.10 defines.
pub const NTLM_REVISION_W2K3: u8 = 0x0F;

/// The eight bytes of a `VERSION` structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// `ProductMajorVersion`.
    pub major: u8,
    /// `ProductMinorVersion`.
    pub minor: u8,
    /// `ProductBuild`.
    pub build: u16,
    /// `NTLMRevisionCurrent`.
    pub revision: u8,
}

impl Version {
    /// The version we report: Windows 10 version 2004, build 19041.
    ///
    /// Two reasons for sending a version at all, since the field is advisory:
    ///
    /// 1. Some servers and middleboxes make policy decisions on the client
    ///    version, and a client reporting 0.0.0 stands out. Reporting a
    ///    Windows 10 build is what every widely deployed non Microsoft client
    ///    does and is the value least likely to trip a rule.
    /// 2. `NTLMSSP_NEGOTIATE_VERSION` is what makes these eight bytes present
    ///    in all three messages, and those eight bytes are inside the MIC and
    ///    inside what the server hashes.
    ///
    /// This is the same build `TS_UD_CS_CORE.clientBuild` carries
    /// (PRDRDP/13 §4.3.1, `clientBuild = 19041`), and the agreement is
    /// deliberate. A client that claims one Windows build in the GCC client
    /// core data and a different one in the NTLM AUTHENTICATE message is
    /// describing a machine that does not exist, and a middlebox keying off
    /// either field then gets an incoherent answer. One constant, one build.
    pub const CLIENT: Version = Version {
        major: 10,
        minor: 0,
        build: 19041,
        revision: NTLM_REVISION_W2K3,
    };

    /// All zeros.
    ///
    /// PRDRDP/11 §5.3 item 4: MS-NLMP errata 2022-02-08 corrected six
    /// sections to say the `VERSION` field MUST be all zero when
    /// `NTLMSSP_NEGOTIATE_VERSION` is unset. The old wording said the field is
    /// ignored, which is false: those eight bytes are inside the MIC and
    /// inside the NTLMv2 hash inputs, so a stale value there breaks the
    /// exchange rather than being overlooked.
    pub const ZERO: Version = Version {
        major: 0,
        minor: 0,
        build: 0,
        revision: 0,
    };

    /// The eight bytes, little endian for `ProductBuild`.
    #[must_use]
    pub fn encode(self) -> [u8; 8] {
        let b = self.build.to_le_bytes();
        [self.major, self.minor, b[0], b[1], 0, 0, 0, self.revision]
    }

    /// Read eight bytes back.
    #[must_use]
    pub fn decode(bytes: [u8; 8]) -> Version {
        Version {
            major: bytes[0],
            minor: bytes[1],
            build: u16::from_le_bytes([bytes[2], bytes[3]]),
            revision: bytes[7],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_version_encodes_as_windows_10_19041() {
        // 19041 = 0x4A61, little endian 61 4A.
        assert_eq!(
            Version::CLIENT.encode(),
            [0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f]
        );
    }

    #[test]
    fn the_zero_version_is_eight_zero_bytes() {
        assert_eq!(Version::ZERO.encode(), [0u8; 8]);
    }

    #[test]
    fn round_trip() {
        // MS-NLMP 4.2.4.3's AUTHENTICATE_MESSAGE reports 5.1.2600 with
        // revision 0x0f at offset 64: 05 01 28 0a 00 00 00 0f.
        let spec = [0x05, 0x01, 0x28, 0x0a, 0x00, 0x00, 0x00, 0x0f];
        let v = Version::decode(spec);
        assert_eq!(
            v,
            Version {
                major: 5,
                minor: 1,
                build: 2600,
                revision: NTLM_REVISION_W2K3
            }
        );
        assert_eq!(v.encode(), spec);
        assert_eq!(Version::decode(Version::CLIENT.encode()), Version::CLIENT);
    }
}
