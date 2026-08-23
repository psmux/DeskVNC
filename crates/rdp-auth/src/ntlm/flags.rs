//! The `NegotiateFlags` bit field, MS-NLMP 2.2.2.5.
//!
//! Every constant below is the value the specification prints for that name.
//! The set we send is an OR of named constants and never a literal, so a
//! future edit to the list changes a value a test names (PRDRDP/14 §5.2).

/// Unicode strings are supported. MS-NLMP 2.2.2.5, `NTLMSSP_NEGOTIATE_UNICODE`.
pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
/// OEM (codepage) strings are supported. `NTLM_NEGOTIATE_OEM`. Never set here.
pub const NEGOTIATE_OEM: u32 = 0x0000_0002;
/// Ask the server for its `TargetName`. `NTLMSSP_REQUEST_TARGET`.
pub const REQUEST_TARGET: u32 = 0x0000_0004;
/// Session key negotiation for message signatures. `NTLMSSP_NEGOTIATE_SIGN`.
pub const NEGOTIATE_SIGN: u32 = 0x0000_0010;
/// Session key negotiation for message confidentiality. `NTLMSSP_NEGOTIATE_SEAL`.
pub const NEGOTIATE_SEAL: u32 = 0x0000_0020;
/// Connectionless mode. `NTLMSSP_NEGOTIATE_DATAGRAM`. Never set here.
pub const NEGOTIATE_DATAGRAM: u32 = 0x0000_0040;
/// The LM session key. `NTLMSSP_NEGOTIATE_LM_KEY`. Never set here.
pub const NEGOTIATE_LM_KEY: u32 = 0x0000_0080;
/// NTLM authentication is supported. `NTLMSSP_NEGOTIATE_NTLM`.
pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
/// Anonymous authentication. `NTLMSSP_ANONYMOUS`. Never set here.
pub const NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;
/// The domain name is supplied in OEM encoding.
/// `NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED`. Never set here.
pub const NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 0x0000_1000;
/// The workstation name is supplied in OEM encoding.
/// `NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED`. Never set here.
pub const NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 0x0000_2000;
/// A signature is present on every message even when it would not otherwise
/// carry one. `NTLMSSP_NEGOTIATE_ALWAYS_SIGN`.
pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
/// The `TargetName` is a domain. `NTLMSSP_TARGET_TYPE_DOMAIN`. Server to client.
pub const TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;
/// The `TargetName` is a server. `NTLMSSP_TARGET_TYPE_SERVER`. Server to client.
pub const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
/// NTLMv2 session security: the HMAC-MD5 signing and sealing key derivations
/// of MS-NLMP 3.4.5.2 and 3.4.5.3 rather than the NTLMv1 forms.
/// `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`.
pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
/// Produce an identify level token. `NTLMSSP_NEGOTIATE_IDENTIFY`. Never set here.
pub const NEGOTIATE_IDENTIFY: u32 = 0x0010_0000;
/// Ask for the LM based key material. `NTLMSSP_REQUEST_NON_NT_SESSION_KEY`.
/// Never set here.
pub const REQUEST_NON_NT_SESSION_KEY: u32 = 0x0040_0000;
/// The `TargetInfo` AV pair list is present in the CHALLENGE.
/// `NTLMSSP_NEGOTIATE_TARGET_INFO`.
pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
/// The `Version` field is present and meaningful. `NTLMSSP_NEGOTIATE_VERSION`.
pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
/// A 128 bit session key. `NTLMSSP_NEGOTIATE_128`.
pub const NEGOTIATE_128: u32 = 0x2000_0000;
/// The client supplies the `ExportedSessionKey`, RC4 encrypted under the
/// `KeyExchangeKey`. `NTLMSSP_NEGOTIATE_KEY_EXCH`.
pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
/// A 56 bit session key. `NTLMSSP_NEGOTIATE_56`.
pub const NEGOTIATE_56: u32 = 0x8000_0000;

/// The flags we put in the NEGOTIATE_MESSAGE (PRDRDP/14 §5.2).
///
/// | Flag | Why |
/// |---|---|
/// | `UNICODE` | Every string we send is UTF-16LE. Without it the server may answer in OEM and the `NTOWFv2` inputs stop matching. |
/// | `REQUEST_TARGET` | Asks for the server's `TargetName`, which we need for the `MsvAvTargetName` cross check and for diagnostics. |
/// | `SIGN` | CredSSP signs every wrapped blob. Without it a server may decline to derive signing keys. |
/// | `SEAL` | CredSSP encrypts `pubKeyAuth` and `authInfo`. This is the flag that makes `GSS_WrapEx` a sealing operation. |
/// | `NTLM` | Says NTLM authentication is available. Required. |
/// | `ALWAYS_SIGN` | MS-NLMP 3.1.5.1.1 requires it whenever signing is negotiated. |
/// | `EXTENDED_SESSIONSECURITY` | Selects NTLMv2 session security. Not optional for us. |
/// | `TARGET_INFO` | NTLMv2 cannot be computed without the AV pair list, because `temp` embeds it. |
/// | `VERSION` | Makes the 8 byte `Version` field present and meaningful. |
/// | `128` | A 128 bit session key, which is what `SEALKEY` uses whole (3.4.5.3). |
/// | `KEY_EXCH` | We generate the `ExportedSessionKey` ourselves. Without it the exported key is a deterministic function of the password hash and the challenges. |
/// | `56` | Sent alongside 128 so a 56 bit only server negotiates down rather than failing. |
///
/// Deliberately absent: `OEM` (forces codepage strings), `LM_KEY` (56 bits
/// with 40 of them known), `DATAGRAM` (changes sequence number handling in
/// 3.4.4), `ANONYMOUS` (authenticates nobody), `REQUEST_NON_NT_SESSION_KEY`,
/// `IDENTIFY` (a server may treat the token as insufficient for a logon), and
/// the two OEM supplied name flags, which force the encoding we do not want.
pub const CLIENT_NEGOTIATE_FLAGS: u32 = NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_SIGN
    | NEGOTIATE_SEAL
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NEGOTIATE_TARGET_INFO
    | NEGOTIATE_VERSION
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

/// The flags a CHALLENGE_MESSAGE must still have set for us to answer it.
///
/// * `UNICODE` cleared means the OEM codepage path, and we would have to
///   guess the codepage.
/// * `EXTENDED_SESSIONSECURITY` cleared means `SIGNKEY` returns NULL
///   (MS-NLMP 3.4.5.2) and the session security is the NTLMv1 form.
///
/// PRDRDP/11 §5.3 item 5: MS-NLMP errata 2022-07-26 corrected section 2.2.1.2
/// to say the server must echo `NTLMSSP_NEGOTIATE_SIGN`. We do not make that
/// a hard requirement, because refusing on it would break hosts that predate
/// the erratum while the exchange still works; a missing `SIGN` is logged
/// where the check runs, in `super::challenge_is_answerable`.
pub const REQUIRED_IN_CHALLENGE: u32 = NEGOTIATE_UNICODE | NEGOTIATE_EXTENDED_SESSIONSECURITY;

/// Flags that must never appear in anything we send, whatever the server asks
/// for (PRDRDP/14 §8.5). Intersecting our set with a server's cannot set a
/// bit, but a future edit to `CLIENT_NEGOTIATE_FLAGS` could, and the test
/// below is what would catch it.
pub const FORBIDDEN: u32 = NEGOTIATE_OEM
    | NEGOTIATE_LM_KEY
    | NEGOTIATE_DATAGRAM
    | NEGOTIATE_ANONYMOUS
    | REQUEST_NON_NT_SESSION_KEY
    | NEGOTIATE_IDENTIFY
    | NEGOTIATE_OEM_DOMAIN_SUPPLIED
    | NEGOTIATE_OEM_WORKSTATION_SUPPLIED;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_flag_word_is_the_value_a_test_names() {
        // MS-NLMP 4.2.4.3's AUTHENTICATE_MESSAGE carries 35 82 88 e2 at offset
        // 60, that is 0xE2888235, and it is exactly this OR. The worked
        // example and our flag list agree bit for bit.
        //
        // PRDRDP/14 §5.2 prints the literal as 0xE2088237, which is not the OR
        // of the twelve flags its own table names: 0x...37 sets
        // NTLM_NEGOTIATE_OEM, which the same section says we deliberately do
        // not set, and 0xE208.... clears NTLMSSP_NEGOTIATE_TARGET_INFO, which
        // the same section says NTLMv2 cannot proceed without. The table wins;
        // the literal in the document is wrong.
        assert_eq!(CLIENT_NEGOTIATE_FLAGS, 0xE288_8235);
    }

    #[test]
    fn we_never_ask_for_a_downgrade() {
        assert_eq!(
            CLIENT_NEGOTIATE_FLAGS & FORBIDDEN,
            0,
            "a flag from the refusal list of PRDRDP/14 §8.5 reached the negotiate set"
        );
    }

    #[test]
    fn what_we_require_back_is_a_subset_of_what_we_ask_for() {
        assert_eq!(
            REQUIRED_IN_CHALLENGE & CLIENT_NEGOTIATE_FLAGS,
            REQUIRED_IN_CHALLENGE
        );
    }
}
