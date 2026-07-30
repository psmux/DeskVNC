//! NetBIOS Name Service (UDP 137) node-status query and response parsing.
//!
//! This is the rung of the resolution ladder that actually names Windows
//! machines on a home LAN (PRD/04 §6.3). Nothing else does: a consumer router
//! registers no DNS, and Windows does not run Avahi, so a Windows VNC server
//! found by the subnet scan is otherwise a bare IP address forever.
//!
//! An `NBSTAT` ("node status") query is a DNS-shaped message asking for the
//! wildcard name `*`. The reply is the host's **name table** plus the adapter's
//! **MAC address**, which is the only place discovery can learn a MAC for
//! Wake-on-LAN without ever having connected (PRD/04 §8).
//!
//! Note this is a *name* query only. It is not an SMB session, carries no
//! credentials, and cannot produce an authentication-failure log entry on the
//! target.
//!
//! As with [`crate::dnsmsg`], every field here is attacker-controlled and is
//! bounds-checked accordingly.

use crate::dnsmsg;

/// NetBIOS name service port.
pub const NBNS_PORT: u16 = 137;

/// A NetBIOS name is always exactly 16 bytes: 15 of name, 1 of suffix.
const NB_NAME_LEN: usize = 16;
/// Each name-table entry is the 16-byte name plus a 2-byte flags field.
const NB_ENTRY_LEN: usize = 18;
/// `G` bit in a name-table entry's flags: the name is a group, not this host.
const NB_FLAG_GROUP: u16 = 0x8000;
/// Sanity cap on the advertised name count. A real table has under a dozen
/// entries; the field is a `u8`, so this only shortens hostile work.
const MAX_NAMES: usize = 64;

/// What a node-status reply told us about a host.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    /// The machine's own (non-group) NetBIOS name, e.g. `"DESKTOP-646U3OK"`.
    pub name: Option<String>,
    /// The adapter MAC, lower-case colon-separated, e.g. `"9c:53:22:6a:36:7c"`.
    pub mac: Option<String>,
}

impl NodeStatus {
    /// True when the reply carried nothing worth keeping.
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.mac.is_none()
    }
}

/// Encode a NetBIOS name into the "first level encoding" of RFC 1001 §4.1:
/// each of the 16 bytes becomes two nibbles, offset by `'A'`.
fn encode_nb_name(raw: [u8; NB_NAME_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(NB_NAME_LEN * 2);
    for byte in raw {
        out.push((byte >> 4) + b'A');
        out.push((byte & 0x0F) + b'A');
    }
    out
}

/// Build the 50-byte `NBSTAT` node-status query.
///
/// The question name is the wildcard `*` padded to 16 bytes with NULs (**not**
/// with spaces, unlike an ordinary NetBIOS name), first-level encoded into a
/// single 32-byte label; the type is `NBSTAT` (0x0021), class `IN`.
pub fn build_nbstat_query(id: u16) -> Vec<u8> {
    let mut raw = [0u8; NB_NAME_LEN];
    raw[0] = b'*';
    let encoded = encode_nb_name(raw);

    let mut qname = Vec::with_capacity(encoded.len() + 2);
    qname.push(encoded.len() as u8); // 0x20
    qname.extend_from_slice(&encoded);
    qname.push(0);

    dnsmsg::build_query(id, &qname, dnsmsg::TYPE_NBSTAT, dnsmsg::CLASS_IN)
}

/// Trim a 15-byte NetBIOS name field to a displayable name.
///
/// Returns `None` unless what remains is non-empty printable ASCII, which
/// drops the `\x01\x02__MSBROWSE__\x02` pseudo-name and anything a hostile
/// host tries to smuggle through.
fn clean_nb_name(field: &[u8]) -> Option<String> {
    let trimmed: &[u8] = {
        let end = field
            .iter()
            .rposition(|&b| b != b' ' && b != 0)
            .map_or(0, |i| i + 1);
        &field[..end]
    };
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.iter().all(|&b| (0x21..0x7F).contains(&b)) {
        return None;
    }
    Some(String::from_utf8_lossy(trimmed).into_owned())
}

/// Format six bytes as a lower-case colon-separated MAC, or `None` when the
/// adapter reported all zeroes (which NetBIOS-over-TCP-only stacks do).
fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 || bytes.iter().all(|&b| b == 0) {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Parse a node-status reply to query `id`.
///
/// Returns the first **non-group** name in the table (with the 16th suffix
/// byte dropped) and the adapter MAC that follows it. `None` if the message is
/// not a well-formed `NBSTAT` answer.
pub fn parse_nbstat_response(msg: &[u8], id: u16) -> Option<NodeStatus> {
    let answers = dnsmsg::parse_answers(msg, id)?;
    let answer = answers
        .iter()
        .find(|a| a.rtype == dnsmsg::TYPE_NBSTAT)
        .copied()?;
    let rdata = answer.rdata(msg);

    let count = usize::from(*rdata.first()?);
    if count > MAX_NAMES {
        return None;
    }
    // The whole name table must be present. A short reply claiming many names
    // is the classic hostile case, and it is rejected outright rather than
    // parsed as far as it goes.
    let table_end = 1usize.checked_add(count.checked_mul(NB_ENTRY_LEN)?)?;
    let table = rdata.get(1..table_end)?;

    let mut status = NodeStatus::default();
    for entry in table.chunks_exact(NB_ENTRY_LEN) {
        let flags = u16::from_be_bytes([entry[NB_NAME_LEN], entry[NB_NAME_LEN + 1]]);
        if flags & NB_FLAG_GROUP != 0 {
            continue; // a workgroup/domain, not this machine
        }
        // entry[15] is the service suffix (0x00 workstation, 0x20 server, …)
        // and is deliberately dropped: it is not part of the machine name.
        if let Some(name) = clean_nb_name(&entry[..NB_NAME_LEN - 1]) {
            status.name = Some(name);
            break;
        }
    }

    // The 6-byte adapter "unit id" directly follows the name table. Its absence
    // is not an error, the names are still useful.
    if let Some(mac) = rdata.get(table_end..table_end + 6) {
        status.mac = format_mac(mac);
    }

    Some(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real capture: `NBSTAT` reply from the Windows host at 192.168.77.126,
    /// transaction id 0x1234. Six name-table entries (two unique, three group,
    /// one `__MSBROWSE__`), then the adapter MAC, then 40 bytes of statistics.
    const NBSTAT_RESPONSE: &[u8] = &[
        0x12, 0x34, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9b, 0x06, 0x44, 0x45, 0x53,
        0x4b, 0x54, 0x4f, 0x50, 0x2d, 0x36, 0x34, 0x36, 0x55, 0x33, 0x4f, 0x4b, 0x00, 0x04, 0x00,
        0x57, 0x4f, 0x52, 0x4b, 0x47, 0x52, 0x4f, 0x55, 0x50, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x00, 0x84, 0x00, 0x44, 0x45, 0x53, 0x4b, 0x54, 0x4f, 0x50, 0x2d, 0x36, 0x34, 0x36, 0x55,
        0x33, 0x4f, 0x4b, 0x20, 0x04, 0x00, 0x57, 0x4f, 0x52, 0x4b, 0x47, 0x52, 0x4f, 0x55, 0x50,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x1e, 0x84, 0x00, 0x57, 0x4f, 0x52, 0x4b, 0x47, 0x52,
        0x4f, 0x55, 0x50, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x1d, 0x04, 0x00, 0x01, 0x02, 0x5f,
        0x5f, 0x4d, 0x53, 0x42, 0x52, 0x4f, 0x57, 0x53, 0x45, 0x5f, 0x5f, 0x02, 0x01, 0x84, 0x00,
        0x9c, 0x53, 0x22, 0x6a, 0x36, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    /// The exact 50-byte query that produced the capture above.
    const NBSTAT_QUERY: &[u8] = &[
        0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00, 0x00, 0x21, 0x00, 0x01,
    ];

    /// Offset of the RDATA within `NBSTAT_RESPONSE` (12 header + 34 name + 10).
    const RDATA_AT: usize = 12 + 34 + 10;

    #[test]
    fn the_query_is_byte_exact() {
        assert_eq!(build_nbstat_query(0x1234), NBSTAT_QUERY);
    }

    #[test]
    fn a_real_windows_reply_yields_the_name_and_mac() {
        let status = parse_nbstat_response(NBSTAT_RESPONSE, 0x1234).expect("well-formed reply");
        assert_eq!(status.name.as_deref(), Some("DESKTOP-646U3OK"));
        assert_eq!(status.mac.as_deref(), Some("9c:53:22:6a:36:7c"));
    }

    #[test]
    fn group_names_are_never_the_machine_name() {
        // WORKGROUP appears three times before any second unique name; if the
        // group bit were ignored the user would see "WORKGROUP" on every row.
        let status = parse_nbstat_response(NBSTAT_RESPONSE, 0x1234).unwrap();
        assert_ne!(status.name.as_deref(), Some("WORKGROUP"));
    }

    #[test]
    fn a_mismatched_transaction_id_is_rejected() {
        assert!(parse_nbstat_response(NBSTAT_RESPONSE, 0x0001).is_none());
    }

    #[test]
    fn truncation_at_every_length_is_survivable() {
        for take in 0..NBSTAT_RESPONSE.len() {
            let _ = parse_nbstat_response(&NBSTAT_RESPONSE[..take], 0x1234);
        }
    }

    #[test]
    fn a_reply_cut_off_mid_table_is_rejected() {
        // Keep the header/answer intact but shrink the message so the declared
        // six entries do not fit.
        let mut msg = NBSTAT_RESPONSE[..RDATA_AT + 40].to_vec();
        let rdlen = (msg.len() - RDATA_AT) as u16;
        msg[RDATA_AT - 2..RDATA_AT].copy_from_slice(&rdlen.to_be_bytes());
        assert!(
            parse_nbstat_response(&msg, 0x1234).is_none(),
            "a table that does not fit its own RDATA must be refused"
        );
    }

    #[test]
    fn a_hostile_name_count_is_refused_without_reading_past_the_buffer() {
        let mut msg = NBSTAT_RESPONSE.to_vec();
        msg[RDATA_AT] = 0xff; // 255 names in a 155-byte RDATA
        assert!(parse_nbstat_response(&msg, 0x1234).is_none());

        // Just over our own cap, still inside a u8.
        msg[RDATA_AT] = (MAX_NAMES + 1) as u8;
        assert!(parse_nbstat_response(&msg, 0x1234).is_none());
    }

    #[test]
    fn an_empty_name_table_is_not_an_error() {
        let mut msg = NBSTAT_RESPONSE[..RDATA_AT].to_vec();
        msg.push(0); // zero names
        msg.extend_from_slice(&[0x9c, 0x53, 0x22, 0x6a, 0x36, 0x7c]);
        let rdlen = (msg.len() - RDATA_AT) as u16;
        msg[RDATA_AT - 2..RDATA_AT].copy_from_slice(&rdlen.to_be_bytes());
        let status = parse_nbstat_response(&msg, 0x1234).expect("still well formed");
        assert_eq!(status.name, None);
        assert_eq!(status.mac.as_deref(), Some("9c:53:22:6a:36:7c"));
    }

    #[test]
    fn a_control_character_name_is_dropped_rather_than_displayed() {
        let mut msg = NBSTAT_RESPONSE[..RDATA_AT].to_vec();
        msg.push(1);
        // A unique (non-group) entry whose name is terminal escape codes.
        let mut entry = [0x20u8; NB_ENTRY_LEN];
        entry[..4].copy_from_slice(&[0x1b, b'[', b'2', b'J']);
        entry[NB_NAME_LEN] = 0x04; // flags: not a group
        entry[NB_NAME_LEN + 1] = 0x00;
        msg.extend_from_slice(&entry);
        msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let rdlen = (msg.len() - RDATA_AT) as u16;
        msg[RDATA_AT - 2..RDATA_AT].copy_from_slice(&rdlen.to_be_bytes());
        let status = parse_nbstat_response(&msg, 0x1234).expect("well formed");
        assert_eq!(status.name, None, "escape codes must never reach the UI");
        assert_eq!(status.mac, None, "an all-zero unit id is not a MAC");
    }

    #[test]
    fn a_missing_unit_id_still_yields_the_name() {
        let mut msg = NBSTAT_RESPONSE[..RDATA_AT].to_vec();
        msg.push(1);
        let mut entry = [b' '; NB_ENTRY_LEN];
        entry[..3].copy_from_slice(b"PC1");
        entry[NB_NAME_LEN] = 0x04;
        entry[NB_NAME_LEN + 1] = 0x00;
        msg.extend_from_slice(&entry);
        let rdlen = (msg.len() - RDATA_AT) as u16;
        msg[RDATA_AT - 2..RDATA_AT].copy_from_slice(&rdlen.to_be_bytes());
        let status = parse_nbstat_response(&msg, 0x1234).expect("well formed");
        assert_eq!(status.name.as_deref(), Some("PC1"));
        assert_eq!(status.mac, None);
    }

    #[test]
    fn the_mac_is_parseable_by_wake_on_lan() {
        let status = parse_nbstat_response(NBSTAT_RESPONSE, 0x1234).unwrap();
        let mac = status.mac.unwrap();
        assert_eq!(
            crate::wol::parse_mac(&mac).unwrap(),
            [0x9c, 0x53, 0x22, 0x6a, 0x36, 0x7c]
        );
    }
}
