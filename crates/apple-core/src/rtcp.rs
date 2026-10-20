//! RTCP feedback for the media path.
//!
//! When a packet is lost, the decoder is left holding a picture that refers
//! to something it never received, and the picture stays wrong until the
//! next independent picture. Asking for one is what makes the session heal
//! by itself instead of waiting for a reconnect.
//!
//! The forms used here are the ones Apple's media stack answers:
//!
//! * a receiver report, so the peer knows a receiver is there,
//! * a Full Intra Request (RFC 5104), which asks for a fresh IDR,
//! * a Picture Loss Indication (RFC 4585), which asks for the same thing
//!   more cheaply,
//! * the legacy intra request (RFC 2032) that the native viewer sends,
//!   which Apple's server answers even when it ignores the newer forms,
//! * a Generic NACK (RFC 4585) for packets that can still be retransmitted.

/// Our own SSRC as an RTCP sender.
pub type Ssrc = u32;

/// A receiver report with no report blocks.
///
/// Some peers reject feedback that is not part of a compound packet that
/// starts with a sender or receiver report, so every feedback packet we
/// send is prefixed with one of these.
pub fn receiver_report(sender: Ssrc) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.push(0x80); // version 2, no report blocks
    out.push(201); // receiver report
    out.extend_from_slice(&1u16.to_be_bytes()); // length in 32-bit words, minus one
    out.extend_from_slice(&sender.to_be_bytes());
    out
}

/// The Full Intra Request command sequence for one sender and target.
///
/// A new command needs a number the target has not seen; a retransmission of
/// the same command keeps it. Every request this client makes is a new
/// command, and the number wraps as the RFC allows. A constant zero made
/// every request look like a repeat of the first one.
#[derive(Debug, Default)]
pub struct FirSequence(u8);

impl FirSequence {
    /// Start at `seed`, which the session randomises so a restarted client
    /// is not mistaken for the old one.
    #[must_use]
    pub fn new(seed: u8) -> Self {
        Self(seed)
    }

    /// The number for a new request, and the next one to hand out.
    pub fn next(&mut self) -> u8 {
        let seq = self.0;
        self.0 = self.0.wrapping_add(1);
        seq
    }
}

/// A Full Intra Request (RFC 5104 §4.3.1.1) for one media stream.
pub fn full_intra_request(sender: Ssrc, target: Ssrc, seq: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.push(0x80 | 4); // version 2, format 4
    out.push(206); // payload-specific feedback
    out.extend_from_slice(&4u16.to_be_bytes()); // length in 32-bit words, minus one
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // the media source, zero for a request
    out.extend_from_slice(&target.to_be_bytes());
    out.push(seq);
    out.extend_from_slice(&[0, 0, 0]); // padding to a 32-bit boundary
    out
}

/// A Picture Loss Indication (RFC 4585 §6.3.1).
pub fn picture_loss_indication(sender: Ssrc, media: Ssrc) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.push(0x80 | 1); // version 2, format 1
    out.push(206); // payload-specific feedback
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(&media.to_be_bytes());
    out
}

/// The legacy intra request (RFC 2032 §5.2.1) that the native viewer
/// sends.
///
/// Apple's server answers this one with a fresh IDR even when it ignores
/// the newer forms, so it is sent alongside them.
pub fn legacy_intra_request(target: Ssrc) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.push(0x80); // version 2
    out.push(192); // the legacy full intra request
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&target.to_be_bytes());
    out
}

/// A Generic NACK (RFC 4585 §6.2.1) for the packets that were lost.
///
/// Consecutive losses are coalesced into a Bitmask of Lost Packets, which
/// is what the format is for.
pub fn generic_nack(sender: Ssrc, media: Ssrc, lost: &[u16]) -> Vec<u8> {
    let mut seqs: Vec<u16> = lost.to_vec();
    seqs.sort_unstable();
    seqs.dedup();
    if seqs.is_empty() {
        return Vec::new();
    }
    // Each Feedback Control Information block is 4 bytes: a packet id and a
    // 16 bit mask of the 16 packets that follow it.
    let mut blocks: Vec<(u16, u16)> = Vec::new();
    for seq in seqs {
        match blocks.last_mut() {
            Some((pid, blp)) if seq.wrapping_sub(*pid) >= 1 && seq.wrapping_sub(*pid) <= 16 => {
                *blp |= 1 << (seq.wrapping_sub(*pid) - 1);
            }
            _ => blocks.push((seq, 0)),
        }
    }
    let mut out = Vec::with_capacity(12 + blocks.len() * 4);
    out.push(0x80 | 1); // version 2, format 1
    out.push(205); // transport-layer feedback
                   // The length counts 32 bit words after the length field: the two
                   // SSRCs and the feedback blocks.
    out.extend_from_slice(&((2 + blocks.len()) as u16).to_be_bytes());
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(&media.to_be_bytes());
    for (pid, blp) in blocks {
        out.extend_from_slice(&pid.to_be_bytes());
        out.extend_from_slice(&blp.to_be_bytes());
    }
    out
}

/// Whether a datagram is RTCP.
///
/// The control socket carries the RTCP the Mac sends, multiplexed with the
/// audio it would send. The media socket carries RTP. The two are told
/// apart by the version and the payload type, which is what the format is
/// for.
pub fn is_rtcp(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    if packet[0] >> 6 != 2 {
        return false;
    }
    matches!(packet[1], 200..=207)
}

/// A feedback packet with a receiver report in front of it.
pub fn compound(sender: Ssrc, feedback: &[u8]) -> Vec<u8> {
    let mut out = receiver_report(sender);
    out.extend_from_slice(feedback);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_receiver_report_is_one_word() {
        let rr = receiver_report(0x1122_3344);
        assert_eq!(rr.len(), 8);
        assert_eq!(rr[0], 0x80);
        assert_eq!(rr[1], 201);
        assert_eq!(&rr[2..4], &1u16.to_be_bytes());
        assert_eq!(&rr[4..8], &0x1122_3344u32.to_be_bytes());
    }

    #[test]
    fn a_full_intra_request_names_the_stream_it_wants() {
        let fir = full_intra_request(0x1111_1111, 0x2222_2222, 7);
        assert_eq!(fir.len(), 20);
        assert_eq!(fir[0], 0x84);
        assert_eq!(fir[1], 206);
        assert_eq!(&fir[2..4], &4u16.to_be_bytes());
        assert_eq!(&fir[4..8], &0x1111_1111u32.to_be_bytes());
        assert_eq!(&fir[8..12], &0u32.to_be_bytes());
        assert_eq!(&fir[12..16], &0x2222_2222u32.to_be_bytes());
        assert_eq!(fir[16], 7);
    }

    #[test]
    fn a_picture_loss_indication_is_two_words() {
        let pli = picture_loss_indication(1, 2);
        assert_eq!(pli.len(), 12);
        assert_eq!(pli[0], 0x81);
        assert_eq!(pli[1], 206);
        assert_eq!(&pli[2..4], &2u16.to_be_bytes());
        assert_eq!(&pli[8..12], &2u32.to_be_bytes());
    }

    #[test]
    fn the_legacy_request_names_the_stream() {
        let fir = legacy_intra_request(0x2222_2222);
        assert_eq!(fir.len(), 8);
        assert_eq!(fir[0], 0x80);
        assert_eq!(fir[1], 192);
        assert_eq!(&fir[4..8], &0x2222_2222u32.to_be_bytes());
    }

    #[test]
    fn a_nack_coalesces_consecutive_losses() {
        let nack = generic_nack(1, 2, &[10, 11, 12, 40]);
        assert_eq!(nack[0], 0x81);
        assert_eq!(nack[1], 205);
        // Two blocks: one for 10..12 and one for 40.
        assert_eq!(nack.len(), 12 + 8);
        assert_eq!(&nack[12..14], &10u16.to_be_bytes());
        assert_eq!(&nack[14..16], &0b011u16.to_be_bytes());
        assert_eq!(&nack[16..18], &40u16.to_be_bytes());
        assert_eq!(&nack[18..20], &0u16.to_be_bytes());
        // The length field counts the words after it.
        assert_eq!(&nack[2..4], &4u16.to_be_bytes());
    }

    #[test]
    fn a_nack_with_nothing_to_say_is_empty() {
        assert!(generic_nack(1, 2, &[]).is_empty());
    }

    #[test]
    fn rtcp_is_told_apart_from_rtp() {
        // The Mac's feedback is RTCP: version 2 and a feedback payload type.
        assert!(is_rtcp(&receiver_report(1)));
        assert!(is_rtcp(&compound(1, &full_intra_request(1, 2, 0))));
        // A video packet is not.
        assert!(!is_rtcp(&[0x80, 123, 0, 1, 0, 0, 0, 7, 0, 0, 0, 7]));
        // Nor is a scrap of nothing.
        assert!(!is_rtcp(&[0x80]));
        assert!(!is_rtcp(&[]));
    }

    #[test]
    fn a_new_fir_command_carries_a_new_sequence_number() {
        let mut fir = FirSequence::new(250);
        let first = full_intra_request(1, 2, fir.next());
        let second = full_intra_request(1, 2, fir.next());
        assert_eq!(first[16], 250, "the sequence number is not in the packet");
        assert_eq!(second[16], 251);
        assert_ne!(first, second, "a new command looked like a repeat");
        // The number wraps, which the RFC allows.
        let mut wrapping = FirSequence::new(255);
        assert_eq!(wrapping.next(), 255);
        assert_eq!(wrapping.next(), 0);
        assert_eq!(wrapping.next(), 1);
    }

    #[test]
    fn a_compound_packet_starts_with_a_receiver_report() {
        let packet = compound(7, &full_intra_request(7, 8, 0));
        assert_eq!(&packet[..8], &receiver_report(7)[..]);
        assert_eq!(packet.len(), 8 + 20);
    }
}
