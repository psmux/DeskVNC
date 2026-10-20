// Review characterization: these probes assert current defects, not corrected behavior.
#[path = "../../../../crates/apple-core/src/h264.rs"]
mod h264;
#[path = "../../../../crates/apple-core/src/pictures.rs"]
mod pictures;
#[path = "../../../../crates/apple-core/src/rtcp.rs"]
mod rtcp;
#[path = "../../../../crates/apple-core/src/srtp.rs"]
mod srtp;
#[path = "../../../../crates/apple-core/src/video.rs"]
mod video;

#[cfg(test)]
mod review {
    use super::*;
    use std::time::{Duration, Instant};
    fn au(id: u8, keyframe: bool) -> h264::AccessUnit {
        h264::AccessUnit {
            annex_b: vec![id],
            keyframe,
            reset: keyframe,
        }
    }
    fn key_picture() -> Vec<u8> {
        let mut p = vec![0x78, 0, 0];
        for nal in [&[0x67, 0x64, 0, 0x34][..], &[0x68, 0xee], &[0x65, 0xb8]] {
            p.extend_from_slice(&(nal.len() as u16).to_be_bytes());
            p.extend_from_slice(nal);
        }
        p
    }
    fn packet(ssrc: u32, seq: u16) -> Vec<u8> {
        let mut p = vec![0x80, 0x80 | 123];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&u32::from(seq).to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&key_picture());
        srtp::SrtpEncryptor::from_blob(&[0x12; 46])
            .unwrap()
            .protect(&p)
            .unwrap()
    }
    fn receiver() -> video::VideoStreams {
        video::VideoStreams::new(
            srtp::SrtpContext::from_blob(&[0x12; 46]).unwrap(),
            Instant::now(),
        )
    }
    fn authenticated_rtp(seq: u16, roc: u32) -> Vec<u8> {
        use cipher::{BlockEncrypt, KeyInit};
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        let aes = aes::Aes256::new((&[0x12; 32]).into());
        let mut iv = [0u8; 16];
        iv[..14].fill(0x12);
        iv[7] ^= 1;
        let mut key = Vec::new();
        while key.len() < 20 {
            let mut block = cipher::generic_array::GenericArray::from(iv);
            aes.encrypt_block(&mut block);
            key.extend_from_slice(&block);
            for b in iv.iter_mut().rev() {
                *b = b.wrapping_add(1);
                if *b != 0 {
                    break;
                }
            }
        }
        key.truncate(20);
        let mut p = vec![0x80, 123];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&10u32.to_be_bytes());
        p.push(0xaa);
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&key).unwrap();
        mac.update(&p);
        mac.update(&roc.to_be_bytes());
        p.extend_from_slice(&mac.finalize().into_bytes()[..10]);
        p
    }
    #[test]
    fn confirms_epoch_reset_rejects_continuing_stream_after_second_rollover() {
        let mut r = srtp::SrtpContext::from_blob(&[0x12; 46]).unwrap();
        for (seq, roc) in [(65534, 0), (0, 1), (65534, 1), (0, 2)] {
            assert!(r.unprotect(&authenticated_rtp(seq, roc)).is_some());
        }
        r.new_epoch();
        assert!(
            r.unprotect(&authenticated_rtp(1, 2)).is_none(),
            "BUG: reset forgets ROC=2 and all continuing media fails authentication"
        );
    }
    #[test]
    fn confirms_epoch_reset_accepts_old_authenticated_replay() {
        let mut r = srtp::SrtpContext::from_blob(&[0x12; 46]).unwrap();
        let p = authenticated_rtp(1, 0);
        assert!(r.unprotect(&p).is_some());
        assert!(r.unprotect(&p).is_none());
        r.new_epoch();
        assert!(
            r.unprotect(&p).is_some(),
            "BUG: local epoch has no authenticated wire discriminator"
        );
    }
    #[test]
    #[ignore = "fixed: the corrected-behaviour regression is in the production suite, see docs/plans/2026-10-20-apple-long-session-progress.md"]
    fn confirms_buffer_replays_delta_preceding_recovery_keyframe() {
        let mut b = pictures::PictureBuffer::with_capacity(3);
        for (id, key) in [(1, false), (2, false), (3, true), (4, false)] {
            b.push(au(id, key));
        }
        assert_eq!(b.pop().unwrap().annex_b, [3]);
        assert_eq!(
            b.pop().unwrap().annex_b,
            [2],
            "BUG: stale delta 2 follows recovery keyframe 3"
        );
    }
    #[test]
    #[ignore = "fixed: the corrected-behaviour regression is in the production suite, see docs/plans/2026-10-20-apple-long-session-progress.md"]
    fn confirms_stream_capacity_permanently_blocks_33rd_restart() {
        let mut r = receiver();
        let now = Instant::now();
        for id in 1..=32 {
            assert_eq!(r.push(&packet(id, 0), id as u64, now).len(), 1);
        }
        assert!(r
            .push(&packet(33, 0), 33, now + Duration::from_secs(2))
            .is_empty());
        r.new_epoch();
        assert!(r
            .push(&packet(33, 0), 34, now + Duration::from_secs(3))
            .is_empty());
        assert_eq!(r.active(), Some(32));
    }
    #[test]
    fn confirms_retired_ssrc_never_recovers_in_new_epoch() {
        let mut r = receiver();
        let now = Instant::now();
        assert_eq!(r.push(&packet(10, 0), 1, now).len(), 1);
        assert_eq!(r.push(&packet(20, 0), 2, now).len(), 1);
        r.new_epoch();
        assert!(r
            .push(&packet(10, 0), 3, now + Duration::from_secs(3))
            .is_empty());
        assert_eq!(r.active(), Some(20));
    }
    #[test]
    #[ignore = "fixed: the corrected-behaviour regression is in the production suite, see docs/plans/2026-10-20-apple-long-session-progress.md"]
    fn confirms_same_timestamp_tail_after_loss_published_as_complete_key() {
        let mut d = h264::Depacketizer::default();
        d.push(1, 100, false, &[0x65, 0xb8]);
        assert!(d.push(3, 100, true, &[0x65, 0xb8]).is_empty());
        std::thread::sleep(Duration::from_millis(70));
        let units = d.flush();
        assert_eq!(units.len(), 1, "BUG: tail of damaged AU is emitted");
        assert!(units[0].keyframe);
        assert_eq!(d.stats.lost_packets, 1);
    }
    #[test]
    #[ignore = "fixed: the corrected-behaviour regression is in the production suite, see docs/plans/2026-10-20-apple-long-session-progress.md"]
    fn confirms_far_gap_lost_count_is_one_short() {
        let mut d = h264::Depacketizer::default();
        d.push(1, 1, true, &[0x65, 0xb8]);
        d.push(20, 2, true, &[0x65, 0xb8]);
        assert_eq!(
            d.stats.lost_packets, 17,
            "BUG: seq 2..19 is 18 missing packets"
        );
        assert_eq!(d.stats.lost_sequences.last(), Some(&18));
    }
    #[test]
    #[ignore = "fixed: the corrected-behaviour regression is in the production suite, see docs/plans/2026-10-20-apple-long-session-progress.md"]
    fn confirms_config_sequence_is_reported_as_lost() {
        let mut d = h264::Depacketizer::default();
        d.push(1, 1, true, &[0x65, 0xb8]);
        d.push(2, 2, false, &[0x92, 0]);
        assert!(d.push(3, 3, true, &[0x65, 0xb8]).is_empty());
        std::thread::sleep(Duration::from_millis(70));
        assert_eq!(d.flush().len(), 1);
        assert_eq!(
            d.stats.lost_sequences,
            [2],
            "BUG: received configuration packet is counted lost"
        );
    }
    #[test]
    #[ignore = "fixed: the corrected-behaviour regression is in the production suite, see docs/plans/2026-10-20-apple-long-session-progress.md"]
    fn confirms_numeric_reorder_wrap_loses_received_pre_wrap_packet() {
        let mut d = h264::Depacketizer::default();
        d.push(65533, 1, true, &[0x65, 0xb8]);
        d.push(0, 2, true, &[0x65, 0xb8]);
        d.push(65535, 2, false, &[0x65, 0xb8]);
        std::thread::sleep(Duration::from_millis(70));
        let units = d.flush();
        assert_eq!(units.len(), 1);
        assert_eq!(
            d.stats.lost_packets, 2,
            "BUG: only 65534 is missing; 65535 is buffered"
        );
        std::thread::sleep(Duration::from_millis(70));
        d.flush();
        assert_eq!(d.stats.late, 1);
    }
    #[test]
    #[ignore = "fixed: the corrected-behaviour regression is in the production suite, see docs/plans/2026-10-20-apple-long-session-progress.md"]
    fn confirms_fragment_buffer_exceeds_documented_8mib_limit() {
        let mut d = h264::Depacketizer::default();
        let mut payload = vec![0xaa; 65500];
        payload[..2].copy_from_slice(&[0x7c, 0x85]);
        d.push(0, 1, false, &payload);
        payload[1] = 5;
        for seq in 1..=130 {
            assert!(d.push(seq, 1, false, &payload).is_empty());
        }
        assert_eq!(
            d.stats.malformed, 0,
            "BUG: unfinished FU > 8 MiB is never rejected"
        );
    }
    #[test]
    #[ignore = "fixed: the corrected-behaviour regression is in the production suite, see docs/plans/2026-10-20-apple-long-session-progress.md"]
    fn confirms_srtp_padding_is_removed_before_decryption() {
        let mut p = vec![0xa0, 123, 0, 1, 0, 0, 0, 1, 0, 0, 0, 10, 0x65, 0xb8, 0, 2];
        let mut tx = srtp::SrtpEncryptor::from_blob(&[0x12; 46]).unwrap();
        let protected = tx.protect(&p).unwrap();
        let mut rx = srtp::SrtpContext::from_blob(&[0x12; 46]).unwrap();
        let result = rx.unprotect(&protected);
        assert!(
            result.is_none() || result.unwrap().payload != p.split_off(12)[..2],
            "BUG present unless ciphertext padding byte happens to match plaintext pad count"
        );
    }
}
