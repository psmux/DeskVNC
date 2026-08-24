//! Message level tests for progressive RemoteFX.
//!
//! The per stage tests live with their stages, in [`super::bands`],
//! [`super::dwt`], [`super::srl`] and [`super::state`]. What is here is the
//! block walk, the tile dispatch, the clip, and the one property that is the
//! whole point of the codec: a tile sent as a first pass and then upgraded
//! converges on the picture a simple tile of the same content produces.

use super::*;
use crate::encode::progressive as enc;
use crate::uncompressed::dst_len;
use remote_pixel::{OutFormat, RowOrder};

const QUANT: [u8; 10] = crate::encode::RFX_QUANT_FINE;

// Byte offsets into a message the reference encoder built. A twelve byte
// sync, a twelve byte frame begin, a ten byte context, then the region.
const CTX_TILE_SIZE: usize = 12 + 12 + 6 + 1;
const CTX_FLAGS: usize = CTX_TILE_SIZE + 2;
const REGION_TILE_SIZE: usize = 12 + 12 + 10 + 6;

fn view<'a>(buf: &'a mut [u8], w: u16, h: u16) -> DstView<'a> {
    DstView::packed(buf, w, h, OutFormat::Rgba, RowOrder::TopDown).unwrap()
}

fn flat(rgb: [u8; 3]) -> Vec<[u8; 3]> {
    vec![rgb; TILE * TILE]
}

fn gradient() -> Vec<[u8; 3]> {
    (0..TILE * TILE)
        .map(|i| {
            let x = (i % TILE) as u8;
            let y = (i / TILE) as u8;
            [x.wrapping_mul(4), y.wrapping_mul(4), 128]
        })
        .collect()
}

/// Decode one message into a fresh 64 by 64 destination.
fn decode_one(msg: &[u8]) -> (Vec<u8>, ProgressiveFrame) {
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    let frame = {
        let mut v = view(&mut buf, 64, 64);
        decode_message(msg, &mut state, &mut scratch, &mut v).unwrap()
    };
    (buf, frame)
}

#[test]
fn a_flat_simple_tile_round_trips_exactly() {
    for rgb in [[0u8, 0, 0], [255, 255, 255], [30, 144, 255]] {
        let planes = enc::planes(&flat(rgb), &QUANT);
        let msg = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);
        let (buf, frame) = decode_one(&msg);
        assert_eq!(frame.tiles, 1);
        assert_eq!(frame.decoded, 1);
        assert_eq!(frame.upgrades, 0);
        assert_eq!(frame.frame_idx, Some(11));
        assert_eq!(
            frame.damage,
            Some(Rect {
                x: 0,
                y: 0,
                w: 64,
                h: 64
            })
        );
        for (i, px) in buf.chunks_exact(4).enumerate() {
            assert!(
                (i32::from(px[0]) - i32::from(rgb[0])).abs() <= 2
                    && (i32::from(px[1]) - i32::from(rgb[1])).abs() <= 2
                    && (i32::from(px[2]) - i32::from(rgb[2])).abs() <= 2
                    && px[3] == 0xFF,
                "pixel {i} is {px:?}, wanted {rgb:?}"
            );
        }
    }
}

/// A `WBT_TILE_SIMPLE` and a `TS_RFX_TILE` of the same pixels at the same
/// quantization have to produce the same picture, byte for byte.
///
/// This is the strongest single check in the module and it is worth saying
/// why. Every stage a simple tile uses is claimed to be shared with RemoteFX:
/// the RLGR1 decode, the LL3 differential, the inverse quantization, the whole
/// three level wavelet, the colour transform and the blit. If any one of them
/// were quietly forked, or if the progressive walk handed a stage a different
/// slice, these two buffers would differ. They cannot differ by a rounding
/// tolerance, because it is the same arithmetic, so this is an equality test.
#[test]
fn a_simple_tile_is_a_remotefx_tile() {
    for px in [flat([30, 144, 255]), gradient()] {
        let planes = enc::planes(&px, &QUANT);
        let prog_msg = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);
        let (prog_buf, _) = decode_one(&prog_msg);

        let rfx_msg = crate::encode::rfx_message(
            crate::remotefx::Entropy::Rlgr1,
            &[(0, 0, px.clone())],
            64,
            64,
        );
        let mut ctx = crate::remotefx::RfxContext::new();
        let mut scratch = RfxScratch::new();
        let mut rfx_buf = vec![0u8; dst_len(64, 64)];
        {
            let mut v = view(&mut rfx_buf, 64, 64);
            crate::remotefx::decode_message(&rfx_msg, &mut ctx, &mut scratch, &mut v).unwrap();
        }
        assert_eq!(prog_buf, rfx_buf);
    }
}

/// The property the codec exists for. A tile arrives as a coarse first pass
/// and is refined twice, and the third picture is the one a simple tile of the
/// same content produces.
///
/// The convergence is exact rather than approximate, and that is not a
/// coincidence: a refinement appends the bits a first pass shifted away, so
/// after the last pass the stored coefficients are the same integers. An
/// approximate result would mean a bit was lost or double counted.
///
/// Each pass is also checked to be an improvement, so a decoder that ignored
/// the upgrade blocks entirely could not pass this by leaving the first pass
/// in place.
#[test]
fn a_first_pass_and_two_upgrades_converge_on_the_simple_tile() {
    let px = gradient();
    let planes = enc::planes(&px, &QUANT);
    let coarse = [4u8; 10];
    let middle = [2u8; 10];
    let fine = [0u8; 10];
    let progs = [coarse, middle, fine];

    let want = {
        let msg = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);
        decode_one(&msg).0
    };

    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];

    let err_of = |buf: &[u8]| -> i64 {
        buf.chunks_exact(4)
            .zip(px.iter())
            .map(|(got, w)| {
                (0..3)
                    .map(|c| (i64::from(got[c]) - i64::from(w[c])).abs())
                    .sum::<i64>()
            })
            .sum()
    };

    let msgs = [
        enc::message(
            &[enc::tile_first(0, 0, &planes, 0, &coarse)],
            &QUANT,
            &progs,
            None,
        ),
        enc::message(
            &[enc::tile_upgrade(0, 0, &planes, 1, &coarse, &middle)],
            &QUANT,
            &progs,
            None,
        ),
        enc::message(
            &[enc::tile_upgrade(0, 0, &planes, 2, &middle, &fine)],
            &QUANT,
            &progs,
            None,
        ),
    ];

    let mut last = i64::MAX;
    for (pass, msg) in msgs.iter().enumerate() {
        let frame = {
            let mut v = view(&mut buf, 64, 64);
            decode_message(msg, &mut state, &mut scratch, &mut v).unwrap()
        };
        assert_eq!(frame.decoded, 1);
        assert_eq!(frame.upgrades, u32::from(pass > 0));
        let err = err_of(&buf);
        assert!(
            err < last,
            "pass {pass} did not improve the picture: {err} against {last}"
        );
        last = err;
    }

    assert_eq!(buf, want, "the upgraded tile is not the simple tile");
    assert_eq!(state.live_tiles(), 1);
}

/// A replacing pass overwrites every coefficient the tile held, which is the
/// property [`super::state::TileState::adopt`] relies on when it skips the
/// zero fill `restart` does.
///
/// Refine one tile across a first pass and two upgrades, then send a
/// `WBT_TILE_SIMPLE` of entirely different content into the same store and
/// require the picture a store that never saw the gradient produces, byte for
/// byte. A replacing pass that left any of the refined coefficients behind
/// changes this picture.
#[test]
fn a_simple_tile_replaces_whatever_the_store_held() {
    let refined = enc::planes(&gradient(), &QUANT);
    let replacing = enc::planes(&flat([30, 144, 255]), &QUANT);
    let coarse = [4u8; 10];
    let fine = [0u8; 10];
    let progs = [coarse, fine];

    let simple = enc::message(&[enc::tile_simple(0, 0, &replacing)], &QUANT, &[], None);
    let want = decode_one(&simple).0;

    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    for msg in [
        enc::message(
            &[enc::tile_first(0, 0, &refined, 0, &coarse)],
            &QUANT,
            &progs,
            None,
        ),
        enc::message(
            &[enc::tile_upgrade(0, 0, &refined, 1, &coarse, &fine)],
            &QUANT,
            &progs,
            None,
        ),
        simple.clone(),
    ] {
        let mut v = view(&mut buf, 64, 64);
        decode_message(&msg, &mut state, &mut scratch, &mut v).unwrap();
    }
    assert_eq!(buf, want, "a simple tile did not replace the refined one");
    assert_eq!(state.live_tiles(), 1);
}

/// `RFX_TILE_DIFFERENCE` (MS-RDPEGFX 2.2.4.2.1.6.1): the coefficients are
/// added to what the tile holds rather than replacing it. The reference
/// encoder never sets the flag, so the block is one it built with the bit
/// flipped, which is also the only way a fuzzer reaches this branch with a
/// decodable body.
///
/// Sent once into a fresh store it is the same picture as the replacing
/// version, because a fresh tile is zeros. Sent twice it doubles every
/// coefficient, and the second picture differs. Both halves matter: the first
/// says the flag is not simply ignored, the second says the addition happens.
#[test]
fn a_difference_pass_adds_to_the_store_rather_than_replacing_it() {
    let planes = enc::planes(&gradient(), &QUANT);
    let plain = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);
    let want = decode_one(&plain).0;

    // Block header, three quantization indices, `xIdx` and `yIdx`, then
    // `flags` (MS-RDPEGFX 2.2.4.2.1.6.1).
    let mut diff = plain.clone();
    let flags = enc::first_tile_offset(&plain) + 6 + 3 + 2 + 2;
    assert_eq!(diff[flags], 0);
    diff[flags] = 0x01;

    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    {
        let mut v = view(&mut buf, 64, 64);
        decode_message(&diff, &mut state, &mut scratch, &mut v).unwrap();
    }
    assert_eq!(
        buf, want,
        "a difference against zeros is not the tile itself"
    );

    let once = buf.clone();
    {
        let mut v = view(&mut buf, 64, 64);
        decode_message(&diff, &mut state, &mut scratch, &mut v).unwrap();
    }
    assert_ne!(buf, once, "the second difference pass changed nothing");
    assert_eq!(state.live_tiles(), 1);
}

/// A first pass on its own is visibly coarser than a simple tile, which is
/// what says the progressive quantization is being applied at all. A decoder
/// that ignored `quality` would pass the convergence test above and fail this
/// one.
#[test]
fn a_first_pass_alone_is_coarser_than_a_simple_tile() {
    let px = gradient();
    let planes = enc::planes(&px, &QUANT);
    let coarse = [5u8; 10];
    let simple = decode_one(&enc::message(
        &[enc::tile_simple(0, 0, &planes)],
        &QUANT,
        &[],
        None,
    ))
    .0;
    let first = decode_one(&enc::message(
        &[enc::tile_first(0, 0, &planes, 0, &coarse)],
        &QUANT,
        &[coarse],
        None,
    ))
    .0;
    assert_ne!(simple, first);
}

/// Tiles land where `xIdx` and `yIdx` say, a tile past the destination edge is
/// clipped, and a tile entirely past it is never decoded and never allocated.
#[test]
fn tiles_are_placed_by_index_and_clipped_to_the_destination() {
    let red = enc::planes(&flat([255, 0, 0]), &QUANT);
    let blue = enc::planes(&flat([0, 0, 255]), &QUANT);
    let msg = enc::message(
        &[
            enc::tile_simple(0, 0, &red),
            enc::tile_simple(1, 0, &blue),
            enc::tile_simple(5, 5, &blue),
        ],
        &QUANT,
        &[],
        None,
    );
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(100, 64)];
    let frame = {
        let mut v = view(&mut buf, 100, 64);
        decode_message(&msg, &mut state, &mut scratch, &mut v).unwrap()
    };
    assert_eq!(frame.tiles, 3);
    assert_eq!(frame.decoded, 2);
    assert_eq!(state.live_tiles(), 2);
    let px = |x: usize, y: usize| &buf[(y * 100 + x) * 4..][..3];
    assert!(px(10, 10)[0] > 200 && px(10, 10)[2] < 60);
    assert!(px(80, 10)[2] > 200 && px(80, 10)[0] < 60);
}

/// The region rectangles clip the blit, and everything outside them keeps
/// whatever the caller had in the buffer.
#[test]
fn a_region_rectangle_clips_the_blit() {
    let white = enc::planes(&flat([255, 255, 255]), &QUANT);
    let msg = enc::message(
        &[enc::tile_simple(0, 0, &white)],
        &QUANT,
        &[],
        Some(&[Rect {
            x: 8,
            y: 8,
            w: 16,
            h: 16,
        }]),
    );
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0x11u8; dst_len(64, 64)];
    let frame = {
        let mut v = view(&mut buf, 64, 64);
        decode_message(&msg, &mut state, &mut scratch, &mut v).unwrap()
    };
    assert_eq!(
        frame.damage,
        Some(Rect {
            x: 8,
            y: 8,
            w: 16,
            h: 16
        })
    );
    let px = |x: usize, y: usize| &buf[(y * 64 + x) * 4..][..4];
    assert_eq!(px(0, 0), &[0x11, 0x11, 0x11, 0x11]);
    assert_eq!(px(7, 8), &[0x11, 0x11, 0x11, 0x11]);
    assert!(px(8, 8)[0] > 200);
    assert!(px(23, 23)[0] > 200);
    assert_eq!(px(24, 24), &[0x11, 0x11, 0x11, 0x11]);
}

/// A tile that draws nothing because the region excludes it is still decoded
/// into the store. This is the documented divergence from RemoteFX's
/// PRDRDP/04 §4.6.7 early out and it is deliberate: the store would otherwise
/// fall a pass behind and the next upgrade would refine coefficients that were
/// never written.
#[test]
fn a_tile_outside_the_region_still_reaches_the_store() {
    let white = enc::planes(&flat([255, 255, 255]), &QUANT);
    let msg = enc::message(
        &[
            enc::tile_simple(0, 0, &white),
            enc::tile_simple(1, 0, &white),
        ],
        &QUANT,
        &[],
        Some(&[Rect {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
        }]),
    );
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(128, 64)];
    let frame = {
        let mut v = view(&mut buf, 128, 64);
        decode_message(&msg, &mut state, &mut scratch, &mut v).unwrap()
    };
    assert_eq!(frame.tiles, 2);
    assert_eq!(frame.decoded, 2);
    assert_eq!(state.live_tiles(), 2);
    // Nothing was written past the region.
    assert!(buf[64 * 4..128 * 4].iter().all(|&b| b == 0));
}

/// An upgrade for a tile no first pass ever arrived for is a named state loss
/// rather than an index. This is exactly the input a fuzzer finds.
#[test]
fn an_upgrade_without_a_first_pass_is_refused_by_name() {
    let planes = enc::planes(&gradient(), &QUANT);
    let progs = [[4u8; 10], [0u8; 10]];
    let msg = enc::message(
        &[enc::tile_upgrade(0, 0, &planes, 1, &progs[0], &progs[1])],
        &QUANT,
        &progs,
        None,
    );
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    let mut v = view(&mut buf, 64, 64);
    assert_eq!(
        decode_message(&msg, &mut state, &mut scratch, &mut v),
        Err(DecodeError::StateLost(
            "progressive upgrade before first pass"
        ))
    );
}

/// A `WBT_CONTEXT` selects the wavelet and the store remembers it, so a tile
/// coded under one layout and upgraded under the other is refused rather than
/// assembled out of two band tables.
#[test]
fn changing_the_wavelet_under_a_live_tile_is_refused() {
    let planes = enc::planes(&gradient(), &QUANT);
    let progs = [[4u8; 10], [0u8; 10]];
    let first = enc::message(
        &[enc::tile_first(0, 0, &planes, 0, &progs[0])],
        &QUANT,
        &progs,
        None,
    );
    let mut second = enc::message(
        &[enc::tile_upgrade(0, 0, &planes, 1, &progs[0], &progs[1])],
        &QUANT,
        &progs,
        None,
    );
    // The message is a twelve byte sync, a twelve byte frame begin and then a
    // ten byte context, whose body is ctxId, tileSize and flags. So the flags
    // byte is at 12 + 12 + 6 + 1 + 2.
    let at = CTX_FLAGS;
    assert_eq!(second[at], 0);
    second[at] = 0x01; // RFX_DWT_REDUCE_EXTRAPOLATE

    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    {
        let mut v = view(&mut buf, 64, 64);
        decode_message(&first, &mut state, &mut scratch, &mut v).unwrap();
    }
    let mut v = view(&mut buf, 64, 64);
    assert_eq!(
        decode_message(&second, &mut state, &mut scratch, &mut v),
        Err(DecodeError::StateLost(
            "progressive wavelet changed mid tile"
        ))
    );
}

/// A quantization index past the end of the region's table is a range error
/// rather than a read of whatever follows it.
#[test]
fn an_out_of_range_quant_index_is_refused() {
    let planes = enc::planes(&flat([10, 20, 30]), &QUANT);
    let mut msg = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);
    // The tile's quantIdxY is the first byte after its six byte block header.
    let at = enc::first_tile_offset(&msg) + 6;
    msg[at] = 3;
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    let mut v = view(&mut buf, 64, 64);
    assert_eq!(
        decode_message(&msg, &mut state, &mut scratch, &mut v),
        Err(DecodeError::Range {
            what: "quantIdxY",
            got: 3
        })
    );
}

/// A `quality` index past the end of the progressive table is a range error
/// too, and it is a separate table from the component one.
#[test]
fn an_out_of_range_quality_index_is_refused() {
    let planes = enc::planes(&flat([10, 20, 30]), &QUANT);
    let progs = [[4u8; 10]];
    let mut msg = enc::message(
        &[enc::tile_first(0, 0, &planes, 0, &progs[0])],
        &QUANT,
        &progs,
        None,
    );
    // quantIdxY, quantIdxCb, quantIdxCr, xIdx, yIdx, flags, then quality.
    let at = enc::first_tile_offset(&msg) + 6 + 3 + 4 + 1;
    assert_eq!(msg[at], 0);
    msg[at] = 9;
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    let mut v = view(&mut buf, 64, 64);
    assert_eq!(
        decode_message(&msg, &mut state, &mut scratch, &mut v),
        Err(DecodeError::Range {
            what: "RFX_PROGRESSIVE_TILE quality",
            got: 9
        })
    );
}

/// A block whose length is smaller than its own header would leave the walk
/// standing still. That is the one shape that can hang this loop, so it is
/// refused explicitly rather than by luck.
#[test]
fn a_zero_length_block_is_refused_rather_than_looping() {
    let mut msg = Vec::new();
    msg.extend_from_slice(&WBT_SYNC.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    let mut v = view(&mut buf, 64, 64);
    assert_eq!(
        decode_message(&msg, &mut state, &mut scratch, &mut v),
        Err(DecodeError::Range {
            what: "RFX_PROGRESSIVE_BLOCK blockLen",
            got: 0
        })
    );
}

#[test]
fn a_wrong_tile_size_is_refused_in_both_places_that_carry_one() {
    let planes = enc::planes(&flat([1, 2, 3]), &QUANT);
    let base = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);

    // The context block's tileSize.
    let mut msg = base.clone();
    let ctx_tile_size = CTX_TILE_SIZE;
    msg[ctx_tile_size] = 0x20;
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    {
        let mut v = view(&mut buf, 64, 64);
        assert_eq!(
            decode_message(&msg, &mut state, &mut scratch, &mut v),
            Err(DecodeError::Range {
                what: "RFX_PROGRESSIVE_CONTEXT tileSize",
                got: 0x20
            })
        );
    }

    // The region block's, which is one byte rather than two.
    let mut msg = base;
    let region_tile_size = REGION_TILE_SIZE;
    assert_eq!(msg[region_tile_size], 0x40);
    msg[region_tile_size] = 0x10;
    let mut v = view(&mut buf, 64, 64);
    assert_eq!(
        decode_message(&msg, &mut state, &mut scratch, &mut v),
        Err(DecodeError::Range {
            what: "RFX_PROGRESSIVE_REGION tileSize",
            got: 0x10
        })
    );
}

#[test]
fn a_bad_sync_magic_is_refused() {
    let planes = enc::planes(&flat([1, 2, 3]), &QUANT);
    let mut msg = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);
    msg[6] ^= 0xFF;
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    let mut v = view(&mut buf, 64, 64);
    assert!(matches!(
        decode_message(&msg, &mut state, &mut scratch, &mut v),
        Err(DecodeError::Range {
            what: "RFX_PROGRESSIVE_SYNC magic",
            ..
        })
    ));
}

/// The truncation sweep. Every prefix of a valid message must return `Err` or
/// `Ok`, must never panic, and must leave the store able to serve the next
/// decode.
#[test]
fn every_prefix_of_a_message_is_handled() {
    let planes = enc::planes(&flat([90, 120, 200]), &QUANT);
    let progs = [[4u8; 10], [0u8; 10]];
    for msg in [
        enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None),
        enc::message(
            &[enc::tile_first(0, 0, &planes, 0, &progs[0])],
            &QUANT,
            &progs,
            None,
        ),
        enc::message(
            &[enc::tile_upgrade(0, 0, &planes, 1, &progs[0], &progs[1])],
            &QUANT,
            &progs,
            None,
        ),
    ] {
        let mut state = ProgressiveState::new();
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0u8; dst_len(64, 64)];
        for n in 0..msg.len() {
            let mut v = view(&mut buf, 64, 64);
            let _ = decode_message(&msg[..n], &mut state, &mut scratch, &mut v);
        }
    }

    // And a whole first pass still works after all of that, so no partial
    // decode left the store or the scratch in a state that breaks the next.
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    let msg = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);
    for n in 0..msg.len() {
        let mut v = view(&mut buf, 64, 64);
        let _ = decode_message(&msg[..n], &mut state, &mut scratch, &mut v);
    }
    let mut v = view(&mut buf, 64, 64);
    assert!(decode_message(&msg, &mut state, &mut scratch, &mut v).is_ok());
}

/// The adversarial sweep over leading bytes: a message whose first block type
/// is replaced by every possible low byte, and separately every possible tile
/// block type.
#[test]
fn every_leading_block_type_terminates() {
    let planes = enc::planes(&flat([10, 20, 30]), &QUANT);
    let base = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);
    let tile_at = enc::first_tile_offset(&base);
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    for lead in 0u16..=255 {
        let mut msg = base.clone();
        msg[0] = lead as u8;
        msg[1] = 0xCC;
        {
            let mut v = view(&mut buf, 64, 64);
            let _ = decode_message(&msg, &mut state, &mut scratch, &mut v);
        }
        let mut msg = base.clone();
        msg[tile_at] = lead as u8;
        msg[tile_at + 1] = 0xCC;
        let mut v = view(&mut buf, 64, 64);
        let _ = decode_message(&msg, &mut state, &mut scratch, &mut v);
    }
}

/// Every single byte value in every position of a short synthetic block, which
/// is the shape a fuzzer reaches first and the one that decides whether a
/// length field can be trusted.
#[test]
fn every_byte_of_a_short_block_terminates() {
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    for pos in 0..12usize {
        for byte in 0u16..=255 {
            let mut msg = vec![0u8; 12];
            msg[0..2].copy_from_slice(&WBT_REGION.to_le_bytes());
            msg[2..6].copy_from_slice(&12u32.to_le_bytes());
            msg[pos] = byte as u8;
            let mut v = view(&mut buf, 64, 64);
            let _ = decode_message(&msg, &mut state, &mut scratch, &mut v);
        }
    }
}

/// The store is the codec's memory budget, so it has to report and release it
/// the way every other cross call state in this crate does.
#[test]
fn the_store_reports_and_releases_its_memory() {
    let planes = enc::planes(&flat([1, 2, 3]), &QUANT);
    let msg = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);
    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    {
        let mut v = view(&mut buf, 64, 64);
        decode_message(&msg, &mut state, &mut scratch, &mut v).unwrap();
    }
    assert_eq!(state.live_tiles(), 1);
    assert!(state.bytes() >= TILE_BYTES);
    assert!(state.seen_sync());
    state.reset();
    assert_eq!(state.bytes(), 0);
    assert!(!state.seen_sync());
    // A reset store still serves a decode, it just starts again from a first
    // pass. That is what makes dropping a context safe.
    let mut v = view(&mut buf, 64, 64);
    assert!(decode_message(&msg, &mut state, &mut scratch, &mut v).is_ok());
}

#[test]
fn the_budget_refuses_a_surface_it_cannot_hold() {
    let planes = enc::planes(&flat([1, 2, 3]), &QUANT);
    let msg = enc::message(
        &[
            enc::tile_simple(0, 0, &planes),
            enc::tile_simple(1, 0, &planes),
        ],
        &QUANT,
        &[],
        None,
    );
    let mut state = ProgressiveState::with_budget(TILE_BYTES);
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(128, 64)];
    let mut v = view(&mut buf, 128, 64);
    assert_eq!(
        decode_message(&msg, &mut state, &mut scratch, &mut v),
        Err(DecodeError::Budget("progressive tile store"))
    );
}

/// `scratch_len` is what a caller sizes a pool from, so it has to agree with
/// what a scratch actually allocates.
#[test]
fn the_scratch_is_the_remotefx_one() {
    assert_eq!(scratch_len(), crate::remotefx::scratch_len());
    let s = RfxScratch::with_capacity();
    assert_eq!(s.bytes(), scratch_len());
}

/// Set `RFX_DWT_REDUCE_EXTRAPOLATE` on a message the reference encoder built.
///
/// The encoder only emits the plain layout, for the reason its module comment
/// gives, so this is how the extrapolated band table, its differential decode,
/// its dequantization and its wavelet are reached through the real message
/// walk rather than only through their own unit tests. The pixels such a
/// message produces are not a picture of anything: the coefficients were
/// quantized against one band table and are read against another. What is
/// being checked is that the flag reaches every stage and that none of them
/// panics, reads out of range or refuses a legal block.
fn extrapolate(msg: &mut [u8]) {
    assert_eq!(msg[CTX_FLAGS], 0);
    msg[CTX_FLAGS] = 0x01;
}

/// The flag has to change the picture. If it did not, the context byte would
/// be parsed and thrown away and every extrapolate test in this crate would
/// be testing the plain path.
#[test]
fn the_extrapolate_flag_reaches_the_band_table_and_the_wavelet() {
    let planes = enc::planes(&gradient(), &QUANT);
    let plain = enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None);
    let mut extra = plain.clone();
    extrapolate(&mut extra);

    let (a, fa) = decode_one(&plain);
    let (b, fb) = decode_one(&extra);
    assert_eq!(fa.decoded, 1);
    assert_eq!(fb.decoded, 1);
    assert_ne!(a, b);
    // Both are real pictures rather than a buffer left at zero.
    assert!(b
        .chunks_exact(4)
        .any(|p| p[0] != 0 || p[1] != 0 || p[2] != 0));
    assert!(b.chunks_exact(4).all(|p| p[3] == 0xFF));
}

/// An upgrade under the extrapolated layout runs the SRL pass over the second
/// band table, whose bands are 1023, 961, 272 and 81 long rather than powers
/// of two. A band length the pass does not expect is the kind of thing that
/// reads one coefficient past a band or leaves the two streams out of step,
/// and neither shows up in the plain layout.
#[test]
fn a_first_pass_and_an_upgrade_run_under_the_extrapolated_layout() {
    let planes = enc::planes(&gradient(), &QUANT);
    let progs = [[4u8; 10], [0u8; 10]];
    let mut first = enc::message(
        &[enc::tile_first(0, 0, &planes, 0, &progs[0])],
        &QUANT,
        &progs,
        None,
    );
    let mut upgrade = enc::message(
        &[enc::tile_upgrade(0, 0, &planes, 1, &progs[0], &progs[1])],
        &QUANT,
        &progs,
        None,
    );
    extrapolate(&mut first);
    extrapolate(&mut upgrade);

    let mut state = ProgressiveState::new();
    let mut scratch = RfxScratch::new();
    let mut buf = vec![0u8; dst_len(64, 64)];
    {
        let mut v = view(&mut buf, 64, 64);
        decode_message(&first, &mut state, &mut scratch, &mut v).unwrap();
    }
    let after_first = buf.clone();
    let frame = {
        let mut v = view(&mut buf, 64, 64);
        decode_message(&upgrade, &mut state, &mut scratch, &mut v).unwrap()
    };
    assert_eq!(frame.upgrades, 1);
    assert_ne!(buf, after_first, "the upgrade changed nothing");
}

/// The truncation and leading byte sweeps again, with the extrapolated band
/// table in force. The two layouts take different code paths through the
/// differential decode, the dequantization and the wavelet, so a sweep that
/// only covers one covers half of it.
#[test]
fn every_prefix_of_an_extrapolated_message_is_handled() {
    let planes = enc::planes(&flat([90, 120, 200]), &QUANT);
    let progs = [[4u8; 10], [0u8; 10]];
    for mut msg in [
        enc::message(&[enc::tile_simple(0, 0, &planes)], &QUANT, &[], None),
        enc::message(
            &[enc::tile_first(0, 0, &planes, 0, &progs[0])],
            &QUANT,
            &progs,
            None,
        ),
        enc::message(
            &[enc::tile_upgrade(0, 0, &planes, 1, &progs[0], &progs[1])],
            &QUANT,
            &progs,
            None,
        ),
    ] {
        extrapolate(&mut msg);
        let mut state = ProgressiveState::new();
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0u8; dst_len(64, 64)];
        for n in 0..msg.len() {
            let mut v = view(&mut buf, 64, 64);
            let _ = decode_message(&msg[..n], &mut state, &mut scratch, &mut v);
        }
        for lead in 0u16..=255 {
            let mut m = msg.clone();
            let at = enc::first_tile_offset(&m);
            m[at] = lead as u8;
            m[at + 1] = 0xCC;
            let mut v = view(&mut buf, 64, 64);
            let _ = decode_message(&m, &mut state, &mut scratch, &mut v);
        }
    }
}
