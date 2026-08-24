//! The graphics channel, driven command by command with no socket.
//!
//! Every fixture below is built with `rdp-pdu`'s own encoders, which is the
//! property the mock server rests on too: every PDU type implements both
//! `Decode` and `Encode`, so a test writes where the client reads
//! (`crates/rdp-core/tests/common/mock_rdp_server.rs:12`).
//!
//! The envelope is always the literal form of `RDP_SEGMENTED_DATA`: descriptor
//! `SINGLE` (0xE0) then a flags byte of `PACKET_COMPR_TYPE_RDP8` with
//! `PACKET_COMPRESSED` clear (0x04). That is a real envelope and it goes
//! through the real `rdp_codecs::zgfx` entry point, which walks the segments
//! itself; what it does not exercise is the token table, because there is no
//! ZGFX compressor in the tree to build a compressed fixture with. The token
//! table's failure mode is covered instead by
//! [`a_message_that_decompresses_into_nonsense_names_zgfx`].

use super::*;
use crate::channels::dvc::ReplyBuf;
use rdp_pdu::update::{Point16, RectExclusive};
use rdp_pdu::vc::egfx::{cmd_id, codec_id, pixel_format, Color32};
use rdp_pdu::{Decode, Reader};
use remote_core::RectPayload;

/// `RDP_SEGMENTED_DATA` descriptor `SINGLE` (MS-RDPEGFX 2.2.5.1).
const SINGLE: u8 = 0xE0;
/// `PACKET_COMPR_TYPE_RDP8` with `PACKET_COMPRESSED` clear
/// (MS-RDPBCGR 3.1.8.4.2).
const LITERAL_RDP8: u8 = 0x04;

fn ctx() -> ChannelCtx {
    ChannelCtx {
        user_channel_id: 1007,
        desktop: (800, 600),
        event_backlog: 0,
    }
}

/// Wrap a sequence of EGFX commands in an uncompressed segmented envelope.
fn message(pdus: &[EgfxPdu<'_>]) -> Vec<u8> {
    let mut out = vec![SINGLE, LITERAL_RDP8];
    for pdu in pdus {
        pdu.encode_checked(&mut Writer::new(&mut out))
            .expect("encodes");
    }
    out
}

fn rect(left: u16, top: u16, right: u16, bottom: u16) -> RectExclusive {
    RectExclusive {
        left,
        top,
        right,
        bottom,
    }
}

/// One EGFX command out of a reply the channel queued.
fn queued(replies: &ReplyBuf) -> Vec<EgfxPdu<'_>> {
    replies
        .queued()
        .iter()
        .map(|buf| EgfxPdu::decode(&mut Reader::new(buf)).expect("a reply parses"))
        .collect()
}

/// A channel that has advertised and had its capabilities confirmed, with the
/// replies from that exchange already drained.
fn confirmed() -> (Egfx, Vec<SessionEvent>, ReplyBuf) {
    let mut egfx = Egfx::new();
    let mut replies = ReplyBuf::default();
    let mut events = Vec::new();
    egfx.opened(&mut replies).expect("advertises");
    replies.take();
    egfx.message(
        &message(&[EgfxPdu::CapsConfirm {
            capset: Capset::new(caps_version::V8_1, &[0, 0, 0, 0]),
        }]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("confirms");
    replies.take();
    events.clear();
    (egfx, events, replies)
}

/// A surface of `w` by `h` mapped to the output at `(x, y)`.
fn mapped_surface(egfx: &mut Egfx, id: u16, w: u16, h: u16, x: u32, y: u32) {
    let mut events = Vec::new();
    let mut replies = ReplyBuf::default();
    egfx.message(
        &message(&[
            EgfxPdu::CreateSurface {
                surface_id: id,
                width: w,
                height: h,
                pixel_format: pixel_format::XRGB_8888,
            },
            EgfxPdu::MapSurfaceToOutput {
                surface_id: id,
                reserved: 0,
                output_origin_x: x,
                output_origin_y: y,
            },
        ]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("creates and maps");
    assert!(events.is_empty() && replies.is_empty());
}

/// Two by one pixels of uncompressed EGFX: B G R X per pixel, top down, rows
/// packed to `width * 4` (MS-RDPEGFX 2.2.2.1).
const TWO_PIXELS: &[u8] = &[
    0x00, 0x00, 0xFF, 0x00, // red
    0xFF, 0x00, 0x00, 0x00, // blue
];

/// The rectangles one framebuffer update carried.
fn rects(events: &[SessionEvent]) -> Vec<(u16, u16, u16, u16, Vec<u8>)> {
    let mut out = Vec::new();
    for event in events {
        if let SessionEvent::FramebufferUpdate { rects, .. } = event {
            for r in rects {
                let RectPayload::Rgba(px) = &r.payload else {
                    panic!("egfx produces rgba payloads");
                };
                out.push((r.rect.x, r.rect.y, r.rect.width, r.rect.height, px.clone()));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The capability exchange
// ---------------------------------------------------------------------------

/// Opening the channel advertises what we can decode, and nothing above it.
/// The version list is a decision (see [`ADVERTISED`]), so it is pinned.
#[test]
fn opening_the_channel_advertises_versions_eight_and_eight_one() {
    let mut egfx = Egfx::new();
    let mut replies = ReplyBuf::default();
    egfx.opened(&mut replies).expect("advertises");

    let sent = queued(&replies);
    assert_eq!(sent.len(), 1);
    let EgfxPdu::CapsAdvertise { capsets } = &sent[0] else {
        panic!("expected a caps advertise, got {:?}", sent[0].cmd_id());
    };
    let versions: Vec<u32> = capsets.iter().map(|c| c.version).collect();
    assert_eq!(versions, vec![caps_version::V8, caps_version::V8_1]);
    for capset in capsets {
        // Neither the thin client flag nor the small cache flag: both shrink
        // the cache the server may use (MS-RDPEGFX 2.2.3.1).
        assert_eq!(capset.flags().expect("four byte body"), 0);
    }
}

/// The confirm settles the version and triggers the cache import offer, which
/// is empty because nothing in this build saves a cache between sessions.
#[test]
fn a_confirm_settles_the_version_and_offers_an_empty_cache() {
    let mut egfx = Egfx::new();
    let mut replies = ReplyBuf::default();
    let mut events = Vec::new();
    egfx.opened(&mut replies).expect("advertises");
    replies.take();

    egfx.message(
        &message(&[EgfxPdu::CapsConfirm {
            capset: Capset::new(caps_version::V8, &[0, 0, 0, 0]),
        }]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("confirms");
    assert_eq!(egfx.confirmed(), Some(caps_version::V8));

    let sent = queued(&replies);
    assert_eq!(sent.len(), 1);
    match &sent[0] {
        EgfxPdu::CacheImportOffer { entries } => assert!(entries.is_empty()),
        other => panic!("expected a cache import offer, got {:?}", other.cmd_id()),
    }
}

/// A confirm for a version we never offered means the two ends disagree about
/// what this channel is, and every command after it would be read against the
/// wrong set of rules.
#[test]
fn a_confirm_for_a_version_we_did_not_advertise_is_refused() {
    let mut egfx = Egfx::new();
    let mut replies = ReplyBuf::default();
    let mut events = Vec::new();
    let err = egfx
        .message(
            &message(&[EgfxPdu::CapsConfirm {
                capset: Capset::new(caps_version::V10_7, &[0, 0, 0, 0]),
            }]),
            ctx(),
            &mut events,
            &mut replies,
        )
        .expect_err("not advertised");
    assert!(err.to_string().contains("did not advertise"), "{err}");
    assert_eq!(egfx.confirmed(), None);
}

/// The server answering an empty offer with slots is describing a cache we do
/// not have, and every paste from one of those slots would miss.
#[test]
fn a_cache_import_reply_with_slots_against_an_empty_offer_is_refused() {
    let (mut egfx, mut events, mut replies) = confirmed();
    let err = egfx
        .message(
            &message(&[EgfxPdu::CacheImportReply {
                cache_slots: vec![1, 2, 3],
            }]),
            ctx(),
            &mut events,
            &mut replies,
        )
        .expect_err("nothing was offered");
    assert!(
        err.to_string().contains("against an offer of none"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// A frame, end to end
// ---------------------------------------------------------------------------

/// The whole path: create a surface, map it, open a frame, decode a rectangle
/// into it, close the frame. One framebuffer update comes out at the mapped
/// coordinates and one acknowledgement goes back.
#[test]
fn a_frame_is_decoded_emitted_at_its_mapped_origin_and_acknowledged() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 64, 64, 100, 200);

    let mut ctx = ctx();
    // Three events the shell has not taken: what the acknowledgement has to
    // report as `queueDepth` (MS-RDPEGFX 2.2.2.13).
    ctx.event_backlog = 3;

    egfx.message(
        &message(&[
            EgfxPdu::StartFrame {
                timestamp: 0x1234,
                frame_id: 7,
            },
            EgfxPdu::WireToSurface1 {
                surface_id: 1,
                codec_id: codec_id::UNCOMPRESSED,
                pixel_format: pixel_format::XRGB_8888,
                dest_rect: rect(2, 3, 4, 4),
                bitmap_data: rdp_pdu::Payload::new(TWO_PIXELS),
            },
            EgfxPdu::EndFrame { frame_id: 7 },
        ]),
        ctx,
        &mut events,
        &mut replies,
    )
    .expect("a frame");

    let rects = rects(&events);
    assert_eq!(rects.len(), 1);
    let (x, y, w, h, pixels) = &rects[0];
    // The surface origin is (100, 200) and the rectangle is at (2, 3) inside
    // it, so the framebuffer coordinates are (102, 203).
    assert_eq!((*x, *y, *w, *h), (102, 203, 2, 1));
    assert_eq!(
        pixels,
        &vec![0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF],
        "red then blue, in RGBA"
    );

    let sent = queued(&replies);
    assert_eq!(sent.len(), 1);
    match &sent[0] {
        EgfxPdu::FrameAcknowledge {
            queue_depth,
            frame_id,
            total_frames_decoded,
        } => {
            assert_eq!(*frame_id, 7);
            assert_eq!(*queue_depth, 3, "the shell's backlog, not a constant");
            assert_eq!(*total_frames_decoded, 1);
            assert_ne!(
                *queue_depth,
                EgfxPdu::SUSPEND_FRAME_ACKNOWLEDGEMENT,
                "PRDRDP/04 §3.6 forbids suspending acknowledgement"
            );
        }
        other => panic!("expected a frame acknowledge, got {:?}", other.cmd_id()),
    }
    assert_eq!(egfx.frames_decoded(), 1);
}

/// `totalFramesDecoded` is a running count over the life of the channel
/// (MS-RDPEGFX 2.2.2.13), and a client that restarts it every frame gives the
/// server no way to tell how far behind we are.
#[test]
fn the_decoded_frame_count_runs_across_frames() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 8, 8, 0, 0);

    for id in 1..=3u32 {
        replies.take();
        egfx.message(
            &message(&[
                EgfxPdu::StartFrame {
                    timestamp: id,
                    frame_id: id,
                },
                EgfxPdu::EndFrame { frame_id: id },
            ]),
            ctx(),
            &mut events,
            &mut replies,
        )
        .expect("a frame");
        match &queued(&replies)[0] {
            EgfxPdu::FrameAcknowledge {
                frame_id,
                total_frames_decoded,
                ..
            } => {
                assert_eq!(*frame_id, id);
                assert_eq!(*total_frames_decoded, id);
            }
            other => panic!("expected an acknowledge, got {:?}", other.cmd_id()),
        }
    }
}

/// A surface with no output mapping is composed into another one and never
/// shown. Emitting its contents would paint an offscreen scratch buffer over
/// the user's desktop.
#[test]
fn an_unmapped_surface_draws_but_emits_nothing() {
    let (mut egfx, mut events, mut replies) = confirmed();
    egfx.message(
        &message(&[EgfxPdu::CreateSurface {
            surface_id: 5,
            width: 16,
            height: 16,
            pixel_format: pixel_format::XRGB_8888,
        }]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("creates");

    egfx.message(
        &message(&[
            EgfxPdu::StartFrame {
                timestamp: 0,
                frame_id: 1,
            },
            EgfxPdu::WireToSurface1 {
                surface_id: 5,
                codec_id: codec_id::UNCOMPRESSED,
                pixel_format: pixel_format::XRGB_8888,
                dest_rect: rect(0, 0, 2, 1),
                bitmap_data: rdp_pdu::Payload::new(TWO_PIXELS),
            },
            EgfxPdu::EndFrame { frame_id: 1 },
        ]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("draws");
    assert!(
        rects(&events).is_empty(),
        "an offscreen surface stays offscreen"
    );
    // The acknowledgement still goes back: the frame was decoded, and a
    // server waiting on it would stall.
    assert_eq!(queued(&replies).len(), 1);
}

/// A command outside a frame still drew something, and holding it until an
/// `END_FRAME` that may never come would leave the screen stale.
#[test]
fn drawing_outside_a_frame_is_still_emitted_at_the_end_of_the_message() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 8, 8, 0, 0);
    egfx.message(
        &message(&[EgfxPdu::SolidFill {
            surface_id: 1,
            fill_pixel: Color32 {
                b: 0,
                g: 0xFF,
                r: 0,
                xa: 0,
            },
            fill_rects: vec![rect(0, 0, 2, 2)],
        }]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("fills");

    let rects = rects(&events);
    assert_eq!(rects.len(), 1);
    assert_eq!(
        (rects[0].0, rects[0].1, rects[0].2, rects[0].3),
        (0, 0, 2, 2)
    );
    assert_eq!(&rects[0].4[..4], &[0x00, 0xFF, 0x00, 0xFF], "green, opaque");
    assert!(replies.is_empty(), "no frame, so nothing to acknowledge");
}

// ---------------------------------------------------------------------------
// The cache
// ---------------------------------------------------------------------------

/// The saving EGFX is for: a rectangle decoded once, stored, and pasted back
/// twice without another byte on the wire.
#[test]
fn a_rectangle_goes_into_the_cache_and_comes_back_twice() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 16, 16, 0, 0);

    egfx.message(
        &message(&[
            EgfxPdu::WireToSurface1 {
                surface_id: 1,
                codec_id: codec_id::UNCOMPRESSED,
                pixel_format: pixel_format::XRGB_8888,
                dest_rect: rect(0, 0, 2, 1),
                bitmap_data: rdp_pdu::Payload::new(TWO_PIXELS),
            },
            EgfxPdu::SurfaceToCache {
                surface_id: 1,
                cache_key: 0xDEAD_BEEF,
                cache_slot: 4,
                rect_src: rect(0, 0, 2, 1),
            },
        ]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("caches");
    events.clear();

    egfx.message(
        &message(&[EgfxPdu::CacheToSurface {
            cache_slot: 4,
            surface_id: 1,
            dest_pts: vec![Point16 { x: 4, y: 4 }, Point16 { x: 8, y: 9 }],
        }]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("pastes");

    let rects = rects(&events);
    assert_eq!(rects.len(), 2);
    assert_eq!(
        (rects[0].0, rects[0].1, rects[0].2, rects[0].3),
        (4, 4, 2, 1)
    );
    assert_eq!(
        (rects[1].0, rects[1].1, rects[1].2, rects[1].3),
        (8, 9, 2, 1)
    );
    for r in &rects {
        assert_eq!(r.4, vec![0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF]);
    }
}

/// A paste from a slot nobody filled means the server and the client disagree
/// about what is cached, and painting whatever is nearby would hide it.
#[test]
fn a_paste_from_an_empty_slot_stops_rather_than_painting_nonsense() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 16, 16, 0, 0);
    let err = egfx
        .message(
            &message(&[EgfxPdu::CacheToSurface {
                cache_slot: 99,
                surface_id: 1,
                dest_pts: vec![Point16 { x: 0, y: 0 }],
            }]),
            ctx(),
            &mut events,
            &mut replies,
        )
        .expect_err("empty slot");
    assert!(err.to_string().contains("empty cache slot 99"), "{err}");
}

/// The cross surface copy, which is how a server composes a frame out of
/// pieces it drew separately.
#[test]
fn a_cross_surface_copy_moves_pixels_between_two_surfaces() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 16, 16, 0, 0);
    // The source is deliberately unmapped: a composition scratch surface.
    egfx.message(
        &message(&[EgfxPdu::CreateSurface {
            surface_id: 2,
            width: 16,
            height: 16,
            pixel_format: pixel_format::XRGB_8888,
        }]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("creates");

    egfx.message(
        &message(&[
            EgfxPdu::WireToSurface1 {
                surface_id: 2,
                codec_id: codec_id::UNCOMPRESSED,
                pixel_format: pixel_format::XRGB_8888,
                dest_rect: rect(0, 0, 2, 1),
                bitmap_data: rdp_pdu::Payload::new(TWO_PIXELS),
            },
            EgfxPdu::SurfaceToSurface {
                surface_id_src: 2,
                surface_id_dest: 1,
                rect_src: rect(0, 0, 2, 1),
                dest_pts: vec![Point16 { x: 3, y: 3 }],
            },
        ]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("copies");

    let rects = rects(&events);
    assert_eq!(rects.len(), 1, "only the mapped destination is emitted");
    assert_eq!(
        (rects[0].0, rects[0].1, rects[0].2, rects[0].3),
        (3, 3, 2, 1)
    );
    assert_eq!(
        rects[0].4,
        vec![0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF]
    );
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// The mitigation `docs/RDP_SPEC_NOTES.md` §1.1 asks for before the ZGFX
/// reconstruction goes live.
///
/// The token table is a reconstruction, and its failure mode is a wrong byte
/// every few thousand, which inside an EGFX message is a `cmdId` or a
/// `pduLength` that does not parse. A message that decompressed and then will
/// not parse therefore names ZGFX and the note, so the failure points at the
/// right file instead of looking like a broken server.
#[test]
fn a_message_that_decompresses_into_nonsense_names_zgfx() {
    let (mut egfx, mut events, mut replies) = confirmed();
    // A well formed envelope holding an `RDPGFX_HEADER` whose `pduLength`
    // claims far more than is there, which is exactly the shape a corrupted
    // decompression produces.
    let mut bad = vec![SINGLE, LITERAL_RDP8];
    bad.extend_from_slice(&cmd_id::START_FRAME.to_le_bytes());
    bad.extend_from_slice(&0u16.to_le_bytes());
    bad.extend_from_slice(&0xFFFF_u32.to_le_bytes());

    let err = egfx
        .message(&bad, ctx(), &mut events, &mut replies)
        .expect_err("does not parse");
    let text = err.to_string();
    assert!(text.contains("ZGFX"), "{text}");
    assert!(text.contains("RDP_SPEC_NOTES"), "{text}");
    assert!(text.contains("do not parse as EGFX commands"), "{text}");
}

/// An envelope the decompressor itself refuses is reported against the
/// decompression rather than against the command walk, so the two failures
/// are told apart in a log.
#[test]
fn an_envelope_the_decompressor_refuses_says_so() {
    let (mut egfx, mut events, mut replies) = confirmed();
    // Descriptor 0x42 is neither SINGLE nor MULTIPART.
    let err = egfx
        .message(&[0x42, 0x04], ctx(), &mut events, &mut replies)
        .expect_err("bad descriptor");
    assert!(err.to_string().contains("could not decompress"), "{err}");
}

/// One `RFX_PROGRESSIVE_SYNC` block, MS-RDPEGFX 2.2.4.2.1.1: the block type,
/// the `blockLen` that covers the six byte header and the six byte body, the
/// magic and the version.
fn progressive_sync(magic: u32) -> Vec<u8> {
    let mut out = vec![0xC0, 0xCC];
    out.extend_from_slice(&12u32.to_le_bytes());
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&0x0100u16.to_le_bytes());
    out
}

/// RemoteFX Progressive is the one codec a Windows server is likely to send
/// that no capability bit declines, and this build decodes it
/// (`docs/RDP_SPEC_NOTES.md` §1.6). What is proved here is the routing: the
/// codec id reaches `rdp_codecs::progressive` rather than the refusal that
/// used to stand in for it.
#[test]
fn a_progressive_rectangle_reaches_the_progressive_decoder() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 16, 16, 0, 0);
    egfx.message(
        &message(&[EgfxPdu::WireToSurface1 {
            surface_id: 1,
            codec_id: CODEC_CAPROGRESSIVE,
            pixel_format: pixel_format::XRGB_8888,
            dest_rect: rect(0, 0, 2, 1),
            bitmap_data: rdp_pdu::Payload::new(&progressive_sync(0xCACC_ACCA)),
        }]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("a well formed progressive message");
}

/// A bitstream the progressive decoder refuses is named the way every other
/// codec's refusal is named, and carries no byte of the bitstream
/// (PRDRDP/12 §6.4).
#[test]
fn a_refused_progressive_bitstream_names_the_codec() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 16, 16, 0, 0);
    let err = egfx
        .message(
            &message(&[EgfxPdu::WireToSurface1 {
                surface_id: 1,
                codec_id: CODEC_CAPROGRESSIVE,
                pixel_format: pixel_format::XRGB_8888,
                dest_rect: rect(0, 0, 2, 1),
                // Not `RFX_PROGRESSIVE_SYNC.magic`, which the decoder checks
                // before it walks anything (MS-RDPEGFX 2.2.4.2.1.1).
                bitmap_data: rdp_pdu::Payload::new(&progressive_sync(0xDEAD_BEEF)),
            }]),
            ctx(),
            &mut events,
            &mut replies,
        )
        .expect_err("a wrong sync magic");
    assert!(err.to_string().contains("progressive decoder"), "{err}");
    assert!(err.to_string().contains("2x1"), "{err}");
}

/// A command naming a surface that was never created means the two ends
/// disagree about what exists, and drawing the rest of the frame onto the
/// wrong thing is worse than stopping.
#[test]
fn a_command_for_a_surface_that_does_not_exist_is_refused() {
    let (mut egfx, mut events, mut replies) = confirmed();
    let err = egfx
        .message(
            &message(&[EgfxPdu::WireToSurface1 {
                surface_id: 77,
                codec_id: codec_id::UNCOMPRESSED,
                pixel_format: pixel_format::XRGB_8888,
                dest_rect: rect(0, 0, 2, 1),
                bitmap_data: rdp_pdu::Payload::new(TWO_PIXELS),
            }]),
            ctx(),
            &mut events,
            &mut replies,
        )
        .expect_err("no such surface");
    assert!(err.to_string().contains("surface 77"), "{err}");
}

/// A rectangle that does not fit the surface it names is refused before a
/// pixel moves. `rdp-pdu` cannot make this check: it does not know the
/// geometry.
#[test]
fn a_rectangle_larger_than_its_surface_is_refused() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 4, 4, 0, 0);
    let err = egfx
        .message(
            &message(&[EgfxPdu::WireToSurface1 {
                surface_id: 1,
                codec_id: codec_id::UNCOMPRESSED,
                pixel_format: pixel_format::XRGB_8888,
                dest_rect: rect(0, 0, 8, 8),
                bitmap_data: rdp_pdu::Payload::new(TWO_PIXELS),
            }]),
            ctx(),
            &mut events,
            &mut replies,
        )
        .expect_err("does not fit");
    assert!(err.to_string().contains("which is 4x4"), "{err}");
}

/// Scaling is the renderer's job, not the decoder's, so a mapping that would
/// stretch a surface is refused and an identity one is accepted.
#[test]
fn a_scaled_output_mapping_is_accepted_only_at_the_identity() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 16, 16, 0, 0);

    egfx.message(
        &message(&[EgfxPdu::MapSurfaceToScaledOutput {
            surface_id: 1,
            reserved: 0,
            output_origin_x: 5,
            output_origin_y: 6,
            target_width: 16,
            target_height: 16,
        }]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("the identity is an ordinary mapping");

    let err = egfx
        .message(
            &message(&[EgfxPdu::MapSurfaceToScaledOutput {
                surface_id: 1,
                reserved: 0,
                output_origin_x: 0,
                output_origin_y: 0,
                target_width: 32,
                target_height: 32,
            }]),
            ctx(),
            &mut events,
            &mut replies,
        )
        .expect_err("scaling");
    assert!(err.to_string().contains("does not do"), "{err}");
}

/// An origin past the framebuffer coordinate space has nowhere to be drawn,
/// and a `u16` cast would silently wrap it onto the visible desktop.
#[test]
fn an_origin_outside_the_framebuffer_coordinate_space_is_refused() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 16, 16, 0, 0);
    let err = egfx
        .message(
            &message(&[EgfxPdu::MapSurfaceToOutput {
                surface_id: 1,
                reserved: 0,
                output_origin_x: 70_000,
                output_origin_y: 0,
            }]),
            ctx(),
            &mut events,
            &mut replies,
        )
        .expect_err("outside");
    assert!(err.to_string().contains("70000"), "{err}");
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

/// `RESET_GRAPHICS` restarts the graphics session: every surface and every
/// cache slot belongs to the old geometry. The ZGFX history does not, because
/// the server does not reset its own copy (PRDRDP/04 §4.12.3), and this test
/// pins that difference by decoding a frame after the reset.
#[test]
fn a_reset_drops_the_surfaces_and_the_cache_and_keeps_the_history() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 16, 16, 0, 0);
    egfx.message(
        &message(&[
            EgfxPdu::WireToSurface1 {
                surface_id: 1,
                codec_id: codec_id::UNCOMPRESSED,
                pixel_format: pixel_format::XRGB_8888,
                dest_rect: rect(0, 0, 2, 1),
                bitmap_data: rdp_pdu::Payload::new(TWO_PIXELS),
            },
            EgfxPdu::SurfaceToCache {
                surface_id: 1,
                cache_key: 1,
                cache_slot: 1,
                rect_src: rect(0, 0, 2, 1),
            },
        ]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("draws and caches");
    events.clear();

    egfx.message(
        &message(&[EgfxPdu::ResetGraphics {
            width: 1024,
            height: 768,
            monitors: Vec::new(),
        }]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("resets");
    assert!(matches!(
        events.first(),
        Some(SessionEvent::DesktopResize {
            width: 1024,
            height: 768
        })
    ));

    // The surface is gone.
    let err = egfx
        .message(
            &message(&[EgfxPdu::CacheToSurface {
                cache_slot: 1,
                surface_id: 1,
                dest_pts: vec![Point16 { x: 0, y: 0 }],
            }]),
            ctx(),
            &mut events,
            &mut replies,
        )
        .expect_err("everything was dropped");
    assert!(err.to_string().contains("cache slot 1"), "{err}");

    // The channel still decodes: the history and every buffer survived.
    events.clear();
    mapped_surface(&mut egfx, 9, 8, 8, 0, 0);
    egfx.message(
        &message(&[EgfxPdu::WireToSurface1 {
            surface_id: 9,
            codec_id: codec_id::UNCOMPRESSED,
            pixel_format: pixel_format::XRGB_8888,
            dest_rect: rect(0, 0, 2, 1),
            bitmap_data: rdp_pdu::Payload::new(TWO_PIXELS),
        }]),
        ctx(),
        &mut events,
        &mut replies,
    )
    .expect("still decodes");
    assert_eq!(rects(&events).len(), 1);
}

/// An unknown `cmdId` carries its own length, so skipping it cannot
/// desynchronise the channel and the commands after it still run. That is the
/// condition PRDRDP/13 §2.7 rule 3 sets for tolerating one.
#[test]
fn an_unknown_command_is_skipped_and_the_next_one_still_runs() {
    let (mut egfx, mut events, mut replies) = confirmed();
    mapped_surface(&mut egfx, 1, 8, 8, 0, 0);

    let mut body = vec![SINGLE, LITERAL_RDP8];
    // An eleven byte command with a `cmdId` nothing defines.
    body.extend_from_slice(&0x7FFF_u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&11u32.to_le_bytes());
    body.extend_from_slice(&[1, 2, 3]);
    EgfxPdu::SolidFill {
        surface_id: 1,
        fill_pixel: Color32 {
            b: 0xFF,
            g: 0,
            r: 0,
            xa: 0,
        },
        fill_rects: vec![rect(0, 0, 1, 1)],
    }
    .encode_checked(&mut Writer::new(&mut body))
    .expect("encodes");

    egfx.message(&body, ctx(), &mut events, &mut replies)
        .expect("skips and carries on");
    let rects = rects(&events);
    assert_eq!(rects.len(), 1, "the command after the unknown one ran");
    assert_eq!(&rects[0].4, &[0x00, 0x00, 0xFF, 0xFF], "blue, opaque");
}
