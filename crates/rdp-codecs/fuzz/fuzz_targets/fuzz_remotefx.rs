//! RemoteFX, the whole message walk down to the tile blit
//! (MS-RDPRFX 2.2.2 and 3.1.8, PRDRDP/04 §4.6, AGENT_BRIEF D11).
//!
//! The message layer is where the interesting attack surface is. A RemoteFX
//! message is a walk over self describing blocks, and inside the tileset a
//! second walk over self describing tiles, so an attacker controls a block
//! length, a tile count, a tiles data size, three component lengths per tile,
//! two quantization index bytes and a tile position. Every one of those is a
//! chance to read past a slice or to place a 64 by 64 tile outside the
//! destination.
//!
//! The entropy stage underneath is not a separate target, deliberately. It
//! cannot fail: `rlgr::decode` is total by construction (bits past the end
//! read as zero) so a fuzzer would only ever be proving that it terminates,
//! which its own unit tests already do exhaustively over leading bytes. What
//! a fuzzer can find is a message layer that hands it the wrong slice, and
//! that is what this target drives.
//!
//! Three decodes per execution through one context and one scratch, because
//! the entropy algorithm and the coefficient buffers both survive a call and
//! a decode that fails partway must not poison the next one.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use rdp_codecs::remotefx::{decode_message, RfxContext, RfxScratch};

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut first) = common::Canvas::draw(&mut u) else {
        return;
    };
    let Ok(mut second) = common::Canvas::draw(&mut u) else {
        return;
    };
    let src = u.take_rest();

    let mut ctx = RfxContext::new();
    let mut scratch = RfxScratch::new();

    {
        let mut v = first.view();
        let _ = decode_message(src, &mut ctx, &mut scratch, &mut v);
    }
    first.check();

    // The same message into a different geometry. A decoder that cached the
    // destination size from the previous call, or that placed tiles from a
    // stale `xIdx`, writes outside the rectangle here.
    {
        let mut v = second.view();
        let _ = decode_message(src, &mut ctx, &mut scratch, &mut v);
    }
    second.check();

    // `reset` is part of the published state contract, and a reset context
    // must still serve a decode.
    ctx.reset();
    scratch.reset();
    {
        let mut v = second.view();
        let _ = decode_message(src, &mut ctx, &mut scratch, &mut v);
    }
    second.check();
});
