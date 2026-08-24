//! Progressive RemoteFX, the whole message walk down to the tile blit
//! (MS-RDPEGFX 2.2.4.2 and 3.3.7, PRDRDP/04 §4.9, AGENT_BRIEF D11).
//!
//! Progressive has everything RemoteFX's target attacks plus the one thing
//! RemoteFX does not have, which is memory. An attacker controls a block
//! length, a rectangle count, two quantization table sizes, a tile count, a
//! tiles data size, three quantization indices and a quality index per tile,
//! six declared blob lengths per upgrade, and a tile position that decides
//! which slot of the store is written. The interesting inputs are the ones
//! that put those out of step with each other:
//!
//! * An upgrade for a tile no first pass ever arrived for, which must be a
//!   named `StateLost` rather than an index.
//! * A `quality` index past the end of the progressive quantization table.
//! * A bit position pair that asks for a shift of minus one, or for more bits
//!   than a coefficient can hold.
//! * A `WBT_CONTEXT` that changes the wavelet, and therefore the subband
//!   layout, under a store full of tiles coded with the other one.
//!
//! The store is deliberately given a small budget, so the budget path is
//! reached rather than being a branch no execution takes.
//!
//! Four decodes per execution through one store and one scratch, because the
//! store is the whole point of the codec: a decode that fails partway must
//! not poison the next one, and a decode into a differently sized destination
//! must not place tiles from a stale grid.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use rdp_codecs::progressive::{decode_message, ProgressiveState, TILE_BYTES};
use rdp_codecs::remotefx::RfxScratch;

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut first) = common::Canvas::draw(&mut u) else {
        return;
    };
    let Ok(mut second) = common::Canvas::draw(&mut u) else {
        return;
    };
    let src = u.take_rest();

    // Sixteen tiles is more than the largest canvas needs at 256 by 256 and
    // small enough that the budget refusal is reachable.
    let mut state = ProgressiveState::with_budget(16 * TILE_BYTES);
    let mut scratch = RfxScratch::new();

    {
        let mut v = first.view();
        let _ = decode_message(src, &mut state, &mut scratch, &mut v);
    }
    first.check();

    // The same message again, through a store that now holds whatever the
    // first decode left in it. This is what reaches the upgrade paths: the
    // second pass finds tiles that exist and refines them.
    {
        let mut v = first.view();
        let _ = decode_message(src, &mut state, &mut scratch, &mut v);
    }
    first.check();

    // A different geometry. The store has to notice the resize and drop its
    // grid; a decoder that kept it would place tiles from a stale `xIdx`.
    {
        let mut v = second.view();
        let _ = decode_message(src, &mut state, &mut scratch, &mut v);
    }
    second.check();

    // `reset` is part of the published state contract, and a reset store must
    // still serve a decode.
    state.reset();
    scratch.reset();
    {
        let mut v = second.view();
        let _ = decode_message(src, &mut state, &mut scratch, &mut v);
    }
    second.check();
});
