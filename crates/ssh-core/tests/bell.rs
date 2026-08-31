//! The terminal bell, end to end through the two pieces the byte pump wires
//! together: [`ModeTracker::take_bell`] decides what is a bell, and
//! [`BellLimiter`] decides how often one is allowed to ring.
//!
//! REGRESSION: `SshEvent::Bell` was declared, translated to
//! `SessionEvent::Bell`, and serialised by the shell, but nothing in this
//! crate ever constructed one. The bell was dead code end to end and the
//! terminal was silent no matter what the remote sent.

use std::time::{Duration, Instant};

use ssh_core::bell::BellLimiter;
use ssh_core::modes::ModeTracker;

/// What the byte pump does with one read from the remote: feed it to the
/// parser, then ring if it held a real bell and the limiter allows it.
/// Returns whether an `SshEvent::Bell` would have been emitted.
fn pump_chunk(
    tracker: &mut ModeTracker,
    limiter: &mut BellLimiter,
    now: Instant,
    data: &[u8],
) -> bool {
    tracker.feed(data);
    tracker.take_bell() && limiter.ring(now)
}

#[test]
fn a_bare_bel_rings() {
    let mut tracker = ModeTracker::new();
    let mut limiter = BellLimiter::new();
    assert!(pump_chunk(
        &mut tracker,
        &mut limiter,
        Instant::now(),
        b"make: *** [all] Error 1\x07\r\n"
    ));
}

/// The one that makes or breaks the feature. `ESC ] 0 ; text BEL` sets the
/// window title, bash, zsh and fish all write it on EVERY prompt, and the BEL
/// there is a string terminator (xterm ctlseqs, "Operating System Commands"),
/// not a sound. A naive scan for 0x07 rings on every prompt the user sees.
#[test]
fn the_bel_that_terminates_an_osc_title_does_not_ring() {
    let mut tracker = ModeTracker::new();
    let mut limiter = BellLimiter::new();
    let now = Instant::now();
    assert!(!pump_chunk(
        &mut tracker,
        &mut limiter,
        now,
        b"\x1b]0;gj@box: ~/src/vncviewer\x07"
    ));
    // Ten prompts in a row, the way a session of short commands looks.
    for i in 0..10 {
        assert!(
            !pump_chunk(
                &mut tracker,
                &mut limiter,
                now + Duration::from_secs(i + 1),
                b"\x1b]0;gj@box: ~\x07$ ls\r\n"
            ),
            "prompt {i} rang the bell"
        );
    }
}

/// The title sequence must not swallow the bell that follows it either: the
/// parser has to come back to ground when the OSC ends.
#[test]
fn a_bel_after_an_osc_title_still_rings() {
    let mut tracker = ModeTracker::new();
    let mut limiter = BellLimiter::new();
    assert!(pump_chunk(
        &mut tracker,
        &mut limiter,
        Instant::now(),
        b"\x1b]0;gj@box\x07done\x07"
    ));
}

/// A TCP read can be cut at any byte, including between the OSC payload and
/// its terminator. The split must not turn the terminator into a bell.
#[test]
fn an_osc_split_across_reads_still_does_not_ring() {
    let mut tracker = ModeTracker::new();
    let mut limiter = BellLimiter::new();
    let now = Instant::now();
    assert!(!pump_chunk(
        &mut tracker,
        &mut limiter,
        now,
        b"\x1b]0;gj@box"
    ));
    assert!(!pump_chunk(&mut tracker, &mut limiter, now, b"\x07"));
}

/// A DCS payload is read out whole and its bytes mean nothing to us; a 0x07
/// inside one is payload, not a bell.
#[test]
fn a_bel_inside_a_dcs_payload_does_not_ring() {
    let mut tracker = ModeTracker::new();
    let mut limiter = BellLimiter::new();
    assert!(!pump_chunk(
        &mut tracker,
        &mut limiter,
        Instant::now(),
        b"\x1bPq\x07 payload \x1b\\"
    ));
}

/// A build printing a bell per error, or `cat` of a binary file, delivers
/// thousands of BELs in a moment. One event each would be thousands of
/// channel sends, thousands of IPC messages, and thousands of overlapping
/// sounds for what a person hears as one burst of noise.
#[test]
fn a_flood_of_bells_coalesces() {
    let mut tracker = ModeTracker::new();
    let mut limiter = BellLimiter::new();
    let start = Instant::now();

    // Two thousand bells spread evenly over one second of wall clock.
    let mut rung = 0;
    for i in 0..2000u64 {
        if pump_chunk(
            &mut tracker,
            &mut limiter,
            start + Duration::from_micros(i * 500),
            &[0x07],
        ) {
            rung += 1;
        }
    }
    assert!(
        rung >= 1,
        "the first bell of a burst must still ring immediately"
    );
    assert!(
        rung <= 5,
        "2000 bells in one second became {rung} events; the quiet period caps it at four a second"
    );
}

/// Coalescing must not become muting: two bells a person actually made, well
/// apart, are two bells.
#[test]
fn bells_a_second_apart_both_ring() {
    let mut tracker = ModeTracker::new();
    let mut limiter = BellLimiter::new();
    let start = Instant::now();
    assert!(pump_chunk(&mut tracker, &mut limiter, start, b"\x07"));
    assert!(pump_chunk(
        &mut tracker,
        &mut limiter,
        start + Duration::from_secs(1),
        b"\x07"
    ));
}

/// Ordinary output has no business ringing anything.
#[test]
fn plain_output_never_rings() {
    let mut tracker = ModeTracker::new();
    let mut limiter = BellLimiter::new();
    assert!(!pump_chunk(
        &mut tracker,
        &mut limiter,
        Instant::now(),
        b"total 48\r\ndrwxr-xr-x  3 gj staff  96 Aug 25 14:40 .\r\n"
    ));
}
