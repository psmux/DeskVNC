#!/usr/bin/env python3
"""Read-only regression probes for the 2026-10-20 resolution audit.

Extract the actual pure resize/descriptor helpers from session.rs and compile
those unchanged helpers in a temporary Rust test binary. No production files,
network connections, app processes, or settings are changed. Failures assert
desired behaviour, not the buggy behaviour, and are expected at the audit HEAD.
This is not a full session integration test.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / "crates/apple-core/src/session.rs"


def main() -> int:
    source = SOURCE.read_text()
    resize = source[
        source.index("#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nstruct DisplayGeometry"):
        source.index("/// Ask for a size, or remember the ask until the running round is over.")
    ]
    descriptor = source[
        source.index("#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nstruct DisplayRequest"):
        source.index("fn set_encodings()")
    ]
    rustc = shutil.which("rustc")
    if rustc is None:
        raise SystemExit("rustc is required; load the existing Rust toolchain first")
    tests = r'''
#[cfg(test)]
mod review {
    use super::*;

    fn geometry(pixels: (u16, u16), points: (u16, u16)) -> DisplayGeometry {
        DisplayGeometry { pixels, points }
    }

    #[test]
    fn one_pixel_rounding_is_not_a_reason_to_restore_the_desktop() {
        let sent = geometry((1800, 1170), (1800, 1169));
        let confirmed = geometry((1800, 1169), (1800, 1169));
        assert!(
            !desktop_shrank(Some((sent, confirmed))),
            "unchanged desktop points plus a one-pixel backing difference triggers rollback"
        );
    }

    #[test]
    fn a_logical_desktop_shrink_is_not_hidden_by_unchanged_backing() {
        let sent = geometry((3600, 2338), (1800, 1169));
        let confirmed = geometry((3600, 2338), (900, 584));
        assert!(
            desktop_shrank(Some((sent, confirmed))),
            "logical desktop shrank while pixel-only check reported no shrink"
        );
    }

    #[test]
    fn queued_round_snapshots_its_own_previous_confirmed_geometry() {
        let original = geometry((3600, 2338), (1800, 1169));
        let low = geometry((1800, 1170), (1800, 1169));
        let actual_low = geometry((1800, 1169), (1800, 1169));
        let medium = geometry((2700, 1754), (1800, 1169));
        let mut round = ResizeRound::default();
        assert_eq!(plan_resize(&mut round, low, original), ResizeAction::Send(low));
        assert_eq!(plan_resize(&mut round, medium, original), ResizeAction::Wait);
        round.confirmed = Some(actual_low);
        round.awaiting_layout = false;
        assert_eq!(finish_round(&mut round), RoundEnd::Send(medium));
        assert_eq!(
            round.before, Some(actual_low),
            "queued round reuses the first round's stale rollback target"
        );
    }

    #[test]
    fn descriptor_must_not_silently_serialize_a_different_pixel_request() {
        // A 4:3 picture on a 16:10 desktop is an intent that cannot be
        // expressed without changing the desktop, so it must be rejected
        // before transmission. What must never happen is reporting one target
        // and sending another.
        let intent = DisplayRequest { points: (1800, 1169), pixels: (1600, 1200) };
        let wire = display_config(intent, (3600, 2338));
        let mode = 12 + 0x9c;
        let actual = (
            u32::from_be_bytes(wire[mode..mode + 4].try_into().unwrap()),
            u32::from_be_bytes(wire[mode + 4..mode + 8].try_into().unwrap()),
        );
        // If the intent is unsupported, validate and reject it before this
        // serializer is called. Reporting one target and sending another is
        // not a valid outcome.
        assert_eq!(actual, (1600, 1200), "requested telemetry differs from the wire");
    }

    #[test]
    fn advertised_bounds_already_cover_first_mode() {
        let request = DisplayRequest { points: (1800, 1169), pixels: (3600, 2338) };
        let wire = display_config(request, (1600, 1200));
        let d = 12;
        let mode = d + 0x9c;
        let bound_w = u32::from_be_bytes(wire[d + 0x8a..d + 0x8e].try_into().unwrap());
        let bound_h = u32::from_be_bytes(wire[d + 0x8e..d + 0x92].try_into().unwrap());
        let mode_w = u32::from_be_bytes(wire[mode..mode + 4].try_into().unwrap());
        let mode_h = u32::from_be_bytes(wire[mode + 4..mode + 8].try_into().unwrap());
        assert!(bound_w >= mode_w && bound_h >= mode_h);
    }
}
'''
    prelude = "use std::time::Instant;\n"
    with tempfile.TemporaryDirectory(prefix="apple-resolution-review-") as directory:
        directory = Path(directory)
        generated = directory / "review.rs"
        binary = directory / "review-tests"
        generated.write_text(prelude + resize + descriptor + tests)
        print(f"Source: {SOURCE}", flush=True)
        compiled = subprocess.run(
            [rustc, "--edition=2021", "--test", "-A", "dead_code", str(generated), "-o", str(binary)],
            check=False,
        )
        if compiled.returncode:
            return compiled.returncode
        return subprocess.run([str(binary), "--nocapture"], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
