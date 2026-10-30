//! The fast lane runner: an agent writes a plan of steps once, and this
//! carries it out against a numbered table of the screen's controls, finding
//! each control by name, with no model in the loop.
//!
//! The rules are `tools/fastlane/spec/README.md`, and `cases.json` beside it
//! is tested here and by the Python prototype, so two runners in two
//! languages cannot drift apart without a test saying so.

pub mod rules;
pub mod run;

pub use rules::{Expect, Row, Table};
pub use run::{Desk, Outcome, Runner, Step};

/// The spec version this runner follows.
pub const SPEC_VERSION: u32 = 1;
