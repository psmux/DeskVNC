//! # rdp-core
//!
//! The RDP session: transport, connection sequence state machine, channel
//! manager, graphics pipeline, input translation, clipboard bridge, lifecycle,
//! reconnect and stats. Implements `remote_core::ProtocolDriver`
//! (AGENT_BRIEF D12, PRDRDP/12 §2.2.4).
//!
//! This is the only crate in the RDP set that owns a socket or a tokio task.
//!
//! Phase 1 skeleton.
#![forbid(unsafe_code)]
