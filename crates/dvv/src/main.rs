//! `dvv`, one binary.
//!
//! `04 §8` OQ-2 recommends shipping it inside the application bundle, so that
//! `dvv doctor` can print the exact `claude mcp add` line including the absolute
//! path and a person copies one line rather than editing their `PATH`. That is
//! why [`dvv::cli`] reads `current_exe` rather than assuming a name.
//!
//! ## Why the log goes to stderr, always
//!
//! `dvv mcp --stdio` speaks JSON-RPC on stdout. One `tracing` line on that
//! stream is a malformed message to the client, and the failure mode is a
//! client that disconnects with a parse error while the server thinks
//! everything is fine. So the subscriber is pinned to stderr here, once, at the
//! only place that can get it wrong.
//!
//! It also matches `04 §7.2`'s rule for the CLI: everything remote is on
//! stdout, everything ours is on stderr, so
//! `dvv run box -- cat /etc/hosts > hosts.txt` produces the file and not our
//! progress chatter.

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("DVV_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    // A multi threaded runtime, because `dvv_group_run` starts every member
    // before any member finishes and a group of four limbs waiting on four
    // machines is the case the group tools exist for.
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("dvv could not start a runtime: {error}");
            return std::process::ExitCode::from(1);
        }
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = runtime.block_on(dvv::cli::run(argv));
    std::process::ExitCode::from(code.clamp(0, 255) as u8)
}
