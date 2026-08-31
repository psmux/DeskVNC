//! Running one command on a channel of its own, with a real exit status.
//!
//! `PRDAgentPlug/05 §3` and `00 R50a`. This is the `exec` tier, and it is the
//! default tier for a reason worth writing down where somebody will try to
//! simplify it away.
//!
//! ## Why a second channel and not the prompt the user is watching
//!
//! The obvious cheap implementation is to type the command into the PTY this
//! session already owns and read the scrollback for an answer. It cannot work.
//! Typing at a prompt gives **no exit status, no stderr split and no output
//! bound**, which is three of the five things `05 §4.1` requires of an answer,
//! and the fourth thing it gives is interleaving with whatever the person at
//! that window is doing. The only way to produce an exit status from a
//! scrollback is to invent one, and an invented exit status is worse than a
//! refusal, because a refusal makes an agent try something else while a number
//! makes it act (`00 R7`).
//!
//! So `exec` opens a SECOND channel, per RFC 4254 §6.5, and reads the far
//! side's own `exit-status` or `exit-signal` off it, per §6.10. The status is
//! the operating system's, delivered by the SSH server, and nothing about
//! `PS1`, locale or shell dialect can corrupt it on the way. That is the whole
//! reason `00 R7` made this tier the default.
//!
//! The shape is not new here. [`crate::pty`]'s `run_probe_raw` has opened a
//! second channel and `exec`ed on it since the multiplexer probe was written
//! (`crates/ssh-core/src/pty.rs:84`), which is what `00 R50a` means when it
//! says the transport was always capable and nothing routed a second channel.
//!
//! ## What the second channel costs
//!
//! It inherits nothing. A fresh channel starts in the user's home directory
//! with a fresh environment, and knows nothing about the `cd` the agent did
//! five commands ago on the PTY. `05 §3` rules that the answer is an explicit
//! `cwd` and `env` on the request rather than a session that quietly
//! remembers, and [`exec_line`] is where that ruling is implemented.
//!
//! ## The capability
//!
//! `exec` is arbitrary code execution on somebody's machine, so it is
//! `NEVER_BUNDLED` (`00 R19`): no role grants it and a token has to name it.
//! Nothing in this module weakens that. The plane has already run every gate
//! before a command reaches this crate at all.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use remote_core::intent::{
    CommandExit, CommandRun, CommandSpec, Dropped, ExitTier, IntentId, IntentName, IntentRefused,
    IntentServed, ServedAnswer, Truncation, Unanswered,
};
use russh::ChannelMsg;
use ssh_transport::SshHandle;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::events::SshEvent;

/// How much of each stream is kept when the agent named no cap of its own.
///
/// 64 KiB, and the number is four times [`crate::session`]'s PTY flush unit,
/// which that module calls one screen of dense output. Four screens is more
/// than any command an agent should be swallowing whole, and it is far under
/// the size at which the answer itself becomes the problem: `00 R24` forbids
/// dropping output silently, not bounding it, and a build printing 200 KB must
/// not become a 200 KB event travelling channel to channel with a model on the
/// end of it. An agent that wants the rest asks a narrower question, which is
/// the behaviour this number is chosen to produce.
pub const DEFAULT_MAX_OUTPUT: u64 = 64 * 1024;

/// The most any request may raise the cap to.
///
/// The default is what an agent gets when it says nothing; this is what stops
/// one that says something from asking for a 200 MB event. One megabyte per
/// stream is roughly a quarter of a million tokens of text, which is past the
/// point where reading it is a plan rather than a call.
pub const MAX_OUTPUT_CEILING: u64 = 1024 * 1024;

/// One `exec` intent, on its way to a channel of its own.
///
/// Carries the intent's id and name rather than the whole [`AgentIntent`],
/// because those two are all the answer needs to name the question and a
/// command that has already been validated should not be re-matched three
/// layers down.
///
/// [`AgentIntent`]: remote_core::intent::AgentIntent
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub id: IntentId,
    /// [`IntentName::Exec`] today. Carried rather than assumed so a second
    /// intent served through this path names itself correctly in the answer.
    pub name: IntentName,
    pub spec: CommandSpec,
}

impl ExecRequest {
    /// The answer, when the command ran.
    pub fn serve(&self, run: CommandRun) -> IntentServed {
        IntentServed {
            id: self.id,
            name: self.name,
            answer: ServedAnswer::Ran(run),
        }
    }

    /// The answer, when nothing went on the wire.
    ///
    /// A refusal is a promise that nothing was delivered, so this is only for
    /// the failures that happen before `exec` is sent: an unopenable channel, a
    /// request the far side rejects, a session that is not connected. Once the
    /// command is running, every ending is a served answer, including the ones
    /// with no exit status in them.
    pub fn refuse(&self, reason: impl Into<String>) -> IntentRefused {
        IntentRefused {
            id: self.id,
            name: self.name,
            reason: reason.into(),
        }
    }

    /// The cap this request runs under, per stream.
    fn cap(&self) -> u64 {
        self.spec
            .max_output_bytes
            .unwrap_or(DEFAULT_MAX_OUTPUT)
            .min(MAX_OUTPUT_CEILING)
    }
}

/// Bounded output, with the count of what did not fit.
///
/// `00 R24`: the plane never drops output without saying how much it dropped.
/// The lines are counted as well as the bytes because they answer different
/// questions, and they have to be counted HERE, on the way past, since the
/// bytes themselves are gone a moment later.
#[derive(Debug, Default)]
struct Collector {
    cap: u64,
    kept: Vec<u8>,
    dropped: Dropped,
}

impl Collector {
    fn new(cap: u64) -> Self {
        Collector {
            cap,
            // Not `with_capacity(cap)`: a one megabyte ceiling would allocate a
            // megabyte for `whoami`. This grows into what actually arrives.
            kept: Vec::new(),
            dropped: Dropped::default(),
        }
    }

    fn push(&mut self, data: &[u8]) {
        let room = (self.cap as usize).saturating_sub(self.kept.len());
        let take = room.min(data.len());
        self.kept.extend_from_slice(&data[..take]);
        let lost = &data[take..];
        if !lost.is_empty() {
            self.dropped.bytes = self.dropped.bytes.saturating_add(lost.len() as u64);
            self.dropped.lines = self
                .dropped
                .lines
                .saturating_add(lost.iter().filter(|b| **b == b'\n').count() as u64);
        }
    }
}

/// Quote one value so a POSIX shell reads it as a single literal word.
///
/// Single quotes, with the one escape single quoting has: a `'` inside is
/// closed, escaped and reopened. It matters more than it looks. `cwd` and the
/// env values come off an agent, which takes them off a model, which may have
/// read them off the remote screen, and a value that ended a quote would run
/// as code in a place the agent never asked for code to run.
fn shell_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Is this a name a POSIX shell will assign to?
///
/// RFC 4254 §6.4 has an `env` request for this and it is very nearly useless in
/// practice: OpenSSH's `AcceptEnv` defaults to `LANG` and `LC_*` and drops
/// everything else without a word, which is exactly the silent failure this
/// design exists to remove. So the assignment is written into the command line
/// instead, and a name that is not a name has to be refused rather than
/// pasted: `PATH; rm -rf ~` on the left of an `=` is not a variable.
fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The line the far side's shell is asked to run.
///
/// `05 §3.3`'s explicit state, and the ordering is the argument. The `cd` comes
/// first and is followed by a bare `exit`, not by `exit 1`: a bare `exit`
/// leaves the shell's own status for the failed `cd` in place, so an agent that
/// named a directory that is not there gets the far side's number and the far
/// side's message on stderr rather than a code this crate made up (`00 R7`).
///
/// The environment is `export`ed on its own lines rather than prefixed to the
/// command, because a prefix only applies to a simple command: `A=1 ls; wc`
/// runs `wc` without `A`, and the agent would never learn that.
///
/// POSIX is assumed. A Windows host running `cmd.exe` gets its command
/// verbatim, which is right, and gets an error from the POSIX `cd` line if it
/// asked for a working directory, which is honest: the failure is reported in
/// the far side's own words instead of being papered over with a second dialect
/// nobody has tested.
///
/// # Errors
///
/// The sentence to refuse with, when an environment name is not one.
pub fn exec_line(spec: &CommandSpec) -> Result<String, String> {
    let mut line = String::new();

    if let Some(cwd) = spec.cwd.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        // The end of options marker, so a directory whose name begins with a
        // dash is a directory and not an option.
        line.push_str("cd -- ");
        line.push_str(&shell_quote(cwd));
        line.push_str(" || exit\n");
    }

    for (name, value) in &spec.env {
        if !is_env_name(name) {
            return Err(format!(
                "{name:?} is not an environment variable name, so nothing was run: a name must start with a letter or an underscore and hold only letters, digits and underscores"
            ));
        }
        line.push_str("export ");
        line.push_str(name);
        line.push('=');
        line.push_str(&shell_quote(value));
        line.push('\n');
    }

    line.push_str(&spec.command);
    Ok(line)
}

/// RFC 4254 §6.10's `exit-status`, as an answer.
///
/// A `u32` on the wire and an `i32` here, and the conversion is checked rather
/// than cast. A value that does not fit is a server saying something this
/// vocabulary cannot represent, and truncating it would produce a plausible
/// wrong number, which is the one outcome `00 R7` rules out. It comes back
/// unanswered instead, with the raw value in the log.
fn from_exit_status(exit_status: u32) -> CommandExit {
    match i32::try_from(exit_status) {
        Ok(code) => CommandExit::code(ExitTier::Exec, code),
        Err(_) => {
            tracing::warn!("the server reported an exit status of {exit_status}, which does not fit an i32; reporting no status rather than a truncated one");
            CommandExit::unanswered(ExitTier::Exec, Unanswered::Tier)
        }
    }
}

/// One command, on a channel of its own, from `exec` to `exit-status`.
///
/// Emits exactly one event, always: a served answer or, for the failures that
/// happen before anything is delivered, a refusal. `00 R28` is the requirement
/// and it has no exceptions, because the agent on the other end is not watching
/// a window, it is waiting for a settlement.
pub async fn serve(
    ssh: Arc<SshHandle>,
    request: ExecRequest,
    events: mpsc::Sender<SshEvent>,
    cancel: CancellationToken,
) {
    let event = match run(&ssh, &request, &cancel).await {
        Ok(run) => SshEvent::AgentServed(Box::new(request.serve(run))),
        Err(reason) => SshEvent::AgentRefused(Box::new(request.refuse(reason))),
    };
    // A closed event channel means the shell has gone, so there is nobody left
    // to answer to. Nothing is retried and nothing is logged as an error: the
    // session is over.
    let _ = events.send(event).await;
}

/// The run itself.
///
/// # Errors
///
/// The refusal sentence, for the failures where nothing was delivered.
async fn run(
    ssh: &SshHandle,
    request: &ExecRequest,
    cancel: &CancellationToken,
) -> Result<CommandRun, String> {
    let line = exec_line(&request.spec)?;
    let cap = request.cap();

    let channel = ssh
        .channel_open_session()
        .await
        .map_err(|e| format!("a second channel for the command could not be opened: {e}"))?;

    // `want_reply` true, so a far side that will not run this says so instead
    // of leaving us waiting for output that is never coming. The same choice
    // the multiplexer probe makes (`crates/ssh-core/src/pty.rs:84`).
    channel
        .exec(true, line.as_bytes())
        .await
        .map_err(|e| format!("the remote refused the exec request: {e}"))?;

    // From here on nothing is a refusal. The command may be running, so every
    // ending below is a served answer, including the ones with no exit status
    // in them: telling an agent that nothing was delivered when something was
    // is the one lie a refusal must never tell.
    let started = Instant::now();
    let mut stdout = Collector::new(cap);
    let mut stderr = Collector::new(cap);

    if let Some(stdin) = request.spec.stdin.as_ref() {
        if let Err(e) = channel.data(&stdin[..]).await {
            tracing::debug!("stdin could not be written to the command channel: {e}");
        }
    }
    // EOF whether or not there was any stdin, and this is load bearing. A
    // command that reads its input (`cat`, `sort`, anything behind a pipe)
    // blocks forever on a channel that is still open, so without this every
    // such command would burn its whole deadline and come back unanswered.
    if let Err(e) = channel.eof().await {
        tracing::debug!("the command channel would not take an EOF: {e}");
    }

    let status = pump(
        channel,
        &mut stdout,
        &mut stderr,
        request.spec.timeout,
        cancel,
    )
    .await;

    Ok(CommandRun {
        status,
        stdout: Bytes::from(stdout.kept),
        stderr: Bytes::from(stderr.kept),
        dropped: Truncation {
            cap,
            stdout: stdout.dropped,
            stderr: stderr.dropped,
        },
        duration: started.elapsed(),
    })
}

/// Read the channel until the far side says how the command ended.
///
/// The deadline is on the whole run rather than on each read, because that is
/// what an agent asked for: `05 §4.1` requires a timeout with no default on
/// the grounds that a command with no timeout on a machine nobody can see is a
/// hang nobody notices.
async fn pump(
    mut channel: russh::Channel<russh::client::Msg>,
    stdout: &mut Collector,
    stderr: &mut Collector,
    timeout: Duration,
    cancel: &CancellationToken,
) -> CommandExit {
    let mut status: Option<CommandExit> = None;

    let reading = async {
        loop {
            let Some(msg) = channel.wait().await else {
                // The channel ended without ever saying how the command ended.
                // That is a dropped carrier, and the command may well have
                // finished on the far side; we were not there to hear it.
                return status.take().unwrap_or_else(|| {
                    CommandExit::unanswered(ExitTier::Exec, Unanswered::LinkLost)
                });
            };
            match msg {
                ChannelMsg::Data { data } => stdout.push(&data),
                // RFC 4254 §5.2: `SSH_EXTENDED_DATA_STDERR` is the only data
                // type code defined, so anything arriving here is stderr. It is
                // kept apart from stdout because separating them is one of
                // `05 §4.1`'s five requirements and the reason a PTY cannot
                // serve this intent: a terminal merges the two by construction,
                // both descriptors pointing at the same device.
                ChannelMsg::ExtendedData { data, .. } => stderr.push(&data),
                // RFC 4254 §6.10. The server sends EOF, then the status, then
                // CHANNEL_CLOSE, so returning on the EOF would throw away the
                // status that is about to arrive and report every run as
                // unanswered. The status is recorded and the close ends the
                // loop, which is the same ordering `crate::session`'s pump
                // already depends on.
                ChannelMsg::ExitStatus { exit_status } => {
                    status = Some(from_exit_status(exit_status));
                }
                // A signal is NOT an exit code. RFC 4254 §6.10 carries both and
                // they mean different things, so `128 + signum` is never
                // computed here: that number is a shell's convention for
                // squeezing a signal through a byte wide status, and an agent
                // handed 137 cannot tell a process that was killed from one
                // that chose to exit 137 (`00 R7`).
                ChannelMsg::ExitSignal {
                    signal_name,
                    error_message,
                    ..
                } => {
                    // The message beside the signal goes to the log rather than
                    // to the agent: RFC 4254 §6.10 says the far side MAY send
                    // one, OpenSSH sends it empty, and the answer an agent reads
                    // has nowhere to put a sentence about a signal it already
                    // knows the name of.
                    if !error_message.is_empty() {
                        tracing::debug!("the remote said this about the signal: {error_message}");
                    }
                    status = Some(CommandExit::signal(
                        ExitTier::Exec,
                        format!("{signal_name:?}"),
                    ));
                }
                ChannelMsg::Eof => {}
                ChannelMsg::Close => {
                    return status.take().unwrap_or_else(|| {
                        // A close with no status at all. Rare, and a server's
                        // right: RFC 4254 §6.10 says the request MAY be sent.
                        CommandExit::unanswered(ExitTier::Exec, Unanswered::Tier)
                    });
                }
                _ => {}
            }
        }
    };

    tokio::select! {
        biased;
        // The session is shutting down. The command is not ours to finish and
        // the answer says so rather than claiming a status nobody read.
        () = cancel.cancelled() => CommandExit::unanswered(ExitTier::Exec, Unanswered::LinkLost),
        exit = reading => exit,
        () = tokio::time::sleep(timeout) => {
            // What happens to a command still running when the deadline
            // passes, stated where the next reader will look for it: it is
            // asked to stop and it may not. RFC 4254 §6.9's `signal` request is
            // the polite way and OpenSSH's sshd has historically ignored it,
            // so the close below is what actually ends most commands, by
            // taking their pipes away. A process that has detached from the
            // channel survives both, keeps running on the far side, and is not
            // ours to kill. The answer is unanswered rather than a status,
            // because that is the truth.
            let _ = channel.signal(russh::Sig::TERM).await;
            let _ = channel.close().await;
            CommandExit::unanswered(ExitTier::Exec, Unanswered::Deadline)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(command: &str) -> CommandSpec {
        CommandSpec {
            command: command.to_string(),
            cwd: None,
            env: Vec::new(),
            timeout: Duration::from_secs(5),
            stdin: None,
            max_output_bytes: None,
        }
    }

    /// A bare command is the command. Nothing is wrapped around it that the
    /// agent did not ask for, because every wrapper is another thing that can
    /// change what runs.
    #[test]
    fn a_command_with_no_declared_state_is_sent_as_it_was_written() {
        assert_eq!(exec_line(&spec("uname -a")).unwrap(), "uname -a");
    }

    /// `05 §3.3`. A second channel inherits nothing, so the working directory
    /// is stated on the request or it is the home directory.
    #[test]
    fn a_working_directory_is_entered_before_the_command_runs() {
        let mut s = spec("ls");
        s.cwd = Some("/var/log".into());
        assert_eq!(exec_line(&s).unwrap(), "cd -- '/var/log' || exit\nls");
    }

    /// The whole point of the bare `exit`: a directory that is not there ends
    /// the run with the far side's own status for the failed `cd`, and this
    /// crate has invented nothing (`00 R7`).
    #[test]
    fn a_failed_cd_exits_with_the_shells_own_status_and_not_an_invented_one() {
        let mut s = spec("ls");
        s.cwd = Some("/nowhere".into());
        let line = exec_line(&s).unwrap();
        assert!(line.contains("|| exit\n"), "{line}");
        assert!(
            !line.contains("exit 1"),
            "a number here would be a status nobody measured: {line}"
        );
    }

    /// A path with a quote in it is a path, not the end of a quote. The value
    /// comes off a model that may have read it off the remote screen.
    #[test]
    fn a_quote_in_a_path_cannot_end_the_quoting() {
        let mut s = spec("ls");
        s.cwd = Some("/tmp/it's here".into());
        assert_eq!(
            exec_line(&s).unwrap(),
            "cd -- '/tmp/it'\\''s here' || exit\nls"
        );
    }

    /// Exported on their own lines rather than prefixed, because a prefix
    /// applies to one simple command and the agent would never find out.
    #[test]
    fn the_environment_is_exported_so_it_survives_a_compound_command() {
        let mut s = spec("printenv A; printenv B");
        s.env = vec![("A".into(), "1".into()), ("B".into(), "two words".into())];
        assert_eq!(
            exec_line(&s).unwrap(),
            "export A='1'\nexport B='two words'\nprintenv A; printenv B"
        );
    }

    /// A name that is not a name is refused, not pasted. `PATH; rm -rf ~` on
    /// the left of an `=` is not a variable.
    #[test]
    fn an_environment_name_that_is_not_a_name_is_refused() {
        let mut s = spec("true");
        s.env = vec![("A; rm -rf ~".into(), "1".into())];
        let err = exec_line(&s).expect_err("must not become a command line");
        assert!(err.contains("environment variable name"), "{err}");
    }

    /// `128 + n` is a shell's convention for squeezing a signal through a byte
    /// wide status. It is not an exit code and this tier never computes one.
    #[test]
    fn a_signal_is_a_signal_and_never_a_hundred_and_twenty_eight_plus_n() {
        let killed = CommandExit::signal(ExitTier::Exec, "KILL");
        assert_eq!(killed.code, None, "a signal must never fill in a code");
        assert_eq!(killed.signal.as_deref(), Some("KILL"));
        assert!(killed.answered(), "being killed is an answer");
    }

    /// A non zero exit is a served answer. The command did exactly what it was
    /// asked and the number is the news, so reporting it as a failure to run
    /// would make an agent retry a machine that is working perfectly.
    #[test]
    fn a_non_zero_exit_is_a_status_rather_than_a_failure() {
        let exit = from_exit_status(3);
        assert_eq!(exit.code, Some(3));
        assert_eq!(exit.signal, None);
        assert_eq!(exit.source, ExitTier::Exec);
        assert!(exit.answered());
    }

    /// `00 R24`. Output past the cap is dropped and the answer says how much,
    /// in bytes and in lines.
    #[test]
    fn output_past_the_cap_is_counted_rather_than_dropped_in_silence() {
        let mut out = Collector::new(8);
        out.push(b"one\ntwo\nthree\n");
        assert_eq!(out.kept, b"one\ntwo\n");
        assert_eq!(out.dropped.bytes, 6);
        assert_eq!(out.dropped.lines, 1);
    }

    /// The cap is per stream and it is applied across reads, not per read: a
    /// program writing a line at a time must not slip past it.
    #[test]
    fn the_cap_holds_across_many_small_writes() {
        let mut out = Collector::new(4);
        for _ in 0..10 {
            out.push(b"ab");
        }
        assert_eq!(out.kept.len(), 4);
        assert_eq!(out.dropped.bytes, 16);
    }

    /// An agent that asks for nothing gets the default, and one that asks for
    /// the moon gets the ceiling. The event has to stay bounded whatever is
    /// asked of it.
    #[test]
    fn the_cap_is_the_agents_number_between_a_default_and_a_ceiling() {
        let request = |max: Option<u64>| ExecRequest {
            id: IntentId(1),
            name: IntentName::Exec,
            spec: CommandSpec {
                max_output_bytes: max,
                ..spec("true")
            },
        };
        assert_eq!(request(None).cap(), DEFAULT_MAX_OUTPUT);
        assert_eq!(request(Some(16)).cap(), 16);
        assert_eq!(request(Some(u64::MAX)).cap(), MAX_OUTPUT_CEILING);
    }
}
