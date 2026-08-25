//! Opening a PTY on the carrier and starting something in it.
//!
//! Two things happen here that plain `ssh` does not do for you.
//!
//! First, before starting anything we ask the far side whether the requested
//! multiplexer is installed and whether the named session already exists.
//! That single round trip is what lets the UI say "resumed your session"
//! rather than guessing, and it is what makes falling back to a plain shell a
//! deliberate, reported decision instead of a confusing error.
//!
//! Second, the PTY is requested with explicit terminal modes. Leaving
//! `terminal_modes` empty means "server defaults", and the default on a good
//! many sshd builds leaves `ECHO` and `ICANON` set in ways that fight a local
//! terminal emulator doing its own line editing.

use russh::client::Msg;
use russh::{Channel, ChannelMsg, Pty};

use crate::error::{Error, Result};
use crate::multiplexer::{Detected, MultiplexerConfig, MultiplexerKind, ShellDialect};
use crate::options::TerminalOptions;
use ssh_transport::SshHandle;

/// The terminal modes we ask for.
///
/// `ECHO` and `ICANON` off is the definition of a raw PTY: the remote line
/// discipline must not echo anything or buffer by lines, because the terminal
/// emulator at the other end of this pipe is doing that job and doubling it up
/// produces every character twice. `ISIG` stays *on* deliberately, that is
/// what makes Ctrl-C reach the foreground program as `SIGINT` instead of
/// arriving as a literal `0x03` byte nothing acts on.
///
/// Everything else is left to the server. `TTY_OP_ISPEED` and `TTY_OP_OSPEED`
/// are required by RFC 4254 §8 to be present, and 38400 is the conventional
/// value every client sends; the numbers are meaningless on a pseudo-terminal
/// but a few servers still sulk without them.
fn terminal_modes() -> Vec<(Pty, u32)> {
    vec![
        (Pty::ECHO, 0),
        (Pty::ICANON, 0),
        (Pty::ISIG, 1),
        (Pty::TTY_OP_ISPEED, 38_400),
        (Pty::TTY_OP_OSPEED, 38_400),
    ]
}

/// A PTY with something running in it.
pub struct PtySession {
    pub channel: Channel<Msg>,
    /// What is actually running, `None` for a plain login shell.
    pub multiplexer: Option<MultiplexerKind>,
    /// True when we attached to a session that already existed.
    pub resumed: bool,
}

/// Run one command on its own channel and collect what it prints.
///
/// Never fails the connection: a probe that errors, times out or says
/// something unexpected comes back as `None`, because the only thing worse
/// than losing persistence is refusing to open a terminal at all. The caller
/// decides what to do about it.
async fn run_probe(ssh: &SshHandle, script: &str) -> Option<String> {
    let mut channel = match ssh.channel_open_session().await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("multiplexer probe could not open a channel: {e}");
            return None;
        }
    };
    if let Err(e) = channel.exec(true, script.as_bytes()).await {
        tracing::debug!("multiplexer probe could not exec: {e}");
        return None;
    }

    let mut out = Vec::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            // stderr matters here: a Windows shell rejecting POSIX syntax
            // says so on stderr, and that is the signal to try the other
            // dialect rather than to conclude nothing is installed.
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                out.extend_from_slice(&data)
            }
            ChannelMsg::Eof | ChannelMsg::Close | ChannelMsg::ExitStatus { .. } => break,
            _ => {}
        }
        // The probe prints a few short lines. Anything longer is a login
        // banner or a chatty rc file, and there is no reason to keep reading.
        if out.len() > 8192 {
            break;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Ask the far side what it has, in whichever shell dialect it speaks.
///
/// POSIX first, because almost every host answers it. If that comes back with
/// nothing a parser recognises, the host is very likely Windows with
/// `cmd.exe` or PowerShell as its default shell, so the question is asked
/// again in that dialect. Note the distinction the parser draws and this
/// function depends on: "every candidate reported missing" is a real answer
/// and stops here, while "no recognisable verdict at all" means the dialect
/// was wrong and is worth retrying. Conflating those two is exactly what
/// silently strands a Windows host on a plain shell.
pub async fn probe_multiplexer(ssh: &SshHandle, mux: &MultiplexerConfig) -> Result<Detected> {
    mux.validate()?;

    if let Some(script) = mux.posix_probe() {
        if let Some(output) = run_probe(ssh, &script).await {
            if let Some(mut found) = mux.read_probe(&output) {
                found.dialect = ShellDialect::Posix;
                return Ok(found);
            }
            tracing::debug!("the remote did not answer the posix probe; trying the windows one");
        }
    }

    if let Some(script) = mux.windows_probe() {
        if let Some(output) = run_probe(ssh, &script).await {
            if let Some(mut found) = mux.read_probe(&output) {
                found.dialect = ShellDialect::Windows;
                return Ok(found);
            }
        }
    }

    // Neither dialect answered. A plain shell still works, which is the point.
    Ok(Detected::plain(ShellDialect::Unknown))
}

/// Open a channel, request a PTY, and start the shell or the attach command.
pub async fn open(
    ssh: &SshHandle,
    term: &TerminalOptions,
    mux: &MultiplexerConfig,
    found: &Detected,
) -> Result<PtySession> {
    let (cols, rows) = term.clamped();

    let channel = ssh
        .channel_open_session()
        .await
        .map_err(|e| Error::ShellRefused(e.to_string()))?;

    channel
        .request_pty(
            true,
            &term.term,
            u32::from(cols),
            u32::from(rows),
            // Pixel dimensions. Zero means "no opinion", which is correct:
            // we do not know the font metrics, and RFC 4254 §6.2 says the
            // character values take precedence when these are zero.
            0,
            0,
            &terminal_modes(),
        )
        .await
        .map_err(|e| Error::PtyRefused(e.to_string()))?;

    // Decide what to run. Nothing found is either a fallback to the login
    // shell or a hard error, depending on what the user asked for.
    //
    // `Auto` never errors: the user asked us to work out what is there, and
    // "there is nothing" is a valid answer to that question, not a failure.
    // An explicitly named multiplexer with `fallback_to_shell` off is the one
    // case where a missing binary should stop the connection, because that
    // combination is someone saying "this host is supposed to have it".
    let command = match found.kind {
        Some(kind) => mux.attach_command(Some(kind))?,
        None => {
            let explicit = !matches!(
                mux.kind,
                MultiplexerKind::Auto | MultiplexerKind::None | MultiplexerKind::Custom
            );
            if explicit && !mux.fallback_to_shell {
                let name = mux.kind.binary().unwrap_or("the multiplexer");
                return Err(Error::ShellRefused(format!(
                    "{name} is not installed on the remote machine"
                )));
            }
            // Custom is never probed for, so it runs on trust.
            if mux.kind == MultiplexerKind::Custom {
                mux.attach_command(Some(MultiplexerKind::Custom))?
            } else {
                None
            }
        }
    };

    let used_mux = command.is_some().then(|| found.kind.unwrap_or(mux.kind));

    match &command {
        Some(cmd) => channel
            .exec(true, cmd.as_bytes())
            .await
            .map_err(|e| Error::ShellRefused(e.to_string()))?,
        None => channel
            .request_shell(true)
            .await
            .map_err(|e| Error::ShellRefused(e.to_string()))?,
    }

    Ok(PtySession {
        channel,
        multiplexer: used_mux,
        // Only a session that was actually there before counts as resumed.
        // Creating one and calling it "resumed" would tell the user their
        // work survived when it did not, which is the one thing this flag
        // must never do.
        resumed: command.is_some() && found.session_exists,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Doubling the line discipline is the classic "every character appears
    /// twice" bug: the local emulator echoes, and so does the remote tty.
    #[test]
    fn the_pty_is_raw_but_still_delivers_signals() {
        let modes = terminal_modes();
        let get = |want: Pty| modes.iter().find(|(m, _)| *m == want).map(|(_, v)| *v);
        assert_eq!(get(Pty::ECHO), Some(0), "remote echo must be off");
        assert_eq!(get(Pty::ICANON), Some(0), "line buffering must be off");
        // Without ISIG, Ctrl-C arrives as a literal 0x03 and nothing is
        // interrupted, which is the other half of a terminal feeling broken.
        assert_eq!(get(Pty::ISIG), Some(1), "Ctrl-C must still signal");
    }

    /// RFC 4254 §8 lists the speed opcodes as ones a client sends; a few
    /// servers refuse the pty-req without them.
    #[test]
    fn the_conventional_baud_opcodes_are_present() {
        let modes = terminal_modes();
        assert!(modes.iter().any(|(m, _)| *m == Pty::TTY_OP_ISPEED));
        assert!(modes.iter().any(|(m, _)| *m == Pty::TTY_OP_OSPEED));
    }
}
