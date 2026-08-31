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
//! Second, the PTY is requested with explicit terminal modes: the ordinary
//! cooked, interactive set an `ssh` client sends, so the remote line
//! discipline echoes and edits the way it would for someone at the keyboard.
//! See [`terminal_modes`] for why that, and not a raw PTY, is correct here.

use russh::client::Msg;
use russh::{Channel, ChannelMsg, Pty};

use crate::error::{Error, Result};
use crate::multiplexer::{Detected, MultiplexerConfig, MultiplexerKind, ShellDialect};
use crate::options::TerminalOptions;
use ssh_transport::SshHandle;

/// The terminal modes we ask for: a conventional interactive terminal, the
/// same cooked defaults every `ssh` client sends.
///
/// This used to ask for a **raw** PTY (`ECHO` and `ICANON` off), on the
/// theory that the emulator at the other end of this pipe echoes locally and
/// a remote echo would double every character. That theory is wrong for the
/// terminal this app actually uses: xterm.js does not echo input, it only
/// renders what the server sends back. So with the remote echo turned off,
/// nothing echoed at all, and a plain login shell showed a blank line no
/// matter what was typed. It was masked for a long time because the default
/// profile attaches a multiplexer, and tmux/psmux draw their own screen and
/// so echo regardless; only a session that fell back to a bare shell (a host
/// with no multiplexer) exposed it.
///
/// The right model is the one `ssh` uses: the REMOTE line discipline echoes
/// and cooks, exactly as it would for someone sitting at the machine, and the
/// local side just ships keystrokes and paints what comes back. A full-screen
/// program (an editor, tmux itself) turns the remote line discipline raw with
/// its own `tcsetattr` when it starts, so these initial modes never fight it;
/// they are only the starting state, and the starting state for a shell
/// prompt is cooked.
///
/// The set below is what a Linux `ssh` encodes for an ordinary interactive
/// terminal: echo on (with the erase/kill/ctrl refinements a person expects
/// while editing a line), canonical input, signals on, `CR` mapped to `NL` on
/// input so Enter submits, and output post-processing so a bare `NL` from a
/// program still returns the cursor to the first column.
///
/// `TTY_OP_ISPEED` and `TTY_OP_OSPEED` are required by RFC 4254 §8 to be
/// present, and 38400 is the conventional value every client sends; the
/// numbers are meaningless on a pseudo-terminal but a few servers still sulk
/// without them.
fn terminal_modes() -> Vec<(Pty, u32)> {
    vec![
        // Input: let Enter (CR) become a submitted line, and keep flow
        // control and 8-bit/UTF-8 input intact.
        (Pty::ICRNL, 1),
        (Pty::IXON, 1),
        (Pty::IMAXBEL, 1),
        (Pty::IUTF8, 1),
        // Local: echo what is typed, cook the line, and honour signals. The
        // ECHOE/ECHOK/ECHOCTL/ECHOKE group is what makes Backspace rub a
        // character out and Ctrl-C show as `^C` rather than a raw byte, which
        // is what a person expects while editing a command.
        (Pty::ISIG, 1),
        (Pty::ICANON, 1),
        (Pty::ECHO, 1),
        (Pty::ECHOE, 1),
        (Pty::ECHOK, 1),
        (Pty::ECHOCTL, 1),
        (Pty::ECHOKE, 1),
        (Pty::IEXTEN, 1),
        // Output: post-process, mapping a bare `NL` to `CR`+`NL` so a program
        // that prints `\n` still starts the next line at column zero.
        (Pty::OPOST, 1),
        (Pty::ONLCR, 1),
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
    run_probe_raw(ssh, script)
        .await
        .map(|out| String::from_utf8_lossy(&out).into_owned())
}

/// As [`run_probe`], but without the UTF-8 conversion.
///
/// `wsl.exe -l -q` answers in UTF-16LE, so its output must reach the parser
/// as bytes. Going through `String::from_utf8_lossy` first would replace
/// anything non-ASCII with U+FFFD before the decoder ever saw it, and the
/// damage would be invisible: ASCII distro names happen to survive the round
/// trip, so it would look correct right up until someone had a name that did
/// not.
async fn run_probe_raw(ssh: &SshHandle, script: &str) -> Option<Vec<u8>> {
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
    Some(out)
}

/// Ask a Windows host which WSL distributions it has.
///
/// Returns an empty list rather than an error for a host with no WSL, no
/// `wsl.exe`, or nothing installed: "none" is a perfectly good answer to this
/// question and the UI shows a plain name field for it, so failing the call
/// would turn an ordinary state into an error dialog.
pub async fn list_wsl_distros(ssh: &SshHandle) -> Vec<String> {
    match run_probe_raw(ssh, crate::multiplexer::WSL_LIST_COMMAND).await {
        Some(out) => crate::multiplexer::parse_wsl_distros(&out),
        None => Vec::new(),
    }
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

/// The one line typed into the login shell, or `None` for a bare shell.
///
/// A startup command runs *inside* the multiplexer when there is one, so it
/// is as persistent as everything else in the session: tmux takes it as the
/// new session's command. It is ignored when `-A` attaches to a session that
/// already exists, which is right, because that session already has whatever
/// the user was doing in it, and replacing that with a fresh command would
/// destroy the very thing the multiplexer is there to protect.
///
/// Split out from [`open`] so it can be tested without a live connection.
fn shell_line(attach: Option<String>, startup: Option<&str>) -> Option<String> {
    match (attach, startup.map(str::trim).filter(|c| !c.is_empty())) {
        (Some(attach), Some(startup)) => Some(format!("{attach} {startup}")),
        (Some(attach), None) => Some(attach),
        (None, Some(startup)) => Some(startup.to_string()),
        (None, None) => None,
    }
}

/// One line, exactly as a person typing it would send it.
///
/// Two details, both of which have already gone wrong once:
///
/// The terminator is CR, not LF. Pressing Enter in a terminal transmits a
/// carriage return, and that is what the shell on the far side waits for.
/// Sending LF left the command sitting typed at the prompt and never run,
/// which is precisely how it looked on a Windows host: `cmd.exe` never saw a
/// completed line. A POSIX shell only tolerated LF because its line
/// discipline happened to translate; sending what a keypress sends removes
/// the dependence on that.
///
/// The leading space is for shells honouring `HISTCONTROL=ignorespace`. This
/// is the app's command, not the user's, and it has no business in their
/// history.
fn typed_line(command: &str) -> String {
    format!(" {command}\r")
}

/// Open a channel, request a PTY, and start the shell or the attach command.
pub async fn open(
    ssh: &SshHandle,
    term: &TerminalOptions,
    mux: &MultiplexerConfig,
    found: &Detected,
    startup_command: Option<&str>,
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

    let command = shell_line(command, startup_command);

    // Always a login shell, never `exec` of the attach command, and this is
    // the difference between detaching and being hung up on.
    //
    // `exec`ing `tmux attach` ties the SSH session's life to tmux: the moment
    // the user detaches, tmux exits, the channel closes and the connection
    // goes with it. That is what `ssh -t host tmux attach` does, and it is
    // not what anyone wants from a terminal. Running a shell and *typing* the
    // attach into it gives the behaviour of `ssh host` followed by `tmux
    // attach`: detaching drops back to the remote prompt with the connection
    // still up, and the user can reattach, start something else, or leave.
    channel
        .request_shell(true)
        .await
        .map_err(|e| Error::ShellRefused(e.to_string()))?;

    // A leading space so shells honouring `HISTCONTROL=ignorespace` keep this
    // out of the user's history. It is our command, not theirs.
    //
    // Terminated with CR, not LF, because this is a terminal: pressing Enter
    // transmits carriage return, and that is what every shell on the far side
    // is waiting for. Sending LF instead left the command sitting typed at the
    // prompt, unexecuted, which is exactly how it looked: `cmd.exe` never
    // treated it as a completed line, and a POSIX shell only did because its
    // line discipline happened to be translating. Sending what a keypress
    // sends removes the dependence on either.
    if let Some(line) = command.as_deref() {
        channel
            .data(typed_line(line).as_bytes())
            .await
            .map_err(|e| Error::ShellRefused(e.to_string()))?;
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

    /// The PTY is cooked and interactive, like the one `ssh` asks for.
    ///
    /// The remote line discipline has to echo, because xterm.js does not: it
    /// renders what the server sends and nothing else. With remote echo off,
    /// a plain login shell showed a blank line for everything typed, the
    /// original "invisible typing" report. It was hidden for a long time
    /// because a multiplexer draws its own screen, so only a bare-shell
    /// session ever surfaced it.
    #[test]
    fn the_pty_echoes_and_cooks_like_a_real_terminal() {
        let modes = terminal_modes();
        let get = |want: Pty| modes.iter().find(|(m, _)| *m == want).map(|(_, v)| *v);
        assert_eq!(get(Pty::ECHO), Some(1), "the remote must echo what is typed");
        assert_eq!(get(Pty::ICANON), Some(1), "the line must be cooked");
        // CR from Enter has to become a submitted line, or nothing runs.
        assert_eq!(get(Pty::ICRNL), Some(1), "Enter must submit the line");
        // A bare LF from a program has to return to column zero, or output
        // walks diagonally down the screen.
        assert_eq!(get(Pty::OPOST), Some(1));
        assert_eq!(get(Pty::ONLCR), Some(1));
        // Without ISIG, Ctrl-C arrives as a literal 0x03 and nothing is
        // interrupted, which is the other half of a terminal feeling broken.
        assert_eq!(get(Pty::ISIG), Some(1), "Ctrl-C must still signal");
        // A full-screen program turns all of this off itself when it starts,
        // so none of it fights an editor or tmux; these are only the state a
        // shell prompt begins in.
    }

    /// A terminal sends CR when Enter is pressed. Sending LF instead left the
    /// attach command typed at the prompt and never executed, which is what a
    /// Windows host actually did: the line was visible, the session was not
    /// attached, and nothing happened.
    #[test]
    fn the_injected_line_ends_the_way_a_keypress_does() {
        let line = typed_line("wsl.exe -- tmux new-session -A -s deskvnc");
        assert!(line.ends_with('\r'), "must end with CR: {line:?}");
        assert!(
            !line.contains('\n'),
            "a bare LF is not what Enter sends: {line:?}"
        );
    }

    /// The app's command, not the user's, so it stays out of their history on
    /// any shell that honours a leading space.
    #[test]
    fn the_injected_line_is_kept_out_of_shell_history() {
        assert!(typed_line("tmux new-session -A -s work").starts_with(' '));
    }

    /// A startup command with a multiplexer has to run inside it, or it dies
    /// with the connection and the whole point of the multiplexer is lost.
    #[test]
    fn a_startup_command_runs_inside_the_multiplexer() {
        let line = shell_line(
            Some("tmux new-session -A -s work".into()),
            Some("tail -f /var/log/syslog"),
        )
        .unwrap();
        assert_eq!(line, "tmux new-session -A -s work tail -f /var/log/syslog");
    }

    /// Without a multiplexer it is simply what the shell runs.
    #[test]
    fn a_startup_command_alone_is_the_command() {
        assert_eq!(shell_line(None, Some("htop")).as_deref(), Some("htop"));
    }

    /// A blank one is not a command. Sending an empty line would just print a
    /// second prompt, which looks like a glitch.
    #[test]
    fn a_blank_startup_command_is_not_sent() {
        assert_eq!(shell_line(None, None), None);
        assert_eq!(shell_line(None, Some("   ")), None);
        assert_eq!(
            shell_line(Some("tmux new-session -A -s work".into()), Some("  ")).as_deref(),
            Some("tmux new-session -A -s work")
        );
    }

    /// Nothing configured at all means a bare login shell, with nothing typed
    /// into it.
    #[test]
    fn a_plain_profile_types_nothing() {
        assert_eq!(shell_line(None, None), None);
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
