//! One connection attempt end-to-end: TCP connect → version handshake →
//! security → ClientInit/ServerInit → format/encoding setup → run loop.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::{Result, VncError};
use crate::proto::{self, messages, version::NegotiatedVersion, ProtocolVersion};
use crate::quality::QualityResolve;
use crate::security::{CredentialAsk, CredentialSource, TrustAsk, MAX_CREDENTIAL_ATTEMPTS};
use crate::types::{
    ClientCommand, ColorDepth, ConnectOptions, Credentials, PixelFormat, QualityPreset, Rect,
    SecurityType, ServerCapabilities, SessionEvent, SessionState,
};
use vnc_transport::BoxedStream;

use super::run_loop::{CountingReader, CountingWriter, RunLoop};
use super::{emit, emit_state};

/// Settings that must survive reconnects (PRD/05 §6.2 "session state
/// preservation"). The supervisor owns one instance and re-applies it on
/// every fresh connection.
#[derive(Debug, Clone)]
pub(crate) struct SessionSettings {
    pub quality: QualityPreset,
    pub view_only: bool,
    /// Repaint lossily-compressed regions at full quality once the screen
    /// stops changing (PRD/09 §3.2). Costs a little bandwidth after motion;
    /// buys back the sharpness JPEG gave away.
    pub lossless_refresh: bool,
    /// Last resolution the user asked the server for (SetDesktopSize).
    pub requested_size: Option<(u16, u16)>,
    /// Re-fetch the whole screen every tick (see
    /// `ClientCommand::SetAlwaysRefresh`). Survives reconnects like every
    /// other session setting, so turning it on is not silently undone by a
    /// dropped connection.
    pub always_refresh: bool,
    /// Prefer QEMU scancodes when the server offers them ("match the remote
    /// layout"); `false` sends layout-aware keysyms only ("match my local
    /// layout"). See `ClientCommand::SetPreferScancodes`.
    pub prefer_scancodes: bool,
}

impl SessionSettings {
    pub fn from_options(options: &ConnectOptions) -> Self {
        Self {
            quality: options.quality,
            view_only: options.view_only,
            lossless_refresh: options
                .vnc_options()
                .map(|v| v.lossless_refresh)
                .unwrap_or(true),
            requested_size: None,
            always_refresh: false,
            prefer_scancodes: true,
        }
    }
}

/// How a connection ended when it did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunOutcome {
    /// The user asked to disconnect (`ClientCommand::Disconnect`).
    UserDisconnect,
}

/// Map a `ColorDepth` preference to the wire pixel format we request.
///
/// `Grayscale` (the BlackAndWhite preset) rides the SAME 8-bit palette wire
/// format as `Palette256` (the Low preset), not full 32bpp true colour.
/// Requesting `bgra8888` for the preset whose whole point is "survive a bad
/// link" made it cost MORE bandwidth than Medium, the opposite of what a
/// user picking it wants. The server sends its colour map exactly as it does
/// for Low (`RunLoop`'s `SetColourMapEntries` handling already covers every
/// non-true-colour format); the client-side shader still does the final
/// black-and-white quantisation via `QualitySettings::grayscale_levels`.
pub(crate) fn pixel_format_for(depth: ColorDepth) -> PixelFormat {
    match depth {
        ColorDepth::Full => PixelFormat::bgra8888(),
        ColorDepth::Palette256 | ColorDepth::Grayscale => PixelFormat::palette8(),
        ColorDepth::Rgb222 | ColorDepth::Rgb111 => PixelFormat::rgb222(),
    }
}

/// Above this many pixels a Mac's screen starts in 16-bit colour under Auto.
/// A 5K iMac's whole screen was 12.9 MB in ZRLE at 32 bits and 5.0 MB at 16:
/// macOS Screen Sharing offers no JPEG and no Tight to a client that is not
/// Apple's, and without Fence the format cannot change once the session runs,
/// so Auto has no other way to make a big Mac screen fit a slow link.
const APPLE_LARGE_SCREEN: u64 = 3840 * 2160;

/// The wire pixel format to ask for. As [`pixel_format_for`], except that
/// macOS Screen Sharing is never asked for an 8-bit format, which it answers
/// by closing the connection, and gets 16-bit colour instead; and under Auto
/// a Mac screen larger than 4K starts in 16-bit colour.
pub(crate) fn wire_format(
    depth: ColorDepth,
    preset: QualityPreset,
    caps: &ServerCapabilities,
) -> PixelFormat {
    if !caps.is_apple_screen_sharing {
        return pixel_format_for(depth);
    }
    let large = caps.width as u64 * caps.height as u64 > APPLE_LARGE_SCREEN;
    match depth {
        ColorDepth::Full if !(large && preset == QualityPreset::Auto) => PixelFormat::bgra8888(),
        _ => PixelFormat::rgb565(),
    }
}

async fn with_timeout<T>(
    limit: Duration,
    fut: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err(VncError::Timeout),
    }
}

/// Open the byte stream the session will run over, within `connect_timeout`:
/// an injected transport (SSH tunnel) when the options carry one, plain TCP
/// otherwise.
async fn open_stream(
    options: &ConnectOptions,
    events: &mpsc::Sender<SessionEvent>,
) -> Result<BoxedStream> {
    let host = options.host.clone();
    let port = options.port;

    // A connector resolves the endpoint itself, for the SSH tunnel on the far
    // side of the carrier, so local DNS resolution would be wrong as well as
    // useless: `localhost` names the *tunnelled* machine's loopback.
    if let Some(connector) = &options.connector {
        emit_state(events, SessionState::Connecting).await?;
        tracing::info!(transport = %connector.0.describe(), "opening the injected transport");
        return Ok(connector
            .0
            .connect(&host, port, options.connect_timeout)
            .await?);
    }

    emit_state(events, SessionState::Resolving).await?;
    // Resolution and connection both go through vnc-transport so we inherit
    // TCP_NODELAY, the tuned keepalive schedule (PRD/05 §6.4, essential for
    // noticing a dead peer quickly after a cable pull), IPv4-first ordering,
    // and refused-vs-timeout classification that the reconnect supervisor
    // depends on to decide whether to retry.
    let addrs = vnc_transport::tcp::resolve(&host, port, options.connect_timeout).await?;
    if addrs.is_empty() {
        return Err(VncError::ResolveFailed(host));
    }

    emit_state(events, SessionState::Connecting).await?;
    let tcp = vnc_transport::tcp::connect(&host, port, options.connect_timeout).await?;
    Ok(Box::pin(tcp))
}

/// Read the server's security-type offer. Returns the raw offered bytes in
/// server order (for 3.3 the single unilaterally-chosen type).
async fn read_security_offer<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    version: ProtocolVersion,
) -> Result<Vec<u8>> {
    match version {
        ProtocolVersion::V3_3 => {
            let ty = stream.read_u32().await.map_err(messages::map_eof)?;
            if ty == 0 {
                let reason = read_reason_string(stream).await?;
                return Err(VncError::AuthFailed(reason));
            }
            if ty > u8::MAX as u32 {
                return Err(VncError::Protocol(format!(
                    "server chose out-of-range security type {ty}"
                )));
            }
            Ok(vec![ty as u8])
        }
        ProtocolVersion::V3_7 | ProtocolVersion::V3_8 => {
            let count = stream.read_u8().await.map_err(messages::map_eof)? as usize;
            if count == 0 {
                let reason = read_reason_string(stream).await?;
                return Err(VncError::AuthFailed(reason));
            }
            messages::read_exact_vec(stream, count).await
        }
    }
}

/// Read a `U32 length + text` failure reason, with a sanity cap.
async fn read_reason_string<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<String> {
    let len = stream.read_u32().await.map_err(messages::map_eof)? as usize;
    if len > 4096 {
        return Err(VncError::Protocol(format!(
            "failure reason length {len} exceeds limit"
        )));
    }
    let bytes = messages::read_exact_vec(stream, len).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Human-readable name of the strongest security type in an offer, used for
/// the `Authenticating { method }` state before negotiation completes.
fn strongest_offered_name(offered: &[u8]) -> String {
    offered
        .iter()
        .map(|&b| SecurityType::from_wire(b))
        .max_by_key(|t| t.strength())
        .map(|t| format!("{t:?}"))
        .unwrap_or_else(|| "unknown".into())
}

/// What `establish` hands back on success. The last element is set for a
/// macOS Screen Sharing encrypted session.
type Established = (
    BoxedStream,
    NegotiatedVersion,
    SecurityType,
    proto::ServerInit,
    Option<crate::apple::RekeyHandle>,
);

/// Everything up to (and including) the ServerInit exchange.
async fn establish(
    options: &ConnectOptions,
    settings: &SessionSettings,
    events: &mpsc::Sender<SessionEvent>,
    creds: &CredentialSource<'_>,
) -> Result<Established> {
    let mut tcp = open_stream(options, events).await?;

    // Version banner (server speaks first), bounded, a silent listener on
    // the port must not hang us forever.
    let negotiated =
        with_timeout(options.connect_timeout, proto::version::negotiate(&mut tcp)).await?;
    tracing::debug!(
        version = %negotiated.version,
        apple = negotiated.is_apple_screen_sharing,
        "negotiated RFB version"
    );

    let offered = with_timeout(
        options.connect_timeout,
        read_security_offer(&mut tcp, negotiated.version),
    )
    .await?;

    // Name the type this client will pick, so a pinned type (or the auto
    // choice) is what the state shows, not merely the strongest on offer.
    let method = crate::security::select_security_type(&offered, options)
        .map(|t| format!("{t:?}"))
        .unwrap_or_else(|_| strongest_offered_name(&offered));
    emit_state(events, SessionState::Authenticating { method }).await?;

    // Adapt our negotiated version to the security module's compact form.
    let version_info = crate::security::ProtocolVersionInfo {
        major: negotiated.version.major() as u8,
        minor: negotiated.version.minor() as u8,
        is_apple: negotiated.is_apple_screen_sharing,
    };
    let crate::security::Authenticated {
        mut stream,
        security,
        trust,
        apple_wrap_key,
    } = crate::security::authenticate_full(tcp, version_info, &offered, options, creds).await?;
    // The security result was OK, so whatever the user typed for this attempt
    // is now proven, whatever happens to the connection after this line.
    creds.mark_authenticated();

    // A server key we have no pin for that the handshake did not already put
    // to the user. RA2 and VeNCrypt ask inside the handshake, before any
    // credential is sent (`CredentialSource::approve_server_key`), so a key
    // they report was approved a moment ago and is not asked about twice.
    // What is left is the macOS SRP host key: SRP never sends the password,
    // the key only hides the account name, and the Mac has proved it knows
    // the password by now, so it is still offered for pinning here, after
    // the login (PRD/10 §4). The scheme travels with it: the answer has to be
    // stored against the key the user was actually shown, not against
    // whichever one the endpoint happened to pin first.
    if let Some(crate::security::ServerIdentity {
        scheme,
        decision:
            vnc_transport::TrustDecision::Unknown {
                fingerprint,
                subject,
                certificate,
            },
    }) = trust
    {
        if creds.was_approved(scheme, &fingerprint) {
            tracing::debug!(?scheme, "server key approved during the handshake");
        } else {
            emit(
                events,
                SessionEvent::CertificatePrompt {
                    fingerprint,
                    subject,
                    is_change: false,
                    scheme,
                    certificate,
                },
            )
            .await?;
        }
    }

    emit_state(events, SessionState::Negotiating).await?;
    let shared = options.vnc_options().map(|v| v.shared).unwrap_or(true);
    let apple_key = apple_wrap_key.filter(|_| security.starts_apple_session());
    if apple_key.is_some() {
        // The native viewer's ClientInit carries two Apple bits beside the
        // shared flag.
        let init = if shared {
            crate::apple::wire::CLIENT_INIT_SHARED
        } else {
            crate::apple::wire::CLIENT_INIT_EXCLUSIVE
        };
        crate::security::write_all(&mut stream, &[init]).await?;
    } else {
        proto::write_client_init(&mut stream, shared).await?;
    }
    let server_init = with_timeout(
        options.connect_timeout,
        proto::read_server_init(&mut stream),
    )
    .await?;

    // macOS Screen Sharing after an SRP login: the cleartext prelude, the
    // first rekey, and from then on the AES record layer.
    let mut rekey = None;
    if let Some(key) = apple_key {
        let (records, handle) = with_timeout(
            options.connect_timeout,
            crate::apple::start_session(stream, &key, crate::apple::PreludeOptions::default()),
        )
        .await?;
        stream = Box::pin(records);
        rekey = Some(handle);
    }

    // The Tight security type appends capability lists to ServerInit. They
    // MUST be consumed or the stream stays offset by 8 + 16N bytes and every
    // later message is parsed from the wrong place (see
    // `read_tight_server_capabilities`).
    if security == SecurityType::Tight {
        let caps = with_timeout(
            options.connect_timeout,
            proto::read_tight_server_capabilities(&mut stream),
        )
        .await?;
        tracing::info!(
            encodings = caps.encodings.len(),
            "consumed Tight extended ServerInit"
        );
    }
    tracing::info!(
        name = %server_init.name,
        width = server_init.width,
        height = server_init.height,
        security = ?security,
        quality = ?settings.quality,
        "server init complete"
    );

    Ok((stream, negotiated, security, server_init, rekey))
}

// ---------------------------------------------------------------------------
// Interactive credentials (PRD/10 §3.4)
// ---------------------------------------------------------------------------

/// Answer one [`CredentialAsk`] by asking the user.
///
/// Emits [`SessionEvent::CredentialsRequired`] and then pumps `commands`, the
/// receiver the supervisor owns and that nothing else reads during the
/// handshake, until the answer (or a teardown) arrives. Cancellation,
/// `Disconnect` and a closed command channel all resolve the ask as "cancelled"
/// so the handshake unwinds instead of hanging.
async fn serve_credential_ask(
    ask: CredentialAsk,
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
) -> Result<()> {
    let CredentialAsk { request, reply } = ask;
    tracing::info!(
        method = %request.method,
        attempt = request.attempt,
        kind = ?request.kind,
        "asking the user for credentials"
    );
    emit(events, SessionEvent::CredentialsRequired(request)).await?;

    loop {
        let answer = tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            cmd = commands.recv() => match cmd {
                // The shell is gone: treat it as a cancellation.
                None => None,
                Some(ClientCommand::ProvideCredentials {
                    username, password, ..
                }) => Some(Credentials {
                    username: username.filter(|u| !u.is_empty()),
                    password: Some(password),
                    domain: None,
                }),
                Some(ClientCommand::CancelCredentials) | Some(ClientCommand::Disconnect) => None,
                // Anything else (input, clipboard, quality) is meaningless
                // before the session exists, drop it and keep waiting.
                Some(_) => continue,
            },
        };
        // The receiver is gone only if the handshake already unwound; either
        // way there is nothing more to do here.
        let _ = reply.send(answer);
        return Ok(());
    }
}

/// Answer one [`TrustAsk`] by asking the user whether to trust a server key.
///
/// Emits [`SessionEvent::CertificatePrompt`] and pumps `commands` until the
/// answer arrives, the way [`serve_credential_ask`] does for a password. Only
/// a `TrustCertificate` that names this key under this scheme approves it. The
/// dialog's cancel, a disconnect, a closed command channel and a teardown all
/// refuse it, and the handshake then closes without sending a credential.
async fn serve_trust_ask(
    ask: TrustAsk,
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
) -> Result<()> {
    let TrustAsk {
        scheme,
        fingerprint,
        subject,
        certificate,
        reply,
    } = ask;
    tracing::info!(%fingerprint, ?scheme, "asking the user to approve an unpinned server key");
    emit(
        events,
        SessionEvent::CertificatePrompt {
            fingerprint: fingerprint.clone(),
            subject,
            is_change: false,
            scheme,
            certificate,
        },
    )
    .await?;

    let wanted = vnc_transport::normalize_fingerprint(&fingerprint);
    let approved = loop {
        let cmd = tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            cmd = commands.recv() => cmd,
        };
        match cmd {
            None => break false,
            Some(ClientCommand::TrustCertificate {
                fingerprint: answered,
                scheme: answered_scheme,
                permanent,
            }) => {
                // An answer for another key or another scheme belongs to a
                // different dialog and must not approve this one.
                let same = answered_scheme == scheme
                    && vnc_transport::normalize_fingerprint(&answered) == wanted;
                if same {
                    tracing::info!(permanent, ?scheme, "the user approved the server key");
                } else {
                    tracing::warn!(?scheme, "a trust answer named a different key; refusing");
                }
                break same;
            }
            Some(ClientCommand::CancelCredentials) | Some(ClientCommand::Disconnect) => break false,
            // Input, clipboard and quality changes mean nothing before the
            // session exists.
            Some(_) => continue,
        }
    };
    let _ = reply.send(approved);
    Ok(())
}

/// Establish a connection, asking the user for credentials when the handshake
/// needs them and re-asking when the server rejects what they typed.
///
/// The retry loop lives *here*, inside a single supervisor iteration, and never
/// returns a transient error, so `VncError::AuthFailed` still reaches the
/// supervisor as a terminal, non-reconnecting failure
/// (`VncError::needs_user_action`). Only credentials the *user* supplied are
/// retried: a stored password the server rejects fails once, opening exactly
/// one TCP connection, because looping on a saved credential locks accounts
/// out.
async fn establish_interactive(
    options: &mut ConnectOptions,
    settings: &SessionSettings,
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
) -> Result<Established> {
    let mut attempt: u32 = 1;
    let mut last_error: Option<String> = None;
    let mut username_hint = options
        .credentials
        .username
        .clone()
        .filter(|u| !u.is_empty());

    loop {
        // One in-flight question at a time; the handshake is linear.
        let (ask_tx, mut ask_rx) = mpsc::channel::<CredentialAsk>(1);
        let (trust_tx, mut trust_rx) = mpsc::channel::<TrustAsk>(1);
        let source = CredentialSource::interactive(
            &ask_tx,
            attempt,
            last_error.clone(),
            username_hint.clone(),
        )
        .with_trust_prompt(&trust_tx);

        let result = {
            let attempt_fut = establish(options, settings, events, &source);
            tokio::pin!(attempt_fut);
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break Err(VncError::Cancelled),
                    outcome = &mut attempt_fut => break outcome,
                    // The handshake is parked on the oneshot while we do this,
                    // so not polling `attempt_fut` here costs nothing.
                    Some(ask) = ask_rx.recv() => {
                        serve_credential_ask(ask, events, commands, cancel).await?;
                    }
                    Some(ask) = trust_rx.recv() => {
                        serve_trust_ask(ask, events, commands, cancel).await?;
                    }
                }
            }
        };

        // A key the user trusted in this attempt is pinned for the rest of the
        // session, so the retry after a mistyped password, and any automatic
        // reconnect, does not ask about it again. Only an empty slot is
        // filled: a key that changes between attempts is still a changed
        // identity.
        for (scheme, fingerprint) in source.approved_keys() {
            remember_trust(options, Some((scheme, fingerprint)));
        }

        // Keep what the server accepted for every later attempt this session
        // makes, the way `rdp-core` keeps a typed credential for the
        // connection after the one it was typed on. Without this an automatic
        // reconnect, after a link drop or a tunnel that went away, raised the
        // same prompt again and the person typed it all a second time. Done
        // before the result is looked at because the attempt can fail after
        // the security handshake succeeded, and the answer is still proven.
        if let Some(accepted) = source.accepted() {
            options.credentials = accepted;
        }

        match result {
            Ok(established) => return Ok(established),
            Err(VncError::AuthFailed(reason))
                if source.prompted() && attempt < MAX_CREDENTIAL_ATTEMPTS =>
            {
                tracing::info!(
                    attempt,
                    "the server rejected the credentials the user supplied; asking again"
                );
                username_hint = source.last_username().or(username_hint);
                last_error = Some(reason);
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Run one full connection attempt: returns `Ok` only for a user-initiated
/// disconnect; every failure (including cancellation) is an `Err` so the
/// supervisor can classify it.
pub(crate) async fn run_once(
    options: &mut ConnectOptions,
    settings: &mut SessionSettings,
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
    connected_at: &mut Option<Instant>,
) -> Result<RunOutcome> {
    // `establish_interactive` handles cancellation itself (it has to, so a
    // pending credential prompt tears down promptly); the run loop does too
    // (it wants to release pressed keys first).
    let (stream, negotiated, security, server_init, apple_rekey) =
        establish_interactive(options, settings, events, commands, cancel).await?;

    let mut caps = proto::build_capabilities(&negotiated, &server_init, security);

    // Let the UI know the initial geometry and name.
    emit(
        events,
        SessionEvent::DesktopResize {
            width: server_init.width,
            height: server_init.height,
        },
    )
    .await?;
    emit(events, SessionEvent::DesktopName(server_init.name.clone())).await?;

    // Split the stream; wrap both halves so every byte is counted for stats, // the writer immediately, so the handshake messages below count too.
    let (read_half, write_half) = tokio::io::split(stream);
    let bytes_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sent_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let link_peak = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let reader = BufReader::with_capacity(
        128 * 1024,
        CountingReader::new(read_half, bytes_counter.clone(), link_peak.clone()),
    );
    let mut write_half = CountingWriter::new(write_half, sent_counter.clone());

    // Negotiate our pixel format and encoding preferences.
    let quality_settings = settings.quality.settings();
    use tokio::io::AsyncWriteExt;
    if let Some(rekey) = apple_rekey {
        // Inside Apple's record layer every write is one record, so each
        // message goes out on its own. The native viewer sends no
        // SetPixelFormat; the server's own format is used when it is one the
        // decoders take, which a Mac's 32-bit true colour is.
        let native = server_init.pixel_format;
        let pf = if native.true_colour && matches!(native.bits_per_pixel, 16 | 32) {
            native
        } else {
            wire_format(quality_settings.pixel_format, settings.quality, &caps)
        };
        caps.pixel_format = Some(pf);
        for msg in crate::apple::opening_messages(server_init.width, server_init.height) {
            write_half
                .write_all(&msg)
                .await
                .map_err(messages::map_eof)?;
            // A SetPixelFormat, when one is needed, goes after SetEncodings
            // so the display configuration stays the first record.
            if msg.first() == Some(&messages::client_msg::SET_ENCODINGS) && pf != native {
                write_half
                    .write_all(&messages::set_pixel_format(&pf))
                    .await
                    .map_err(messages::map_eof)?;
            }
        }
        write_half.flush().await.map_err(messages::map_eof)?;
        emit_state(events, SessionState::Connected).await?;
        *connected_at = Some(Instant::now());
        let mut run_loop = RunLoop::new(
            reader,
            write_half,
            caps,
            pf,
            quality_settings,
            bytes_counter,
            sent_counter,
            link_peak,
        );
        run_loop.set_apple_session(crate::apple::AppleSession::new(rekey));
        let outcome = run_loop.run(settings, events, commands, cancel).await;
        remember_trust(options, run_loop.take_trusted());
        return outcome;
    }

    let pf = wire_format(quality_settings.pixel_format, settings.quality, &caps);
    let encodings = crate::quality::encodings_for(&quality_settings, &caps);
    caps.pixel_format = Some(pf);

    write_half
        .write_all(&messages::set_pixel_format(&pf))
        .await
        .map_err(messages::map_eof)?;
    write_half
        .write_all(&messages::set_encodings(&encodings))
        .await
        .map_err(messages::map_eof)?;
    // Prime the update pipeline with one full non-incremental request.
    write_half
        .write_all(&messages::framebuffer_update_request(
            false,
            Rect::new(0, 0, server_init.width, server_init.height),
        ))
        .await
        .map_err(messages::map_eof)?;
    write_half.flush().await.map_err(messages::map_eof)?;
    tracing::trace!("sent priming non-incremental FramebufferUpdateRequest");

    emit_state(events, SessionState::Connected).await?;
    *connected_at = Some(Instant::now());

    let mut run_loop = RunLoop::new(
        reader,
        write_half,
        caps,
        pf,
        quality_settings,
        bytes_counter,
        sent_counter,
        link_peak,
    );
    let outcome = run_loop.run(settings, events, commands, cancel).await;
    remember_trust(options, run_loop.take_trusted());
    outcome
}

/// Keep a key the person accepted at the trust prompt for the rest of this
/// session.
///
/// The prompt is raised after the handshake, while the connection goes on,
/// and the answer used to change nothing in the core: the options the
/// supervisor dials again with still held no pin, so every automatic
/// reconnect saw an unknown key and raised the prompt again over a live
/// session. "Connect once" means this session, reconnects included, and
/// "Trust" is persisted by the shell for the next session; either way the
/// key goes into this session's pins. Only an empty slot is filled: a pin
/// already there is never replaced from here, and a reconnect that meets a
/// different key still stops as a changed identity.
fn remember_trust(
    options: &mut ConnectOptions,
    trusted: Option<(crate::types::PinScheme, String)>,
) {
    if let Some((scheme, fingerprint)) = trusted {
        if options.cert_pins.for_scheme(scheme).is_none() {
            tracing::info!(?scheme, "keeping the accepted server key for this session");
            options.cert_pins.set(scheme, Some(fingerprint));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(apple: bool, width: u16, height: u16) -> ServerCapabilities {
        ServerCapabilities {
            is_apple_screen_sharing: apple,
            width,
            height,
            ..Default::default()
        }
    }

    /// A Mac closes the connection on any 8-bit format, so it gets 16-bit
    /// colour where another server gets a palette.
    #[test]
    fn a_mac_is_never_asked_for_eight_bits() {
        let mac = caps(true, 1920, 1080);
        for depth in [
            ColorDepth::Palette256,
            ColorDepth::Grayscale,
            ColorDepth::Rgb222,
            ColorDepth::Rgb111,
        ] {
            for preset in [QualityPreset::Auto, QualityPreset::Low] {
                assert_eq!(wire_format(depth, preset, &mac), PixelFormat::rgb565());
            }
        }
        let other = caps(false, 1920, 1080);
        assert_eq!(
            wire_format(ColorDepth::Palette256, QualityPreset::Low, &other),
            PixelFormat::palette8()
        );
    }

    /// A 5K iMac starts in 16-bit colour under Auto; a smaller Mac screen,
    /// a chosen preset or another server keeps full colour.
    #[test]
    fn a_large_mac_screen_starts_in_sixteen_bits_under_auto() {
        let imac = caps(true, 5120, 2880);
        assert_eq!(
            wire_format(ColorDepth::Full, QualityPreset::Auto, &imac),
            PixelFormat::rgb565()
        );
        assert_eq!(
            wire_format(ColorDepth::Full, QualityPreset::High, &imac),
            PixelFormat::bgra8888()
        );
        assert_eq!(
            wire_format(
                ColorDepth::Full,
                QualityPreset::Auto,
                &caps(true, 2560, 1440)
            ),
            PixelFormat::bgra8888()
        );
        assert_eq!(
            wire_format(
                ColorDepth::Full,
                QualityPreset::Auto,
                &caps(false, 5120, 2880)
            ),
            PixelFormat::bgra8888()
        );
    }

    /// REGRESSION: `Grayscale` used to map to full 32bpp true colour, making
    /// the BlackAndWhite preset the single MOST expensive one on the wire
    /// despite being the "survive a bad link" choice. It must ride the same
    /// 8-bit palette format as `Palette256` (Low).
    #[test]
    fn grayscale_rides_the_same_wire_format_as_palette256() {
        assert_eq!(
            pixel_format_for(ColorDepth::Grayscale),
            pixel_format_for(ColorDepth::Palette256)
        );
        assert_eq!(
            pixel_format_for(ColorDepth::Grayscale),
            PixelFormat::palette8()
        );
        assert_eq!(pixel_format_for(ColorDepth::Grayscale).bits_per_pixel, 8);
        assert!(!pixel_format_for(ColorDepth::Grayscale).true_colour);
    }

    #[test]
    fn full_colour_still_maps_to_bgra8888() {
        assert_eq!(pixel_format_for(ColorDepth::Full), PixelFormat::bgra8888());
    }

    #[test]
    fn rgb_reductions_map_to_rgb222() {
        assert_eq!(pixel_format_for(ColorDepth::Rgb222), PixelFormat::rgb222());
        assert_eq!(pixel_format_for(ColorDepth::Rgb111), PixelFormat::rgb222());
    }

    // -----------------------------------------------------------------------
    // RA2: the trust prompt comes before the credentials, through a session
    // -----------------------------------------------------------------------

    use crate::security::ra2::test_server::{self, Finish, Recorded};
    use crate::types::PinScheme;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    /// A ServerInit for a 2x2 true colour screen named "pi".
    fn server_init() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&2u16.to_be_bytes());
        v.extend_from_slice(&2u16.to_be_bytes());
        // 32 bpp, depth 24, little endian, true colour, 255/255/255, 16/8/0.
        v.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
        v.extend_from_slice(&2u32.to_be_bytes());
        v.extend_from_slice(b"pi");
        v
    }

    /// An RFB 3.8 server on loopback that offers only RA2 and then runs the
    /// simulated RA2 server from `ra2.rs`.
    async fn ra2_server() -> (
        u16,
        Recorded,
        tokio::task::JoinHandle<Option<Vec<u8>>>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let recorded = Recorded::default();
        let log = recorded.clone();
        let task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.ok()?;
            sock.write_all(b"RFB 003.008\n").await.ok()?;
            let mut version = [0u8; 12];
            sock.read_exact(&mut version).await.ok()?;
            sock.write_all(&[1, SecurityType::Ra2.to_wire()]).await.ok()?;
            let chosen = sock.read_u8().await.ok()?;
            assert_eq!(chosen, SecurityType::Ra2.to_wire());
            test_server::serve(
                &mut sock,
                SecurityType::Ra2,
                Some(1),
                log,
                Finish::Accept {
                    server_init: server_init(),
                },
            )
            .await
        });
        (port, recorded, task)
    }

    /// Everything a test needs to play the shell.
    struct Shell {
        events: mpsc::Receiver<SessionEvent>,
        commands: mpsc::Sender<ClientCommand>,
    }

    impl Shell {
        async fn next(&mut self) -> SessionEvent {
            loop {
                let ev = tokio::time::timeout(Duration::from_secs(30), self.events.recv())
                    .await
                    .expect("an event in time")
                    .expect("the session is alive");
                if !matches!(ev, SessionEvent::StateChanged(_)) {
                    return ev;
                }
            }
        }
    }

    fn start_establish(
        mut options: ConnectOptions,
    ) -> (
        Shell,
        tokio::task::JoinHandle<(Result<()>, ConnectOptions)>,
    ) {
        let (ev_tx, ev_rx) = mpsc::channel(64);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(64);
        let task = tokio::spawn(async move {
            let settings = SessionSettings::from_options(&options);
            let cancel = CancellationToken::new();
            let r = establish_interactive(&mut options, &settings, &ev_tx, &mut cmd_rx, &cancel)
                .await
                .map(|_| ());
            (r, options)
        });
        (
            Shell {
                events: ev_rx,
                commands: cmd_tx,
            },
            task,
        )
    }

    /// First contact through the session: the certificate prompt is raised
    /// with the server's subtype already waiting, nothing reaches the server
    /// until the user trusts the key, the credential prompt comes after, and
    /// the approved key is pinned for the rest of the session.
    #[tokio::test]
    async fn ra2_first_contact_asks_about_the_key_before_the_password() {
        let (port, recorded, server) = ra2_server().await;
        let (mut shell, task) = start_establish(ConnectOptions::vnc("127.0.0.1", port));

        let (fingerprint, scheme) = match shell.next().await {
            SessionEvent::CertificatePrompt {
                fingerprint,
                subject,
                is_change,
                scheme,
                ..
            } => {
                assert!(!is_change);
                assert_eq!(subject, "RSA-AES server key (2048-bit)");
                (fingerprint, scheme)
            }
            other => panic!("expected the certificate prompt first, got {other:?}"),
        };
        assert_eq!(scheme, PinScheme::Ra2);
        assert_eq!(fingerprint, test_server::fingerprint());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            recorded.lock().unwrap().is_empty(),
            "bytes reached the server while the trust prompt was open"
        );

        shell
            .commands
            .send(ClientCommand::TrustCertificate {
                fingerprint: fingerprint.clone(),
                permanent: false,
                scheme,
            })
            .await
            .unwrap();

        match shell.next().await {
            SessionEvent::CredentialsRequired(req) => {
                assert_eq!(req.method, crate::security::ra2::METHOD);
            }
            other => panic!("expected the credential prompt, got {other:?}"),
        }
        assert!(
            recorded.lock().unwrap().is_empty(),
            "bytes reached the server before the user typed anything"
        );
        shell
            .commands
            .send(ClientCommand::ProvideCredentials {
                username: Some("pi".into()),
                password: "raspberry".into(),
                save: false,
            })
            .await
            .unwrap();

        let (result, options) = task.await.unwrap();
        result.expect("the connection is established");
        // The key the user trusted is pinned for every later attempt in this
        // session, so a reconnect does not ask again.
        assert_eq!(
            options.cert_pins.for_scheme(PinScheme::Ra2),
            Some(fingerprint.as_str())
        );
        // No second prompt for the same key after the handshake.
        while let Ok(ev) = shell.events.try_recv() {
            assert!(
                !matches!(ev, SessionEvent::CertificatePrompt { .. }),
                "the key was asked about twice"
            );
        }
        drop(options);
        let credentials = server.await.unwrap().expect("credentials arrived");
        assert_eq!(credentials[0] as usize, 2);
        assert_eq!(&credentials[1..3], b"pi");
    }

    /// Refusing the key at the prompt, which the shells do by disconnecting,
    /// ends the attempt as untrusted, never asks for a password, and sends
    /// the server nothing after the key confirmation.
    #[tokio::test]
    async fn ra2_a_refused_key_never_sees_the_password() {
        for answer in [ClientCommand::Disconnect, ClientCommand::CancelCredentials] {
            let (port, recorded, server) = ra2_server().await;
            let mut o = ConnectOptions::vnc("127.0.0.1", port);
            // Even a stored password stays here.
            o.credentials = Credentials::user_pass("pi", "raspberry");
            let (mut shell, task) = start_establish(o);
            match shell.next().await {
                SessionEvent::CertificatePrompt { .. } => {}
                other => panic!("expected the certificate prompt, got {other:?}"),
            }
            shell.commands.send(answer).await.unwrap();
            let (result, options) = task.await.unwrap();
            let err = result.expect_err("a refused key does not connect");
            assert!(matches!(err, VncError::CertificateUntrusted(_)), "{err:?}");
            assert!(options.cert_pins.for_scheme(PinScheme::Ra2).is_none());
            while let Ok(ev) = shell.events.try_recv() {
                assert!(
                    !matches!(ev, SessionEvent::CredentialsRequired(_)),
                    "asked for a password after the key was refused"
                );
            }
            drop(shell);
            assert_eq!(server.await.unwrap(), None);
            assert!(
                recorded.lock().unwrap().is_empty(),
                "{} bytes sent to a refused key",
                recorded.lock().unwrap().len()
            );
        }
    }

    /// A key pinned from an earlier session connects with no prompt at all.
    #[tokio::test]
    async fn ra2_a_pinned_key_connects_without_a_prompt() {
        let (port, _recorded, server) = ra2_server().await;
        let mut o = ConnectOptions::vnc("127.0.0.1", port);
        o.credentials = Credentials::user_pass("pi", "raspberry");
        o.cert_pins = crate::types::CertPins::one(PinScheme::Ra2, test_server::fingerprint());
        let (mut shell, task) = start_establish(o);
        let (result, _options) = task.await.unwrap();
        result.expect("a pinned key connects");
        while let Ok(ev) = shell.events.try_recv() {
            assert!(
                !matches!(
                    ev,
                    SessionEvent::CertificatePrompt { .. } | SessionEvent::CredentialsRequired(_)
                ),
                "a pinned key with a stored password asked the user: {ev:?}"
            );
        }
        assert!(server.await.unwrap().is_some());
    }
}
