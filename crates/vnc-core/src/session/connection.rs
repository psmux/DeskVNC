//! One connection attempt end-to-end: TCP connect → version handshake →
//! security → ClientInit/ServerInit → format/encoding setup → run loop.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::{Result, VncError};
use crate::proto::{self, messages, version::NegotiatedVersion, ProtocolVersion};
use crate::security::{CredentialAsk, CredentialSource, MAX_CREDENTIAL_ATTEMPTS};
use crate::types::{
    ClientCommand, ColorDepth, ConnectOptions, Credentials, PixelFormat, QualityPreset, Rect,
    SecurityType, SessionEvent, SessionState,
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
}

impl SessionSettings {
    pub fn from_options(options: &ConnectOptions) -> Self {
        Self {
            quality: options.quality,
            view_only: options.view_only,
            lossless_refresh: options.lossless_refresh,
            requested_size: None,
            always_refresh: false,
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
pub(crate) fn pixel_format_for(depth: ColorDepth) -> PixelFormat {
    match depth {
        // Grayscale reduction happens client-side in the shader.
        ColorDepth::Full | ColorDepth::Grayscale => PixelFormat::bgra8888(),
        ColorDepth::Palette256 => PixelFormat::palette8(),
        ColorDepth::Rgb222 | ColorDepth::Rgb111 => PixelFormat::rgb222(),
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

/// What `establish` hands back on success.
type Established = (
    BoxedStream,
    NegotiatedVersion,
    SecurityType,
    proto::ServerInit,
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

    emit_state(
        events,
        SessionState::Authenticating {
            method: strongest_offered_name(&offered),
        },
    )
    .await?;

    // Adapt our negotiated version to the security module's compact form.
    let version_info = crate::security::ProtocolVersionInfo {
        major: negotiated.version.major() as u8,
        minor: negotiated.version.minor() as u8,
        is_apple: negotiated.is_apple_screen_sharing,
    };
    let (mut stream, security, trust) =
        crate::security::authenticate_with_trust(tcp, version_info, &offered, options, creds)
            .await?;

    // First contact with a server key we have no pin for, a TLS certificate
    // (VeNCrypt) or a bare RSA key (RA2). Surface it so the UI can run its
    // trust-on-first-use prompt (PRD/10 §4). The scheme travels with it: the
    // answer has to be stored against the key the user was actually shown,
    // not against whichever one the endpoint happened to pin first.
    if let Some(crate::security::ServerIdentity {
        scheme,
        decision:
            vnc_transport::TrustDecision::Unknown {
                fingerprint,
                subject,
            },
    }) = trust
    {
        emit(
            events,
            SessionEvent::CertificatePrompt {
                fingerprint,
                subject,
                is_change: false,
                scheme,
            },
        )
        .await?;
    }

    emit_state(events, SessionState::Negotiating).await?;
    proto::write_client_init(&mut stream, options.shared).await?;
    let server_init = with_timeout(
        options.connect_timeout,
        proto::read_server_init(&mut stream),
    )
    .await?;

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

    Ok((stream, negotiated, security, server_init))
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
    options: &ConnectOptions,
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
        let source = CredentialSource::interactive(
            &ask_tx,
            attempt,
            last_error.clone(),
            username_hint.clone(),
        );

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
                }
            }
        };

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
    options: &ConnectOptions,
    settings: &mut SessionSettings,
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
    connected_at: &mut Option<Instant>,
) -> Result<RunOutcome> {
    // `establish_interactive` handles cancellation itself (it has to, so a
    // pending credential prompt tears down promptly); the run loop does too
    // (it wants to release pressed keys first).
    let (stream, negotiated, security, server_init) =
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
    let pf = pixel_format_for(quality_settings.pixel_format);
    let encodings = crate::quality::encodings_for(&quality_settings, &caps);
    caps.pixel_format = Some(pf);

    use tokio::io::AsyncWriteExt;
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
    run_loop.run(settings, events, commands, cancel).await
}
