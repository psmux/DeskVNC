//! Native Rust Radmin driver using DeskVNC's shared session and transport APIs.
//! No helper process, Python runtime, vendor binary or alternate rendering path.
#![forbid(unsafe_code)]

mod auth;
mod channel;
mod clipboard;
mod cursor;
mod desktop;
mod input;
#[cfg(test)]
mod integration;

use anyhow::{ensure, Context, Result};
use channel::{read_record, write_record, CipherState};
use remote_core::*;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Default)]
pub struct RadminDriver;
impl ProtocolDriver for RadminDriver {
    fn kind(&self) -> ProtocolKind {
        ProtocolKind::Radmin
    }
    fn spawn(
        &self,
        id: String,
        options: ConnectOptions,
        events: mpsc::Sender<SessionEvent>,
    ) -> Result<SessionHandle, OptionsMismatch> {
        if options.kind() != self.kind() {
            return Err(OptionsMismatch {
                expected: self.kind(),
                actual: options.kind(),
            });
        }
        let (commands, receiver) = mpsc::channel(256);
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            let result = run(options, receiver, &events, &token).await;
            let reason = result
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "Disconnected".into());
            let _ = emit_state(
                &events,
                SessionState::Disconnected {
                    reason,
                    can_retry: false,
                    symbol: None,
                },
            )
            .await;
        });
        Ok(SessionHandle {
            id,
            kind: self.kind(),
            commands,
            cancel,
        })
    }
}

async fn encrypted_send<W: AsyncWrite + Unpin>(
    stream: &mut W,
    cipher: &mut CipherState,
    data: &[u8],
) -> Result<()> {
    let encrypted = cipher.encrypt(data)?;
    write_record(stream, &encrypted).await
}

async fn negotiate(
    options: &ConnectOptions,
    events: &mpsc::Sender<SessionEvent>,
) -> Result<(BoxedStream, CipherState, CipherState, desktop::Deflate)> {
    let mut stream: BoxedStream = if let Some(connector) = &options.connector {
        connector
            .0
            .connect(&options.host, options.port, options.connect_timeout)
            .await?
    } else {
        let stream = tokio::net::TcpStream::connect((options.host.as_str(), options.port)).await?;
        stream.set_nodelay(true)?;
        Box::pin(stream)
    };
    emit_state(
        events,
        SessionState::Authenticating {
            method: "Radmin security".into(),
        },
    )
    .await?;
    let password = Zeroizing::new(options.credentials.password.clone().unwrap_or_default());
    let key = auth::authenticate(
        &mut stream,
        options.credentials.username.as_deref().unwrap_or(""),
        &password,
    )
    .await?;
    emit_state(events, SessionState::Negotiating).await?;
    write_record(&mut stream, &[0x2e]).await?;
    let token = read_record(&mut stream).await?;
    ensure!(
        token.len() == 33 && token[0] == 0x2e,
        "Unexpected Radmin channel negotiation"
    );
    let mut tx = CipherState::new(&key[..32], &token[17..33])?;
    let mut rx = CipherState::new(&key[..32], &token[1..17])?;
    drop(key);
    let mut mode = vec![0x1a];
    mode.extend_from_slice(&(if options.view_only { 6u32 } else { 1u32 }).to_be_bytes());
    encrypted_send(&mut stream, &mut tx, &mode).await?;
    let response = rx.decrypt(read_record(&mut stream).await?)?;
    if response == [0x30] {
        encrypted_send(&mut stream, &mut tx, &[0x31]).await?;
        ensure!(
            rx.decrypt(read_record(&mut stream).await?)? == [0x31],
            "Radmin desktop approval was not granted"
        );
    } else {
        ensure!(
            response == [0x1a],
            "Radmin desktop connection was not accepted"
        );
    }
    encrypted_send(&mut stream, &mut tx, &[0x32]).await?;
    let response = rx.decrypt(read_record(&mut stream).await?)?;
    ensure!(
        response.first() == Some(&0x32),
        "Unexpected Radmin desktop negotiation"
    );
    desktop::fields(&response[1..], false)?;
    encrypted_send(&mut stream, &mut tx, &[0x28]).await?;
    ensure!(
        rx.decrypt(read_record(&mut stream).await?)? == [0x28],
        "Radmin desktop stream was not accepted"
    );
    let mut deflate = desktop::Deflate::default();
    let mut request = desktop::tlv(0x40000000, &13u32.to_be_bytes());
    request.extend(desktop::tlv(0x30000000, &24u32.to_be_bytes()));
    request.extend(desktop::tlv(
        0x10000000,
        &[24u32, 0xff0000, 0xff00, 0xff]
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>(),
    ));
    encrypted_send(&mut stream, &mut tx, &deflate.encode(&request)?).await?;
    Ok((stream, tx, rx, deflate))
}

struct ReaderGuard(tokio::task::JoinHandle<()>);
impl Drop for ReaderGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn run(
    mut options: ConnectOptions,
    mut commands: mpsc::Receiver<ClientCommand>,
    events: &mpsc::Sender<SessionEvent>,
    cancel: &CancellationToken,
) -> Result<()> {
    emit_state(events, SessionState::Connecting).await?;
    if options
        .credentials
        .username
        .as_deref()
        .is_none_or(str::is_empty)
        || options.credentials.password.is_none()
    {
        emit(
            events,
            SessionEvent::CredentialsRequired(CredentialRequest {
                method: "Radmin security".into(),
                kind: CredentialKind::UsernameAndPassword,
                attempt: 1,
                error: None,
                truncates_password: false,
                username_hint: options.credentials.username.clone(),
            }),
        )
        .await?;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                command = commands.recv() => match command {
                    Some(ClientCommand::ProvideCredentials {username,password,..}) => {
                        options.credentials = Credentials {username,password:Some(password),domain:None}; break;
                    }
                    None | Some(ClientCommand::CancelCredentials|ClientCommand::Disconnect) => return Ok(()),
                    Some(ClientCommand::Agent(intent)) => emit(events,SessionEvent::AgentRefused(intent.refuse("Authentication pending"))).await?,
                    _ => {}
                }
            }
        }
    }
    let (stream, mut tx, mut rx, mut deflate) = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(options.connect_timeout,negotiate(&options,events)) => result.context("Radmin connection/authentication timed out")??,
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (frames, mut incoming) = mpsc::channel::<Result<Vec<u8>>>(2);
    // Read complete records in one owner. Cancelling a select/read_exact in
    // the input loop would otherwise lose partial TCP headers on every click.
    let _reader = ReaderGuard(tokio::spawn(async move {
        loop {
            let result: Result<Vec<u8>> = async {
                let first = reader.read_u8().await?; // idle connections have no deadline
                tokio::time::timeout(Duration::from_secs(10), async {
                    let mut header = [first, 0, 0, 0];
                    reader.read_exact(&mut header[1..]).await?;
                    let len = u32::from_be_bytes(header) as usize;
                    ensure!(
                        (1..=channel::MAX_RECORD).contains(&len),
                        "Invalid Radmin record length"
                    );
                    let mut data = vec![0; len];
                    reader.read_exact(&mut data).await?;
                    Ok(data)
                })
                .await
                .context("Radmin partial record timed out")?
            }
            .await;
            let failed = result.is_err();
            if frames.send(result).await.is_err() || failed {
                break;
            }
        }
    }));
    emit_state(events, SessionState::Connected).await?;
    let mut desktop = desktop::Desktop::default();
    let mut cursors = cursor::CursorCache::default();
    let mut input = input::Input::default();
    let server_view_only = options.view_only;
    let mut view_only = options.view_only;
    let mut clipboard_pending = false;
    let mut clipboard_deadline = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        let mut disconnect = false;
        let payload = tokio::select! {
            _ = cancel.cancelled() => { disconnect = true; input.release() }
            _ = tick.tick() => {
                if clipboard_pending && tokio::time::Instant::now() >= clipboard_deadline { clipboard_pending = false; }
                Vec::new()
            }
            data = incoming.recv() => {
                let data = data.context("Radmin connection closed")??;
                let data = deflate.decode(&rx.decrypt(data)?)?;
                let fields = desktop::fields(&data,false)?;
                for event in desktop.decode(&fields)? { emit(events,event).await?; }
                if let Some(data) = desktop::field(&fields,0x80000000) { emit(events,SessionEvent::CursorUpdate(cursors.decode(data)?)).await?; }
                if let Some(data) = desktop::field(&fields,0x70000000) {
                    ensure!(data.len() == 4,"Invalid Radmin cursor position");
                    let x = i16::from_be_bytes(data[..2].try_into()?).max(0) as u16;
                    let y = i16::from_be_bytes(data[2..].try_into()?).max(0) as u16;
                    emit(events,SessionEvent::CursorPosition {x,y}).await?;
                }
                if let Some(data) = desktop::field(&fields,0x90000000) {
                    let text = clipboard::receive(data)?;
                    if clipboard_pending && !view_only {
                        if let Some(text) = text { emit(events,SessionEvent::ClipboardText(text)).await?; }
                    }
                    clipboard_pending = false;
                }
                Vec::new()
            }
            command = commands.recv() => match command {
                None | Some(ClientCommand::Disconnect|ClientCommand::CancelCredentials) => {disconnect = true; input.release()}
                Some(ClientCommand::ReleaseAllKeys) => input.release(),
                Some(ClientCommand::SecureAttention) if !view_only && desktop.has_frame() => input::Input::secure_attention(),
                Some(ClientCommand::SetViewOnly(value)) => {
                    view_only = value || server_view_only;
                    if view_only { clipboard_pending = false; }
                    input.release()
                }
                Some(ClientCommand::Pointer {x,y,button_mask}) if !view_only && desktop.has_frame() => input.pointer(x,y,button_mask,desktop.size()),
                Some(ClientCommand::Key {keysym,keycode,down}) if !view_only && desktop.has_frame() => input.key(keysym,keycode,down),
                Some(ClientCommand::ClipboardText(text)) if !view_only && desktop.has_frame() => clipboard::send(&text)?,
                Some(ClientCommand::ClipboardRequest {..}) if !view_only && desktop.has_frame() && !clipboard_pending => {
                    clipboard_pending = true;
                    clipboard_deadline = tokio::time::Instant::now()+Duration::from_secs(10);
                    desktop::tlv(0x70000000,&[0x13])
                }
                Some(ClientCommand::Refresh) => { if let Some(event) = desktop.refresh() {emit(events,event).await?;} Vec::new() }
                Some(ClientCommand::Agent(intent)) => {emit(events,SessionEvent::AgentRefused(intent.refuse("Radmin supports desktop input only"))).await?; Vec::new()}
                _ => Vec::new(),
            }
        };
        if !payload.is_empty() {
            let compressed = deflate.encode(&payload)?;
            let timeout = if disconnect {
                Duration::from_millis(300)
            } else {
                Duration::from_secs(10)
            };
            let operation =
                tokio::time::timeout(timeout, encrypted_send(&mut writer, &mut tx, &compressed));
            let result = if disconnect {
                operation.await
            } else {
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    result = operation => result,
                }
            };
            if !disconnect {
                result.context("Radmin write timed out")??;
            }
        }
        if disconnect {
            let _ = tokio::time::timeout(Duration::from_millis(300), writer.shutdown()).await;
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn credential_prompt_can_be_cancelled_without_opening_socket() {
        let (events, mut rx) = mpsc::channel(8);
        let handle = RadminDriver
            .spawn(
                "test".into(),
                ConnectOptions::radmin("localhost", 4899),
                events,
            )
            .unwrap();
        assert!(matches!(
            rx.recv().await,
            Some(SessionEvent::StateChanged(SessionState::Connecting))
        ));
        assert!(matches!(
            rx.recv().await,
            Some(SessionEvent::CredentialsRequired(_))
        ));
        handle.shutdown();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap(),
            Some(SessionEvent::StateChanged(
                SessionState::Disconnected { .. }
            ))
        ));
    }
}
