//! macOS Screen Sharing's encrypted session.
//!
//! After an SRP login (security type 33 or 36) and the ordinary ServerInit,
//! the client sends a short cleartext prelude, the server answers it with a
//! rekey that carries the session's AES key, and from then on every message
//! in both directions travels inside the record layer in [`record`]. Inside
//! it the client picks encodings, asks for the whole picture and then pulls
//! changes with ordinary incremental update requests (see
//! [`AppleSession::full_request_pending`] for why it does not rely on server
//! pushed updates), and the server sends Apple's metadata rectangles and
//! messages, parsed in [`wire`], alongside ordinary RFB.
//!
//! ```text
//! C->S ClientInit 0xC1            S->C ServerInit
//! C->S ViewerInfo, SetEncryption(1), SetMode(1), SetEncryption(2)
//! S->C FramebufferUpdate [rekey]  (cleartext; may arrive at any point above)
//! ---- record layer from here ----
//! C->S SetDisplayConfiguration, SetEncodings, FramebufferUpdateRequest,
//!      AutoFrameBufferUpdate
//! S->C layout, keysyms, input source, device info, cursor, then updates
//! ```

pub mod record;
pub mod wire;

use tokio::io::AsyncReadExt;
use vnc_transport::BoxedStream;

use crate::error::{Result, VncError};
use crate::proto::messages::map_eof;
use crate::security::{read_bytes_max, write_all};
use crate::types::{encoding as std_enc, Rect};

pub use record::{ContentKeys, RecordStream, RekeyHandle};

/// Which optional parts of the prelude to send.
///
/// ViewerInfo is sent by default, in the native layout ([`wire::viewer_info`]).
/// It matters: without it the Mac never tells the viewer its clipboard
/// changed. An earlier, shorter ViewerInfo made the Mac stall, which is why
/// it can still be turned off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreludeOptions {
    pub viewer_info: bool,
    pub set_mode: bool,
}

impl Default for PreludeOptions {
    fn default() -> Self {
        Self {
            viewer_info: true,
            set_mode: true,
        }
    }
}

/// Messages the server may send before the first rekey that we skip.
const MAX_PRELUDE_MESSAGES: usize = 64;

/// Send the cleartext prelude and wait for the first rekey, then start the
/// record layer. Call it right after ServerInit has been read.
pub async fn start_session(
    mut stream: BoxedStream,
    wrap_key: &[u8; 16],
    options: PreludeOptions,
) -> Result<(RecordStream, RekeyHandle)> {
    let mut out = Vec::with_capacity(64);
    if options.viewer_info {
        out.extend_from_slice(&wire::viewer_info());
    }
    out.extend_from_slice(&wire::set_encryption_start());
    if options.set_mode {
        out.extend_from_slice(&wire::set_mode(true));
    }
    out.extend_from_slice(&wire::set_encryption_finish());
    write_all(&mut stream, &out).await?;

    let keys = read_first_rekey(&mut stream, wrap_key).await?;
    tracing::info!(generation = keys.generation, "Apple record layer starting");
    Ok(RecordStream::new(stream, &keys))
}

/// Read cleartext server messages until the rekey rectangle arrives.
///
/// The server sends it as soon as it has SetEncryption(1). A heartbeat may
/// come first and is skipped; anything else before the rekey cannot be
/// framed without knowing the session's encodings, so it is an error.
async fn read_first_rekey(stream: &mut BoxedStream, wrap_key: &[u8; 16]) -> Result<ContentKeys> {
    for _ in 0..MAX_PRELUDE_MESSAGES {
        let ty = stream.read_u8().await.map_err(map_eof)?;
        match ty {
            0 => {
                let _pad = stream.read_u8().await.map_err(map_eof)?;
                let count = stream.read_u16().await.map_err(map_eof)?;
                let mut header = [0u8; 12];
                stream.read_exact(&mut header).await.map_err(map_eof)?;
                let enc = i32::from_be_bytes(header[8..12].try_into().expect("four"));
                if enc != wire::encoding::REKEY {
                    return Err(VncError::Protocol(format!(
                        "the Mac sent encoding {enc} before the session key"
                    )));
                }
                if count != 1 {
                    tracing::warn!(count, "rekey update carries more than one rectangle");
                }
                let payload =
                    read_bytes_max(stream, record::REKEY_LEN, record::REKEY_LEN, "rekey").await?;
                return record::unwrap_rekey(wrap_key, &payload);
            }
            wire::server_msg::MISC_STATUS => {
                let cmd = wire::read_misc_status(stream).await?;
                tracing::debug!(cmd, "MiscStatus before the session key");
            }
            other => {
                return Err(VncError::Protocol(format!(
                    "the Mac sent message type {other} before the session key"
                )))
            }
        }
    }
    Err(VncError::Protocol(
        "the Mac never sent the session key".into(),
    ))
}

/// The encodings an Apple encrypted session asks for: only what this client
/// can decode, zlib first as the native viewer does, and Apple's metadata.
pub fn session_encodings() -> Vec<i32> {
    let mut v = vec![
        std_enc::ZLIB,
        std_enc::ZRLE,
        std_enc::COPY_RECT,
        std_enc::RAW,
        std_enc::PSEUDO_LAST_RECT,
        std_enc::PSEUDO_DESKTOP_SIZE,
        std_enc::PSEUDO_CURSOR,
    ];
    v.extend_from_slice(&wire::encoding::ADVERTISED);
    v
}

/// The messages that open the record layer: encodings, a full update
/// request, the switch to server pushed updates, and clipboard sync. Each
/// element is one message.
///
/// No SetDisplayConfiguration. A macOS 26 Mac answers one by adding a virtual
/// display for the session (its log: `set virtual display count to 1`),
/// which widens the desktop beside the real screens and can move the user's
/// windows. Without it the Mac shares its real displays at their own size.
/// The builder stays for a virtual display mode.
pub fn opening_messages(width: u16, height: u16) -> Vec<Vec<u8>> {
    let full = Rect::new(0, 0, width, height);
    vec![
        crate::proto::messages::set_encodings(&session_encodings()),
        crate::proto::messages::framebuffer_update_request(false, full).to_vec(),
        wire::auto_framebuffer_update(full).to_vec(),
        wire::auto_pasteboard(true).to_vec(),
    ]
}

/// What the run loop keeps for an Apple session.
#[derive(Debug, Clone)]
pub struct AppleSession {
    pub rekey: RekeyHandle,
    /// Whether the full picture has been asked for again after the Mac
    /// announced its desktop. See the run loop's DesktopSize handling.
    pub rearmed_after_announce: bool,
    /// The logical size pointer positions are given in, when the layout says
    /// it differs from the framebuffer.
    pub logical: Option<(u16, u16)>,
    /// A full (non incremental) update request is out and its picture has
    /// not arrived yet.
    ///
    /// A Mac keeps one update request, the last one it was sent, rather than
    /// the union of all of them: an incremental request sent behind a full
    /// one cancels the full picture, and a one pixel request narrows every
    /// later update to that pixel. Nor does it push changes on its own after
    /// AutoFrameBufferUpdate when the viewer shares its real displays (no
    /// SetDisplayConfiguration): a macOS 26 Mac sent nothing after the first
    /// picture for minutes while its clock and windows changed. So the
    /// session pulls with ordinary incremental requests, one at a time, and
    /// holds them back while a full request waits for its picture. Starts
    /// true because the opening sends one.
    pub full_request_pending: bool,
    /// When the pending full request went out. A full request still
    /// unanswered after [`FULL_REQUEST_PATIENCE`] stops holding back the
    /// incremental ones, so a Mac that never answers it cannot freeze the
    /// picture.
    pub full_request_at: Option<std::time::Instant>,
}

/// How long a full update request may hold back incremental ones.
pub const FULL_REQUEST_PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

impl AppleSession {
    pub fn new(rekey: RekeyHandle) -> Self {
        Self {
            rekey,
            rearmed_after_announce: false,
            logical: None,
            full_request_pending: true,
            full_request_at: Some(std::time::Instant::now()),
        }
    }

    /// Map a framebuffer position to the logical one the Mac expects.
    pub fn map_pointer(&self, x: u16, y: u16, fb: (u16, u16)) -> (u16, u16) {
        match self.logical {
            Some((lw, lh)) if fb.0 > 0 && fb.1 > 0 && (lw, lh) != fb => (
                ((x as u32 * lw as u32) / fb.0 as u32).min(lw.saturating_sub(1) as u32) as u16,
                ((y as u32 * lh as u32) / fb.1 as u32).min(lh.saturating_sub(1) as u32) as u16,
            ),
            _ => (x, y),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn pointer_maps_to_the_logical_size() {
        let (_a, _b) = tokio::io::duplex(8);
        let (s, h) = RecordStream::new(
            Box::pin(_a),
            &ContentKeys {
                generation: 1,
                key: [1; 16],
                iv: [2; 16],
            },
        );
        drop(s);
        let mut a = AppleSession::new(h);
        assert_eq!(a.map_pointer(100, 50, (3840, 2160)), (100, 50));
        a.logical = Some((1920, 1080));
        assert_eq!(a.map_pointer(3838, 2158, (3840, 2160)), (1919, 1079));
        assert_eq!(a.map_pointer(0, 0, (3840, 2160)), (0, 0));
    }

    #[tokio::test]
    async fn prelude_skips_a_heartbeat_and_takes_the_rekey() {
        let (client, mut server) = tokio::io::duplex(4096);
        let wrap = [9u8; 16];
        let keys = ContentKeys {
            generation: 1,
            key: [3; 16],
            iv: [4; 16],
        };
        let wrapped = record::wrap_rekey(&wrap, &keys);
        let task = tokio::spawn(async move {
            let mut got = vec![0u8; wire::viewer_info().len() + 12 + 4 + 8];
            server.read_exact(&mut got).await.unwrap();
            server
                .write_all(&[0x14, 0, 0, 4, 0, 1, 0, 12])
                .await
                .unwrap();
            let mut fbu = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
            fbu.extend_from_slice(&wire::encoding::REKEY.to_be_bytes());
            fbu.extend_from_slice(&wrapped);
            server.write_all(&fbu).await.unwrap();
            (got, server)
        });
        let (_stream, handle) = start_session(Box::pin(client), &wrap, PreludeOptions::default())
            .await
            .unwrap();
        assert_eq!(handle.generation(), 1);
        let (sent, _server) = task.await.unwrap();
        let vi = wire::viewer_info();
        assert_eq!(&sent[..vi.len()], &vi[..]);
        let rest = &sent[vi.len()..];
        assert_eq!(&rest[..12], &wire::set_encryption_start());
        assert_eq!(&rest[12..16], &wire::set_mode(true));
        assert_eq!(&rest[16..], &wire::set_encryption_finish());
    }

    #[tokio::test]
    async fn prelude_refuses_a_picture_before_the_key() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut fbu = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 10, 0, 10];
            fbu.extend_from_slice(&0i32.to_be_bytes());
            server.write_all(&fbu).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        });
        assert!(matches!(
            start_session(Box::pin(client), &[0; 16], PreludeOptions::default()).await,
            Err(VncError::Protocol(_))
        ));
    }
}
