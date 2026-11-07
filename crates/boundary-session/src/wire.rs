use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{
    EndpointAddr,
    endpoint::{RecvStream, SendStream},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::{SystemTime, UNIX_EPOCH};

pub const ALPN: &[u8] = b"boundary/support-experimental/1";
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
pub const MAX_CONTROL: usize = 8192;
pub const MAX_SIDE: u32 = 4096;
pub const MAX_PIXELS: u64 = 4096 * 2160;
pub const INVITE_SECONDS: u64 = 600;
/// The most clipboard text that goes either way in one message, in bytes of
/// UTF-8. Larger text is refused and the session goes on.
pub const MAX_CLIPBOARD: usize = 1024 * 1024;
/// The longest a control message carrying clipboard text may be on the wire:
/// JSON can spell one byte of text in six (`\u0001`), plus the envelope.
const MAX_CLIPBOARD_FRAME: usize = MAX_CLIPBOARD * 6 + 64;

/// What the host lets a helper do with the person's clipboard right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClipboardRights {
    /// The host takes text from the helper and puts it on the person's
    /// clipboard. True exactly while the helper has control, since it could
    /// type the same text.
    pub write: bool,
    /// The host sends the helper what the person copies. The person's own
    /// tick, off unless they turn it on, because what they copy is a
    /// password often enough to matter.
    pub read: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub version: u8,
    pub address: EndpointAddr,
    pub secret: [u8; 32],
    pub expires: u64,
}
impl Invitation {
    pub fn encode(&self) -> Result<String> {
        Ok(format!(
            "boundary1:{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?)
        ))
    }
    pub fn decode(text: &str) -> Result<Self> {
        ensure!(text.len() <= MAX_CONTROL * 2, "Invitation is too large");
        let text = text.trim().strip_prefix("boundary1:").ok_or_else(|| {
            anyhow::anyhow!("Paste a DeskVNC invitation beginning with boundary1:")
        })?;
        let result: Self = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(text)?)?;
        ensure!(result.version == 1, "Unsupported invitation version");
        ensure!(
            result.expires > now(),
            "This invitation has expired. Ask for a new one"
        );
        ensure!(
            result.expires <= now() + INVITE_SECONDS + 60,
            "Invalid invitation expiry"
        );
        Ok(result)
    }
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Key {
    Enter,
    Tab,
    Escape,
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Shift,
    Control,
    Alt,
    Meta,
    Space,
    Letter(char),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Button {
    Left,
    Middle,
    Right,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Input {
    Move { x: f32, y: f32 },
    Button { button: Button, down: bool },
    Key { key: Key, down: bool },
    Text(String),
    Scroll { lines: i32 },
    Release,
}
impl Input {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Move { x, y } => ensure!(
                x.is_finite()
                    && y.is_finite()
                    && (0.0..=1.0).contains(x)
                    && (0.0..=1.0).contains(y),
                "Invalid pointer coordinates"
            ),
            Self::Text(s) => ensure!(s.len() <= 1024, "Text is too long"),
            Self::Scroll { lines } => {
                ensure!((-20..=20).contains(lines), "Invalid scroll distance")
            }
            Self::Key {
                key: Key::Letter(c),
                ..
            } => ensure!(c.is_ascii_alphanumeric(), "Invalid shortcut key"),
            _ => {}
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
pub enum Message {
    Hello {
        version: u8,
        secret: [u8; 32],
        name: String,
        /// The helper can send commands and file requests (`crate::tools`).
        /// An older helper leaves it out, and is never offered them.
        #[serde(default)]
        tools: bool,
        /// The helper decodes JPEG screens, which are a tenth the size of
        /// PNG. An older helper leaves it out and is sent PNG.
        #[serde(default)]
        jpeg: bool,
        /// The helper draws screens sent as changed rectangles on one
        /// stream (`crate::screen`) and says when it has shown each one. An
        /// older helper leaves it out and is sent whole screens.
        #[serde(default)]
        tiles: bool,
        /// Video codecs the helper decodes, such as `"h264"`. A host that
        /// can encode one may send moving parts of the screen as video on
        /// the stream of updates. An older helper leaves it out and gets
        /// rectangles only.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        video: Vec<String>,
        /// The helper reads and sends clipboard messages. An older helper
        /// leaves it out and is never sent one, since it ends the session on
        /// a message it does not know.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        clipboard: bool,
    },
    Granted {
        control: bool,
        /// Present only for a helper that declared `tools`, and only from a
        /// host that serves them: whether they are allowed right now.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tools: Option<bool>,
        /// Present only for a helper that declared `clipboard`, and only from
        /// a host that serves it: what the helper may do with the person's
        /// clipboard right now.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clipboard: Option<ClipboardRights>,
    },
    Denied,
    Control(bool),
    /// The person changed whether commands and files are allowed. Sent only
    /// to a helper that declared `tools`, since an older one ends the session
    /// on a message it does not know.
    Tools(bool),
    Input(Input),
    Ping,
    /// The helper has drawn the screen update with this number. Sent only
    /// to a host that sends updates, which is the only kind that reads it.
    Shown(u64),
    /// The helper asks for the whole screen again as rectangles, because
    /// what it holds went stale under video. Sent only to a host whose
    /// stream of updates said it sends video, since an older host ends the
    /// session on a message it does not know.
    Refresh,
    /// A helper asking an unattended machine to let it in. The helper's
    /// identity is the key it connected with, which the encrypted handshake
    /// has already proved, so a paired helper sends no password at all.
    Knock {
        version: u8,
        name: String,
        password: Option<String>,
        #[serde(default)]
        tools: bool,
        /// The helper decodes JPEG screens, which are a tenth the size of
        /// PNG. An older helper leaves it out and is sent PNG.
        #[serde(default)]
        jpeg: bool,
        /// The helper draws screens sent as changed rectangles on one
        /// stream (`crate::screen`) and says when it has shown each one. An
        /// older helper leaves it out and is sent whole screens.
        #[serde(default)]
        tiles: bool,
        /// Video codecs the helper decodes, such as `"h264"`. A host that
        /// can encode one may send moving parts of the screen as video on
        /// the stream of updates. An older helper leaves it out and gets
        /// rectangles only.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        video: Vec<String>,
        /// The helper reads and sends clipboard messages. An older helper
        /// leaves it out and is never sent one, since it ends the session on
        /// a message it does not know.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        clipboard: bool,
    },
    /// Sent during an attended session when the person being helped chooses
    /// to let this helper connect any time. `machine` is the ID the helper
    /// connects to later, which is not the ID of this attended session.
    Paired {
        machine: String,
        name: String,
    },
    /// An unattended machine turning a helper away, and why.
    Refused(String),
    /// Clipboard text, UTF-8, at most [`MAX_CLIPBOARD`] bytes. From the
    /// helper, for the person's clipboard; from the host, what the person
    /// copied. Sent only to a peer that said it reads clipboard messages.
    Clipboard(String),
    /// The host changed what the helper may do with the clipboard. Sent only
    /// to a helper that declared `clipboard`.
    ClipboardRights(ClipboardRights),
}
pub async fn write<T: Serialize>(stream: &mut SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_CONTROL, "Control message is too large");
    write_bytes(stream, &bytes).await
}
async fn write_bytes(stream: &mut SendStream, bytes: &[u8]) -> Result<()> {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(bytes).await?;
    Ok(())
}
/// Write a message during a session, where clipboard text may be longer
/// than any other control message. Text over [`MAX_CLIPBOARD`] is refused
/// before anything is written, so the stream stays whole.
pub async fn write_message(stream: &mut SendStream, message: &Message) -> Result<()> {
    if let Message::Clipboard(text) = message {
        check_clipboard(text)?;
        let bytes = serde_json::to_vec(message)?;
        ensure!(
            bytes.len() <= MAX_CLIPBOARD_FRAME,
            "Clipboard text is too large"
        );
        return write_bytes(stream, &bytes).await;
    }
    write(stream, message).await
}
/// Clipboard text that may go over the wire, or why it may not.
pub fn check_clipboard(text: &str) -> Result<()> {
    ensure!(
        text.len() <= MAX_CLIPBOARD,
        "Clipboard text is too large: {} bytes, and at most {} go to the other computer",
        text.len(),
        MAX_CLIPBOARD
    );
    Ok(())
}
/// Read a message during a session. Only a clipboard message may be longer
/// than [`MAX_CONTROL`]; its text is checked against [`MAX_CLIPBOARD`] by
/// whoever handles it, so text that is too long is refused without ending
/// the session.
pub async fn read_message(stream: &mut RecvStream) -> Result<Message> {
    let length = read_length(stream).await?;
    read_body(stream, length).await
}
/// The length of the next session message, which is what a reader waits on
/// while the other side has nothing to say.
pub async fn read_length(stream: &mut RecvStream) -> Result<usize> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(
        length > 0 && length <= MAX_CLIPBOARD_FRAME,
        "Invalid control message length"
    );
    Ok(length)
}
/// The session message of `length` bytes that [`read_length`] announced.
/// Only a clipboard message may be longer than [`MAX_CONTROL`].
pub async fn read_body(stream: &mut RecvStream, length: usize) -> Result<Message> {
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let message: Message = serde_json::from_slice(&bytes)?;
    ensure!(
        length <= MAX_CONTROL || matches!(message, Message::Clipboard(_)),
        "Invalid control message length"
    );
    Ok(message)
}
pub async fn read<T: DeserializeOwned>(stream: &mut RecvStream) -> Result<T> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(
        length > 0 && length <= MAX_CONTROL,
        "Invalid control message length"
    );
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}
/// The one video codec a host sends today.
pub const H264: &str = "h264";

/// How screens go to a helper, from what its first message said it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screens {
    Png,
    Jpeg,
    Tiles,
    /// Rectangles, and H.264 while much of the screen moves, on one stream
    /// that starts with [`crate::screen::MAGIC_VIDEO`].
    Video,
}
impl Screens {
    pub fn from_hello(jpeg: bool, tiles: bool, video: &[String]) -> Self {
        match (jpeg, tiles) {
            (_, true) if video.iter().any(|c| c == H264) => Self::Video,
            (_, true) => Self::Tiles,
            (true, false) => Self::Jpeg,
            (false, false) => Self::Png,
        }
    }
    /// Whether the helper says when it has shown each update.
    pub fn acknowledged(self) -> bool {
        matches!(self, Self::Tiles | Self::Video)
    }
}
/// What a helper said in its hello that the host goes on.
pub struct Hello {
    pub name: String,
    /// It can send commands and file requests.
    pub tools: bool,
    pub screens: Screens,
    /// It reads and sends clipboard messages.
    pub clipboard: bool,
}
/// The helper's name, what it can do, and how it takes screens.
pub fn validate_hello(message: Message, invite: &Invitation) -> Result<Hello> {
    use subtle::ConstantTimeEq;
    if let Message::Hello {
        version,
        secret,
        name,
        tools,
        jpeg,
        tiles,
        video,
        clipboard,
    } = message
    {
        ensure!(
            version == 1 && bool::from(secret.ct_eq(&invite.secret)),
            "Invalid invitation"
        );
        ensure!(invite.expires > now(), "Invitation expired");
        ensure!(
            !name.trim().is_empty() && name.len() <= 80 && !name.chars().any(char::is_control),
            "Invalid helper name"
        );
        Ok(Hello {
            name,
            tools,
            screens: Screens::from_hello(jpeg, tiles, &video),
            clipboard,
        })
    } else {
        bail!("Expected session handshake")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_input() {
        for input in [
            Input::Move {
                x: f32::NAN,
                y: 0.0,
            },
            Input::Move { x: 1.1, y: 0.0 },
            Input::Text("x".repeat(1025)),
            Input::Scroll { lines: i32::MIN },
            Input::Key {
                key: Key::Letter('\n'),
                down: true,
            },
        ] {
            assert!(input.validate().is_err());
        }
    }
    /// The first messages as a copy from before video wrote and read them.
    mod before_video {
        use serde::{Deserialize, Serialize};
        #[derive(Serialize, Deserialize)]
        pub enum Message {
            Hello {
                version: u8,
                secret: [u8; 32],
                name: String,
                #[serde(default)]
                tools: bool,
                #[serde(default)]
                jpeg: bool,
                #[serde(default)]
                tiles: bool,
            },
            Knock {
                version: u8,
                name: String,
                password: Option<String>,
                #[serde(default)]
                tools: bool,
                #[serde(default)]
                jpeg: bool,
                #[serde(default)]
                tiles: bool,
            },
        }
    }

    #[test]
    fn video_is_offered_without_breaking_older_peers() {
        // A helper that decodes video, read by a host from before video:
        // the new field is passed over and it is sent tiles.
        let hello = serde_json::to_vec(&Message::Hello {
            version: 1,
            secret: [7; 32],
            name: "Helper".into(),
            tools: true,
            jpeg: true,
            tiles: true,
            video: vec![H264.into()],
            clipboard: false,
        })
        .unwrap();
        assert!(matches!(
            serde_json::from_slice(&hello).unwrap(),
            before_video::Message::Hello { tiles: true, .. }
        ));
        let knock = serde_json::to_vec(&Message::Knock {
            version: 2,
            name: "Helper".into(),
            password: None,
            tools: false,
            jpeg: true,
            tiles: true,
            video: vec![H264.into()],
            clipboard: false,
        })
        .unwrap();
        assert!(matches!(
            serde_json::from_slice(&knock).unwrap(),
            before_video::Message::Knock { tiles: true, .. }
        ));
        // A helper from before video, read by this host: no codecs, tiles.
        let old = serde_json::to_vec(&before_video::Message::Hello {
            version: 1,
            secret: [7; 32],
            name: "Helper".into(),
            tools: false,
            jpeg: true,
            tiles: true,
        })
        .unwrap();
        let Message::Hello {
            jpeg, tiles, video, ..
        } = serde_json::from_slice(&old).unwrap()
        else {
            panic!("not a hello");
        };
        assert_eq!(Screens::from_hello(jpeg, tiles, &video), Screens::Tiles);
        // A helper that does not decode video writes exactly what an older
        // one did.
        let plain = serde_json::to_string(&Message::Hello {
            version: 1,
            secret: [7; 32],
            name: "Helper".into(),
            tools: false,
            jpeg: true,
            tiles: true,
            video: Vec::new(),
            clipboard: false,
        })
        .unwrap();
        assert_eq!(plain, String::from_utf8(old).unwrap());
        // Codecs this host does not send, and video without tiles, get none.
        let other = ["av1".to_string()];
        assert_eq!(Screens::from_hello(true, true, &other), Screens::Tiles);
        assert_eq!(
            Screens::from_hello(true, false, &[H264.into()]),
            Screens::Jpeg
        );
        assert_eq!(
            Screens::from_hello(true, true, &[H264.into()]),
            Screens::Video
        );
    }

    /// The grant as 0.34.1 wrote and read it, before clipboard.
    mod before_clipboard {
        use serde::{Deserialize, Serialize};
        #[derive(Serialize, Deserialize)]
        pub enum Message {
            Granted {
                control: bool,
                #[serde(default, skip_serializing_if = "Option::is_none")]
                tools: Option<bool>,
            },
        }
    }

    #[test]
    fn clipboard_messages_round_trip() {
        for message in [
            Message::Clipboard("line one\nline two \u{1F600} \u{0001}".into()),
            Message::ClipboardRights(ClipboardRights {
                write: true,
                read: false,
            }),
            Message::Granted {
                control: true,
                tools: None,
                clipboard: Some(ClipboardRights {
                    write: true,
                    read: true,
                }),
            },
        ] {
            let bytes = serde_json::to_vec(&message).unwrap();
            let back: Message = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(serde_json::to_vec(&back).unwrap(), bytes);
        }
        let hello = serde_json::to_vec(&Message::Hello {
            version: 1,
            secret: [1; 32],
            name: "Helper".into(),
            tools: false,
            jpeg: true,
            tiles: true,
            video: Vec::new(),
            clipboard: true,
        })
        .unwrap();
        let Message::Hello { clipboard, .. } = serde_json::from_slice(&hello).unwrap() else {
            panic!("not a hello");
        };
        assert!(clipboard);
    }

    #[test]
    fn older_peers_read_and_write_what_they_always_did() {
        // A hello and a knock from before clipboard say nothing about it.
        let old = serde_json::to_vec(&before_video::Message::Hello {
            version: 1,
            secret: [7; 32],
            name: "Helper".into(),
            tools: true,
            jpeg: true,
            tiles: true,
        })
        .unwrap();
        let Message::Hello { clipboard, .. } = serde_json::from_slice(&old).unwrap() else {
            panic!("not a hello");
        };
        assert!(!clipboard);
        let old = serde_json::to_vec(&before_video::Message::Knock {
            version: 2,
            name: "Helper".into(),
            password: None,
            tools: false,
            jpeg: true,
            tiles: true,
        })
        .unwrap();
        let Message::Knock { clipboard, .. } = serde_json::from_slice(&old).unwrap() else {
            panic!("not a knock");
        };
        assert!(!clipboard);
        // A helper that takes clipboard is still read by an older host.
        let knock = serde_json::to_vec(&Message::Knock {
            version: 2,
            name: "Helper".into(),
            password: None,
            tools: false,
            jpeg: true,
            tiles: true,
            video: Vec::new(),
            clipboard: true,
        })
        .unwrap();
        assert!(matches!(
            serde_json::from_slice(&knock).unwrap(),
            before_video::Message::Knock { tiles: true, .. }
        ));
        // A grant from an older host has no clipboard rights.
        let old = serde_json::to_vec(&before_clipboard::Message::Granted {
            control: true,
            tools: Some(false),
        })
        .unwrap();
        let Message::Granted {
            control,
            tools,
            clipboard,
        } = serde_json::from_slice(&old).unwrap()
        else {
            panic!("not a grant");
        };
        assert_eq!((control, tools, clipboard), (true, Some(false), None));
        // A grant to a helper that did not ask about clipboard is written
        // exactly as an older host wrote it, and one with rights is still
        // read by an older helper.
        let plain = serde_json::to_vec(&Message::Granted {
            control: true,
            tools: Some(false),
            clipboard: None,
        })
        .unwrap();
        assert_eq!(plain, old);
        let rich = serde_json::to_vec(&Message::Granted {
            control: false,
            tools: None,
            clipboard: Some(ClipboardRights {
                write: false,
                read: true,
            }),
        })
        .unwrap();
        assert!(matches!(
            serde_json::from_slice(&rich).unwrap(),
            before_clipboard::Message::Granted {
                control: false,
                tools: None
            }
        ));
    }

    #[test]
    fn clipboard_text_has_its_own_limit() {
        assert!(check_clipboard(&"a".repeat(MAX_CLIPBOARD)).is_ok());
        let error = check_clipboard(&"a".repeat(MAX_CLIPBOARD + 1)).unwrap_err();
        assert!(error.to_string().contains("too large"), "{error}");
        // The worst case of JSON escaping still fits a frame.
        let worst =
            serde_json::to_vec(&Message::Clipboard("\u{0001}".repeat(MAX_CLIPBOARD))).unwrap();
        assert!(worst.len() <= MAX_CLIPBOARD_FRAME, "{}", worst.len());
    }

    #[test]
    fn rejects_bad_tickets() {
        assert!(Invitation::decode("hello").is_err());
        assert!(Invitation::decode(&"x".repeat(20000)).is_err());
        assert!(Invitation::decode("boundary1:AAAA").is_err());
    }
}
