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
            anyhow::anyhow!("Paste a Boundary invitation beginning with boundary1:")
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
    },
    Granted {
        control: bool,
    },
    Denied,
    Control(bool),
    Input(Input),
    Ping,
}
pub async fn write<T: Serialize>(stream: &mut SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_CONTROL, "Control message is too large");
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await?;
    Ok(())
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
pub fn validate_hello(message: Message, invite: &Invitation) -> Result<String> {
    use subtle::ConstantTimeEq;
    if let Message::Hello {
        version,
        secret,
        name,
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
        Ok(name)
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
    #[test]
    fn rejects_bad_tickets() {
        assert!(Invitation::decode("hello").is_err());
        assert!(Invitation::decode(&"x".repeat(20000)).is_err());
        assert!(Invitation::decode("boundary1:AAAA").is_err());
    }
}
