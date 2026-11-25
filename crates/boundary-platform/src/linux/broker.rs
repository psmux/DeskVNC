//! The screen and input of a Wayland sign in screen, handed from root to the
//! host over a socket.
//!
//! Reading the kernel's display planes and making an input device both need
//! root, but the host that talks to helpers over the network runs as the
//! person who set the service up. The service keeps the privileged part
//! here, small: it answers "what is on the screen" and takes pointer and
//! key events, nothing else, on a socket in a root owned folder that only
//! that person may open.
//!
//! Messages, host to service: `C` for a picture; `M` x y (f32) to move the
//! pointer; `B` button down; `K` key down char (u32); `T` length text; `S`
//! lines (i32); `R` to let go of everything. The service answers `C` with
//! width and height (u32) and the RGBA bytes, or a zero width, a length and
//! the reason it could not.

use super::kms::Kms;
use super::uinput::Uinput;
use anyhow::{Context, Result, bail};
use boundary_session::{Button, Desktop, Frame, Input, Key};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

fn read_u32(s: &mut impl Read) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    s.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn key_code(key: Key) -> u32 {
    match key {
        Key::Enter => 1,
        Key::Tab => 2,
        Key::Escape => 3,
        Key::Backspace => 4,
        Key::Delete => 5,
        Key::Left => 6,
        Key::Right => 7,
        Key::Up => 8,
        Key::Down => 9,
        Key::Home => 10,
        Key::End => 11,
        Key::PageUp => 12,
        Key::PageDown => 13,
        Key::Shift => 14,
        Key::Control => 15,
        Key::Alt => 16,
        Key::Meta => 17,
        Key::Space => 18,
        Key::Letter(c) => 0x100 + c as u32,
    }
}
fn key_from(code: u32) -> Option<Key> {
    Some(match code {
        1 => Key::Enter,
        2 => Key::Tab,
        3 => Key::Escape,
        4 => Key::Backspace,
        5 => Key::Delete,
        6 => Key::Left,
        7 => Key::Right,
        8 => Key::Up,
        9 => Key::Down,
        10 => Key::Home,
        11 => Key::End,
        12 => Key::PageUp,
        13 => Key::PageDown,
        14 => Key::Shift,
        15 => Key::Control,
        16 => Key::Alt,
        17 => Key::Meta,
        18 => Key::Space,
        n if n >= 0x100 => Key::Letter(char::from_u32(n - 0x100)?),
        _ => return None,
    })
}

/// Encode one input as the service reads it.
pub(crate) fn encode(input: &Input) -> Vec<u8> {
    let mut out = Vec::new();
    match input {
        Input::Move { x, y } => {
            out.push(b'M');
            out.extend_from_slice(&x.to_le_bytes());
            out.extend_from_slice(&y.to_le_bytes());
        }
        Input::Button { button, down } => {
            out.extend_from_slice(&[
                b'B',
                match button {
                    Button::Left => 0,
                    Button::Middle => 1,
                    Button::Right => 2,
                },
                *down as u8,
            ]);
        }
        Input::Key { key, down } => {
            out.extend_from_slice(&[b'K', *down as u8]);
            out.extend_from_slice(&key_code(*key).to_le_bytes());
        }
        Input::Text(text) => {
            out.push(b'T');
            out.extend_from_slice(&(text.len() as u32).to_le_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        Input::Scroll { lines } => {
            out.push(b'S');
            out.extend_from_slice(&lines.to_le_bytes());
        }
        Input::Release => out.push(b'R'),
    }
    out
}

/// Read one input after its leading byte, or `None` for a capture request.
pub(crate) fn decode(kind: u8, s: &mut impl Read) -> Result<Option<Input>> {
    Ok(Some(match kind {
        b'C' => return Ok(None),
        b'M' => {
            let x = f32::from_bits(read_u32(s)?);
            let y = f32::from_bits(read_u32(s)?);
            Input::Move { x, y }
        }
        b'B' => {
            let mut b = [0u8; 2];
            s.read_exact(&mut b)?;
            Input::Button {
                button: match b[0] {
                    1 => Button::Middle,
                    2 => Button::Right,
                    _ => Button::Left,
                },
                down: b[1] != 0,
            }
        }
        b'K' => {
            let mut d = [0u8; 1];
            s.read_exact(&mut d)?;
            let key = key_from(read_u32(s)?).context("Unknown key")?;
            Input::Key {
                key,
                down: d[0] != 0,
            }
        }
        b'T' => {
            let len = read_u32(s)? as usize;
            anyhow::ensure!(len <= 4096, "Text is too long");
            let mut text = vec![0u8; len];
            s.read_exact(&mut text)?;
            Input::Text(String::from_utf8(text)?)
        }
        b'S' => Input::Scroll {
            lines: read_u32(s)? as i32,
        },
        b'R' => Input::Release,
        other => bail!("Unknown request {other}"),
    }))
}

/// Answer one host on `stream` until it goes away.
/// A picture of the screen, waking it first when it is asleep. A screen
/// that stays asleep is sent as black at its last size, so the helper's
/// session goes on and their first move wakes it.
fn picture(
    kms: &Kms,
    uinput: &mut Option<Uinput>,
    last: &mut Option<(u32, u32)>,
) -> Result<super::kms::Picture> {
    for _ in 0..10 {
        match kms.capture() {
            Ok(p) => {
                *last = Some((p.width, p.height));
                return Ok(p);
            }
            Err(error) if error.is::<super::kms::Asleep>() => {
                if uinput.is_none() {
                    *uinput = Some(Uinput::new()?);
                }
                if let Some(u) = uinput.as_mut() {
                    u.wake()?;
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            Err(error) => return Err(error),
        }
    }
    let (width, height) = last.context("The screen is asleep and did not wake")?;
    Ok(super::kms::Picture {
        width,
        height,
        rgba: [0, 0, 0, 255].repeat(width as usize * height as usize),
    })
}

fn answer(mut stream: UnixStream) -> Result<()> {
    let kms = Kms::open();
    let mut uinput = None;
    let mut last = None;
    loop {
        let mut kind = [0u8; 1];
        if stream.read_exact(&mut kind).is_err() {
            break;
        }
        match decode(kind[0], &mut stream)? {
            None => match kms
                .as_ref()
                .map_err(|e| anyhow::anyhow!("{e:#}"))
                .and_then(|k| picture(k, &mut uinput, &mut last))
            {
                Ok(p) => {
                    stream.write_all(&p.width.to_le_bytes())?;
                    stream.write_all(&p.height.to_le_bytes())?;
                    stream.write_all(&p.rgba)?;
                }
                Err(error) => {
                    let text = format!("{error:#}");
                    stream.write_all(&0u32.to_le_bytes())?;
                    stream.write_all(&(text.len() as u32).to_le_bytes())?;
                    stream.write_all(text.as_bytes())?;
                }
            },
            Some(input) => {
                if uinput.is_none() {
                    uinput = Some(Uinput::new()?);
                }
                if let Some(u) = uinput.as_mut() {
                    u.input(input)?;
                }
            }
        }
    }
    if let Some(mut u) = uinput {
        let _ = u.release();
    }
    Ok(())
}

/// Whether the screen can be read here at all: a picture, or why not.
pub fn kms_probe() -> Result<(u32, u32)> {
    let picture = Kms::open()?.capture()?;
    Ok((picture.width, picture.height))
}

/// Serve hosts on `listener` until `stop` is set, one thread each.
pub fn kms_serve(listener: UnixListener, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::Ordering;
    let _ = listener.set_nonblocking(true);
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                std::thread::spawn(move || {
                    if let Err(error) = answer(stream) {
                        eprintln!("Sign in screen input or capture stopped: {error:#}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(200)),
        }
    }
}

/// The host's side: a desktop whose screen and input are the service's.
pub(crate) struct Brokered {
    stream: UnixStream,
}

impl Brokered {
    pub fn connect(path: &str) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("Cannot reach the sign in screen service at {path}"))?;
        Ok(Self { stream })
    }
}

impl Desktop for Brokered {
    fn capture(&mut self) -> Result<Frame> {
        self.stream.write_all(b"C")?;
        let width = read_u32(&mut self.stream)?;
        if width == 0 {
            let len = read_u32(&mut self.stream)? as usize;
            let mut text = vec![0u8; len.min(4096)];
            self.stream.read_exact(&mut text)?;
            bail!("{}", String::from_utf8_lossy(&text));
        }
        let height = read_u32(&mut self.stream)?;
        anyhow::ensure!(width <= 16384 && height <= 16384, "Odd screen size");
        let mut rgba = vec![0u8; width as usize * height as usize * 4];
        self.stream.read_exact(&mut rgba)?;
        Ok(Frame {
            width,
            height,
            rgba,
        })
    }
    fn input(&mut self, input: Input) -> Result<()> {
        self.stream.write_all(&encode(&input))?;
        Ok(())
    }
    fn release(&mut self) {
        let _ = self.stream.write_all(&encode(&Input::Release));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inputs_survive_the_socket() {
        let all = [
            Input::Move { x: 0.25, y: 0.75 },
            Input::Button {
                button: Button::Right,
                down: true,
            },
            Input::Key {
                key: Key::Letter('q'),
                down: false,
            },
            Input::Key {
                key: Key::Backspace,
                down: true,
            },
            Input::Text("Hello, world".into()),
            Input::Scroll { lines: -3 },
            Input::Release,
        ];
        for input in all {
            let bytes = encode(&input);
            let mut rest = &bytes[1..];
            let back = decode(bytes[0], &mut rest).unwrap().unwrap();
            assert_eq!(format!("{back:?}"), format!("{input:?}"));
            assert!(rest.is_empty());
        }
        assert!(decode(b'C', &mut &[][..]).unwrap().is_none());
    }
}
