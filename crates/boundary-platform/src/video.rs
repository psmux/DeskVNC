//! H.264 encoders for moving screens (`boundary_session::video`).
//!
//! The platform's hardware encoder where there is one: VideoToolbox on a
//! Mac, a Media Foundation hardware encoder on Windows. Everywhere else,
//! and where the hardware one will not start, OpenH264 in software, built
//! from source with this crate.
use anyhow::{Result, ensure};
use boundary_session::{
    Frame,
    video::{Encoded, Shown, VideoEncoder, VideoEncoders},
};
use openh264::encoder::{
    BitRate, Complexity, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod,
    RateControlMode, UsageType, VuiConfig,
};
use openh264::formats::{RgbaSliceU8, YUVBuffer};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

/// The best encoder this machine has, made for each size of screen.
pub fn encoders() -> VideoEncoders {
    Arc::new(best)
}

/// Only the software encoder, to compare against the hardware one.
pub fn software() -> VideoEncoders {
    Arc::new(|width, height| Shadowed::wrap(Box::new(OpenH264::new(width, height)?), false))
}

fn best(width: u32, height: u32) -> Result<Box<dyn VideoEncoder>> {
    // VideoToolbox is told its pictures are BT.709; the others convert to
    // BT.601 themselves.
    #[cfg(target_os = "macos")]
    if let Ok(encoder) = crate::vt::VideoToolbox::new(width, height) {
        return Shadowed::wrap(Box::new(encoder), true);
    }
    #[cfg(windows)]
    if let Ok(encoder) = crate::mf::MediaFoundation::new(width, height) {
        return Shadowed::wrap(Box::new(encoder), false);
    }
    Shadowed::wrap(Box::new(OpenH264::new(width, height)?), false)
}

/// How long to wait for the shadow decoder to catch up when the screen
/// settles, before sending the whole screen instead.
const SHADOW_WAIT: Duration = Duration::from_millis(50);
/// More pictures than this still to decode, and the decoder is not waited for.
const SHADOW_BEHIND: u64 = 2;

/// An encoder with a decoder of its own output beside it, on its own
/// thread, so that when the screen settles the host knows what the helper's
/// picture looks like and sends sharp tiles only where it is visibly wrong.
/// Decoding a 1920 by 1200 picture takes a few milliseconds of one core,
/// off the path a picture takes to the helper.
struct Shadowed {
    inner: Box<dyn VideoEncoder>,
    bt709: bool,
    pictures: Option<mpsc::Sender<Vec<u8>>>,
    state: Arc<(Mutex<Mirror>, Condvar)>,
    sent: u64,
    thread: Option<std::thread::JoinHandle<()>>,
}
#[derive(Default)]
struct Mirror {
    decoded: u64,
    luma: Vec<u8>,
    stride: usize,
    u: Vec<u8>,
    v: Vec<u8>,
    chroma_stride: usize,
    /// The decoder lost its place, until the next keyframe.
    lost: bool,
}
impl Shadowed {
    fn wrap(inner: Box<dyn VideoEncoder>, bt709: bool) -> Result<Box<dyn VideoEncoder>> {
        let (pictures, queue) = mpsc::channel::<Vec<u8>>();
        let state = Arc::new((Mutex::new(Mirror::default()), Condvar::new()));
        let shared = state.clone();
        let thread = std::thread::Builder::new()
            .name("boundary-shadow-decoder".into())
            .spawn(move || shadow(queue, &shared))?;
        Ok(Box::new(Self {
            inner,
            bt709,
            pictures: Some(pictures),
            state,
            sent: 0,
            thread: Some(thread),
        }))
    }
}
fn shadow(queue: mpsc::Receiver<Vec<u8>>, state: &(Mutex<Mirror>, Condvar)) {
    let mut decoder = openh264::decoder::Decoder::new().ok();
    let mut waiting = std::collections::VecDeque::new();
    loop {
        if waiting.is_empty() {
            match queue.recv() {
                Ok(picture) => waiting.push_back(picture),
                Err(_) => return,
            }
        }
        waiting.extend(queue.try_iter());
        let Some(picture) = waiting.pop_front() else {
            continue;
        };
        // Only the newest picture is ever compared with, so the planes of
        // one with others queued behind it are not copied out.
        let newest = waiting.is_empty();
        // A NAL unit at a time: OpenH264 refuses a picture of several
        // slices handed over at once.
        let mut luma = None;
        let mut failed = decoder.is_none();
        if let Some(decoder) = decoder.as_mut() {
            for nal in openh264::nal_units(&picture) {
                match decoder.decode(nal) {
                    Ok(Some(_)) if !newest => {}
                    Ok(Some(yuv)) => {
                        use openh264::formats::YUVSource;
                        let (_, height) = yuv.dimensions();
                        let (stride, chroma, _) = yuv.strides();
                        let half = height.div_ceil(2);
                        luma = Some((
                            yuv.y()[..stride * height].to_vec(),
                            stride,
                            yuv.u()[..chroma * half].to_vec(),
                            yuv.v()[..chroma * half].to_vec(),
                            chroma,
                        ));
                    }
                    Ok(None) => {}
                    Err(_) => failed = true,
                }
            }
        }
        let keyframe = openh264::nal_units(&picture).any(|nal| {
            nal.get(if nal[2] == 1 { 3 } else { 4 })
                .is_some_and(|b| b & 31 == 5)
        });
        let (lock, ready) = state;
        let mut mirror = lock.lock().unwrap_or_else(|e| e.into_inner());
        match luma {
            None if !failed && !newest => {}
            Some((luma, stride, u, v, chroma)) if !failed => {
                mirror.luma = luma;
                mirror.stride = stride;
                mirror.u = u;
                mirror.v = v;
                mirror.chroma_stride = chroma;
                if keyframe {
                    mirror.lost = false;
                }
            }
            _ => mirror.lost = true,
        }
        mirror.decoded += 1;
        ready.notify_all();
    }
}
impl Drop for Shadowed {
    fn drop(&mut self) {
        self.pictures.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl VideoEncoder for Shadowed {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn set_rate(&mut self, bits_per_second: u32, frames_per_second: u32) {
        self.inner.set_rate(bits_per_second, frames_per_second);
    }
    fn encode(&mut self, frame: &Frame, keyframe: bool) -> Result<Encoded> {
        let encoded = self.inner.encode(frame, keyframe)?;
        if !encoded.data.is_empty()
            && let Some(pictures) = &self.pictures
            && pictures.send(encoded.data.clone()).is_ok()
        {
            self.sent += 1;
        }
        Ok(encoded)
    }
    fn shown(&mut self) -> Option<Shown> {
        let (lock, ready) = &*self.state;
        let mirror = lock.lock().unwrap_or_else(|e| e.into_inner());
        // A decoder more than a couple of pictures behind is slower than the
        // encoder, as OpenH264 is behind VideoToolbox at 60 screens a second
        // of 1920 by 1200 on an Intel i9: waiting for it only delays the
        // whole screen the caller sends instead.
        if self.sent - mirror.decoded > SHADOW_BEHIND {
            return None;
        }
        let (mirror, _) = ready
            .wait_timeout_while(mirror, SHADOW_WAIT, |m| m.decoded < self.sent)
            .unwrap_or_else(|e| e.into_inner());
        (mirror.decoded == self.sent && !mirror.lost && !mirror.luma.is_empty()).then(|| Shown {
            luma: mirror.luma.clone(),
            stride: mirror.stride,
            u: mirror.u.clone(),
            v: mirror.v.clone(),
            chroma_stride: mirror.chroma_stride,
            bt709: self.bt709,
        })
    }
}

/// Cisco's OpenH264, in software. It makes Constrained Baseline, which
/// every decoder takes.
pub struct OpenH264 {
    encoder: Encoder,
    width: u32,
    height: u32,
    /// The screen padded to even sides, which 4:2:0 needs, when it is odd.
    padded: Vec<u8>,
    yuv: YUVBuffer,
    /// OpenH264 starts with a keyframe by itself. Asking for one before
    /// its first picture made the second picture a keyframe too.
    started: bool,
    rate: Option<(u32, u32)>,
    started_at: std::time::Instant,
}
// SAFETY: the encoder holds a pointer to its C state, which is used from one
// thread at a time (`&mut self`) and tied to no thread.
unsafe impl Send for OpenH264 {}

impl OpenH264 {
    pub fn new(width: u32, height: u32) -> Result<Self> {
        let (w, h) = (width.next_multiple_of(2), height.next_multiple_of(2));
        ensure!(w <= 3840 && h <= 2160, "Too large for OpenH264");
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(4));
        let config = EncoderConfig::new()
            // Its screen content mode made every picture a keyframe.
            .usage_type(UsageType::CameraVideoRealTime)
            .rate_control_mode(RateControlMode::Bitrate)
            .bitrate(BitRate::from_bps(4_000_000))
            .max_frame_rate(FrameRate::from_hz(30.0))
            // The sender already holds back screens the link has no room
            // for. OpenH264 still keeps near its rate by its quantizer.
            .skip_frames(false)
            // Scrolling looks like a new scene to it, and a keyframe for
            // each is the most expensive thing it could send.
            .scene_change_detect(false)
            .complexity(Complexity::Low)
            // Keyframes come when video starts, and at most this often.
            .intra_frame_period(IntraFramePeriod::from_num_frames(600))
            .num_threads(threads as u16)
            // The colours `YUVBuffer` converts with: BT.601, limited range.
            .vui(VuiConfig::bt601());
        let encoder = Encoder::with_api_config(openh264::OpenH264API::from_source(), config)?;
        Ok(Self {
            encoder,
            width,
            height,
            padded: Vec::new(),
            yuv: YUVBuffer::new(w as usize, h as usize),
            started: false,
            rate: None,
            started_at: std::time::Instant::now(),
        })
    }
}

impl VideoEncoder for OpenH264 {
    fn name(&self) -> &str {
        "OpenH264 (software)"
    }
    fn set_rate(&mut self, bits_per_second: u32, frames_per_second: u32) {
        // OpenH264 sets itself up on its first picture, and options given
        // before that are applied then.
        if !self.started {
            self.rate = Some((bits_per_second, frames_per_second));
            return;
        }
        let mut bitrate = openh264_sys2::TagBitrateInfo {
            iLayer: openh264_sys2::SPATIAL_LAYER_ALL,
            iBitrate: bits_per_second as i32,
        };
        let mut rate = frames_per_second as f32;
        // SAFETY: both options take a pointer to the type given, which lives
        // for the call; neither changes anything the wrapper relies on.
        unsafe {
            let api = self.encoder.raw_api();
            api.set_option(
                openh264_sys2::ENCODER_OPTION_BITRATE,
                (&mut bitrate as *mut openh264_sys2::TagBitrateInfo).cast(),
            );
            api.set_option(
                openh264_sys2::ENCODER_OPTION_FRAME_RATE,
                (&mut rate as *mut f32).cast(),
            );
        }
    }
    fn encode(&mut self, frame: &Frame, keyframe: bool) -> Result<Encoded> {
        ensure!(
            frame.width == self.width && frame.height == self.height,
            "The screen changed size under the encoder"
        );
        let (w, h) = (
            self.width.next_multiple_of(2),
            self.height.next_multiple_of(2),
        );
        let rgba: &[u8] = if (w, h) == (self.width, self.height) {
            &frame.rgba
        } else {
            // Repeat the last column and row.
            self.padded.clear();
            let row = self.width as usize * 4;
            for line in frame.rgba.chunks_exact(row) {
                self.padded.extend_from_slice(line);
                if w != self.width {
                    self.padded.extend_from_slice(&line[row - 4..]);
                }
            }
            if h != self.height {
                let last = self.padded.len() - w as usize * 4;
                self.padded.extend_from_within(last..);
            }
            &self.padded
        };
        self.yuv
            .read_rgba8(RgbaSliceU8::new(rgba, (w as usize, h as usize)));
        if keyframe && self.started {
            self.encoder.force_intra_frame();
        }
        // Its rate control counts time by these, so they are the real clock.
        let at = openh264::Timestamp::from_millis(self.started_at.elapsed().as_millis() as u64);
        let stream = self.encoder.encode_at(&self.yuv, at)?;
        let keyframe = matches!(stream.frame_type(), FrameType::IDR);
        let data = stream.to_vec();
        if !self.started {
            self.started = true;
            if let Some((bits, frames)) = self.rate.take() {
                self.set_rate(bits, frames);
            }
        }
        Ok(Encoded { data, keyframe })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(width: u32, height: u32, shift: u32) -> Frame {
        Frame {
            width,
            height,
            rgba: (0..width * height)
                .flat_map(|i| {
                    let (x, y) = ((i % width + shift) % width, i / width);
                    let v = if (y % 18) < 11 && (x * 31 + y * 7) % 13 < 6 {
                        40
                    } else {
                        230
                    };
                    [v, v, (x % 256) as u8, 255]
                })
                .collect(),
        }
    }

    /// Encode a moving screen with every encoder this machine has and
    /// decode it back, one picture in and the same picture out, starting
    /// with a keyframe.
    #[test]
    fn encoders_make_decodable_low_latency_h264() {
        let makers: Vec<VideoEncoders> = vec![software(), encoders()];
        for make in makers {
            for (width, height) in [(1280, 720), (641, 361)] {
                let mut encoder = make(width, height).unwrap();
                encoder.set_rate(4_000_000, 30);
                let mut decoder = openh264::decoder::Decoder::new().unwrap();
                let mut sizes = Vec::new();
                let mut times = Vec::new();
                for n in 0..10 {
                    let frame = screen(width, height, n * 6);
                    let t = std::time::Instant::now();
                    let unit = encoder.encode(&frame, n == 0).unwrap();
                    times.push(t.elapsed().as_micros() as u64 / 100);
                    // The first is a keyframe. The Intel encoder may add one of its own
                    // after it, which is honest, so later ones are not checked.
                    assert!(
                        n > 0 || unit.keyframe,
                        "{} started without a keyframe",
                        encoder.name()
                    );
                    sizes.push(unit.data.len());
                    if unit.data.is_empty() {
                        // Skipped to keep to the rate, which only OpenH264 does.
                        assert!(n > 0, "{} skipped its keyframe", encoder.name());
                        continue;
                    }
                    assert!(
                        unit.data.starts_with(&[0, 0, 0, 1]) || unit.data.starts_with(&[0, 0, 1])
                    );
                    // One picture in, the same picture out: no frame held back.
                    let picture = decoder.decode(&unit.data).unwrap();
                    let picture =
                        picture.unwrap_or_else(|| panic!("{} held a frame back", encoder.name()));
                    use openh264::formats::YUVSource;
                    let (dw, dh) = picture.dimensions();
                    assert!(dw >= width as usize && dh >= height as usize);
                }
                assert!(
                    sizes.iter().filter(|s| **s > 0).count() >= 7,
                    "{} skipped too much: {sizes:?}",
                    encoder.name()
                );
                // A keyframe on demand, as when video starts again.
                let unit = encoder.encode(&screen(width, height, 3), true).unwrap();
                assert!(unit.keyframe, "{}", encoder.name());
                eprintln!(
                    "{} {width}x{height}: bytes {sizes:?} tenths of ms {times:?}",
                    encoder.name()
                );
            }
        }
    }
}
