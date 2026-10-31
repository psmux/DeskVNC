//! H.264 decoded for the agent's mirror, so an agent can see a screen that
//! is moving.
//!
//! The window decodes H.264 itself, in the webview, and the mirror beside it
//! could not, so every region video passed over was stale and a read of it
//! was refused (`00 R6`). On VNC the mirror turns H.264 off for the session.
//! Boundary has no such switch: its computer picks video by itself whenever
//! much of the screen moves, which on a busy Mac is most of the time. So an
//! agent on a Boundary session was refused screen reads, and the typing and
//! clicks behind them, for minutes at a stretch.
//!
//! Here the video is decoded a second time, for the mirror only, and only
//! while a session has one. It runs on a thread of its own per session, so a
//! picture a person is waiting for never waits for a decode an agent wants.
//! Updates after the first video one go through the same thread, in order,
//! because a tile drawn after a picture must land after it.
//!
//! A picture that does not decode, because the decoder joined a run after
//! its keyframe or fell too far behind, goes to the mirror as the H.264 it
//! was, which marks its region stale exactly as before. Nothing is guessed.

use std::collections::HashMap;
use std::sync::{mpsc, Arc, Weak};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use vnc_core::{DecodedRect, RectPayload};

use super::mirror::Mirrors;

/// How many updates may wait for one session's decoder. Past this the
/// decoder is behind for good, so what waits is handed on undecoded and the
/// decoder starts again at the next keyframe.
const BACKLOG: u64 = 48;

/// The longest a read waits for the decoder to apply what came before it.
/// A picture takes a few milliseconds, so this is only reached when the
/// machine is starved, and then the read goes ahead on what is there.
const CATCH_UP: Duration = Duration::from_millis(400);

enum Job {
    Feed(Vec<DecodedRect>),
    /// Fed as it is, because the decoder could not keep up.
    Skip(Vec<DecodedRect>),
    Resize(u16, u16),
}

/// Jobs queued and jobs applied, so a read can wait for the ones before it.
#[derive(Default)]
struct Progress {
    counts: Mutex<(u64, u64)>,
    applied: Condvar,
}

struct Worker {
    jobs: mpsc::Sender<Job>,
    progress: Arc<Progress>,
}

impl Worker {
    fn send(&self, job: Job) -> Result<(), Job> {
        self.progress.counts.lock().0 += 1;
        self.jobs.send(job).map_err(|mpsc::SendError(job)| {
            self.progress.counts.lock().0 -= 1;
            job
        })
    }
}

/// One decoding thread per session whose mirror has seen video.
#[derive(Default)]
pub struct Video {
    workers: Mutex<HashMap<String, Worker>>,
}

/// Whether an update carries a picture to decode.
pub fn has_video(rects: &[DecodedRect]) -> bool {
    rects
        .iter()
        .any(|r| matches!(&r.payload, RectPayload::H264 { data, .. } if !data.is_empty()))
}

impl Video {
    /// Whether this session's updates go through its decoding thread.
    pub fn carries(&self, session_id: &str) -> bool {
        self.workers.lock().contains_key(session_id)
    }

    /// Queue an update for the session's decoding thread, starting one when
    /// there is none.
    pub fn feed(&self, mirrors: &Arc<Mirrors>, session_id: &str, rects: Vec<DecodedRect>) {
        let mut workers = self.workers.lock();
        let worker = workers
            .entry(session_id.to_string())
            .or_insert_with(|| spawn(Arc::downgrade(mirrors), session_id.to_string()));
        let (queued, applied) = *worker.progress.counts.lock();
        let job = if queued - applied >= BACKLOG {
            Job::Skip(rects)
        } else {
            Job::Feed(rects)
        };
        if let Err(Job::Feed(rects) | Job::Skip(rects)) = worker.send(job) {
            // The thread is gone, so the mirror is fed here as it was before.
            workers.remove(session_id);
            drop(workers);
            mirrors.feed(session_id, &rects, super::now());
        }
    }

    /// Resize the mirror behind whatever is already queued for it. False
    /// when the session has no decoding thread, so the caller resizes it.
    pub fn resize(&self, session_id: &str, width: u16, height: u16) -> bool {
        let workers = self.workers.lock();
        workers
            .get(session_id)
            .is_some_and(|worker| worker.send(Job::Resize(width, height)).is_ok())
    }

    /// Wait until what was queued for this session before now has reached
    /// its mirror, so a read or a typing check sees every update that came
    /// before it, as it did when the mirror was fed directly.
    pub fn caught_up(&self, session_id: &str) {
        let progress = match self.workers.lock().get(session_id) {
            Some(worker) => worker.progress.clone(),
            None => return,
        };
        let deadline = Instant::now() + CATCH_UP;
        let mut counts = progress.counts.lock();
        let target = counts.0;
        while counts.1 < target {
            if progress
                .applied
                .wait_until(&mut counts, deadline)
                .timed_out()
            {
                tracing::info!(session = %session_id, behind = target - counts.1, "read before the mirror's video decoder caught up");
                return;
            }
        }
    }

    /// Stop the session's decoding thread. Whatever it has queued still
    /// reaches the mirror, if the mirror is still there.
    pub fn forget(&self, session_id: &str) {
        self.workers.lock().remove(session_id);
    }

    /// Stop every decoding thread.
    pub fn forget_all(&self) {
        self.workers.lock().clear();
    }
}

fn spawn(mirrors: Weak<Mirrors>, session_id: String) -> Worker {
    let (jobs, queue) = mpsc::channel::<Job>();
    let progress = Arc::new(Progress::default());
    let done = progress.clone();
    let spawned = std::thread::Builder::new()
        .name("mirror-video".into())
        .spawn(move || {
            let mut decoder = Decoders::default();
            while let Ok(job) = queue.recv() {
                let Some(mirrors) = mirrors.upgrade() else {
                    return;
                };
                match job {
                    Job::Feed(rects) => {
                        let rects = decoder.decode(rects);
                        mirrors.feed(&session_id, &rects, super::now());
                    }
                    Job::Skip(rects) => {
                        decoder.lost();
                        mirrors.feed(&session_id, &rects, super::now());
                    }
                    Job::Resize(width, height) => mirrors.resize(&session_id, width, height),
                }
                done.counts.lock().1 += 1;
                done.applied.notify_all();
            }
        });
    if let Err(error) = spawned {
        // The receiver went with the closure, so the first send fails and
        // the session goes back to feeding its mirror directly.
        tracing::warn!(%error, "could not start the mirror's video decoder");
    }
    Worker { jobs, progress }
}

/// The decoder for each H.264 context, as the window keeps one per context.
#[derive(Default)]
struct Decoders {
    contexts: HashMap<u32, Decoder>,
    /// A picture was not decoded, so the ones after it cannot be until the
    /// next keyframe.
    broken: bool,
}

impl Decoders {
    fn lost(&mut self) {
        self.contexts.clear();
        self.broken = true;
    }

    /// The same update with every picture that decoded turned into pixels.
    fn decode(&mut self, rects: Vec<DecodedRect>) -> Vec<DecodedRect> {
        rects
            .into_iter()
            .map(|rect| {
                let RectPayload::H264 {
                    data,
                    flags,
                    context_id,
                    reset,
                    keyframe,
                } = &rect.payload
                else {
                    return rect;
                };
                // The flags as RFB numbers them: bit 1 resets every context,
                // bit 0 this one.
                if flags & 2 != 0 {
                    self.contexts.clear();
                }
                if *reset || flags & 1 != 0 {
                    self.contexts.remove(context_id);
                }
                if data.is_empty() {
                    return rect;
                }
                if *keyframe {
                    self.broken = false;
                }
                if self.broken {
                    return rect;
                }
                let (width, height) = (u32::from(rect.rect.width), u32::from(rect.rect.height));
                let picture = self
                    .contexts
                    .entry(*context_id)
                    .or_insert_with(Decoder::new)
                    .decode(data, width, height);
                match picture {
                    Some(rgba) => DecodedRect {
                        rect: rect.rect,
                        payload: RectPayload::Rgba(rgba),
                    },
                    None => {
                        // Every picture after this one refers back to it.
                        self.lost();
                        rect
                    }
                }
            })
            .collect()
    }
}

/// One H.264 stream: VideoToolbox on a Mac, which reads the High profile
/// pictures Apple's encoders make and OpenH264 stops on, and OpenH264
/// everywhere else.
struct Decoder {
    #[cfg(target_os = "macos")]
    vt: Option<boundary_platform::video::VtDecoder>,
    software: Option<openh264::decoder::Decoder>,
}

impl Decoder {
    fn new() -> Self {
        #[cfg(target_os = "macos")]
        {
            let vt = boundary_platform::video::VtDecoder::new().ok();
            let software = if vt.is_some() {
                None
            } else {
                openh264::decoder::Decoder::new().ok()
            };
            Decoder { vt, software }
        }
        #[cfg(not(target_os = "macos"))]
        Decoder {
            software: openh264::decoder::Decoder::new().ok(),
        }
    }

    /// RGBA for a picture of `width` by `height`, or None when it did not
    /// decode or decoded to another size.
    fn decode(&mut self, data: &[u8], width: u32, height: u32) -> Option<Vec<u8>> {
        #[cfg(target_os = "macos")]
        if let Some(vt) = self.vt.as_mut() {
            let planes = vt.decode(data).ok()??;
            return Some(bt709(&planes, width as usize, height as usize));
        }
        use openh264::formats::YUVSource;
        let yuv = self.software.as_mut()?.decode(data).ok()??;
        if yuv.dimensions() != (width as usize, height as usize) {
            return None;
        }
        let mut rgba = vec![0u8; width as usize * height as usize * 4];
        yuv.write_rgba8(&mut rgba);
        Some(rgba)
    }
}

/// Decoded planes to RGBA, BT.709 limited range, as VideoToolbox on the
/// computer tags its pictures. Fixed point, so a whole screen takes a few
/// milliseconds rather than tens.
#[cfg(target_os = "macos")]
fn bt709(planes: &boundary_platform::video::Planes, width: usize, height: usize) -> Vec<u8> {
    let mut out = vec![0u8; width * height * 4];
    for y in 0..height {
        let luma = planes.luma.get(y * planes.stride..).unwrap_or(&[]);
        let row = (y / 2) * planes.chroma_stride;
        let u = planes.u.get(row..).unwrap_or(&[]);
        let v = planes.v.get(row..).unwrap_or(&[]);
        let line = &mut out[y * width * 4..(y + 1) * width * 4];
        for (x, pixel) in line.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let l = (i32::from(luma.get(x).copied().unwrap_or(16)) - 16) * 298;
            let cb = i32::from(u.get(x / 2).copied().unwrap_or(128)) - 128;
            let cr = i32::from(v.get(x / 2).copied().unwrap_or(128)) - 128;
            let clamp = |n: i32| ((n + 128) >> 8).clamp(0, 255) as u8;
            pixel[0] = clamp(l + 459 * cr);
            pixel[1] = clamp(l - 55 * cb - 136 * cr);
            pixel[2] = clamp(l + 541 * cb);
            pixel[3] = 255;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vnc_core::Rect;

    fn picture(keyframe: bool, data: Vec<u8>) -> DecodedRect {
        DecodedRect {
            rect: Rect::new(0, 0, 64, 48),
            payload: RectPayload::H264 {
                data,
                flags: 0,
                context_id: 0,
                reset: keyframe,
                keyframe,
            },
        }
    }

    /// A picture that does not decode stays H.264, so the mirror marks its
    /// region stale, and so do the ones after it until a keyframe.
    #[test]
    fn what_does_not_decode_is_left_for_the_mirror_to_mark_stale() {
        let mut decoders = Decoders::default();
        let out = decoders.decode(vec![picture(false, vec![0, 0, 0, 1, 0x41, 1, 2, 3])]);
        assert!(matches!(out[0].payload, RectPayload::H264 { .. }));
        assert!(decoders.broken);
        let tile = DecodedRect {
            rect: Rect::new(0, 0, 1, 1),
            payload: RectPayload::Rgba(vec![1, 2, 3, 255]),
        };
        let out = decoders.decode(vec![tile]);
        assert!(matches!(out[0].payload, RectPayload::Rgba(_)));
    }

    /// Pictures from the encoder DeskVNC Support uses come out as pixels of
    /// the colour that went in.
    #[test]
    fn a_picture_decodes_to_the_colour_it_was() {
        let (width, height) = (64u32, 48u32);
        let mut encoder =
            boundary_platform::video::OpenH264::new(width, height).expect("an encoder");
        let frame = boundary_session::Frame {
            width,
            height,
            rgba: [200u8, 40, 40, 255].repeat((width * height) as usize),
        };
        use boundary_session::video::VideoEncoder;
        let encoded = encoder.encode(&frame, true).expect("encodes");
        let mut decoders = Decoders::default();
        let out = decoders.decode(vec![picture(true, encoded.data)]);
        let RectPayload::Rgba(rgba) = &out[0].payload else {
            panic!("the keyframe did not decode");
        };
        let middle = ((height / 2 * width + width / 2) * 4) as usize;
        let (r, g, b) = (rgba[middle], rgba[middle + 1], rgba[middle + 2]);
        assert!(
            r.abs_diff(200) < 24 && g.abs_diff(40) < 24 && b.abs_diff(40) < 24,
            "{r} {g} {b}"
        );
    }
}
