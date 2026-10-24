//! Mac screens through ScreenCaptureKit.
//!
//! Asking the window server for a picture took 17 to 35 ms on the iMacs we
//! tested, and a capture only happened on the next turn of the clock, so a
//! click could wait most of a tenth of a second before anything looked. A
//! stream instead hands over each new screen as soon as it is drawn, already
//! scaled on the GPU, and hands over nothing while the screen is still.
use anyhow::{Context, Result, bail, ensure};
use boundary_session::Frame;
use dispatch2::{DispatchQueue, DispatchQueueAttr};
use objc2::{
    AllocAnyThread, DefinedClass, define_class, msg_send,
    rc::Retained,
    runtime::{NSObject, NSObjectProtocol, ProtocolObject},
};
use objc2_core_media::{CMSampleBuffer, CMTime};
use objc2_core_video::{
    CVPixelBufferGetBaseAddress, CVPixelBufferGetBytesPerRow, CVPixelBufferGetHeight,
    CVPixelBufferGetWidth, CVPixelBufferLockBaseAddress, CVPixelBufferLockFlags,
    CVPixelBufferUnlockBaseAddress, kCVPixelFormatType_32BGRA,
};
use objc2_foundation::{NSArray, NSError};
use objc2_screen_capture_kit::{
    SCContentFilter, SCShareableContent, SCStream, SCStreamConfiguration, SCStreamDelegate,
    SCStreamOutput, SCStreamOutputType,
};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

/// How long a capture waits for a new screen before saying nothing changed.
const WAIT: Duration = Duration::from_millis(8);

#[derive(Default)]
struct Shared {
    latest: Mutex<Latest>,
    ready: Condvar,
}
#[derive(Default)]
struct Latest {
    frame: Option<Frame>,
    stopped: bool,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "BoundaryScreenOutput"]
    #[ivars = Arc<Shared>]
    struct Output;

    unsafe impl NSObjectProtocol for Output {}

    unsafe impl SCStreamOutput for Output {
        #[unsafe(method(stream:didOutputSampleBuffer:ofType:))]
        unsafe fn stream_did_output(
            &self,
            _stream: &SCStream,
            sample: &CMSampleBuffer,
            kind: SCStreamOutputType,
        ) {
            if kind != SCStreamOutputType::Screen {
                return;
            }
            // Frames that only say the screen is still carry no pixels.
            if let Some(frame) = unsafe { copy(sample) } {
                let shared = self.ivars();
                shared.latest.lock().unwrap_or_else(|e| e.into_inner()).frame = Some(frame);
                shared.ready.notify_all();
            }
        }
    }

    unsafe impl SCStreamDelegate for Output {
        #[unsafe(method(stream:didStopWithError:))]
        unsafe fn stream_did_stop(&self, _stream: &SCStream, _error: &NSError) {
            let shared = self.ivars();
            shared.latest.lock().unwrap_or_else(|e| e.into_inner()).stopped = true;
            shared.ready.notify_all();
        }
    }
);

impl Output {
    fn new(shared: Arc<Shared>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(shared);
        unsafe { msg_send![super(this), init] }
    }
}

/// The pixels of one screen sample, as RGBA.
///
/// # Safety
/// `sample` must be a screen sample from ScreenCaptureKit in 32BGRA.
unsafe fn copy(sample: &CMSampleBuffer) -> Option<Frame> {
    let pixels = unsafe { sample.image_buffer() }?;
    unsafe { CVPixelBufferLockBaseAddress(&pixels, CVPixelBufferLockFlags::ReadOnly) };
    let (width, height) = (
        CVPixelBufferGetWidth(&pixels),
        CVPixelBufferGetHeight(&pixels),
    );
    let stride = CVPixelBufferGetBytesPerRow(&pixels);
    let base = CVPixelBufferGetBaseAddress(&pixels) as *const u8;
    let frame = (!base.is_null() && width > 0 && height > 0 && stride >= width * 4).then(|| {
        // SAFETY: the buffer is locked and holds `height` rows of `stride`.
        let data = unsafe { std::slice::from_raw_parts(base, stride * height) };
        let mut rgba = Vec::with_capacity(width * height * 4);
        for row in data.chunks_exact(stride) {
            rgba.extend(
                row[..width * 4]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .flat_map(|p| [p[2], p[1], p[0], 255]),
            );
        }
        Frame {
            width: width as u32,
            height: height as u32,
            rgba,
        }
    });
    unsafe { CVPixelBufferUnlockBaseAddress(&pixels, CVPixelBufferLockFlags::ReadOnly) };
    frame
}

/// An Objective-C object handed from a completion handler to the thread
/// that waits for it.
struct Handed<T>(T);
// SAFETY: the objects passed this way (shareable content, errors) are
// immutable once made and Apple documents them as usable from any thread.
unsafe impl<T> Send for Handed<T> {}

pub(crate) struct Stream {
    stream: Retained<SCStream>,
    _output: Retained<Output>,
    _queue: dispatch2::DispatchRetained<DispatchQueue>,
    shared: Arc<Shared>,
}
// SAFETY: SCStream may be stopped from any thread, and that is all this
// side does with it; the frames cross over through the mutex.
unsafe impl Send for Stream {}

impl Stream {
    /// Stream the display `id`, at no more than `max` pixels across and down.
    pub fn open(id: u32, max: (u32, u32)) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let handler = block2::RcBlock::new(
            move |content: *mut SCShareableContent, error: *mut NSError| {
                let content = unsafe { Retained::retain(content) };
                let _ = tx.send(Handed(content.ok_or_else(|| {
                    let error = unsafe { Retained::retain(error) };
                    error.map_or("Screen capture is not available".into(), |e| {
                        e.localizedDescription().to_string()
                    })
                })));
            },
        );
        unsafe { SCShareableContent::getShareableContentWithCompletionHandler(&handler) };
        let content = rx
            .recv_timeout(Duration::from_secs(5))
            .context("Screen capture did not answer")?
            .0
            .map_err(anyhow::Error::msg)?;
        let displays = unsafe { content.displays() };
        let display = displays
            .iter()
            .find(|d| unsafe { d.displayID() } == id)
            .context("The selected display is not available to capture")?;
        // Points, which is what the screen is drawn at; Retina pixels would
        // only be shrunk again before sending.
        let (w, h) = unsafe { (display.width() as f64, display.height() as f64) };
        ensure!(w > 0.0 && h > 0.0, "The display has no size");
        let scale = (max.0 as f64 / w).min(max.1 as f64 / h).min(1.0);
        let (width, height) = (
            ((w * scale).round() as usize).max(1),
            ((h * scale).round() as usize).max(1),
        );
        let filter = unsafe {
            SCContentFilter::initWithDisplay_excludingWindows(
                SCContentFilter::alloc(),
                &display,
                &NSArray::new(),
            )
        };
        let config = unsafe { SCStreamConfiguration::new() };
        unsafe {
            config.setWidth(width);
            config.setHeight(height);
            config.setMinimumFrameInterval(CMTime::new(1, 60));
            config.setPixelFormat(kCVPixelFormatType_32BGRA);
            // DeskVNC draws its own pointer, which moves with no lag at all.
            config.setShowsCursor(false);
            config.setQueueDepth(3);
        }
        let shared = Arc::new(Shared::default());
        let output = Output::new(shared.clone());
        let delegate = ProtocolObject::<dyn SCStreamDelegate>::from_ref(&*output);
        let stream = unsafe {
            SCStream::initWithFilter_configuration_delegate(
                SCStream::alloc(),
                &filter,
                &config,
                Some(delegate),
            )
        };
        let queue = DispatchQueue::new("boundary.screen", DispatchQueueAttr::SERIAL);
        unsafe {
            stream.addStreamOutput_type_sampleHandlerQueue_error(
                ProtocolObject::from_ref(&*output),
                SCStreamOutputType::Screen,
                Some(&queue),
            )
        }
        .map_err(|e| anyhow::anyhow!("{}", e.localizedDescription()))?;
        let (tx, rx) = mpsc::channel();
        let started = block2::RcBlock::new(move |error: *mut NSError| {
            let error = unsafe { Retained::retain(error) };
            let _ = tx.send(Handed(error.map(|e| e.localizedDescription().to_string())));
        });
        unsafe { stream.startCaptureWithCompletionHandler(Some(&started)) };
        if let Some(error) = rx
            .recv_timeout(Duration::from_secs(5))
            .context("Screen capture did not start")?
            .0
        {
            bail!("Screen capture did not start: {error}");
        }
        let this = Self {
            stream,
            _output: output,
            _queue: queue,
            shared,
        };
        // The first screen comes as the stream starts. A stream that sends
        // nothing at all, as for a session that is not on the display, is no
        // use, and the caller falls back to asking for pictures.
        let latest = this.shared.latest.lock().unwrap_or_else(|e| e.into_inner());
        let (latest, _) = this
            .shared
            .ready
            .wait_timeout_while(latest, Duration::from_secs(2), |l| {
                l.frame.is_none() && !l.stopped
            })
            .unwrap_or_else(|e| e.into_inner());
        ensure!(latest.frame.is_some(), "Screen capture sent no screen");
        drop(latest);
        Ok(this)
    }

    /// The newest screen, if one came since the last call. Errors once the
    /// stream has stopped, such as when the display went away.
    pub fn next(&self) -> Result<Option<Frame>> {
        let latest = self.shared.latest.lock().unwrap_or_else(|e| e.into_inner());
        let (mut latest, _) = self
            .shared
            .ready
            .wait_timeout_while(latest, WAIT, |l| l.frame.is_none() && !l.stopped)
            .unwrap_or_else(|e| e.into_inner());
        ensure!(!latest.stopped, "Screen capture stopped");
        Ok(latest.frame.take())
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        unsafe { self.stream.stopCaptureWithCompletionHandler(None) };
    }
}
