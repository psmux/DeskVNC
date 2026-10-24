//! H.264 on a Mac through VideoToolbox, in hardware where the Mac has it.
//!
//! Every VideoToolbox and CoreMedia function and constant is looked up by
//! name when first used rather than linked. An earlier ScreenCaptureKit
//! binding linked a CoreMedia symbol that resolved to the Swift overlay on
//! Intel Macs and crashed there (see `sck::image_buffer_fn`), so this file
//! takes no chance with the same frameworks: a symbol that is missing makes
//! the encoder unavailable, and the session sends tiles instead.
use anyhow::{Context, Result, bail, ensure};
use boundary_session::{
    Frame,
    video::{Encoded, VideoEncoder},
};
use std::ffi::{CStr, c_void};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFAllocatorRef = *const c_void;
type OSStatus = i32;

#[repr(C)]
#[derive(Clone, Copy)]
struct CMTime {
    value: i64,
    timescale: i32,
    flags: u32,
    epoch: i64,
}
const INVALID_TIME: CMTime = CMTime {
    value: 0,
    timescale: 0,
    flags: 0,
    epoch: 0,
};

/// `'avc1'`
const CODEC_H264: u32 = 0x6176_6331;
/// `'BGRA'`
const PIXEL_BGRA: u32 = 0x4247_5241;
const CF_NUMBER_SINT32: isize = 3;
const CF_NUMBER_FLOAT64: isize = 6;

type OutputCallback =
    unsafe extern "C" fn(*mut c_void, *mut c_void, OSStatus, u32, *const c_void);

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFBooleanTrue: CFTypeRef;
    static kCFBooleanFalse: CFTypeRef;
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
    static kCFTypeArrayCallBacks: c_void;
    fn CFRelease(value: CFTypeRef);
    fn CFNumberCreate(allocator: CFAllocatorRef, kind: isize, value: *const c_void) -> CFTypeRef;
    fn CFDictionaryCreate(
        allocator: CFAllocatorRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFDictionaryRef;
    fn CFDictionaryGetValue(dictionary: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;
    fn CFArrayCreate(
        allocator: CFAllocatorRef,
        values: *const CFTypeRef,
        count: isize,
        callbacks: *const c_void,
    ) -> CFTypeRef;
    fn CFArrayGetCount(array: CFTypeRef) -> isize;
    fn CFArrayGetValueAtIndex(array: CFTypeRef, index: isize) -> CFTypeRef;
    fn CFBooleanGetValue(boolean: CFTypeRef) -> u8;
}

/// The functions and constants used here, found once.
struct Api {
    create: unsafe extern "C" fn(
        CFAllocatorRef,
        i32,
        i32,
        u32,
        CFDictionaryRef,
        CFDictionaryRef,
        CFAllocatorRef,
        Option<OutputCallback>,
        *mut c_void,
        *mut *mut c_void,
    ) -> OSStatus,
    set_property: unsafe extern "C" fn(*mut c_void, CFStringRef, CFTypeRef) -> OSStatus,
    copy_property:
        unsafe extern "C" fn(*mut c_void, CFStringRef, CFAllocatorRef, *mut CFTypeRef) -> OSStatus,
    prepare: unsafe extern "C" fn(*mut c_void) -> OSStatus,
    encode_frame: unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        CMTime,
        CMTime,
        CFDictionaryRef,
        *mut c_void,
        *mut u32,
    ) -> OSStatus,
    complete: unsafe extern "C" fn(*mut c_void, CMTime) -> OSStatus,
    invalidate: unsafe extern "C" fn(*mut c_void),
    pool: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    pool_buffer: unsafe extern "C" fn(CFAllocatorRef, *mut c_void, *mut *mut c_void) -> i32,
    lock: unsafe extern "C" fn(*mut c_void, u64) -> i32,
    unlock: unsafe extern "C" fn(*mut c_void, u64) -> i32,
    base: unsafe extern "C" fn(*mut c_void) -> *mut u8,
    stride: unsafe extern "C" fn(*mut c_void) -> usize,
    data_buffer: unsafe extern "C" fn(*const c_void) -> *mut c_void,
    data_length: unsafe extern "C" fn(*mut c_void) -> usize,
    copy_bytes: unsafe extern "C" fn(*mut c_void, usize, usize, *mut u8) -> OSStatus,
    format: unsafe extern "C" fn(*const c_void) -> *const c_void,
    parameter_set: unsafe extern "C" fn(
        *const c_void,
        usize,
        *mut *const u8,
        *mut usize,
        *mut usize,
        *mut i32,
    ) -> OSStatus,
    attachments: unsafe extern "C" fn(*const c_void, u8) -> CFTypeRef,
    keys: Keys,
}
/// Constant names, each a `CFStringRef` VideoToolbox, CoreMedia or
/// CoreVideo exports. Optional ones are newer than some Macs.
struct Keys {
    real_time: CFStringRef,
    allow_reordering: CFStringRef,
    max_delay: Option<CFStringRef>,
    average_bit_rate: CFStringRef,
    data_rate_limits: Option<CFStringRef>,
    expected_frame_rate: Option<CFStringRef>,
    max_key_interval_duration: Option<CFStringRef>,
    profile_level: CFStringRef,
    profile_main: CFStringRef,
    profile_constrained_high: Option<CFStringRef>,
    force_key_frame: CFStringRef,
    enable_hardware: Option<CFStringRef>,
    low_latency: Option<CFStringRef>,
    using_hardware: Option<CFStringRef>,
    not_sync: CFStringRef,
    pixel_format: CFStringRef,
    width: CFStringRef,
    height: CFStringRef,
    color: Option<[CFStringRef; 6]>,
}
// SAFETY: the pointers are immutable, process wide constants and functions.
unsafe impl Send for Api {}
unsafe impl Sync for Api {}

fn open(path: &CStr) -> *mut c_void {
    // SAFETY: a system framework path; RTLD_LAZY loads it once.
    unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_LAZY) }
}
fn symbol(library: *mut c_void, name: &CStr) -> Option<*mut c_void> {
    if library.is_null() {
        return None;
    }
    // SAFETY: looking up a name in a library that is open.
    let found = unsafe { libc::dlsym(library, name.as_ptr()) };
    (!found.is_null()).then_some(found)
}
/// A `CFStringRef` constant: the symbol is the address of the variable.
fn constant(library: *mut c_void, name: &CStr) -> Option<CFStringRef> {
    // SAFETY: the symbol is a `const CFStringRef` variable.
    symbol(library, name).map(|p| unsafe { *(p as *const CFStringRef) })
}

fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        let vt = open(c"/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox");
        let cm = open(c"/System/Library/Frameworks/CoreMedia.framework/CoreMedia");
        let cv = open(c"/System/Library/Frameworks/CoreVideo.framework/CoreVideo");
        macro_rules! function {
            ($lib:expr, $name:literal) => {
                // SAFETY: each symbol has the C signature of the field it
                // fills, as declared in the framework headers.
                unsafe { std::mem::transmute::<*mut c_void, _>(symbol($lib, $name)?) }
            };
        }
        let color = (|| {
            Some([
                constant(vt, c"kVTCompressionPropertyKey_ColorPrimaries")?,
                constant(cv, c"kCVImageBufferColorPrimaries_ITU_R_709_2")?,
                constant(vt, c"kVTCompressionPropertyKey_TransferFunction")?,
                constant(cv, c"kCVImageBufferTransferFunction_ITU_R_709_2")?,
                constant(vt, c"kVTCompressionPropertyKey_YCbCrMatrix")?,
                constant(cv, c"kCVImageBufferYCbCrMatrix_ITU_R_709_2")?,
            ])
        })();
        Some(Api {
            create: function!(vt, c"VTCompressionSessionCreate"),
            set_property: function!(vt, c"VTSessionSetProperty"),
            copy_property: function!(vt, c"VTSessionCopyProperty"),
            prepare: function!(vt, c"VTCompressionSessionPrepareToEncodeFrames"),
            encode_frame: function!(vt, c"VTCompressionSessionEncodeFrame"),
            complete: function!(vt, c"VTCompressionSessionCompleteFrames"),
            invalidate: function!(vt, c"VTCompressionSessionInvalidate"),
            pool: function!(vt, c"VTCompressionSessionGetPixelBufferPool"),
            pool_buffer: function!(cv, c"CVPixelBufferPoolCreatePixelBuffer"),
            lock: function!(cv, c"CVPixelBufferLockBaseAddress"),
            unlock: function!(cv, c"CVPixelBufferUnlockBaseAddress"),
            base: function!(cv, c"CVPixelBufferGetBaseAddress"),
            stride: function!(cv, c"CVPixelBufferGetBytesPerRow"),
            data_buffer: function!(cm, c"CMSampleBufferGetDataBuffer"),
            data_length: function!(cm, c"CMBlockBufferGetDataLength"),
            copy_bytes: function!(cm, c"CMBlockBufferCopyDataBytes"),
            format: function!(cm, c"CMSampleBufferGetFormatDescription"),
            parameter_set: function!(cm, c"CMVideoFormatDescriptionGetH264ParameterSetAtIndex"),
            attachments: function!(cm, c"CMSampleBufferGetSampleAttachmentsArray"),
            keys: Keys {
                real_time: constant(vt, c"kVTCompressionPropertyKey_RealTime")?,
                allow_reordering: constant(vt, c"kVTCompressionPropertyKey_AllowFrameReordering")?,
                max_delay: constant(vt, c"kVTCompressionPropertyKey_MaxFrameDelayCount"),
                average_bit_rate: constant(vt, c"kVTCompressionPropertyKey_AverageBitRate")?,
                data_rate_limits: constant(vt, c"kVTCompressionPropertyKey_DataRateLimits"),
                expected_frame_rate: constant(vt, c"kVTCompressionPropertyKey_ExpectedFrameRate"),
                max_key_interval_duration: constant(
                    vt,
                    c"kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration",
                ),
                profile_level: constant(vt, c"kVTCompressionPropertyKey_ProfileLevel")?,
                profile_main: constant(vt, c"kVTProfileLevel_H264_Main_AutoLevel")?,
                profile_constrained_high: constant(
                    vt,
                    c"kVTProfileLevel_H264_ConstrainedHigh_AutoLevel",
                ),
                force_key_frame: constant(vt, c"kVTEncodeFrameOptionKey_ForceKeyFrame")?,
                enable_hardware: constant(
                    vt,
                    c"kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder",
                ),
                low_latency: constant(
                    vt,
                    c"kVTVideoEncoderSpecification_EnableLowLatencyRateControl",
                ),
                using_hardware: constant(
                    vt,
                    c"kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder",
                ),
                not_sync: constant(cm, c"kCMSampleAttachmentKey_NotSync")?,
                pixel_format: constant(cv, c"kCVPixelBufferPixelFormatTypeKey")?,
                width: constant(cv, c"kCVPixelBufferWidthKey")?,
                height: constant(cv, c"kCVPixelBufferHeightKey")?,
                color,
            },
        })
    })
    .as_ref()
}

/// A Core Foundation object this code made, released when dropped.
struct Owned(CFTypeRef);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: made by a Create function here, released once.
            unsafe { CFRelease(self.0) }
        }
    }
}
fn int(value: i32) -> Owned {
    // SAFETY: a plain number.
    Owned(unsafe { CFNumberCreate(std::ptr::null(), CF_NUMBER_SINT32, (&value as *const i32).cast()) })
}
fn float(value: f64) -> Owned {
    // SAFETY: a plain number.
    Owned(unsafe { CFNumberCreate(std::ptr::null(), CF_NUMBER_FLOAT64, (&value as *const f64).cast()) })
}
fn dictionary(pairs: &[(CFStringRef, CFTypeRef)]) -> Owned {
    let keys: Vec<CFTypeRef> = pairs.iter().map(|p| p.0).collect();
    let values: Vec<CFTypeRef> = pairs.iter().map(|p| p.1).collect();
    // SAFETY: the arrays hold `len` live CF objects, retained by the
    // dictionary through the standard callbacks.
    Owned(unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            pairs.len() as isize,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    })
}

/// What the output callback hands back for the picture just encoded.
type Slot = Mutex<Option<Result<Encoded>>>;

pub struct VideoToolbox {
    session: *mut c_void,
    /// Boxed so its address, which VideoToolbox holds, never moves.
    slot: Box<Slot>,
    width: u32,
    height: u32,
    started: Instant,
    hardware: bool,
}
// SAFETY: a compression session may be used from any thread, one call at a
// time, which `&mut self` guarantees.
unsafe impl Send for VideoToolbox {}

impl VideoToolbox {
    pub fn new(width: u32, height: u32) -> Result<Self> {
        let api = api().context("VideoToolbox is not available")?;
        // Low latency rate control is the mode made for video calls: no
        // frames held back, a rate that follows what it is told at once. A
        // Mac that has no such mode, as some Intel ones, gets the ordinary
        // real time mode.
        match Self::create(api, width, height, true) {
            Ok(encoder) => Ok(encoder),
            Err(_) => Self::create(api, width, height, false),
        }
    }
    fn create(api: &'static Api, width: u32, height: u32, low_latency: bool) -> Result<Self> {
        let k = &api.keys;
        let yes = unsafe { kCFBooleanTrue };
        let mut spec: Vec<(CFStringRef, CFTypeRef)> = Vec::new();
        if let Some(key) = k.enable_hardware {
            spec.push((key, yes));
        }
        if low_latency {
            spec.push((k.low_latency.context("No low latency mode")?, yes));
        }
        let spec = dictionary(&spec);
        let (w, h, format) = (int(width as i32), int(height as i32), int(PIXEL_BGRA as i32));
        let source = dictionary(&[(k.pixel_format, format.0), (k.width, w.0), (k.height, h.0)]);
        let slot: Box<Slot> = Box::new(Mutex::new(None));
        let mut session: *mut c_void = std::ptr::null_mut();
        // SAFETY: arguments as the header declares them; the refcon is the
        // boxed slot, which outlives the session (see Drop).
        let status = unsafe {
            (api.create)(
                std::ptr::null(),
                width as i32,
                height as i32,
                CODEC_H264,
                spec.0,
                source.0,
                std::ptr::null(),
                Some(output),
                (&*slot as *const Slot).cast_mut().cast(),
                &mut session,
            )
        };
        ensure!(
            status == 0 && !session.is_null(),
            "VideoToolbox would not make an H.264 encoder ({status})"
        );
        let mut encoder = Self {
            session,
            slot,
            width,
            height,
            started: Instant::now(),
            hardware: false,
        };
        let set = |key: CFStringRef, value: CFTypeRef| unsafe {
            (api.set_property)(session, key, value)
        };
        let no = unsafe { kCFBooleanFalse };
        ensure!(set(k.real_time, yes) == 0, "No real time encoding");
        // No B frames: every picture can be shown as soon as it arrives.
        ensure!(set(k.allow_reordering, no) == 0, "Frames would be reordered");
        if let Some(key) = k.max_delay {
            // One picture in, the same picture out. Not every encoder takes
            // it; one that does not still hands each frame over at once in
            // real time mode, since `encode` waits for it.
            let _ = set(key, int(0).0);
        }
        let profile = match (low_latency, k.profile_constrained_high) {
            (true, Some(high)) => high,
            _ => k.profile_main,
        };
        let _ = set(k.profile_level, profile);
        if let Some(key) = k.max_key_interval_duration {
            // Keyframes come when video starts; this only bounds how long a
            // decoder that lost its place has to wait.
            let _ = set(key, float(10.0).0);
        }
        if let Some([p, pv, t, tv, m, mv]) = k.color {
            // Say which colours these are, so the helper's decoder turns
            // them back into the same RGB the tiles show.
            let _ = set(p, pv);
            let _ = set(t, tv);
            let _ = set(m, mv);
        }
        if let Some(key) = k.using_hardware {
            let mut value: CFTypeRef = std::ptr::null();
            // SAFETY: a Copy function: the value is released below.
            let status = unsafe { (api.copy_property)(session, key, std::ptr::null(), &mut value) };
            if status == 0 && !value.is_null() {
                encoder.hardware = unsafe { CFBooleanGetValue(value) } != 0;
                drop(Owned(value));
            }
        }
        encoder.set_rate(4_000_000, 30);
        // SAFETY: a live session.
        let _ = unsafe { (api.prepare)(session) };
        Ok(encoder)
    }
}

impl Drop for VideoToolbox {
    fn drop(&mut self) {
        if let Some(api) = api() {
            // SAFETY: the session is live; after invalidating it no callback
            // runs, so the slot can go.
            unsafe {
                (api.invalidate)(self.session);
                CFRelease(self.session);
            }
        }
    }
}

impl VideoEncoder for VideoToolbox {
    fn name(&self) -> &str {
        if self.hardware {
            "VideoToolbox (hardware)"
        } else {
            "VideoToolbox (software)"
        }
    }
    fn set_rate(&mut self, bits_per_second: u32, frames_per_second: u32) {
        let Some(api) = api() else { return };
        let k = &api.keys;
        let set = |key: CFStringRef, value: CFTypeRef| unsafe {
            (api.set_property)(self.session, key, value)
        };
        let _ = set(k.average_bit_rate, int(bits_per_second as i32).0);
        if let Some(key) = k.data_rate_limits {
            // A hard ceiling over each second, half again the average, so a
            // burst of motion cannot fill the link's queue.
            let bytes = int((bits_per_second / 8 * 3 / 2) as i32);
            let second = float(1.0);
            let values = [bytes.0, second.0];
            // SAFETY: two live numbers, retained by the array.
            let limits = Owned(unsafe {
                CFArrayCreate(std::ptr::null(), values.as_ptr(), 2, &kCFTypeArrayCallBacks)
            });
            let _ = set(key, limits.0);
        }
        if let Some(key) = k.expected_frame_rate {
            let _ = set(key, int(frames_per_second as i32).0);
        }
    }
    fn encode(&mut self, frame: &Frame, keyframe: bool) -> Result<Encoded> {
        let api = api().context("VideoToolbox is not available")?;
        ensure!(
            frame.width == self.width && frame.height == self.height,
            "The screen changed size under the encoder"
        );
        // SAFETY: the pool belongs to the session and lives as long as it.
        let pool = unsafe { (api.pool)(self.session) };
        ensure!(!pool.is_null(), "VideoToolbox has no picture buffers");
        let mut pixels: *mut c_void = std::ptr::null_mut();
        // SAFETY: a Create function: the buffer is released below.
        let status = unsafe { (api.pool_buffer)(std::ptr::null(), pool, &mut pixels) };
        ensure!(status == 0 && !pixels.is_null(), "No picture buffer ({status})");
        let pixels = Owned(pixels);
        let buffer = pixels.0 as *mut c_void;
        // SAFETY: the buffer is locked while it is written, and holds
        // `height` rows of `stride` bytes of BGRA.
        unsafe {
            ensure!((api.lock)(buffer, 0) == 0, "Cannot lock a picture buffer");
            let stride = (api.stride)(buffer);
            let base = (api.base)(buffer);
            let row = self.width as usize * 4;
            if !base.is_null() && stride >= row {
                let out = std::slice::from_raw_parts_mut(base, stride * self.height as usize);
                for (dst, src) in out.chunks_exact_mut(stride).zip(frame.rgba.chunks_exact(row)) {
                    for (d, s) in dst[..row]
                        .as_chunks_mut::<4>()
                        .0
                        .iter_mut()
                        .zip(src.as_chunks::<4>().0)
                    {
                        *d = [s[2], s[1], s[0], 255];
                    }
                }
            }
            (api.unlock)(buffer, 0);
        }
        let force = keyframe.then(|| dictionary(&[(api.keys.force_key_frame, unsafe { kCFBooleanTrue })]));
        let now = CMTime {
            value: self.started.elapsed().as_micros() as i64,
            timescale: 1_000_000,
            flags: 1,
            epoch: 0,
        };
        self.slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        // SAFETY: a live session and buffer; VideoToolbox retains the buffer.
        let status = unsafe {
            (api.encode_frame)(
                self.session,
                buffer,
                now,
                INVALID_TIME,
                force.as_ref().map_or(std::ptr::null(), |d| d.0),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        ensure!(status == 0, "VideoToolbox could not encode ({status})");
        // Wait for this picture: with no frames held back it is the only one.
        // SAFETY: a live session.
        let status = unsafe { (api.complete)(self.session, INVALID_TIME) };
        ensure!(status == 0, "VideoToolbox did not finish ({status})");
        match self.slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
            Some(result) => result,
            None => bail!("VideoToolbox dropped a picture"),
        }
    }
}

/// VideoToolbox's output callback: one encoded picture, turned into Annex B.
unsafe extern "C" fn output(
    refcon: *mut c_void,
    _frame: *mut c_void,
    status: OSStatus,
    _flags: u32,
    sample: *const c_void,
) {
    // SAFETY: the refcon is the encoder's boxed slot (see `create`).
    let slot = unsafe { &*(refcon as *const Slot) };
    let result = if status != 0 || sample.is_null() {
        Err(anyhow::anyhow!("VideoToolbox failed to encode ({status})"))
    } else {
        // SAFETY: a sample VideoToolbox hands over for this call.
        unsafe { annex_b(sample) }
    };
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
}

/// The sample's NAL units after start codes, with the parameter sets first
/// on a keyframe so a decoder can start there.
///
/// # Safety
/// `sample` must be a live H.264 sample buffer.
unsafe fn annex_b(sample: *const c_void) -> Result<Encoded> {
    let api = api().context("VideoToolbox is not available")?;
    const START: [u8; 4] = [0, 0, 0, 1];
    // A sample is a sync sample unless it carries NotSync = true.
    let keyframe = unsafe {
        let attachments = (api.attachments)(sample, 0);
        if attachments.is_null() || CFArrayGetCount(attachments) == 0 {
            true
        } else {
            let first = CFArrayGetValueAtIndex(attachments, 0);
            let not_sync = CFDictionaryGetValue(first, api.keys.not_sync);
            not_sync.is_null() || CFBooleanGetValue(not_sync) == 0
        }
    };
    let mut out = Vec::new();
    let mut header = 4usize;
    if keyframe {
        let format = unsafe { (api.format)(sample) };
        ensure!(!format.is_null(), "A keyframe without its format");
        let mut count = 0usize;
        let mut length = 0i32;
        let status = unsafe {
            (api.parameter_set)(
                format,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut count,
                &mut length,
            )
        };
        ensure!(status == 0, "No parameter sets ({status})");
        header = length.max(1) as usize;
        for i in 0..count {
            let mut pointer: *const u8 = std::ptr::null();
            let mut size = 0usize;
            let status = unsafe {
                (api.parameter_set)(
                    format,
                    i,
                    &mut pointer,
                    &mut size,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            ensure!(status == 0 && !pointer.is_null(), "Bad parameter set");
            out.extend_from_slice(&START);
            out.extend_from_slice(unsafe { std::slice::from_raw_parts(pointer, size) });
        }
    }
    let block = unsafe { (api.data_buffer)(sample) };
    ensure!(!block.is_null(), "An encoded picture without data");
    let length = unsafe { (api.data_length)(block) };
    let mut avcc = vec![0u8; length];
    let status = unsafe { (api.copy_bytes)(block, 0, length, avcc.as_mut_ptr()) };
    ensure!(status == 0, "Cannot read an encoded picture ({status})");
    out.reserve(length + 16);
    let mut rest = &avcc[..];
    while rest.len() > header {
        let size = rest[..header]
            .iter()
            .fold(0usize, |n, b| (n << 8) | *b as usize);
        rest = &rest[header..];
        ensure!(size <= rest.len(), "A NAL unit runs past its picture");
        out.extend_from_slice(&START);
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
    }
    Ok(Encoded {
        data: out,
        keyframe,
    })
}
