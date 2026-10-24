//! H.264 on Windows through a Media Foundation hardware encoder (Intel Quick
//! Sync, NVIDIA NVENC, AMD VCE), in its low latency mode.
//!
//! Only hardware encoders are tried. Without one the session uses OpenH264,
//! which is faster than Microsoft's software encoder at screen sizes and
//! behaves the same on every machine.
use anyhow::{Context, Result, bail, ensure};
use boundary_session::{
    Frame,
    video::{Encoded, VideoEncoder},
};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree};
use windows::Win32::System::Variant::VARIANT;
use windows::core::Interface;

/// How long to wait for a picture before calling it skipped.
const OUTPUT_WAIT: Duration = Duration::from_millis(250);

fn started() -> Result<()> {
    static STARTED: OnceLock<bool> = OnceLock::new();
    // SAFETY: plain initialisation calls; both are safe to repeat.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }
    let ok = *STARTED.get_or_init(|| unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL).is_ok() });
    ensure!(ok, "Media Foundation would not start");
    Ok(())
}

pub struct MediaFoundation {
    transform: IMFTransform,
    codec: Option<ICodecAPI>,
    /// Hardware encoders run on their own and say by events when they want
    /// a picture and when one is ready.
    events: Option<IMFMediaEventGenerator>,
    /// The encoder already asked for a picture it has not been given.
    wants_input: bool,
    width: u32,
    height: u32,
    name: String,
    started: Instant,
    nv12: Vec<u8>,
}
// SAFETY: the encoder lives in the multithreaded apartment, where its
// interfaces may be called from any thread; `&mut self` keeps it to one at
// a time.
unsafe impl Send for MediaFoundation {}

impl MediaFoundation {
    pub fn new(width: u32, height: u32) -> Result<Self> {
        started()?;
        let (w, h) = (width.next_multiple_of(2), height.next_multiple_of(2));
        // SAFETY: Media Foundation calls with arguments as documented; every
        // interface returned is reference counted by the bindings.
        unsafe {
            let output = MFT_REGISTER_TYPE_INFO {
                guidMajorType: MFMediaType_Video,
                guidSubtype: MFVideoFormat_H264,
            };
            let mut list: *mut Option<IMFActivate> = std::ptr::null_mut();
            let mut count = 0u32;
            MFTEnumEx(
                MFT_CATEGORY_VIDEO_ENCODER,
                MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
                None,
                Some(&output),
                &mut list,
                &mut count,
            )?;
            let activates: Vec<IMFActivate> = (0..count as usize)
                .filter_map(|i| (*list.add(i)).take())
                .collect();
            if !list.is_null() {
                CoTaskMemFree(Some(list as *const _));
            }
            let mut last = anyhow::anyhow!("No hardware H.264 encoder");
            for activate in activates {
                match Self::open(&activate, w, h) {
                    Ok(mut encoder) => {
                        encoder.width = width;
                        encoder.height = height;
                        return Ok(encoder);
                    }
                    Err(error) => {
                        let _ = activate.ShutdownObject();
                        last = error;
                    }
                }
            }
            Err(last)
        }
    }

    unsafe fn open(activate: &IMFActivate, w: u32, h: u32) -> Result<Self> {
        unsafe {
            let name = {
                let mut text = windows::core::PWSTR::null();
                let mut length = 0u32;
                match activate.GetAllocatedString(
                    &MFT_FRIENDLY_NAME_Attribute,
                    &mut text,
                    &mut length,
                ) {
                    Ok(()) => {
                        let name = text.to_string().unwrap_or_default();
                        CoTaskMemFree(Some(text.0 as *const _));
                        name
                    }
                    Err(_) => "hardware".into(),
                }
            };
            let transform: IMFTransform = activate.ActivateObject()?;
            let attributes = transform.GetAttributes()?;
            let asynchronous = attributes.GetUINT32(&MF_TRANSFORM_ASYNC).unwrap_or(0) == 1;
            if asynchronous {
                attributes.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)?;
            }
            let _ = attributes.SetUINT32(&MF_LOW_LATENCY, 1);
            let codec = transform.cast::<ICodecAPI>().ok();
            if let Some(codec) = &codec {
                // Low latency: no B frames, every picture out as soon as it
                // is in. CBR keeps each picture near its share of the link.
                let _ = codec.SetValue(&CODECAPI_AVLowLatencyMode, &VARIANT::from(true));
                let _ = codec.SetValue(
                    &CODECAPI_AVEncCommonRateControlMode,
                    &VARIANT::from(eAVEncCommonRateControlMode_CBR.0 as u32),
                );
                let _ = codec.SetValue(&CODECAPI_AVEncMPVGOPSize, &VARIANT::from(600u32));
                let _ =
                    codec.SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &VARIANT::from(0u32));
            }
            let size = ((w as u64) << 32) | h as u64;
            let rate = (30u64 << 32) | 1;
            let out = MFCreateMediaType()?;
            out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            out.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            out.SetUINT32(&MF_MT_AVG_BITRATE, 4_000_000)?;
            out.SetUINT64(&MF_MT_FRAME_SIZE, size)?;
            out.SetUINT64(&MF_MT_FRAME_RATE, rate)?;
            out.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, (1u64 << 32) | 1)?;
            out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            out.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main.0 as u32)?;
            out.SetUINT32(&MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT601.0 as u32)?;
            out.SetUINT32(&MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235.0 as u32)?;
            transform.SetOutputType(0, &out, 0)?;
            let input = MFCreateMediaType()?;
            input.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
            input.SetUINT64(&MF_MT_FRAME_SIZE, size)?;
            input.SetUINT64(&MF_MT_FRAME_RATE, rate)?;
            input.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, (1u64 << 32) | 1)?;
            input.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            transform.SetInputType(0, &input, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
            let events = if asynchronous {
                Some(transform.cast::<IMFMediaEventGenerator>()?)
            } else {
                None
            };
            Ok(Self {
                transform,
                codec,
                events,
                wants_input: false,
                width: w,
                height: h,
                name: format!("Media Foundation ({name})"),
                started: Instant::now(),
                nv12: Vec::new(),
            })
        }
    }

    /// The next event, waiting at most until `until`.
    fn event(&self, until: Instant) -> Result<Option<u32>> {
        let events = self.events.as_ref().context("Not asynchronous")?;
        loop {
            // SAFETY: a live event generator.
            match unsafe { events.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
                Ok(event) => return Ok(Some(unsafe { event.GetType()? })),
                Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => {
                    if Instant::now() >= until {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// One encoded picture, if the encoder has one ready.
    fn output(&self) -> Result<Option<Encoded>> {
        // SAFETY: Media Foundation calls as documented. The output buffer's
        // sample, when the encoder makes it, is released with the struct.
        unsafe {
            let info = self.transform.GetOutputStreamInfo(0)?;
            let provides = info.dwFlags
                & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0)
                    as u32
                != 0;
            let mut buffer = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                ..Default::default()
            };
            if !provides {
                let sample = MFCreateSample()?;
                sample.AddBuffer(&MFCreateMemoryBuffer(info.cbSize.max(1 << 20))?)?;
                buffer.pSample = std::mem::ManuallyDrop::new(Some(sample));
            }
            let mut status = 0u32;
            let result =
                self.transform
                    .ProcessOutput(0, std::slice::from_mut(&mut buffer), &mut status);
            let sample = std::mem::ManuallyDrop::take(&mut buffer.pSample);
            drop(std::mem::ManuallyDrop::take(&mut buffer.pEvents));
            match result {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                Err(e) => return Err(e.into()),
            }
            let sample = sample.context("The encoder gave no picture")?;
            let keyframe = sample.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) == 1;
            let contiguous = sample.ConvertToContiguousBuffer()?;
            let mut data = std::ptr::null_mut();
            let mut length = 0u32;
            contiguous.Lock(&mut data, None, Some(&mut length))?;
            let bytes = std::slice::from_raw_parts(data, length as usize).to_vec();
            contiguous.Unlock()?;
            Ok(Some(Encoded {
                data: bytes,
                keyframe,
            }))
        }
    }
}

impl Drop for MediaFoundation {
    fn drop(&mut self) {
        // SAFETY: a live transform, told the stream is over.
        unsafe {
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
    }
}

impl VideoEncoder for MediaFoundation {
    fn name(&self) -> &str {
        &self.name
    }
    fn set_rate(&mut self, bits_per_second: u32, _frames_per_second: u32) {
        if let Some(codec) = &self.codec {
            // SAFETY: a live codec interface and a plain number.
            let _ = unsafe {
                codec.SetValue(
                    &CODECAPI_AVEncCommonMeanBitRate,
                    &VARIANT::from(bits_per_second),
                )
            };
        }
    }
    fn encode(&mut self, frame: &Frame, keyframe: bool) -> Result<Encoded> {
        started()?;
        let (w, h) = (
            self.width.next_multiple_of(2),
            self.height.next_multiple_of(2),
        );
        ensure!(
            frame.width == self.width && frame.height == self.height,
            "The screen changed size under the encoder"
        );
        nv12(frame, w, h, &mut self.nv12);
        // SAFETY: Media Foundation calls as documented; the buffer is locked
        // while it is written and holds `nv12.len()` bytes.
        unsafe {
            let buffer = MFCreateMemoryBuffer(self.nv12.len() as u32)?;
            let mut data = std::ptr::null_mut();
            buffer.Lock(&mut data, None, None)?;
            std::ptr::copy_nonoverlapping(self.nv12.as_ptr(), data, self.nv12.len());
            buffer.Unlock()?;
            buffer.SetCurrentLength(self.nv12.len() as u32)?;
            let sample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            // Media Foundation counts time in hundreds of nanoseconds.
            sample.SetSampleTime((self.started.elapsed().as_nanos() / 100) as i64)?;
            sample.SetSampleDuration(333_333)?;
            if keyframe && let Some(codec) = &self.codec {
                let _ = codec.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &VARIANT::from(1u32));
            }
            if self.events.is_none() {
                self.transform.ProcessInput(0, &sample, 0)?;
                return Ok(self.output()?.unwrap_or(Encoded {
                    data: Vec::new(),
                    keyframe: false,
                }));
            }
            let until = Instant::now() + OUTPUT_WAIT;
            while !self.wants_input {
                match self.event(until)? {
                    Some(t) if t == METransformNeedInput.0 as u32 => self.wants_input = true,
                    Some(t) if t == METransformHaveOutput.0 as u32 => {
                        // A picture from before, which has been given up on.
                        let _ = self.output()?;
                    }
                    Some(_) => {}
                    None => bail!("The hardware encoder stopped asking for pictures"),
                }
            }
            self.transform.ProcessInput(0, &sample, 0)?;
            self.wants_input = false;
            loop {
                match self.event(until)? {
                    Some(t) if t == METransformHaveOutput.0 as u32 => {
                        if let Some(encoded) = self.output()? {
                            return Ok(encoded);
                        }
                    }
                    Some(t) if t == METransformNeedInput.0 as u32 => self.wants_input = true,
                    Some(_) => {}
                    // Held back: send nothing for this screen.
                    None => {
                        return Ok(Encoded {
                            data: Vec::new(),
                            keyframe: false,
                        });
                    }
                }
            }
        }
    }
}

/// RGBA to NV12, BT.601 limited range, as the media type says.
fn nv12(frame: &Frame, w: u32, h: u32, out: &mut Vec<u8>) {
    let (w, h) = (w as usize, h as usize);
    let (fw, fh) = (frame.width as usize, frame.height as usize);
    out.resize(w * h * 3 / 2, 0);
    let pixel = |x: usize, y: usize| {
        let i = (y.min(fh - 1) * fw + x.min(fw - 1)) * 4;
        (
            frame.rgba[i] as i32,
            frame.rgba[i + 1] as i32,
            frame.rgba[i + 2] as i32,
        )
    };
    let (luma, chroma) = out.split_at_mut(w * h);
    for y in 0..h {
        for x in 0..w {
            let (r, g, b) = pixel(x, y);
            luma[y * w + x] = (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16) as u8;
        }
    }
    for y in 0..h / 2 {
        for x in 0..w / 2 {
            let mut sum = (0, 0, 0);
            for (dx, dy) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
                let (r, g, b) = pixel(x * 2 + dx, y * 2 + dy);
                sum = (sum.0 + r, sum.1 + g, sum.2 + b);
            }
            let (r, g, b) = (sum.0 / 4, sum.1 / 4, sum.2 / 4);
            chroma[y * w + x * 2] = (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128) as u8;
            chroma[y * w + x * 2 + 1] = (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128) as u8;
        }
    }
}
