//! Windows screens through DXGI Desktop Duplication.
//!
//! xcap copies the whole screen through GDI on every call, whether anything
//! changed or not, and a screen larger than the one sent was then shrunk on
//! the CPU. Desktop Duplication instead hands over a new picture only when the
//! desktop was drawn, says which rectangles changed, and leaves the picture on
//! the GPU, where it is shrunk by the video processor before the changed parts
//! alone are copied back.
//!
//! A duplication is lost whenever the desktop it shows goes away: a switch to
//! the secure desktop for UAC or the lock screen, a change of resolution, a
//! full screen program taking the display. The caller drops it and opens a new
//! one, attached to whatever desktop has the input by then.
use crate::damage;
use anyhow::{Context, Result, bail, ensure};
use boundary_session::{Frame, Rect};
use windows::Win32::Foundation::{HMODULE, RECT};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_MODE_ROTATION_IDENTITY, DXGI_MODE_ROTATION_UNSPECIFIED,
    DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
    DXGI_OUTDUPL_MOVE_RECT, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource,
};
use windows::core::Interface;

/// The video processor that shrinks a large screen on the GPU.
struct Scaler {
    video: ID3D11VideoContext,
    processor: ID3D11VideoProcessor,
    input: ID3D11VideoProcessorInputView,
    output: ID3D11VideoProcessorOutputView,
    /// The shrunk picture the changed parts are copied from.
    scaled: ID3D11Texture2D,
}

/// One display's desktop, duplicated.
pub(crate) struct Duplication {
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    /// The desktop at full size, kept on the GPU between frames so only the
    /// changed parts need copying into it. Present only with a scaler.
    full: Option<ID3D11Texture2D>,
    scaler: Option<Scaler>,
    /// Where changed parts are copied for the CPU to read.
    staging: ID3D11Texture2D,
    /// The desktop's size, and the size it is handed over at.
    size: (u32, u32),
    out: (u32, u32),
    /// The picture so far, updated in place.
    frame: Frame,
    /// Nothing has been read yet, so all of it must be.
    fresh: bool,
    /// Reused buffers for what DXGI reports.
    dirty: Vec<RECT>,
    moves: Vec<DXGI_OUTDUPL_MOVE_RECT>,
}

/// Why a frame could not be had.
pub(crate) enum Lost {
    /// The duplication no longer shows the desktop and must be opened again.
    Access,
    Other(anyhow::Error),
}
impl From<windows::core::Error> for Lost {
    fn from(error: windows::core::Error) -> Self {
        if error.code() == DXGI_ERROR_ACCESS_LOST {
            Lost::Access
        } else {
            Lost::Other(error.into())
        }
    }
}

impl Duplication {
    /// Duplicate the display xcap knows as `monitor` (its HMONITOR), handing
    /// pictures over at no more than `max` pixels.
    pub fn open(monitor: u32, max: (u32, u32)) -> Result<Self> {
        // SAFETY: plain COM calls; every out pointer is a local that lives
        // past the call, and the interfaces are released when dropped.
        unsafe {
            let factory: IDXGIFactory1 = CreateDXGIFactory1()?;
            let (adapter, output) = find(&factory, monitor)?;
            // The device must be on the adapter that drives this display. A
            // laptop with two GPUs refuses to duplicate from the other one.
            let mut device = None;
            let mut context = None;
            let mut created = Err(windows::core::Error::empty());
            for flags in [
                D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            ] {
                created = D3D11CreateDevice(
                    &adapter,
                    D3D_DRIVER_TYPE_UNKNOWN,
                    HMODULE::default(),
                    flags,
                    None,
                    D3D11_SDK_VERSION,
                    Some(&mut device),
                    None,
                    Some(&mut context),
                );
                if created.is_ok() {
                    break;
                }
            }
            created.context("No Direct3D device for this display")?;
            let device: ID3D11Device = device.context("No Direct3D device")?;
            let context = context.context("No Direct3D context")?;
            let duplication = output
                .DuplicateOutput(&device)
                .context("Desktop Duplication is unavailable")?;
            let desc = duplication.GetDesc();
            ensure!(
                desc.Rotation == DXGI_MODE_ROTATION_IDENTITY
                    || desc.Rotation == DXGI_MODE_ROTATION_UNSPECIFIED,
                "A rotated display is captured another way"
            );
            let size = (desc.ModeDesc.Width, desc.ModeDesc.Height);
            ensure!(size.0 > 0 && size.1 > 0, "The display has no size");
            let fit = crate::fit(size.0, size.1, max);
            let (full, scaler) = if fit != size {
                // Where the GPU cannot shrink, the whole screen comes back
                // and the caller shrinks it, as it did before.
                match Scaler::new(&device, &context, size, fit) {
                    Ok((full, scaler)) => (Some(full), Some(scaler)),
                    Err(_) => (None, None),
                }
            } else {
                (None, None)
            };
            let out = if scaler.is_some() { fit } else { size };
            let staging = texture(
                &device,
                out,
                D3D11_USAGE_STAGING,
                0,
                D3D11_CPU_ACCESS_READ.0 as u32,
            )?;
            Ok(Self {
                context,
                duplication,
                full,
                scaler,
                staging,
                size,
                out,
                frame: Frame {
                    width: out.0,
                    height: out.1,
                    rgba: vec![0; out.0 as usize * out.1 as usize * 4],
                },
                fresh: true,
                dirty: Vec::new(),
                moves: Vec::new(),
            })
        }
    }

    /// Nothing has been handed over yet.
    pub fn fresh(&self) -> bool {
        self.fresh
    }

    /// The next picture and the parts of it that changed, waiting up to
    /// `wait_ms` for the desktop to be drawn, or `None` if it was not.
    pub fn next(&mut self, wait_ms: u32) -> Result<Option<(&Frame, Vec<Rect>)>, Lost> {
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        // SAFETY: both out pointers are locals that outlive the call.
        match unsafe {
            self.duplication
                .AcquireNextFrame(wait_ms, &mut info, &mut resource)
        } {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let result = self.read(&info, resource);
        // SAFETY: a frame was acquired above and is released once.
        let released = unsafe { self.duplication.ReleaseFrame() };
        let damage = result?;
        released?;
        Ok(damage.map(|damage| (&self.frame, damage)))
    }

    fn read(
        &mut self,
        info: &DXGI_OUTDUPL_FRAME_INFO,
        resource: Option<IDXGIResource>,
    ) -> Result<Option<Vec<Rect>>, Lost> {
        // Only the pointer moved, and the pointer is not part of the picture.
        if info.LastPresentTime == 0 && !self.fresh {
            return Ok(None);
        }
        let resource =
            resource.ok_or_else(|| Lost::Other(anyhow::anyhow!("No desktop picture")))?;
        let desktop: ID3D11Texture2D = resource.cast()?;
        let whole = Rect {
            x: 0,
            y: 0,
            width: self.size.0,
            height: self.size.1,
        };
        let changed = if self.fresh || info.TotalMetadataBufferSize == 0 {
            vec![whole]
        } else {
            self.changed(info.TotalMetadataBufferSize)?
        };
        let changed = damage::tidy(changed, self.size.0, self.size.1);
        if changed.is_empty() {
            return Ok(None);
        }
        // SAFETY: every texture here belongs to this device, and each copy
        // stays inside both textures, since rectangles were clipped above.
        unsafe {
            let damage = if let (Some(full), Some(scaler)) = (&self.full, &self.scaler) {
                for r in &changed {
                    self.context.CopySubresourceRegion(
                        full,
                        0,
                        r.x,
                        r.y,
                        0,
                        &desktop,
                        0,
                        Some(&boxed(r)),
                    );
                }
                scaler.blt()?;
                let scaled = changed
                    .iter()
                    .map(|r| damage::scale(*r, self.size, self.out));
                let scaled = damage::tidy(scaled, self.out.0, self.out.1);
                for r in &scaled {
                    self.context.CopySubresourceRegion(
                        &self.staging,
                        0,
                        r.x,
                        r.y,
                        0,
                        &scaler.scaled,
                        0,
                        Some(&boxed(r)),
                    );
                }
                scaled
            } else {
                for r in &changed {
                    self.context.CopySubresourceRegion(
                        &self.staging,
                        0,
                        r.x,
                        r.y,
                        0,
                        &desktop,
                        0,
                        Some(&boxed(r)),
                    );
                }
                changed
            };
            self.copy_out(&damage)?;
            self.fresh = false;
            Ok(Some(damage))
        }
    }

    /// The rectangles DXGI says were drawn, and where moved ones landed.
    fn changed(&mut self, size: u32) -> Result<Vec<Rect>, Lost> {
        let size = size as usize;
        self.dirty
            .resize(size / size_of::<RECT>() + 1, RECT::default());
        self.moves.resize(
            size / size_of::<DXGI_OUTDUPL_MOVE_RECT>() + 1,
            DXGI_OUTDUPL_MOVE_RECT::default(),
        );
        let (mut moves, mut dirty) = (0u32, 0u32);
        // SAFETY: each buffer is passed with its size in bytes.
        unsafe {
            self.duplication.GetFrameMoveRects(
                (self.moves.len() * size_of::<DXGI_OUTDUPL_MOVE_RECT>()) as u32,
                self.moves.as_mut_ptr(),
                &mut moves,
            )?;
            self.duplication.GetFrameDirtyRects(
                (self.dirty.len() * size_of::<RECT>()) as u32,
                self.dirty.as_mut_ptr(),
                &mut dirty,
            )?;
        }
        let moves = moves as usize / size_of::<DXGI_OUTDUPL_MOVE_RECT>();
        let dirty = dirty as usize / size_of::<RECT>();
        // The picture already has moved parts in their new place, so a move
        // is a change where it landed, read like any other.
        Ok(self.moves[..moves]
            .iter()
            .map(|m| m.DestinationRect)
            .chain(self.dirty[..dirty].iter().copied())
            .filter_map(rect)
            .collect())
    }

    /// Read the changed parts of the staging texture into the picture.
    fn copy_out(&mut self, damage: &[Rect]) -> Result<(), Lost> {
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: the staging texture was made for CPU reads; it is unmapped
        // below before anything else touches it.
        unsafe {
            self.context
                .Map(&self.staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
        }
        let pitch = mapped.RowPitch as usize;
        let width = self.out.0 as usize;
        // SAFETY: a mapped texture is RowPitch bytes for each of its rows.
        let src = unsafe {
            std::slice::from_raw_parts(mapped.pData as *const u8, pitch * self.out.1 as usize)
        };
        for r in damage {
            let (x, w) = (r.x as usize * 4, r.width as usize * 4);
            for y in r.y as usize..(r.y + r.height) as usize {
                let from = &src[y * pitch + x..y * pitch + x + w];
                let start = y * width * 4 + x;
                damage::bgra_to_rgba(from, &mut self.frame.rgba[start..start + w]);
            }
        }
        // SAFETY: mapped above.
        unsafe { self.context.Unmap(&self.staging, 0) };
        Ok(())
    }
}

impl Scaler {
    /// A video processor that shrinks `size` to `out`, with the texture it
    /// reads from.
    unsafe fn new(
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        size: (u32, u32),
        out: (u32, u32),
    ) -> Result<(ID3D11Texture2D, Self)> {
        // SAFETY: the caller's device and context are alive; descriptions
        // are locals.
        unsafe {
            let devices: ID3D11VideoDevice = device.cast()?;
            let video: ID3D11VideoContext = context.cast()?;
            let rate = DXGI_RATIONAL {
                Numerator: 60,
                Denominator: 1,
            };
            let content = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
                InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
                InputFrameRate: rate,
                InputWidth: size.0,
                InputHeight: size.1,
                OutputFrameRate: rate,
                OutputWidth: out.0,
                OutputHeight: out.1,
                Usage: D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
            };
            let kinds = devices.CreateVideoProcessorEnumerator(&content)?;
            let support = kinds.CheckVideoProcessorFormat(DXGI_FORMAT_B8G8R8A8_UNORM)?;
            let both = (D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT.0
                | D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT.0) as u32;
            if support & both != both {
                bail!("The video processor cannot shrink BGRA");
            }
            let processor = devices.CreateVideoProcessor(&kinds, 0)?;
            let full = texture(
                device,
                size,
                D3D11_USAGE_DEFAULT,
                (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
                0,
            )?;
            let scaled = texture(
                device,
                out,
                D3D11_USAGE_DEFAULT,
                D3D11_BIND_RENDER_TARGET.0 as u32,
                0,
            )?;
            let mut input = None;
            devices.CreateVideoProcessorInputView(
                &full,
                &kinds,
                &D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
                    FourCC: 0,
                    ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
                    Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                        Texture2D: D3D11_TEX2D_VPIV {
                            MipSlice: 0,
                            ArraySlice: 0,
                        },
                    },
                },
                Some(&mut input),
            )?;
            let mut output = None;
            devices.CreateVideoProcessorOutputView(
                &scaled,
                &kinds,
                &D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                    ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                    Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                        Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
                    },
                },
                Some(&mut output),
            )?;
            // Full range RGB in and out, and none of the driver's own
            // sharpening or noise reduction, which would change still parts.
            let rgb = D3D11_VIDEO_PROCESSOR_COLOR_SPACE::default();
            video.VideoProcessorSetStreamColorSpace(&processor, 0, &rgb);
            video.VideoProcessorSetOutputColorSpace(&processor, &rgb);
            video.VideoProcessorSetStreamFrameFormat(
                &processor,
                0,
                D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            );
            video.VideoProcessorSetStreamAutoProcessingMode(&processor, 0, false);
            let source = RECT {
                left: 0,
                top: 0,
                right: size.0 as i32,
                bottom: size.1 as i32,
            };
            let target = RECT {
                left: 0,
                top: 0,
                right: out.0 as i32,
                bottom: out.1 as i32,
            };
            video.VideoProcessorSetStreamSourceRect(&processor, 0, true, Some(&source));
            video.VideoProcessorSetStreamDestRect(&processor, 0, true, Some(&target));
            video.VideoProcessorSetOutputTargetRect(&processor, true, Some(&target));
            Ok((
                full,
                Self {
                    video,
                    processor,
                    input: input.context("No video input view")?,
                    output: output.context("No video output view")?,
                    scaled,
                },
            ))
        }
    }

    /// Shrink the whole desktop. A shrunk pixel blends several, so doing it
    /// all keeps the edges of changed parts right; the GPU takes well under a
    /// millisecond for it.
    unsafe fn blt(&self) -> windows::core::Result<()> {
        let stream = D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            pInputSurface: std::mem::ManuallyDrop::new(Some(self.input.clone())),
            ..Default::default()
        };
        let mut streams = [stream];
        // SAFETY: the views belong to this processor's device.
        let result = unsafe {
            self.video
                .VideoProcessorBlt(&self.processor, &self.output, 0, &streams)
        };
        // SAFETY: taken once, releasing the reference cloned above.
        unsafe { std::mem::ManuallyDrop::drop(&mut streams[0].pInputSurface) };
        result
    }
}

/// The adapter and output that show the display with this HMONITOR.
unsafe fn find(factory: &IDXGIFactory1, monitor: u32) -> Result<(IDXGIAdapter1, IDXGIOutput1)> {
    // SAFETY: enumeration stops at the first index that is not there.
    unsafe {
        let mut a = 0;
        while let Ok(adapter) = factory.EnumAdapters1(a) {
            let mut o = 0;
            while let Ok(output) = adapter.EnumOutputs(o) {
                let desc = output.GetDesc()?;
                if desc.Monitor.0 as u32 == monitor {
                    return Ok((adapter, output.cast()?));
                }
                o += 1;
            }
            a += 1;
        }
    }
    bail!("No DXGI output for this display")
}

unsafe fn texture(
    device: &ID3D11Device,
    (width, height): (u32, u32),
    usage: D3D11_USAGE,
    bind: u32,
    cpu: u32,
) -> windows::core::Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_B8G8R8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: usage,
        BindFlags: bind,
        CPUAccessFlags: cpu,
        MiscFlags: 0,
    };
    let mut texture = None;
    // SAFETY: the description is a local.
    unsafe { device.CreateTexture2D(&desc, None, Some(&mut texture))? };
    texture.ok_or_else(windows::core::Error::empty)
}

fn rect(r: RECT) -> Option<Rect> {
    (r.right > r.left && r.bottom > r.top && r.left >= 0 && r.top >= 0).then(|| Rect {
        x: r.left as u32,
        y: r.top as u32,
        width: (r.right - r.left) as u32,
        height: (r.bottom - r.top) as u32,
    })
}

fn boxed(r: &Rect) -> D3D11_BOX {
    D3D11_BOX {
        left: r.x,
        top: r.y,
        front: 0,
        right: r.x + r.width,
        bottom: r.y + r.height,
        back: 1,
    }
}
