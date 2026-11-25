//! The screen straight from the kernel's display planes, for a Wayland sign
//! in screen.
//!
//! GDM's sign in screen on Wayland refuses every screen sharing request,
//! by design, and no X server shows it. What it shows is still a buffer the
//! kernel scans out, and root may read it: the primary plane's framebuffer
//! (GETFB2 hands out its buffer only to CAP_SYS_ADMIN), exported as a
//! dma-buf. This is the route `ffmpeg -f kmsgrab` takes.
//!
//! A plain (linear) buffer is mapped and copied. A tiled or compressed one,
//! as Intel and AMD scan out, is handed to the graphics card to untile
//! through EGL ([`super::egl`]); where EGL is missing [`Kms::capture`] says
//! so instead of returning a scrambled picture.
//!
//! One screen is read: the largest one lit, as GDM shows the sign in
//! prompt on every screen. The pointer's own plane is drawn on top.

use super::egl::{DmaBuf, DmaPlane, Gpu, Region};
use anyhow::{Context, Result, bail, ensure};
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const fn iowr(nr: u32, size: usize) -> libc::c_ulong {
    ((3u32 << 30) | ((size as u32) << 16) | (0x64 << 8) | nr) as libc::c_ulong
}
const fn iow(ty: u32, nr: u32, size: usize) -> libc::c_ulong {
    ((1u32 << 30) | ((size as u32) << 16) | (ty << 8) | nr) as libc::c_ulong
}

#[repr(C)]
#[derive(Default)]
struct SetClientCap {
    capability: u64,
    value: u64,
}
#[repr(C)]
#[derive(Default)]
struct Version {
    major: i32,
    minor: i32,
    patch: i32,
    name_len: usize,
    name: u64,
    date_len: usize,
    date: u64,
    desc_len: usize,
    desc: u64,
}
#[repr(C)]
#[derive(Default)]
struct CardRes {
    fb_id_ptr: u64,
    crtc_id_ptr: u64,
    connector_id_ptr: u64,
    encoder_id_ptr: u64,
    count_fbs: u32,
    count_crtcs: u32,
    count_connectors: u32,
    count_encoders: u32,
    min_width: u32,
    max_width: u32,
    min_height: u32,
    max_height: u32,
}
#[repr(C)]
#[derive(Default)]
struct Crtc {
    set_connectors_ptr: u64,
    count_connectors: u32,
    crtc_id: u32,
    fb_id: u32,
    x: u32,
    y: u32,
    gamma_size: u32,
    mode_valid: u32,
    // struct drm_mode_modeinfo
    clock: u32,
    hdisplay: u16,
    hsync_start: u16,
    hsync_end: u16,
    htotal: u16,
    hskew: u16,
    vdisplay: u16,
    vsync_start: u16,
    vsync_end: u16,
    vtotal: u16,
    vscan: u16,
    vrefresh: u32,
    mode_flags: u32,
    mode_type: u32,
    mode_name: [u8; 32],
}
#[repr(C)]
#[derive(Default)]
struct PlaneRes {
    plane_id_ptr: u64,
    count_planes: u32,
}
#[repr(C)]
#[derive(Default)]
struct GetPlane {
    plane_id: u32,
    crtc_id: u32,
    fb_id: u32,
    possible_crtcs: u32,
    gamma_size: u32,
    count_format_types: u32,
    format_type_ptr: u64,
}
#[repr(C)]
#[derive(Default)]
struct ObjProps {
    props_ptr: u64,
    prop_values_ptr: u64,
    count_props: u32,
    obj_id: u32,
    obj_type: u32,
}
#[repr(C)]
#[derive(Default)]
struct GetProperty {
    values_ptr: u64,
    enum_blob_ptr: u64,
    prop_id: u32,
    flags: u32,
    name: [u8; 32],
    count_values: u32,
    count_enum_blobs: u32,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct FbCmd2 {
    fb_id: u32,
    width: u32,
    height: u32,
    pixel_format: u32,
    flags: u32,
    handles: [u32; 4],
    pitches: [u32; 4],
    offsets: [u32; 4],
    modifier: [u64; 4],
}
#[repr(C)]
#[derive(Default)]
struct PrimeHandle {
    handle: u32,
    flags: u32,
    fd: i32,
}
#[repr(C)]
#[derive(Default)]
struct GemClose {
    handle: u32,
    pad: u32,
}
#[repr(C)]
struct DmaBufSync {
    flags: u64,
}

const VERSION: libc::c_ulong = iowr(0x00, size_of::<Version>());
const SET_CLIENT_CAP: libc::c_ulong = iow(0x64, 0x0d, size_of::<SetClientCap>());
const GETRESOURCES: libc::c_ulong = iowr(0xa0, size_of::<CardRes>());
const GETCRTC: libc::c_ulong = iowr(0xa1, size_of::<Crtc>());
const GETPROPERTY: libc::c_ulong = iowr(0xaa, size_of::<GetProperty>());
const GETPLANERESOURCES: libc::c_ulong = iowr(0xb5, size_of::<PlaneRes>());
const GETPLANE: libc::c_ulong = iowr(0xb6, size_of::<GetPlane>());
const OBJ_GETPROPERTIES: libc::c_ulong = iowr(0xb9, size_of::<ObjProps>());
const GETFB2: libc::c_ulong = iowr(0xce, size_of::<FbCmd2>());
const PRIME_HANDLE_TO_FD: libc::c_ulong = iowr(0x2d, size_of::<PrimeHandle>());
const GEM_CLOSE: libc::c_ulong = iow(0x64, 0x09, size_of::<GemClose>());
const DMA_BUF_SYNC: libc::c_ulong = iow(b'b' as u32, 0, size_of::<DmaBufSync>());
const CAP_UNIVERSAL_PLANES: u64 = 2;
/// Shows a plane's position and source properties; nothing is committed.
const CAP_ATOMIC: u64 = 3;
const OBJECT_PLANE: u32 = 0xeeee_eeee;
const FB_MODIFIERS: u32 = 2;
pub(crate) const XRGB8888: u32 = u32::from_le_bytes(*b"XR24");
pub(crate) const ARGB8888: u32 = u32::from_le_bytes(*b"AR24");
pub(crate) const MOD_LINEAR: u64 = 0;
pub(crate) const MOD_INVALID: u64 = 0x00ff_ffff_ffff_ffff;
const PLANE_PRIMARY: u64 = 1;
const PLANE_CURSOR: u64 = 2;

/// Drivers whose buffers are always plain, so mapping one is right even
/// when its framebuffer names no modifier.
const PLAIN_DRIVERS: &[&str] = &[
    "virtio_gpu",
    "bochs-drm",
    "bochs",
    "qxl",
    "cirrus",
    "cirrus-qemu",
    "vkms",
    "simpledrm",
    "efidrm",
    "vesadrm",
    "ofdrm",
    "hyperv_drm",
    "ast",
    "mgag200",
    "vboxvideo",
    "udl",
    "gm12u320",
];

fn ioctl<T>(fd: &File, request: libc::c_ulong, arg: &mut T) -> std::io::Result<()> {
    // SAFETY: `arg` is the repr(C) struct the request's size encodes, and
    // the kernel writes no further than that, or than the arrays its
    // pointers name, which the callers size from the counts it gave.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, arg as *mut T) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Nothing is scanned out: the screen is blank or asleep, as a sign in
/// screen goes after a few idle minutes. Input wakes it.
#[derive(Debug)]
pub(crate) struct Asleep;
impl std::fmt::Display for Asleep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The screen is asleep")
    }
}
impl std::error::Error for Asleep {}

/// One frame as the kernel scans it out.
pub(crate) struct Picture {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// A plane showing a framebuffer: where on its screen, and which part of
/// the framebuffer, in pixels.
#[derive(Clone, Copy, Debug, Default)]
struct Layer {
    fb_id: u32,
    crtc_id: u32,
    kind: u64,
    at: (i32, i32),
    size: (u32, u32),
    src: Option<Region>,
}

/// A display device, opened for reading what it shows.
pub(crate) struct Kms {
    card: File,
    path: String,
    driver: String,
    names: HashMap<u32, String>,
    gpu: Option<std::result::Result<Gpu, String>>,
    /// How the last picture was read, for the log.
    pub how: String,
}

impl Kms {
    /// The first card with a plane showing something.
    pub fn open() -> Result<Self> {
        let mut last = None;
        for n in 0..8 {
            let path = format!("/dev/dri/card{n}");
            let Ok(card) = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
            else {
                continue;
            };
            let mut cap = SetClientCap {
                capability: CAP_UNIVERSAL_PLANES,
                value: 1,
            };
            let _ = ioctl(&card, SET_CLIENT_CAP, &mut cap);
            let mut cap = SetClientCap {
                capability: CAP_ATOMIC,
                value: 1,
            };
            let _ = ioctl(&card, SET_CLIENT_CAP, &mut cap);
            let driver = driver_name(&card);
            let mut kms = Self {
                card,
                path: path.clone(),
                driver,
                names: HashMap::new(),
                gpu: None,
                how: String::new(),
            };
            match kms.capture() {
                Ok(_) => return Ok(kms),
                Err(error) if error.is::<Asleep>() && kms.planes().is_ok_and(|p| !p.is_empty()) => {
                    return Ok(kms);
                }
                Err(error) => last = Some(error.context(path)),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("No display device under /dev/dri")))
    }

    fn planes(&self) -> Result<Vec<u32>> {
        let mut res = PlaneRes::default();
        ioctl(&self.card, GETPLANERESOURCES, &mut res).context("No display planes")?;
        let mut ids = vec![0u32; res.count_planes as usize];
        res.plane_id_ptr = ids.as_mut_ptr() as u64;
        ioctl(&self.card, GETPLANERESOURCES, &mut res).context("No display planes")?;
        ids.truncate(res.count_planes as usize);
        Ok(ids)
    }

    /// Each lit screen (CRTC) and the size of its mode.
    fn crtcs(&self) -> Vec<(u32, u32, u32)> {
        let mut res = CardRes::default();
        if ioctl(&self.card, GETRESOURCES, &mut res).is_err() {
            return Vec::new();
        }
        let mut ids = vec![0u32; res.count_crtcs as usize];
        let mut res = CardRes {
            crtc_id_ptr: ids.as_mut_ptr() as u64,
            count_crtcs: ids.len() as u32,
            ..Default::default()
        };
        if ioctl(&self.card, GETRESOURCES, &mut res).is_err() {
            return Vec::new();
        }
        ids.truncate(res.count_crtcs as usize);
        ids.into_iter()
            .filter_map(|crtc_id| {
                let mut c = Crtc {
                    crtc_id,
                    ..Default::default()
                };
                ioctl(&self.card, GETCRTC, &mut c).ok()?;
                (c.mode_valid != 0 && c.hdisplay > 0 && c.vdisplay > 0).then_some((
                    crtc_id,
                    c.hdisplay as u32,
                    c.vdisplay as u32,
                ))
            })
            .collect()
    }

    fn name(&mut self, prop: u32) -> String {
        if let Some(n) = self.names.get(&prop) {
            return n.clone();
        }
        let mut p = GetProperty {
            prop_id: prop,
            ..Default::default()
        };
        let name = if ioctl(&self.card, GETPROPERTY, &mut p).is_ok() {
            let end = p.name.iter().position(|&b| b == 0).unwrap_or(32);
            String::from_utf8_lossy(&p.name[..end]).into_owned()
        } else {
            String::new()
        };
        self.names.insert(prop, name.clone());
        name
    }

    /// A plane's properties by name.
    fn props(&mut self, plane: u32) -> HashMap<String, u64> {
        let mut q = ObjProps {
            obj_id: plane,
            obj_type: OBJECT_PLANE,
            ..Default::default()
        };
        if ioctl(&self.card, OBJ_GETPROPERTIES, &mut q).is_err() {
            return HashMap::new();
        }
        let n = q.count_props as usize;
        let (mut ids, mut values) = (vec![0u32; n], vec![0u64; n]);
        let mut q = ObjProps {
            props_ptr: ids.as_mut_ptr() as u64,
            prop_values_ptr: values.as_mut_ptr() as u64,
            count_props: n as u32,
            obj_id: plane,
            obj_type: OBJECT_PLANE,
        };
        if ioctl(&self.card, OBJ_GETPROPERTIES, &mut q).is_err() {
            return HashMap::new();
        }
        let n = (q.count_props as usize).min(n);
        ids[..n]
            .iter()
            .zip(&values[..n])
            .map(|(&id, &v)| (self.name(id), v))
            .collect()
    }

    /// Every plane showing a framebuffer.
    fn layers(&mut self) -> Result<Vec<Layer>> {
        let mut out = Vec::new();
        for id in self.planes()? {
            let mut plane = GetPlane {
                plane_id: id,
                ..Default::default()
            };
            if ioctl(&self.card, GETPLANE, &mut plane).is_err() || plane.fb_id == 0 {
                continue;
            }
            let p = self.props(id);
            let int = |k: &str| p.get(k).map(|&v| v as i64);
            let fixed = |k: &str| p.get(k).map(|&v| (v >> 16) as u32);
            let src = match (
                fixed("SRC_X"),
                fixed("SRC_Y"),
                fixed("SRC_W"),
                fixed("SRC_H"),
            ) {
                (Some(x), Some(y), Some(w), Some(h)) if w > 0 && h > 0 => {
                    Some(Region { x, y, w, h })
                }
                _ => None,
            };
            out.push(Layer {
                fb_id: plane.fb_id,
                crtc_id: plane.crtc_id,
                kind: p.get("type").copied().unwrap_or(u64::MAX),
                at: (
                    int("CRTC_X").unwrap_or(0) as i32,
                    int("CRTC_Y").unwrap_or(0) as i32,
                ),
                size: (
                    int("CRTC_W").unwrap_or(0) as u32,
                    int("CRTC_H").unwrap_or(0) as u32,
                ),
                src,
            });
        }
        Ok(out)
    }

    fn getfb(&self, fb_id: u32) -> Result<FbCmd2> {
        let mut fb = FbCmd2 {
            fb_id,
            ..Default::default()
        };
        if let Err(error) = ioctl(&self.card, GETFB2, &mut fb) {
            bail!("The kernel would not hand out the screen's buffer ({error}); this needs root");
        }
        Ok(fb)
    }

    fn close(&self, fb: &FbCmd2) {
        let mut seen = Vec::new();
        for &handle in fb.handles.iter().filter(|&&h| h != 0) {
            if seen.contains(&handle) {
                continue;
            }
            seen.push(handle);
            let mut close = GemClose { handle, pad: 0 };
            let _ = ioctl(&self.card, GEM_CLOSE, &mut close);
        }
    }

    /// The screen and the pointer on it, as two layers.
    fn scene(&mut self) -> Result<(Layer, Option<Layer>)> {
        let layers = self.layers()?;
        let crtcs = self.crtcs();
        let primary_on = |crtc: u32| {
            layers
                .iter()
                .find(|l| l.crtc_id == crtc && l.kind == PLANE_PRIMARY)
        };
        let pointer_on = |crtc: u32| {
            layers
                .iter()
                .any(|l| l.crtc_id == crtc && l.kind == PLANE_CURSOR)
        };
        // The largest lit screen with something on its primary plane; of
        // equals the one the pointer is on, else the first the driver lists.
        let mut best: Option<((u64, bool), Layer)> = None;
        for &(crtc, w, h) in &crtcs {
            if let Some(&layer) = primary_on(crtc) {
                let rank = (w as u64 * h as u64, pointer_on(crtc));
                if best.as_ref().is_none_or(|(r, _)| rank > *r) {
                    best = Some((rank, layer));
                }
            }
        }
        let primary = match best {
            Some((_, layer)) => layer,
            // No plane types (an old driver): the biggest framebuffer.
            None => {
                let mut biggest: Option<(u64, Layer)> = None;
                for &layer in &layers {
                    if layer.kind == PLANE_CURSOR {
                        continue;
                    }
                    let fb = self.getfb(layer.fb_id)?;
                    self.close(&fb);
                    let area = fb.width as u64 * fb.height as u64;
                    if biggest.as_ref().is_none_or(|(a, _)| area > *a) {
                        biggest = Some((area, layer));
                    }
                }
                biggest
                    .map(|(_, l)| l)
                    .ok_or_else(|| anyhow::Error::new(Asleep))?
            }
        };
        let cursor = layers
            .iter()
            .find(|l| l.crtc_id == primary.crtc_id && l.kind == PLANE_CURSOR)
            .copied();
        Ok((primary, cursor))
    }

    pub fn capture(&mut self) -> Result<Picture> {
        let (primary, cursor) = self.scene()?;
        let fb = self.getfb(primary.fb_id)?;
        let region = clamp(primary.src, &fb);
        let result = self.read(&fb, region);
        self.close(&fb);
        let (mut rgba, how) = result?;
        for px in rgba.as_chunks_mut::<4>().0 {
            px[3] = 255;
        }
        let mut picture = Picture {
            width: region.w,
            height: region.h,
            rgba,
        };
        self.how = format!(
            "{} on {}, {}x{} {} modifier {:#x}, {how}",
            self.driver,
            self.path,
            fb.width,
            fb.height,
            fourcc(fb.pixel_format),
            modifier(&fb).unwrap_or(MOD_INVALID)
        );
        if let Some(cursor) = cursor {
            // A pointer that cannot be read leaves the screen as it is.
            if let Ok(fb) = self.getfb(cursor.fb_id) {
                let region = clamp(cursor.src, &fb);
                if let Ok((pixels, _)) = self.read(&fb, region) {
                    // Where the pointer is, in the picture's pixels, when
                    // the screen's plane is scaled to its CRTC.
                    let scale = |v: i32, plane: i32, src: u32, crtc: u32| {
                        if crtc == 0 || src == crtc {
                            v - plane
                        } else {
                            ((v - plane) as i64 * src as i64 / crtc as i64) as i32
                        }
                    };
                    let x = scale(
                        cursor.at.0,
                        primary.at.0,
                        region_w(&primary),
                        primary.size.0,
                    );
                    let y = scale(
                        cursor.at.1,
                        primary.at.1,
                        region_h(&primary),
                        primary.size.1,
                    );
                    blend(&mut picture, &pixels, region.w, region.h, x, y);
                }
                self.close(&fb);
            }
        }
        Ok(picture)
    }

    fn gpu(&mut self) -> std::result::Result<&mut Gpu, String> {
        if self.gpu.is_none() {
            self.gpu = Some(Gpu::new(&self.path).map_err(|e| format!("{e:#}")));
        }
        match self.gpu.as_mut() {
            Some(Ok(gpu)) => Ok(gpu),
            Some(Err(e)) => Err(e.clone()),
            None => unreachable!(),
        }
    }

    /// `region` of `fb` as RGBA, and how it was read.
    fn read(&mut self, fb: &FbCmd2, region: Region) -> Result<(Vec<u8>, String)> {
        ensure!(
            fb.handles[0] != 0,
            "The kernel gave no buffer for the screen"
        );
        let modifier = modifier(fb);
        let mappable = matches!(fb.pixel_format, XRGB8888 | ARGB8888);
        let plain_driver = PLAIN_DRIVERS.contains(&self.driver.as_str());
        let route = route(modifier, mappable, plain_driver);
        let mut why = Vec::new();
        for way in route {
            let attempt = match way {
                Way::Map => self.map(fb, region).map(|p| (p, "mapped".to_string())),
                Way::Gpu => self.untile(fb, region),
            };
            match attempt {
                Ok(done) => return Ok(done),
                Err(error) => why.push(format!("{error:#}")),
            }
        }
        if why.is_empty() {
            bail!(
                "The screen's buffer is in a format this cannot read ({})",
                fourcc(fb.pixel_format)
            );
        }
        bail!("{}", why.join("; "))
    }

    fn export(&self, fb: &FbCmd2) -> Result<Vec<DmaPlane>> {
        let mut planes = Vec::new();
        for i in 0..4 {
            if fb.handles[i] == 0 {
                break;
            }
            let mut prime = PrimeHandle {
                handle: fb.handles[i],
                flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u32,
                fd: -1,
            };
            ioctl(&self.card, PRIME_HANDLE_TO_FD, &mut prime)
                .context("The screen's buffer could not be shared")?;
            planes.push(DmaPlane {
                // SAFETY: the kernel just gave this descriptor to this process.
                fd: unsafe { OwnedFd::from_raw_fd(prime.fd) },
                offset: fb.offsets[i],
                pitch: fb.pitches[i],
            });
        }
        Ok(planes)
    }

    fn untile(&mut self, fb: &FbCmd2, region: Region) -> Result<(Vec<u8>, String)> {
        let planes = self.export(fb)?;
        let buf = DmaBuf {
            width: fb.width,
            height: fb.height,
            fourcc: fb.pixel_format,
            modifier: modifier(fb),
            planes,
        };
        let gpu = self
            .gpu()
            .map_err(|e| anyhow::anyhow!("The graphics card cannot untile its screen: {e}"))?;
        let rgba = gpu.read(&buf, region)?;
        Ok((rgba, format!("untiled through {}", gpu.name)))
    }

    fn map(&self, fb: &FbCmd2, r: Region) -> Result<Vec<u8>> {
        let buf = self
            .export(fb)?
            .into_iter()
            .next()
            .context("The kernel gave no buffer for the screen")?;
        let buf = File::from(buf.fd);
        let pitch = fb.pitches[0] as usize;
        let offset = fb.offsets[0] as usize;
        let (w, h) = (fb.width as usize, fb.height as usize);
        ensure!(pitch >= w * 4 && w > 0 && h > 0, "Odd screen buffer");
        let len = offset + pitch * h;
        // SAFETY: a read only shared mapping of `len` bytes of the buffer,
        // unmapped below before the descriptor closes.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                buf.as_raw_fd(),
                0,
            )
        };
        ensure!(
            addr != libc::MAP_FAILED,
            "The screen's buffer could not be mapped: {}",
            std::io::Error::last_os_error()
        );
        let mut sync = DmaBufSync { flags: 1 }; // start, read
        let _ = ioctl(&buf, DMA_BUF_SYNC, &mut sync);
        let (rw, rx) = (r.w as usize, r.x as usize);
        let mut rgba = vec![0u8; rw * r.h as usize * 4];
        // SAFETY: `len` bytes are mapped at `addr`.
        let src = unsafe { std::slice::from_raw_parts(addr as *const u8, len) };
        for row in 0..r.h as usize {
            let start = offset + (row + r.y as usize) * pitch + rx * 4;
            bgra_to_rgba(
                &src[start..start + rw * 4],
                &mut rgba[row * rw * 4..(row + 1) * rw * 4],
            );
        }
        let mut sync = DmaBufSync { flags: 1 | 4 }; // end, read
        let _ = ioctl(&buf, DMA_BUF_SYNC, &mut sync);
        // SAFETY: mapped above, and nothing points into it any more.
        unsafe { libc::munmap(addr, len) };
        Ok(rgba)
    }
}

fn region_w(l: &Layer) -> u32 {
    l.src.map_or(l.size.0, |s| s.w)
}
fn region_h(l: &Layer) -> u32 {
    l.src.map_or(l.size.1, |s| s.h)
}

/// The part of `fb` a plane shows, kept inside the buffer.
fn clamp(src: Option<Region>, fb: &FbCmd2) -> Region {
    let whole = Region {
        x: 0,
        y: 0,
        w: fb.width,
        h: fb.height,
    };
    match src {
        Some(r) if r.x < fb.width && r.y < fb.height => Region {
            x: r.x,
            y: r.y,
            w: r.w.min(fb.width - r.x),
            h: r.h.min(fb.height - r.y),
        },
        _ => whole,
    }
}

fn modifier(fb: &FbCmd2) -> Option<u64> {
    (fb.flags & FB_MODIFIERS != 0).then_some(fb.modifier[0])
}

fn fourcc(f: u32) -> String {
    f.to_le_bytes().iter().map(|&b| b as char).collect()
}

fn driver_name(card: &File) -> String {
    let mut name = [0u8; 64];
    let mut v = Version {
        name_len: name.len(),
        name: name.as_mut_ptr() as u64,
        ..Default::default()
    };
    if ioctl(card, VERSION, &mut v).is_err() {
        return "unknown driver".into();
    }
    let len = v.name_len.min(name.len());
    String::from_utf8_lossy(&name[..len]).into_owned()
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Way {
    Map,
    Gpu,
}

/// Which ways to try to read a buffer, in order. A plain buffer is mapped,
/// which is cheap, and the graphics card tries if that fails. A tiled one
/// only the card can read. A buffer that names no modifier may still be
/// tiled on a real card (an X server's, say), so the card goes first there,
/// except on drivers that never tile.
fn route(modifier: Option<u64>, mappable: bool, plain_driver: bool) -> Vec<Way> {
    let map = mappable.then_some(Way::Map);
    match modifier {
        Some(MOD_LINEAR) => map.into_iter().chain([Way::Gpu]).collect(),
        Some(m) if m != MOD_INVALID => vec![Way::Gpu],
        _ if plain_driver => map.into_iter().chain([Way::Gpu]).collect(),
        _ => [Way::Gpu].into_iter().chain(map).collect(),
    }
}

fn bgra_to_rgba(src: &[u8], dst: &mut [u8]) {
    for (s, d) in src
        .as_chunks::<4>()
        .0
        .iter()
        .zip(dst.as_chunks_mut::<4>().0)
    {
        d.copy_from_slice(&[s[2], s[1], s[0], s[3]]);
    }
}

/// Draw a pointer of `w` by `h` RGBA, with its colour already multiplied
/// by its alpha as KMS takes it, with its corner at `x`, `y`.
fn blend(picture: &mut Picture, pointer: &[u8], w: u32, h: u32, x: i32, y: i32) {
    for row in 0..h as i32 {
        let py = y + row;
        if py < 0 || py >= picture.height as i32 {
            continue;
        }
        for col in 0..w as i32 {
            let px = x + col;
            if px < 0 || px >= picture.width as i32 {
                continue;
            }
            let s = ((row * w as i32 + col) * 4) as usize;
            let d = ((py as u32 * picture.width + px as u32) * 4) as usize;
            let a = pointer[s + 3] as u32;
            if a == 0 {
                continue;
            }
            for c in 0..3 {
                let over = pointer[s + c] as u32 + picture.rgba[d + c] as u32 * (255 - a) / 255;
                picture.rgba[d + c] = over.min(255) as u8;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_numbers_match_the_kernel_headers() {
        // From linux/drm.h, drm_mode.h and dma-buf.h on x86_64.
        assert_eq!(size_of::<FbCmd2>(), 104);
        assert_eq!(size_of::<GetPlane>(), 32);
        assert_eq!(size_of::<Crtc>(), 104);
        assert_eq!(size_of::<CardRes>(), 64);
        assert_eq!(size_of::<GetProperty>(), 64);
        assert_eq!(size_of::<ObjProps>(), 32);
        assert_eq!(size_of::<Version>(), 64);
        assert_eq!(VERSION, 0xc040_6400);
        assert_eq!(GETRESOURCES, 0xc040_64a0);
        assert_eq!(GETCRTC, 0xc068_64a1);
        assert_eq!(GETPROPERTY, 0xc040_64aa);
        assert_eq!(OBJ_GETPROPERTIES, 0xc020_64b9);
        assert_eq!(GETPLANERESOURCES, 0xc010_64b5);
        assert_eq!(GETPLANE, 0xc020_64b6);
        assert_eq!(GETFB2, 0xc068_64ce);
        assert_eq!(PRIME_HANDLE_TO_FD, 0xc00c_642d);
        assert_eq!(GEM_CLOSE, 0x4008_6409);
        assert_eq!(SET_CLIENT_CAP, 0x4010_640d);
        assert_eq!(DMA_BUF_SYNC, 0x4008_6200);
        assert_eq!(XRGB8888, 0x3432_5258);
    }

    #[test]
    fn a_tiled_buffer_goes_to_the_graphics_card() {
        const Y_TILED: u64 = 0x0100_0000_0000_0002;
        assert_eq!(route(Some(Y_TILED), true, false), [Way::Gpu]);
        assert_eq!(route(Some(MOD_LINEAR), true, false), [Way::Map, Way::Gpu]);
        // An X server's buffer names no modifier and may be tiled.
        assert_eq!(route(None, true, false), [Way::Gpu, Way::Map]);
        assert_eq!(route(Some(MOD_INVALID), true, false), [Way::Gpu, Way::Map]);
        // A virtual card's never is.
        assert_eq!(route(None, true, true), [Way::Map, Way::Gpu]);
        // Ten bit colour only the card can turn into RGBA.
        assert_eq!(route(Some(MOD_LINEAR), false, false), [Way::Gpu]);
    }

    #[test]
    fn the_pointer_is_drawn_over_the_screen() {
        let mut picture = Picture {
            width: 4,
            height: 3,
            rgba: [10, 20, 30, 255].repeat(12),
        };
        // A 2x2 pointer: opaque white, half see through black, clear, and
        // opaque red, hanging off the right edge.
        let pointer = [
            255, 255, 255, 255, 0, 0, 0, 128, //
            9, 9, 9, 0, 255, 0, 0, 255,
        ];
        blend(&mut picture, &pointer, 2, 2, 3, 1);
        let px = |x: u32, y: u32| {
            let i = ((y * 4 + x) * 4) as usize;
            picture.rgba[i..i + 4].to_vec()
        };
        assert_eq!(px(3, 1), [255, 255, 255, 255]);
        assert_eq!(px(3, 2), [10, 20, 30, 255]); // clear
        assert_eq!(px(2, 1), [10, 20, 30, 255]); // untouched
        let mut picture2 = Picture {
            width: 2,
            height: 1,
            rgba: [200, 100, 50, 255].repeat(2),
        };
        blend(&mut picture2, &pointer[..8], 2, 1, -1, 0);
        // The half see through black lands at x 0 and halves it.
        assert_eq!(picture2.rgba[..4], [99, 49, 24, 255]);
        assert_eq!(picture2.rgba[4..], [200, 100, 50, 255]);
    }

    #[test]
    fn a_planes_source_is_kept_inside_its_buffer() {
        let fb = FbCmd2 {
            width: 1920,
            height: 1080,
            ..Default::default()
        };
        let r = |x, y, w, h| Region { x, y, w, h };
        assert_eq!(clamp(None, &fb), r(0, 0, 1920, 1080));
        assert_eq!(clamp(Some(r(0, 0, 1280, 800)), &fb), r(0, 0, 1280, 800));
        assert_eq!(clamp(Some(r(1900, 0, 100, 10)), &fb), r(1900, 0, 20, 10));
        assert_eq!(clamp(Some(r(5000, 0, 100, 10)), &fb), r(0, 0, 1920, 1080));
    }
}
