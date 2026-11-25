//! The screen straight from the kernel's display planes, for a Wayland sign
//! in screen.
//!
//! GDM's sign in screen on Wayland refuses every screen sharing request,
//! by design, and no X server shows it. What it shows is still a buffer the
//! kernel scans out, and root may read it: the primary plane's framebuffer
//! (GETFB2 hands out its buffer only to CAP_SYS_ADMIN), exported as a
//! dma-buf and mapped. This is the route `ffmpeg -f kmsgrab` takes.
//!
//! Only linear buffers in XRGB8888 or ARGB8888 are read. A tiled buffer, as
//! Intel and AMD drivers scan out, needs the GPU to untile it, and that is
//! not done here: [`Kms::capture`] says so instead of returning a scrambled
//! picture. The pointer is a plane of its own and is not drawn in.

use anyhow::{Context, Result, bail, ensure};
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

const SET_CLIENT_CAP: libc::c_ulong = iow(0x64, 0x0d, size_of::<SetClientCap>());
const GETPLANERESOURCES: libc::c_ulong = iowr(0xb5, size_of::<PlaneRes>());
const GETPLANE: libc::c_ulong = iowr(0xb6, size_of::<GetPlane>());
const GETFB2: libc::c_ulong = iowr(0xce, size_of::<FbCmd2>());
const PRIME_HANDLE_TO_FD: libc::c_ulong = iowr(0x2d, size_of::<PrimeHandle>());
const GEM_CLOSE: libc::c_ulong = iow(0x64, 0x09, size_of::<GemClose>());
const DMA_BUF_SYNC: libc::c_ulong = iow(b'b' as u32, 0, size_of::<DmaBufSync>());
const CAP_UNIVERSAL_PLANES: u64 = 2;
const XRGB8888: u32 = u32::from_le_bytes(*b"XR24");
const ARGB8888: u32 = u32::from_le_bytes(*b"AR24");
const MOD_LINEAR: u64 = 0;
const MOD_INVALID: u64 = 0x00ff_ffff_ffff_ffff;

fn ioctl<T>(fd: &File, request: libc::c_ulong, arg: &mut T) -> std::io::Result<()> {
    // SAFETY: `arg` is the repr(C) struct the request's size encodes, and
    // the kernel writes no further than that.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, arg as *mut T) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// One frame as the kernel scans it out.
pub(crate) struct Picture {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// A display device, opened for reading what it shows.
pub(crate) struct Kms {
    card: File,
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
            let kms = Self { card };
            match kms.capture() {
                Ok(_) => return Ok(kms),
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

    /// The biggest framebuffer on any plane: the primary plane of the
    /// screen, not the pointer's small one.
    fn framebuffer(&self) -> Result<FbCmd2> {
        let mut best: Option<FbCmd2> = None;
        for id in self.planes()? {
            let mut plane = GetPlane {
                plane_id: id,
                ..Default::default()
            };
            if ioctl(&self.card, GETPLANE, &mut plane).is_err() || plane.fb_id == 0 {
                continue;
            }
            let mut fb = FbCmd2 {
                fb_id: plane.fb_id,
                ..Default::default()
            };
            if let Err(error) = ioctl(&self.card, GETFB2, &mut fb) {
                bail!(
                    "The kernel would not hand out the screen's buffer ({error}); this needs root"
                );
            }
            let area = |f: &FbCmd2| f.width as u64 * f.height as u64;
            if best.as_ref().is_none_or(|b| area(&fb) > area(b)) {
                if let Some(old) = best.replace(fb) {
                    self.close(&old);
                }
            } else {
                self.close(&fb);
            }
        }
        best.context("Nothing is on the screen: it may be asleep")
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

    pub fn capture(&self) -> Result<Picture> {
        let fb = self.framebuffer()?;
        let result = self.read(&fb);
        self.close(&fb);
        result
    }

    fn read(&self, fb: &FbCmd2) -> Result<Picture> {
        ensure!(
            matches!(fb.pixel_format, XRGB8888 | ARGB8888),
            "The screen's buffer is in a format this cannot read ({:#x})",
            fb.pixel_format
        );
        ensure!(
            matches!(fb.modifier[0], MOD_LINEAR | MOD_INVALID) || fb.flags & 2 == 0,
            "The screen's buffer is tiled ({:#x}), which needs the graphics card to read",
            fb.modifier[0]
        );
        ensure!(
            fb.handles[0] != 0,
            "The kernel gave no buffer for the screen"
        );
        let mut prime = PrimeHandle {
            handle: fb.handles[0],
            flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u32,
            fd: -1,
        };
        ioctl(&self.card, PRIME_HANDLE_TO_FD, &mut prime)
            .context("The screen's buffer could not be shared")?;
        // SAFETY: the kernel just gave this descriptor to this process.
        let buf = unsafe { File::from(OwnedFd::from_raw_fd(prime.fd)) };
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
        let mut rgba = vec![0u8; w * h * 4];
        // SAFETY: `len` bytes are mapped at `addr`.
        let src = unsafe { std::slice::from_raw_parts(addr as *const u8, len) };
        for y in 0..h {
            let row = &src[offset + y * pitch..offset + y * pitch + w * 4];
            super::bgrx_to_rgba(row, &mut rgba[y * w * 4..(y + 1) * w * 4]);
        }
        let mut sync = DmaBufSync { flags: 1 | 4 }; // end, read
        let _ = ioctl(&buf, DMA_BUF_SYNC, &mut sync);
        // SAFETY: mapped above, and nothing points into it any more.
        unsafe { libc::munmap(addr, len) };
        Ok(Picture {
            width: fb.width,
            height: fb.height,
            rgba,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_numbers_match_the_kernel_headers() {
        // From linux/drm.h and linux/dma-buf.h on x86_64.
        assert_eq!(size_of::<FbCmd2>(), 104);
        assert_eq!(size_of::<GetPlane>(), 32);
        assert_eq!(GETPLANERESOURCES, 0xc010_64b5);
        assert_eq!(GETPLANE, 0xc020_64b6);
        assert_eq!(GETFB2, 0xc068_64ce);
        assert_eq!(PRIME_HANDLE_TO_FD, 0xc00c_642d);
        assert_eq!(GEM_CLOSE, 0x4008_6409);
        assert_eq!(SET_CLIENT_CAP, 0x4010_640d);
        assert_eq!(DMA_BUF_SYNC, 0x4008_6200);
        assert_eq!(XRGB8888, 0x3432_5258);
    }
}
