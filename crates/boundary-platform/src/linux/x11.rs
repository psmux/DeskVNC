//! X11 screens through MIT-SHM, with DAMAGE saying what changed.
//!
//! The server copies the changed part of the screen into memory this process
//! shares with it, so no pixels cross the socket. DAMAGE reports each area
//! anything drew to; while it reports nothing the screen is still and nothing
//! is read at all. Without either extension, as over a forwarded connection,
//! the screen is read whole over the socket and compared with the last one.
use super::{Area, Raw, bgrx_to_rgba};
use anyhow::{Context, Result, bail, ensure};
use boundary_session::Rect;
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::damage::{self, ConnectionExt as _};
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::protocol::xfixes::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{self, ConnectionExt as _, ImageFormat, ImageOrder};
use x11rb::rust_connection::RustConnection;

/// With damage, a whole screen is still read this often, for the rare
/// driver that draws without reporting it.
const RECHECK: Duration = Duration::from_secs(2);
/// More damaged rectangles than this are sent on as their bounding box.
const MAX_RECTS: usize = 128;

/// Monitors, as (RandR output, name with size).
pub(crate) fn displays() -> Result<Vec<(u32, String)>> {
    let (conn, screen) = RustConnection::connect(None).context("No X display to share")?;
    let root = conn.setup().roots[screen].root;
    Ok(monitors(&conn, root)?
        .into_iter()
        .map(|(id, name, area)| (id, format!("{name} ({} × {})", area.width, area.height)))
        .collect())
}

fn monitors(conn: &RustConnection, root: xproto::Window) -> Result<Vec<(u32, String, Area)>> {
    let reply = conn.randr_get_monitors(root, true)?.reply();
    let mut all = Vec::new();
    if let Ok(reply) = reply {
        for (i, m) in reply.monitors.iter().enumerate() {
            let name = conn
                .get_atom_name(m.name)
                .ok()
                .and_then(|c| c.reply().ok())
                .map(|r| String::from_utf8_lossy(&r.name).into_owned())
                .unwrap_or_else(|| format!("Screen {}", i + 1));
            let area = Area {
                x: m.x as i32,
                y: m.y as i32,
                width: m.width as u32,
                height: m.height as u32,
            };
            // The id xcap used, so a choice made before still means the same
            // monitor; a monitor with no output, as on Xvfb, gets its index.
            let id = m.outputs.first().copied().unwrap_or(i as u32);
            all.push((id, name, area));
        }
    }
    if all.is_empty() {
        let s = &conn
            .setup()
            .roots
            .iter()
            .find(|s| s.root == root)
            .context("No X screen")?;
        all.push((
            0,
            "Screen".into(),
            Area {
                x: 0,
                y: 0,
                width: s.width_in_pixels as u32,
                height: s.height_in_pixels as u32,
            },
        ));
    }
    Ok(all)
}

/// A System V shared memory segment attached to this process and the server.
struct Shm {
    seg: u32,
    addr: *mut u8,
    size: usize,
}
impl Shm {
    fn new(conn: &RustConnection, size: usize) -> Result<Self> {
        // SAFETY: plain System V calls; the segment is checked before use and
        // marked for removal as soon as both sides hold it, so it goes away
        // with this process however that ends.
        unsafe {
            let id = libc::shmget(libc::IPC_PRIVATE, size, libc::IPC_CREAT | 0o600);
            ensure!(id >= 0, "No shared memory");
            let addr = libc::shmat(id, std::ptr::null(), 0);
            if addr as isize == -1 {
                libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
                bail!("Shared memory could not be attached");
            }
            let seg = conn.generate_id()?;
            let attached = conn
                .shm_attach(seg, id as u32, false)
                .map_err(anyhow::Error::from)
                .and_then(|c| c.check().map_err(anyhow::Error::from));
            libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
            if let Err(e) = attached {
                libc::shmdt(addr);
                return Err(e.context("The X server could not share memory"));
            }
            Ok(Self {
                seg,
                addr: addr as *mut u8,
                size,
            })
        }
    }
    fn bytes(&self, len: usize) -> &[u8] {
        // SAFETY: the segment is `size` bytes and stays mapped while self lives;
        // the server has finished writing once its reply arrived.
        unsafe { std::slice::from_raw_parts(self.addr, len.min(self.size)) }
    }
    fn free(self, conn: &RustConnection) {
        let _ = conn.shm_detach(self.seg);
        let _ = conn.flush();
        // SAFETY: attached by `new` and not used after this.
        unsafe { libc::shmdt(self.addr as *const libc::c_void) };
    }
}

struct Damage {
    damage: damage::Damage,
    region: xfixes::Region,
    /// The server said something was drawn since the last look.
    dirty: bool,
}

pub(crate) struct Screen {
    conn: RustConnection,
    root: xproto::Window,
    id: u32,
    area: Area,
    shm: Option<Shm>,
    damage: Option<Damage>,
    /// The screen as last read, in RGBA.
    rgba: Vec<u8>,
    first: bool,
    checked: Instant,
}
impl Screen {
    pub fn open(id: u32) -> Result<Self> {
        let (conn, screen) = RustConnection::connect(None).context("No X display to share")?;
        let setup = conn.setup();
        let root = setup.roots[screen].root;
        let visual = setup.roots[screen].root_visual;
        let depth = setup.roots[screen].root_depth;
        let format = setup
            .pixmap_formats
            .iter()
            .find(|f| f.depth == depth)
            .context("The X server lists no format for its own depth")?;
        let masks = setup.roots[screen]
            .allowed_depths
            .iter()
            .flat_map(|d| &d.visuals)
            .find(|v| v.visual_id == visual)
            .map(|v| (v.red_mask, v.green_mask, v.blue_mask));
        ensure!(
            format.bits_per_pixel == 32
                && setup.image_byte_order == ImageOrder::LSB_FIRST
                && masks == Some((0xff0000, 0xff00, 0xff)),
            "This X display uses a pixel format other than 32 bit BGRX"
        );
        let all = monitors(&conn, root)?;
        let area = all
            .iter()
            .find(|(i, _, _)| *i == id)
            .or(all.first())
            .map(|(_, _, a)| *a)
            .context("The selected display is no longer connected")?;
        let mut this = Self {
            conn,
            root,
            id,
            area,
            shm: None,
            damage: None,
            rgba: vec![0; area.width as usize * area.height as usize * 4],
            first: true,
            checked: Instant::now(),
        };
        if this.conn.shm_query_version()?.reply().is_ok() {
            this.shm = Shm::new(&this.conn, this.rgba.len()).ok();
        }
        this.damage = this.watch().ok();
        Ok(this)
    }
    fn watch(&self) -> Result<Damage> {
        self.conn.xfixes_query_version(5, 0)?.reply()?;
        self.conn.damage_query_version(1, 1)?.reply()?;
        let damage = self.conn.generate_id()?;
        self.conn
            .damage_create(damage, self.root, damage::ReportLevel::NON_EMPTY)?
            .check()?;
        let region = self.conn.generate_id()?;
        self.conn.xfixes_create_region(region, &[])?.check()?;
        Ok(Damage {
            damage,
            region,
            dirty: true,
        })
    }
    pub fn area(&self) -> Area {
        self.area
    }
    pub fn damage(&self) -> bool {
        self.damage.is_some()
    }
    pub fn shm(&self) -> bool {
        self.shm.is_some()
    }

    /// The screen if it changed since the last call.
    pub fn next(&mut self) -> Result<Option<Raw>> {
        let whole = Rect {
            x: 0,
            y: 0,
            width: self.area.width,
            height: self.area.height,
        };
        let recheck = self.checked.elapsed() >= RECHECK;
        let rects = match self.damage.as_mut() {
            Some(d) => {
                while let Some(event) = self.conn.poll_for_event()? {
                    if matches!(event, Event::DamageNotify(_)) {
                        d.dirty = true;
                    }
                }
                if d.dirty || self.first {
                    d.dirty = false;
                    // Take what was damaged and start counting afresh. Anything
                    // drawn from here on raises a new notice.
                    self.conn.damage_subtract(d.damage, x11rb::NONE, d.region)?;
                    let region = self.conn.xfixes_fetch_region(d.region)?.reply()?;
                    let rects = clip(&region.rectangles, self.area);
                    if rects.is_empty() && !self.first && !recheck {
                        return Ok(None);
                    }
                    Some(rects)
                } else if recheck {
                    None
                } else {
                    return Ok(None);
                }
            }
            None => None,
        };
        if recheck {
            self.checked = Instant::now();
            self.refresh_area()?;
        }
        let damage = match rects {
            Some(rects) if !self.first && !recheck && !rects.is_empty() => {
                let bounds = bounding(&rects);
                let changed = self.read(bounds)?;
                if !changed {
                    return Ok(None);
                }
                Some(if rects.len() > MAX_RECTS {
                    vec![bounds]
                } else {
                    rects
                })
            }
            _ => {
                let changed = self.read(whole)?;
                if !changed && !self.first {
                    return Ok(None);
                }
                None
            }
        };
        self.first = false;
        Ok(Some(Raw {
            width: self.area.width,
            height: self.area.height,
            rgba: self.rgba.clone(),
            damage,
        }))
    }

    /// Follow a monitor that moved or changed size.
    fn refresh_area(&mut self) -> Result<()> {
        let all = monitors(&self.conn, self.root)?;
        let Some(area) = all
            .iter()
            .find(|(i, _, _)| *i == self.id)
            .or(all.first())
            .map(|(_, _, a)| *a)
        else {
            return Ok(());
        };
        if area != self.area {
            self.area = area;
            self.rgba = vec![0; area.width as usize * area.height as usize * 4];
            self.first = true;
            if let Some(shm) = self.shm.take() {
                shm.free(&self.conn);
                self.shm = Shm::new(&self.conn, self.rgba.len()).ok();
            }
        }
        Ok(())
    }

    /// Read `rect` of the screen into `rgba`, saying whether any of it
    /// differed from what was there.
    fn read(&mut self, rect: Rect) -> Result<bool> {
        if rect.width == 0 || rect.height == 0 {
            return Ok(false);
        }
        let (x, y) = (
            (self.area.x + rect.x as i32) as i16,
            (self.area.y + rect.y as i32) as i16,
        );
        let (w, h) = (rect.width as u16, rect.height as u16);
        let len = rect.width as usize * rect.height as usize * 4;
        let owned;
        let src: &[u8] = match &self.shm {
            Some(shm) => {
                self.conn
                    .shm_get_image(
                        self.root,
                        x,
                        y,
                        w,
                        h,
                        !0,
                        ImageFormat::Z_PIXMAP.into(),
                        shm.seg,
                        0,
                    )?
                    .reply()?;
                shm.bytes(len)
            }
            None => {
                owned = self
                    .conn
                    .get_image(ImageFormat::Z_PIXMAP, self.root, x, y, w, h, !0)?
                    .reply()?
                    .data;
                &owned
            }
        };
        ensure!(src.len() >= len, "The X server sent a short image");
        let stride = self.area.width as usize * 4;
        let row = rect.width as usize * 4;
        let mut changed = false;
        let mut line = vec![0u8; row];
        for (i, s) in src.chunks_exact(row).take(rect.height as usize).enumerate() {
            let at = (rect.y as usize + i) * stride + rect.x as usize * 4;
            bgrx_to_rgba(s, &mut line);
            let dst = &mut self.rgba[at..at + row];
            if dst != line.as_slice() {
                dst.copy_from_slice(&line);
                changed = true;
            }
        }
        Ok(changed)
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        if let Some(d) = self.damage.take() {
            let _ = self.conn.damage_destroy(d.damage);
            let _ = self.conn.xfixes_destroy_region(d.region);
        }
        if let Some(shm) = self.shm.take() {
            shm.free(&self.conn);
        }
        let _ = self.conn.flush();
    }
}

/// Damaged rectangles in root coordinates, cut to `area` and moved into it.
fn clip(rects: &[xproto::Rectangle], area: Area) -> Vec<Rect> {
    rects
        .iter()
        .filter_map(|r| {
            let x0 = (r.x as i32 - area.x).max(0);
            let y0 = (r.y as i32 - area.y).max(0);
            let x1 = (r.x as i32 + r.width as i32 - area.x).min(area.width as i32);
            let y1 = (r.y as i32 + r.height as i32 - area.y).min(area.height as i32);
            (x1 > x0 && y1 > y0).then(|| Rect {
                x: x0 as u32,
                y: y0 as u32,
                width: (x1 - x0) as u32,
                height: (y1 - y0) as u32,
            })
        })
        .collect()
}
fn bounding(rects: &[Rect]) -> Rect {
    let x0 = rects.iter().map(|r| r.x).min().unwrap_or(0);
    let y0 = rects.iter().map(|r| r.y).min().unwrap_or(0);
    let x1 = rects.iter().map(|r| r.x + r.width).max().unwrap_or(0);
    let y1 = rects.iter().map(|r| r.y + r.height).max().unwrap_or(0);
    Rect {
        x: x0,
        y: y0,
        width: x1 - x0,
        height: y1 - y0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damage_is_cut_to_the_monitor() {
        let area = Area {
            x: 100,
            y: 0,
            width: 200,
            height: 100,
        };
        let r = |x, y, width, height| xproto::Rectangle {
            x,
            y,
            width,
            height,
        };
        let rects = clip(
            &[r(0, 0, 50, 50), r(90, 10, 20, 20), r(290, 90, 50, 50)],
            area,
        );
        assert_eq!(
            rects,
            vec![
                Rect {
                    x: 0,
                    y: 10,
                    width: 10,
                    height: 20
                },
                Rect {
                    x: 190,
                    y: 90,
                    width: 10,
                    height: 10
                }
            ]
        );
        assert_eq!(
            bounding(&rects),
            Rect {
                x: 0,
                y: 10,
                width: 200,
                height: 90
            }
        );
    }
}
