//! The scenes a remote desktop benchmark draws, and how a client reads them
//! back out of whatever pixels the protocol delivered.
//!
//! Everything is laid out in units of a sixtieth of the stage's width, so a
//! client that receives the stage scaled (Boundary sends at most 1920 wide)
//! finds every spot by the same arithmetic. The stage sits inside a teal
//! border, which is how a client finds it on a remote desktop that has other
//! windows on it.
//!
//! Two rows of black and white squares at the top carry the frame code: a
//! frame counter, the stage's clock in milliseconds, the scene, and how many
//! keys it has seen, with a checksum. A client reading the code knows which
//! source frame it is looking at and when it was drawn, so frame rate, dropped
//! frames and latency come from the content itself rather than from the
//! protocol's own idea of an update.
#![forbid(unsafe_code)]

use std::sync::OnceLock;

/// The stage background. No scene draws it anywhere else.
pub const TEAL: [u8; 3] = [0x12, 0xb4, 0xa0];
/// The pointer marker.
pub const MAGENTA: [u8; 3] = [0xff, 0x00, 0xff];
/// The stage is this many units wide.
pub const UNITS: u32 = 60;
/// The rate the stage draws at.
pub const FPS: u32 = 60;
/// Height of the band at the top that holds the code, in units.
pub const BAND: f32 = 4.0;

const BITS: usize = 80;
const ROW_BITS: usize = 40;
const GRID_COLS: u32 = 20;
const GRID_ROWS: u32 = 8;
const GRID_PITCH: f32 = 1.25;
/// The patch a client watches to see when the picture turns sharp, in units.
pub const PATCH: (f32, f32, f32, f32) = (40.0, 5.0, 16.0, 8.0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scene {
    /// A still desktop with a marker under the pointer.
    Idle = 0,
    /// A grid where each key press fills the next cell.
    Typing = 1,
    /// Lines of text sliding up a quarter unit every frame.
    Scroll = 2,
    /// The whole content area changes every frame, as a video does.
    Motion = 3,
    /// Fine detail that a lossy codec has to settle on once motion stops.
    Still = 4,
}

impl Scene {
    pub const ALL: [Scene; 5] = [
        Scene::Idle,
        Scene::Typing,
        Scene::Scroll,
        Scene::Motion,
        Scene::Still,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Scene::Idle => "idle",
            Scene::Typing => "typing",
            Scene::Scroll => "scroll",
            Scene::Motion => "motion",
            Scene::Still => "still",
        }
    }
    pub fn parse(name: &str) -> Option<Scene> {
        Scene::ALL.into_iter().find(|s| s.name() == name)
    }
    fn from_bits(v: u8) -> Option<Scene> {
        Scene::ALL.get(v as usize).copied()
    }
}

/// What the code at the top of every frame says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code {
    /// Frames drawn since the stage started, wrapping.
    pub frame: u16,
    /// The low 32 bits of the stage's wall clock in milliseconds since 1970.
    pub clock_ms: u32,
    pub scene: Scene,
    /// Key presses seen, wrapping.
    pub keys: u16,
}

fn crc8(bytes: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &b in bytes {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

impl Code {
    fn payload(&self) -> [u8; 9] {
        let f = self.frame.to_be_bytes();
        let c = self.clock_ms.to_be_bytes();
        let k = self.keys.to_be_bytes();
        [f[0], f[1], c[0], c[1], c[2], c[3], k[0], k[1], self.scene as u8]
    }
    /// The squares, left to right then the second row.
    pub fn bits(&self) -> [bool; BITS] {
        let payload = self.payload();
        let mut bytes = [0u8; 10];
        bytes[..9].copy_from_slice(&payload);
        bytes[9] = crc8(&payload);
        let mut bits = [false; BITS];
        // A fixed preamble, so an all black or all white band never decodes.
        bits[..4].copy_from_slice(&[true, false, true, false]);
        // Frame, clock, keys, then the scene in four bits and the checksum.
        let mut i = 4;
        for &b in &bytes[..8] {
            for bit in (0..8).rev() {
                bits[i] = b >> bit & 1 == 1;
                i += 1;
            }
        }
        for bit in (0..4).rev() {
            bits[i] = bytes[8] >> bit & 1 == 1;
            i += 1;
        }
        for bit in (0..8).rev() {
            bits[i] = bytes[9] >> bit & 1 == 1;
            i += 1;
        }
        debug_assert_eq!(i, BITS);
        bits
    }
    pub fn from_bits(bits: &[bool; BITS]) -> Option<Code> {
        if bits[..4] != [true, false, true, false] {
            return None;
        }
        let byte = |from: usize, n: usize| {
            bits[from..from + n]
                .iter()
                .fold(0u8, |acc, &b| acc << 1 | b as u8)
        };
        let mut payload = [0u8; 9];
        for (j, slot) in payload.iter_mut().take(8).enumerate() {
            *slot = byte(4 + j * 8, 8);
        }
        payload[8] = byte(68, 4);
        if crc8(&payload) != byte(72, 8) {
            return None;
        }
        Some(Code {
            frame: u16::from_be_bytes([payload[0], payload[1]]),
            clock_ms: u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]),
            keys: u16::from_be_bytes([payload[6], payload[7]]),
            scene: Scene::from_bits(payload[8])?,
        })
    }
}

/// Where code square `i` sits, top left, in units.
fn bit_at(i: usize) -> (f32, f32) {
    ((2 + i % ROW_BITS) as f32, (1 + i / ROW_BITS) as f32)
}

/// Where the cell for key press `k` sits, top left, in units.
pub fn glyph_at(k: u16) -> (f32, f32) {
    let i = k as u32 % (GRID_COLS * GRID_ROWS);
    (
        2.0 + (i % GRID_COLS) as f32 * GRID_PITCH,
        5.0 + (i / GRID_COLS) as f32 * GRID_PITCH,
    )
}

/// Pointer targets for the lag test, in units, spread over the content area
/// and clear of the typing grid and the patch.
pub fn pointer_target(n: usize, height_units: f32) -> (f32, f32) {
    const SPOTS: [(f32, f32); 8] = [
        (0.15, 0.55),
        (0.85, 0.60),
        (0.50, 0.85),
        (0.25, 0.80),
        (0.70, 0.45),
        (0.40, 0.65),
        (0.90, 0.90),
        (0.10, 0.92),
    ];
    let (fx, fy) = SPOTS[n % SPOTS.len()];
    let top = 15.0f32.min(height_units * 0.4);
    let bottom = height_units - 2.0;
    (2.0 + fx * 56.0, top + fy * (bottom - top))
}

/// The stage's size in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub unit: u32,
    pub width: u32,
    pub height: u32,
}

impl Layout {
    /// The largest stage that fits a window this size. Any width beyond a
    /// whole number of units is left black.
    pub fn fit(window_width: u32, window_height: u32) -> Layout {
        let unit = (window_width / UNITS).max(4);
        Layout {
            unit,
            width: unit * UNITS,
            height: window_height,
        }
    }
    pub fn height_units(&self) -> f32 {
        self.height as f32 / self.unit as f32
    }
}

/// What the stage is showing, as the window or an offscreen host keeps it.
#[derive(Clone, Copy, Debug)]
pub struct StageState {
    pub scene: Scene,
    /// The frame the current scene started on.
    pub scene_start: u32,
    /// The pointer, in stage pixels.
    pub pointer: Option<(f32, f32)>,
    pub keys: u16,
}

impl Default for StageState {
    fn default() -> Self {
        StageState {
            scene: Scene::Idle,
            scene_start: 0,
            pointer: None,
            keys: 0,
        }
    }
}

impl StageState {
    pub fn set_scene(&mut self, scene: Scene, frame: u32) {
        self.scene = scene;
        self.scene_start = frame;
        if scene == Scene::Typing {
            self.keys = 0;
        }
    }
}

fn rgb(c: [u8; 3]) -> u32 {
    (c[0] as u32) << 16 | (c[1] as u32) << 8 | c[2] as u32
}

/// Text-like marks: short dark runs in lines, the way a page of text looks
/// to an encoder.
fn text(x: u32, y: u32) -> bool {
    (y % 18) < 11 && ((x * 31 + (y / 18) * 7 + (x / 7) * (y / 18)) % 13) < 6 && (x % 400) < 320
}

struct Plasma {
    sx: [u8; 512],
    sy: [u8; 512],
    palette: [u32; 256],
}

fn plasma() -> &'static Plasma {
    static TABLES: OnceLock<Plasma> = OnceLock::new();
    TABLES.get_or_init(|| {
        let wave = |i: usize, period: f32| {
            (64.0 + 63.0 * (i as f32 * std::f32::consts::TAU / period).sin()) as u8
        };
        let mut sx = [0u8; 512];
        let mut sy = [0u8; 512];
        for i in 0..512 {
            sx[i] = wave(i, 512.0).wrapping_add(wave(i, 128.0) / 2);
            sy[i] = wave(i, 256.0).wrapping_add(wave(i, 170.0) / 2);
        }
        let mut palette = [0u32; 256];
        for (i, p) in palette.iter_mut().enumerate() {
            let a = i as f32 * std::f32::consts::TAU / 256.0;
            // Red never drops below 64, so no colour comes near the teal.
            let r = (160.0 + 95.0 * a.sin()) as u8;
            let g = (128.0 + 127.0 * (a + 2.1).sin()) as u8;
            let b = (128.0 + 127.0 * (a + 4.2).sin()) as u8;
            *p = rgb([r, g, b]);
        }
        Plasma { sx, sy, palette }
    })
}

/// Draw one frame into `buf`, a window `stride` pixels wide, as 0RGB words.
pub fn render(buf: &mut [u32], stride: u32, layout: Layout, state: &StageState, frame: u32, clock_ms: u32) {
    let (w, h, u) = (layout.width, layout.height, layout.unit);
    let teal = rgb(TEAL);
    let paper = rgb([0xf4, 0xf4, 0xf0]);
    let ink = rgb([0x28, 0x28, 0x30]);
    let band = (BAND * u as f32) as u32;
    let since = frame.wrapping_sub(state.scene_start);
    let plasma = plasma();
    for y in 0..h.min(buf.len() as u32 / stride) {
        let row = &mut buf[(y * stride) as usize..((y + 1) * stride) as usize];
        let inside_y = y >= band && y + u < h;
        for (x, px) in row.iter_mut().enumerate() {
            let x = x as u32;
            *px = if x >= w {
                0
            } else if !inside_y || x < u || x + u >= w {
                teal
            } else {
                match state.scene {
                    Scene::Idle | Scene::Typing => {
                        if x > 28 * u && text(x, y) {
                            ink
                        } else {
                            paper
                        }
                    }
                    Scene::Scroll => {
                        if text(x, y + since * (u / 4).max(1)) {
                            ink
                        } else {
                            paper
                        }
                    }
                    Scene::Motion => {
                        let a = plasma.sx[((x + since * 5) & 511) as usize];
                        let b = plasma.sy[((y + since * 3) & 511) as usize];
                        let c = plasma.sx[((x / 2 + y / 2 + since * 2) & 511) as usize];
                        plasma.palette[(a as usize + b as usize + c as usize) & 255]
                    }
                    Scene::Still => {
                        if text(x, y) {
                            ink
                        } else {
                            paper
                        }
                    }
                }
            };
        }
    }
    let fill = |buf: &mut [u32], ux: f32, uy: f32, uw: f32, uh: f32, colour: u32| {
        let x0 = (ux.max(0.0) * u as f32) as u32;
        let y0 = (uy.max(0.0) * u as f32) as u32;
        let x1 = ((ux + uw) * u as f32) as u32;
        let y1 = ((uy + uh) * u as f32) as u32;
        for y in y0..y1.min(h) {
            for x in x0..x1.min(w) {
                buf[(y * stride + x) as usize] = colour;
            }
        }
    };
    if state.scene == Scene::Typing {
        for k in 0..GRID_COLS * GRID_ROWS {
            let (gx, gy) = glyph_at(k as u16);
            let typed = (k as u16) < state.keys % (GRID_COLS * GRID_ROWS) as u16
                || (state.keys > 0 && state.keys % (GRID_COLS * GRID_ROWS) as u16 == 0);
            fill(
                buf,
                gx,
                gy,
                1.0,
                1.0,
                if typed { ink } else { rgb([0xdc, 0xdc, 0xe0]) },
            );
        }
    }
    if state.scene == Scene::Still {
        let (px, py, pw, ph) = PATCH;
        let (x0, y0) = ((px * u as f32) as u32, (py * u as f32) as u32);
        let (x1, y1) = (((px + pw) * u as f32) as u32, ((py + ph) * u as f32) as u32);
        for y in y0..y1.min(h) {
            for x in x0..x1.min(w) {
                buf[(y * stride + x) as usize] = if (x + y) & 1 == 0 { ink } else { paper };
            }
        }
    }
    if let Some((px, py)) = state.pointer {
        let (ux, uy) = (px / u as f32, py / u as f32);
        if uy > BAND {
            fill(buf, ux - 0.75, uy - 0.75, 1.5, 1.5, rgb(MAGENTA));
        }
    }
    let code = Code {
        frame: frame as u16,
        clock_ms,
        scene: state.scene,
        keys: state.keys,
    };
    for (i, on) in code.bits().into_iter().enumerate() {
        let (bx, by) = bit_at(i);
        fill(buf, bx, by, 1.0, 1.0, if on { 0xffffff } else { 0 });
    }
}

/// Where the stage sits in a received frame, in that frame's pixels.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Mapping {
    pub x0: f32,
    pub y0: f32,
    pub width: f32,
    pub height: f32,
}

impl Mapping {
    pub fn unit(&self) -> f32 {
        self.width / UNITS as f32
    }
    pub fn height_units(&self) -> f32 {
        self.height / self.unit()
    }
    /// The frame pixel at a point given in units.
    pub fn pixel(&self, ux: f32, uy: f32) -> (u32, u32) {
        let u = self.unit();
        (
            (self.x0 + ux * u).max(0.0) as u32,
            (self.y0 + uy * u).max(0.0) as u32,
        )
    }
}

/// A received frame, tightly packed RGBA.
#[derive(Clone, Copy)]
pub struct View<'a> {
    pub rgba: &'a [u8],
    pub width: u32,
    pub height: u32,
}

impl View<'_> {
    pub fn rgb(&self, x: u32, y: u32) -> [u8; 3] {
        let (x, y) = (x.min(self.width - 1), y.min(self.height - 1));
        let i = ((y * self.width + x) * 4) as usize;
        [self.rgba[i], self.rgba[i + 1], self.rgba[i + 2]]
    }
    fn luma(&self, x: u32, y: u32) -> u32 {
        let [r, g, b] = self.rgb(x, y);
        (r as u32 * 3 + g as u32 * 6 + b as u32) / 10
    }
    /// The average brightness of a few pixels around a point.
    fn luma_around(&self, x: u32, y: u32, r: u32) -> u32 {
        let mut sum = 0;
        let mut n = 0;
        for dy in 0..=2 * r {
            for dx in 0..=2 * r {
                sum += self.luma((x + dx).saturating_sub(r), (y + dy).saturating_sub(r));
                n += 1;
            }
        }
        sum / n
    }

    /// Find the stage by its teal border. `None` when it is not on screen.
    pub fn locate(&self) -> Option<Mapping> {
        let near = |p: [u8; 3]| {
            p.iter()
                .zip(TEAL)
                .all(|(&a, b)| (a as i32 - b as i32).abs() < 24)
        };
        let (mut x0, mut y0, mut x1, mut y1) = (u32::MAX, u32::MAX, 0, 0);
        let mut count = 0u64;
        for y in (0..self.height).step_by(2) {
            for x in (0..self.width).step_by(2) {
                if near(self.rgb(x, y)) {
                    x0 = x0.min(x);
                    y0 = y0.min(y);
                    x1 = x1.max(x);
                    y1 = y1.max(y);
                    count += 1;
                }
            }
        }
        if count < 200 || x1 <= x0 + 60 || y1 <= y0 + 20 {
            return None;
        }
        // Each sample stands for a two pixel square.
        Some(Mapping {
            x0: x0 as f32,
            y0: y0 as f32,
            width: (x1 + 2 - x0) as f32,
            height: (y1 + 2 - y0) as f32,
        })
    }

    pub fn code(&self, map: &Mapping) -> Option<Code> {
        let r = (map.unit() / 5.0) as u32;
        let mut bits = [false; BITS];
        for (i, bit) in bits.iter_mut().enumerate() {
            let (bx, by) = bit_at(i);
            let (x, y) = map.pixel(bx + 0.5, by + 0.5);
            *bit = self.luma_around(x, y, r) > 128;
        }
        Code::from_bits(&bits)
    }

    /// Is the pointer marker drawn at this point, given in units?
    pub fn marked(&self, map: &Mapping, ux: f32, uy: f32) -> bool {
        [(0.0, 0.0), (-0.3, -0.3), (0.3, 0.3)].iter().all(|(dx, dy)| {
            let (x, y) = map.pixel(ux + dx, uy + dy);
            let [r, g, b] = self.rgb(x, y);
            r > 190 && g < 90 && b > 190
        })
    }

    /// Is the cell for key press `k` filled?
    pub fn typed(&self, map: &Mapping, k: u16) -> bool {
        let (gx, gy) = glyph_at(k);
        let (x, y) = map.pixel(gx + 0.5, gy + 0.5);
        self.luma_around(x, y, (map.unit() / 5.0) as u32) < 100
    }

    /// The patch's pixels, as brightness, for telling when it settles.
    pub fn patch(&self, map: &Mapping) -> Vec<u8> {
        let (px, py, pw, ph) = PATCH;
        let (x0, y0) = map.pixel(px, py);
        let (x1, y1) = map.pixel(px + pw, py + ph);
        let mut out = Vec::with_capacity(((x1 - x0) * (y1 - y0)) as usize);
        for y in y0..y1 {
            for x in x0..x1 {
                out.push(self.luma(x, y) as u8);
            }
        }
        out
    }
}

/// How much fine detail a patch holds: the mean difference between
/// neighbouring pixels, which is about 200 for the checkerboard drawn
/// sharp at full size and falls as a codec smears it.
pub fn detail(patch: &[u8], width: usize) -> f32 {
    if width < 2 || patch.len() < width {
        return 0.0;
    }
    let mut sum = 0u64;
    let mut n = 0u64;
    for row in patch.chunks_exact(width) {
        for pair in row.windows(2) {
            sum += (pair[0] as i32 - pair[1] as i32).unsigned_abs() as u64;
            n += 1;
        }
    }
    sum as f32 / n.max(1) as f32
}

/// Draw a frame straight to RGBA, for an offscreen host.
pub fn render_rgba(layout: Layout, state: &StageState, frame: u32, clock_ms: u32) -> Vec<u8> {
    let mut words = vec![0u32; (layout.width * layout.height) as usize];
    render(&mut words, layout.width, layout, state, frame, clock_ms);
    words
        .iter()
        .flat_map(|p| [(p >> 16) as u8, (p >> 8) as u8, *p as u8, 255])
        .collect()
}

/// The low 32 bits of the wall clock in milliseconds, which is what the code
/// carries.
pub fn clock_ms() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(layout: Layout, state: &StageState, n: u32, clock: u32) -> Vec<u8> {
        render_rgba(layout, state, n, clock)
    }

    #[test]
    fn codes_round_trip_and_reject_damage() {
        let code = Code {
            frame: 0xbeef,
            clock_ms: 0x1234_5678,
            scene: Scene::Motion,
            keys: 77,
        };
        let mut bits = code.bits();
        assert_eq!(Code::from_bits(&bits), Some(code));
        bits[30] = !bits[30];
        assert_eq!(Code::from_bits(&bits), None);
        assert_eq!(Code::from_bits(&[false; BITS]), None);
        assert_eq!(Code::from_bits(&[true; BITS]), None);
    }

    #[test]
    fn a_client_finds_the_stage_and_reads_every_scene() {
        let layout = Layout::fit(960, 600);
        // The stage on a bigger desktop, away from the corner.
        let (dw, dh) = (1400u32, 900u32);
        for scene in Scene::ALL {
            let mut state = StageState::default();
            state.set_scene(scene, 10);
            state.pointer = Some((300.0, 400.0));
            state.keys = 5;
            let stage = frame(layout, &state, 42, 99_000);
            let mut desk = vec![40u8; (dw * dh * 4) as usize];
            for y in 0..layout.height {
                let src = &stage[(y * layout.width * 4) as usize..((y + 1) * layout.width * 4) as usize];
                let at = (((y + 100) * dw + 200) * 4) as usize;
                desk[at..at + src.len()].copy_from_slice(src);
            }
            let view = View {
                rgba: &desk,
                width: dw,
                height: dh,
            };
            let map = view.locate().expect("stage found");
            assert!((map.x0 - 200.0).abs() <= 2.0 && (map.y0 - 100.0).abs() <= 2.0, "{map:?}");
            let code = view.code(&map).expect("code reads");
            assert_eq!((code.frame, code.clock_ms, code.scene, code.keys), (42, 99_000, scene, 5));
            assert!(view.marked(&map, 300.0 / 16.0, 400.0 / 16.0), "{scene:?}");
            assert!(!view.marked(&map, 10.0, 20.0));
            if scene == Scene::Typing {
                assert!(view.typed(&map, 4) && !view.typed(&map, 5));
            }
            if scene == Scene::Still {
                let patch = view.patch(&map);
                assert!(detail(&patch, (PATCH.2 * 16.0) as usize) > 150.0);
            }
        }
    }

    #[test]
    fn a_scaled_stage_still_reads() {
        let layout = Layout::fit(1920, 1080);
        let state = StageState::default();
        let stage = frame(layout, &state, 7, 5);
        // Halve it, as a client receiving a smaller screen would see it.
        let (w, h) = (layout.width / 2, layout.height / 2);
        let mut half = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                let i = (((y * 2) * layout.width + x * 2) * 4) as usize;
                half.extend_from_slice(&stage[i..i + 4]);
            }
        }
        let view = View {
            rgba: &half,
            width: w,
            height: h,
        };
        let map = view.locate().unwrap();
        assert_eq!(view.code(&map).unwrap().frame, 7);
    }

    #[test]
    fn pointer_targets_stay_inside_the_content() {
        for n in 0..8 {
            let (x, y) = pointer_target(n, 37.5);
            assert!((2.0..58.0).contains(&x) && (BAND + 1.0..36.0).contains(&y), "{x} {y}");
        }
    }
}
