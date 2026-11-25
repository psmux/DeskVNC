//! A screen buffer in the graphics card's own layout, read back as plain
//! pixels by the graphics card.
//!
//! Intel and AMD scan out buffers that are tiled, and often compressed, in
//! a layout only their driver knows. Mesa does: the buffer is imported as an
//! EGL image (EGL_EXT_image_dma_buf_import, with its modifier), drawn into a
//! plain RGBA texture by OpenGL ES, and read back. The libraries are loaded
//! when first needed, so the program still starts where they are missing
//! and the caller says why the screen cannot be read.

use anyhow::{Context, Result, bail, ensure};
use std::ffi::{CStr, c_char, c_void};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::OnceLock;

type Ptr = *mut c_void;

/// A table of C functions looked up by name.
macro_rules! api {
    ($name:ident { $($f:ident : fn($($a:ty),*) $(-> $r:ty)?;)* }) => {
        #[allow(non_snake_case)]
        pub(crate) struct $name { $(pub $f: unsafe extern "C" fn($($a),*) $(-> $r)?,)* }
        impl $name {
            /// # Safety
            /// `get` returns the address of the function of that name, with
            /// the signature written here, or null.
            pub unsafe fn load(get: &dyn Fn(&CStr) -> Ptr) -> Result<Self> {
                Ok(Self { $($f: {
                    let name = CStr::from_bytes_with_nul(concat!(stringify!($f), "\0").as_bytes())
                        .expect("a C name");
                    let p = get(name);
                    ensure!(!p.is_null(), "{} is missing", stringify!($f));
                    // SAFETY: the caller's promise above.
                    unsafe { std::mem::transmute::<Ptr, unsafe extern "C" fn($($a),*) $(-> $r)?>(p) }
                },)* })
            }
        }
    };
}
pub(crate) use api;

/// A shared library, opened for good: GL drivers do not like being closed.
pub(crate) fn open_library(names: &[&CStr]) -> Result<Ptr> {
    for name in names {
        // SAFETY: a NUL terminated name; the handle is never closed.
        let lib = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if !lib.is_null() {
            return Ok(lib);
        }
    }
    bail!(
        "{} is not installed",
        names[0].to_string_lossy().trim_end_matches(".1")
    )
}

pub(crate) fn symbol(lib: Ptr) -> impl Fn(&CStr) -> Ptr {
    // SAFETY: `lib` is an open handle and `name` NUL terminated.
    move |name| unsafe { libc::dlsym(lib, name.as_ptr()) }
}

api!(Egl {
    eglGetProcAddress: fn(*const c_char) -> Ptr;
    eglGetError: fn() -> i32;
    eglQueryString: fn(Ptr, i32) -> *const c_char;
    eglGetDisplay: fn(Ptr) -> Ptr;
    eglInitialize: fn(Ptr, *mut i32, *mut i32) -> u32;
    eglBindAPI: fn(u32) -> u32;
    eglChooseConfig: fn(Ptr, *const i32, *mut Ptr, i32, *mut i32) -> u32;
    eglCreateContext: fn(Ptr, Ptr, Ptr, *const i32) -> Ptr;
    eglDestroyContext: fn(Ptr, Ptr) -> u32;
    eglMakeCurrent: fn(Ptr, Ptr, Ptr, Ptr) -> u32;
});

api!(Image {
    eglCreateImageKHR: fn(Ptr, Ptr, u32, Ptr, *const i32) -> Ptr;
    eglDestroyImageKHR: fn(Ptr, Ptr) -> u32;
    glEGLImageTargetTexture2DOES: fn(u32, Ptr);
});

api!(Gl {
    glGetError: fn() -> u32;
    glGetString: fn(u32) -> *const u8;
    glGenTextures: fn(i32, *mut u32);
    glDeleteTextures: fn(i32, *const u32);
    glBindTexture: fn(u32, u32);
    glTexParameteri: fn(u32, u32, i32);
    glTexImage2D: fn(u32, i32, i32, i32, i32, i32, u32, u32, *const c_void);
    glActiveTexture: fn(u32);
    glGenFramebuffers: fn(i32, *mut u32);
    glDeleteFramebuffers: fn(i32, *const u32);
    glBindFramebuffer: fn(u32, u32);
    glFramebufferTexture2D: fn(u32, u32, u32, u32, i32);
    glCheckFramebufferStatus: fn(u32) -> u32;
    glCreateShader: fn(u32) -> u32;
    glShaderSource: fn(u32, i32, *const *const c_char, *const i32);
    glCompileShader: fn(u32);
    glGetShaderiv: fn(u32, u32, *mut i32);
    glGetShaderInfoLog: fn(u32, i32, *mut i32, *mut c_char);
    glCreateProgram: fn() -> u32;
    glAttachShader: fn(u32, u32);
    glBindAttribLocation: fn(u32, u32, *const c_char);
    glLinkProgram: fn(u32);
    glGetProgramiv: fn(u32, u32, *mut i32);
    glUseProgram: fn(u32);
    glDeleteProgram: fn(u32);
    glGetUniformLocation: fn(u32, *const c_char) -> i32;
    glUniform1i: fn(i32, i32);
    glUniform4f: fn(i32, f32, f32, f32, f32);
    glBindBuffer: fn(u32, u32);
    glVertexAttribPointer: fn(u32, i32, u32, u8, i32, *const c_void);
    glEnableVertexAttribArray: fn(u32);
    glViewport: fn(i32, i32, i32, i32);
    glDrawArrays: fn(u32, i32, i32);
    glPixelStorei: fn(u32, i32);
    glReadPixels: fn(i32, i32, i32, i32, u32, u32, *mut c_void);
});

type GetPlatformDisplay = unsafe extern "C" fn(u32, Ptr, *const i32) -> Ptr;
type QueryDevices = unsafe extern "C" fn(i32, *mut Ptr, *mut i32) -> u32;
type QueryDeviceString = unsafe extern "C" fn(Ptr, i32) -> *const c_char;

const EGL_NONE: i32 = 0x3038;
const EGL_EXTENSIONS: i32 = 0x3055;
const EGL_OPENGL_ES_API: u32 = 0x30A0;
const EGL_CONTEXT_CLIENT_VERSION: i32 = 0x3098;
const EGL_RENDERABLE_TYPE: i32 = 0x3040;
const EGL_OPENGL_ES2_BIT: i32 = 4;
const EGL_SURFACE_TYPE: i32 = 0x3033;
const EGL_PBUFFER_BIT: i32 = 1;
const EGL_PLATFORM_DEVICE_EXT: u32 = 0x313F;
const EGL_PLATFORM_SURFACELESS_MESA: u32 = 0x31DD;
const EGL_DRM_DEVICE_FILE_EXT: i32 = 0x3233;
const EGL_DRM_RENDER_NODE_FILE_EXT: i32 = 0x3377;
const EGL_LINUX_DMA_BUF_EXT: u32 = 0x3270;
const EGL_WIDTH: i32 = 0x3057;
const EGL_HEIGHT: i32 = 0x3056;
const EGL_LINUX_DRM_FOURCC_EXT: i32 = 0x3271;
const EGL_IMAGE_PRESERVED_KHR: i32 = 0x30D2;
/// FD, offset, pitch, modifier low and high, for each of four planes.
const PLANE_ATTRS: [[i32; 5]; 4] = [
    [0x3272, 0x3273, 0x3274, 0x3443, 0x3444],
    [0x3275, 0x3276, 0x3277, 0x3445, 0x3446],
    [0x3278, 0x3279, 0x327A, 0x3447, 0x3448],
    [0x3440, 0x3441, 0x3442, 0x3449, 0x344A],
];

const GL_EXTENSIONS: u32 = 0x1F03;
const GL_RENDERER: u32 = 0x1F01;
const GL_TEXTURE_2D: u32 = 0x0DE1;
const GL_TEXTURE_EXTERNAL_OES: u32 = 0x8D65;
const GL_TEXTURE_MIN_FILTER: u32 = 0x2801;
const GL_TEXTURE_MAG_FILTER: u32 = 0x2800;
const GL_TEXTURE_WRAP_S: u32 = 0x2802;
const GL_TEXTURE_WRAP_T: u32 = 0x2803;
const GL_NEAREST: i32 = 0x2600;
const GL_CLAMP_TO_EDGE: i32 = 0x812F;
const GL_RGBA: u32 = 0x1908;
const GL_UNSIGNED_BYTE: u32 = 0x1401;
const GL_FLOAT: u32 = 0x1406;
const GL_FRAMEBUFFER: u32 = 0x8D40;
const GL_COLOR_ATTACHMENT0: u32 = 0x8CE0;
const GL_FRAMEBUFFER_COMPLETE: u32 = 0x8CD5;
const GL_VERTEX_SHADER: u32 = 0x8B31;
const GL_FRAGMENT_SHADER: u32 = 0x8B30;
const GL_COMPILE_STATUS: u32 = 0x8B81;
const GL_LINK_STATUS: u32 = 0x8B82;
const GL_TRIANGLE_STRIP: u32 = 5;
const GL_TEXTURE0: u32 = 0x84C0;
const GL_PACK_ALIGNMENT: u32 = 0x0D05;
const GL_ARRAY_BUFFER: u32 = 0x8892;

const VERTEX: &CStr = c"attribute vec2 p;
uniform vec4 r;
varying vec2 t;
void main() {
    t = r.xy + (p * 0.5 + 0.5) * r.zw;
    gl_Position = vec4(p, 0.0, 1.0);
}";
const FRAGMENT_EXTERNAL: &CStr = c"#extension GL_OES_EGL_image_external : require
#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif
uniform samplerExternalOES s;
varying vec2 t;
void main() { gl_FragColor = texture2D(s, t); }";
const FRAGMENT_2D: &CStr = c"#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif
uniform sampler2D s;
varying vec2 t;
void main() { gl_FragColor = texture2D(s, t); }";

struct Apis {
    egl: Egl,
    gl: Gl,
    image: Image,
    get_platform_display: Option<GetPlatformDisplay>,
    query_devices: Option<QueryDevices>,
    query_device_string: Option<QueryDeviceString>,
}
// SAFETY: plain function pointers.
unsafe impl Send for Apis {}
unsafe impl Sync for Apis {}

fn apis() -> Result<&'static Apis> {
    static APIS: OnceLock<std::result::Result<Apis, String>> = OnceLock::new();
    APIS.get_or_init(|| load().map_err(|e| format!("{e:#}")))
        .as_ref()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn load() -> Result<Apis> {
    let egl_lib = open_library(&[c"libEGL.so.1", c"libEGL.so"])?;
    let gl_lib = open_library(&[c"libGLESv2.so.2", c"libGLESv2.so"])?;
    // SAFETY: names from the EGL and GLES headers, with their signatures.
    unsafe {
        let egl = Egl::load(&symbol(egl_lib))?;
        let get_proc = egl.eglGetProcAddress;
        let proc = move |name: &CStr| get_proc(name.as_ptr());
        let gl_sym = symbol(gl_lib);
        let gl = Gl::load(&|name: &CStr| {
            let p = gl_sym(name);
            if p.is_null() { proc(name) } else { p }
        })?;
        let image = Image::load(&proc).context("This EGL cannot import a screen buffer")?;
        let opt = |name: &CStr| {
            let p = proc(name);
            (!p.is_null()).then_some(p)
        };
        Ok(Apis {
            get_platform_display: opt(c"eglGetPlatformDisplayEXT")
                .map(|p| std::mem::transmute::<Ptr, GetPlatformDisplay>(p)),
            query_devices: opt(c"eglQueryDevicesEXT")
                .map(|p| std::mem::transmute::<Ptr, QueryDevices>(p)),
            query_device_string: opt(c"eglQueryDeviceStringEXT")
                .map(|p| std::mem::transmute::<Ptr, QueryDeviceString>(p)),
            egl,
            gl,
            image,
        })
    }
}

fn has(list: *const c_char, name: &str) -> bool {
    if list.is_null() {
        return false;
    }
    // SAFETY: EGL and GL extension strings are NUL terminated.
    let list = unsafe { CStr::from_ptr(list) }.to_string_lossy();
    list.split_ascii_whitespace().any(|e| e == name)
}

/// One plane of a buffer as the kernel exported it.
pub(crate) struct DmaPlane {
    pub fd: OwnedFd,
    pub offset: u32,
    pub pitch: u32,
}

/// A buffer to read: its size, DRM fourcc, modifier (`None` when the
/// driver knows it from the buffer itself) and planes.
pub(crate) struct DmaBuf {
    pub width: u32,
    pub height: u32,
    pub fourcc: u32,
    pub modifier: Option<u64>,
    pub planes: Vec<DmaPlane>,
}

/// A region of a buffer, in its pixels.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Region {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

/// An OpenGL ES context on the graphics card, with nowhere to draw but its
/// own texture.
pub(crate) struct Gpu {
    api: &'static Apis,
    display: Ptr,
    context: Ptr,
    modifiers: bool,
    target: u32,
    program: u32,
    rect: i32,
    /// Framebuffer and texture to draw into, at their size.
    canvas: Option<(u32, u32, u32, u32)>,
    /// Which card and renderer, for the log.
    pub name: String,
}

impl Gpu {
    /// A context on the card at `card` (`/dev/dri/cardN`), or on whatever
    /// Mesa finds when EGL cannot tell its devices apart.
    pub fn new(card: &str) -> Result<Self> {
        let api = apis()?;
        let (display, how) = Self::display(api, card)?;
        let egl = &api.egl;
        // SAFETY: EGL calls on a display EGL gave, with NONE ended lists.
        unsafe {
            let (mut major, mut minor) = (0, 0);
            ensure!(
                (egl.eglInitialize)(display, &mut major, &mut minor) != 0,
                "EGL would not start ({:#x})",
                (egl.eglGetError)()
            );
            let ext = (egl.eglQueryString)(display, EGL_EXTENSIONS);
            ensure!(
                has(ext, "EGL_EXT_image_dma_buf_import"),
                "This EGL cannot import a screen buffer (no EGL_EXT_image_dma_buf_import)"
            );
            ensure!(
                has(ext, "EGL_KHR_surfaceless_context"),
                "This EGL cannot draw without a window (no EGL_KHR_surfaceless_context)"
            );
            let modifiers = has(ext, "EGL_EXT_image_dma_buf_import_modifiers");
            ensure!((egl.eglBindAPI)(EGL_OPENGL_ES_API) != 0, "No OpenGL ES");
            let mut config: Ptr = std::ptr::null_mut();
            if !has(ext, "EGL_KHR_no_config_context") {
                let want = [
                    EGL_RENDERABLE_TYPE,
                    EGL_OPENGL_ES2_BIT,
                    EGL_SURFACE_TYPE,
                    EGL_PBUFFER_BIT,
                    EGL_NONE,
                ];
                let mut n = 0;
                ensure!(
                    (egl.eglChooseConfig)(display, want.as_ptr(), &mut config, 1, &mut n) != 0
                        && n > 0,
                    "No OpenGL ES configuration"
                );
            }
            let attrs = [EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE];
            let context =
                (egl.eglCreateContext)(display, config, std::ptr::null_mut(), attrs.as_ptr());
            ensure!(
                !context.is_null(),
                "No OpenGL ES context ({:#x})",
                (egl.eglGetError)()
            );
            let mut gpu = Self {
                api,
                display,
                context,
                modifiers,
                target: GL_TEXTURE_2D,
                program: 0,
                rect: -1,
                canvas: None,
                name: how,
            };
            gpu.current()?;
            let gl = &api.gl;
            let renderer = (gl.glGetString)(GL_RENDERER);
            if !renderer.is_null() {
                let r = CStr::from_ptr(renderer.cast()).to_string_lossy();
                gpu.name = format!("{} ({r})", gpu.name);
            }
            let external = has(
                (gl.glGetString)(GL_EXTENSIONS).cast(),
                "GL_OES_EGL_image_external",
            );
            if external {
                gpu.target = GL_TEXTURE_EXTERNAL_OES;
            }
            gpu.program = gpu.build(if external {
                FRAGMENT_EXTERNAL
            } else {
                FRAGMENT_2D
            })?;
            gpu.rect = (gl.glGetUniformLocation)(gpu.program, c"r".as_ptr());
            Ok(gpu)
        }
    }

    /// The EGL display on `card`'s device when EGL can say which device is
    /// which, else Mesa's surfaceless platform, else the default.
    fn display(api: &Apis, card: &str) -> Result<(Ptr, String)> {
        let egl = &api.egl;
        // SAFETY: EGL calls with the arguments their extensions define.
        unsafe {
            let client = (egl.eglQueryString)(std::ptr::null_mut(), EGL_EXTENSIONS);
            let wanted = std::fs::canonicalize(card).ok();
            if let (Some(get), Some(devices), Some(string)) = (
                api.get_platform_display,
                api.query_devices,
                api.query_device_string,
            ) && has(client, "EGL_EXT_platform_device")
            {
                let mut list = [std::ptr::null_mut(); 16];
                let mut n = 0;
                if devices(list.len() as i32, list.as_mut_ptr(), &mut n) != 0 {
                    for &device in &list[..n.max(0) as usize] {
                        for which in [EGL_DRM_DEVICE_FILE_EXT, EGL_DRM_RENDER_NODE_FILE_EXT] {
                            let file = string(device, which);
                            if file.is_null() {
                                continue;
                            }
                            let file = CStr::from_ptr(file).to_string_lossy().into_owned();
                            if std::fs::canonicalize(&file).ok() == wanted && wanted.is_some() {
                                let display =
                                    get(EGL_PLATFORM_DEVICE_EXT, device, [EGL_NONE].as_ptr());
                                if !display.is_null() {
                                    return Ok((display, format!("EGL on {file}")));
                                }
                            }
                        }
                    }
                }
            }
            if let Some(get) = api.get_platform_display
                && has(client, "EGL_MESA_platform_surfaceless")
            {
                let display = get(
                    EGL_PLATFORM_SURFACELESS_MESA,
                    std::ptr::null_mut(),
                    [EGL_NONE].as_ptr(),
                );
                if !display.is_null() {
                    return Ok((display, "EGL, surfaceless".into()));
                }
            }
            let display = (egl.eglGetDisplay)(std::ptr::null_mut());
            ensure!(!display.is_null(), "No EGL display");
            Ok((display, "EGL, default display".into()))
        }
    }

    fn current(&self) -> Result<()> {
        let egl = &self.api.egl;
        // SAFETY: a display and context made in `new`.
        unsafe {
            ensure!(
                (egl.eglMakeCurrent)(
                    self.display,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    self.context
                ) != 0,
                "The OpenGL ES context would not start ({:#x})",
                (egl.eglGetError)()
            );
        }
        Ok(())
    }

    unsafe fn build(&self, fragment: &CStr) -> Result<u32> {
        let gl = &self.api.gl;
        let shader = |kind, source: &CStr| -> Result<u32> {
            // SAFETY: GL calls on the current context.
            unsafe {
                let s = (gl.glCreateShader)(kind);
                let p = source.as_ptr();
                (gl.glShaderSource)(s, 1, &p, std::ptr::null());
                (gl.glCompileShader)(s);
                let mut ok = 0;
                (gl.glGetShaderiv)(s, GL_COMPILE_STATUS, &mut ok);
                if ok == 0 {
                    let mut log = [0 as c_char; 512];
                    let mut len = 0;
                    (gl.glGetShaderInfoLog)(s, log.len() as i32, &mut len, log.as_mut_ptr());
                    bail!(
                        "A shader did not compile: {}",
                        CStr::from_ptr(log.as_ptr()).to_string_lossy()
                    );
                }
                Ok(s)
            }
        };
        let vs = shader(GL_VERTEX_SHADER, VERTEX)?;
        let fs = shader(GL_FRAGMENT_SHADER, fragment)?;
        // SAFETY: as above.
        unsafe {
            let program = (gl.glCreateProgram)();
            (gl.glAttachShader)(program, vs);
            (gl.glAttachShader)(program, fs);
            (gl.glBindAttribLocation)(program, 0, c"p".as_ptr());
            (gl.glLinkProgram)(program);
            let mut ok = 0;
            (gl.glGetProgramiv)(program, GL_LINK_STATUS, &mut ok);
            ensure!(ok != 0, "The shaders did not link");
            Ok(program)
        }
    }

    /// A framebuffer of `w` by `h` to draw into, bound.
    unsafe fn canvas(&mut self, w: u32, h: u32) -> Result<()> {
        let gl = &self.api.gl;
        // SAFETY: GL calls on the current context.
        unsafe {
            if let Some((fbo, tex, cw, ch)) = self.canvas {
                if (cw, ch) == (w, h) {
                    (gl.glBindFramebuffer)(GL_FRAMEBUFFER, fbo);
                    return Ok(());
                }
                (gl.glDeleteFramebuffers)(1, &fbo);
                (gl.glDeleteTextures)(1, &tex);
                self.canvas = None;
            }
            let (mut fbo, mut tex) = (0, 0);
            (gl.glGenTextures)(1, &mut tex);
            (gl.glBindTexture)(GL_TEXTURE_2D, tex);
            (gl.glTexImage2D)(
                GL_TEXTURE_2D,
                0,
                GL_RGBA as i32,
                w as i32,
                h as i32,
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                std::ptr::null(),
            );
            (gl.glGenFramebuffers)(1, &mut fbo);
            (gl.glBindFramebuffer)(GL_FRAMEBUFFER, fbo);
            (gl.glFramebufferTexture2D)(
                GL_FRAMEBUFFER,
                GL_COLOR_ATTACHMENT0,
                GL_TEXTURE_2D,
                tex,
                0,
            );
            self.canvas = Some((fbo, tex, w, h));
            ensure!(
                (gl.glCheckFramebufferStatus)(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE,
                "Cannot draw into a {w}x{h} picture"
            );
        }
        Ok(())
    }

    /// `region` of `buf` as RGBA, top row first, with the alpha the buffer
    /// has (opaque for an X format).
    pub fn read(&mut self, buf: &DmaBuf, region: Region) -> Result<Vec<u8>> {
        ensure!(
            !buf.planes.is_empty() && buf.planes.len() <= 4,
            "Odd buffer"
        );
        ensure!(
            region.w > 0
                && region.h > 0
                && region.x + region.w <= buf.width
                && region.y + region.h <= buf.height,
            "The region is outside the buffer"
        );
        let explicit = buf.modifier.filter(|&m| m != super::kms::MOD_INVALID);
        if let Some(m) = explicit
            && m != 0
            && !self.modifiers
        {
            bail!(
                "This EGL cannot import a tiled buffer ({m:#x}); it lacks EGL_EXT_image_dma_buf_import_modifiers"
            );
        }
        self.current()?;
        let mut attrs = vec![
            EGL_WIDTH,
            buf.width as i32,
            EGL_HEIGHT,
            buf.height as i32,
            EGL_LINUX_DRM_FOURCC_EXT,
            buf.fourcc as i32,
            EGL_IMAGE_PRESERVED_KHR,
            1,
        ];
        for (plane, names) in buf.planes.iter().zip(PLANE_ATTRS) {
            attrs.extend_from_slice(&[
                names[0],
                plane.fd.as_raw_fd(),
                names[1],
                plane.offset as i32,
                names[2],
                plane.pitch as i32,
            ]);
            if let Some(m) = explicit.filter(|_| self.modifiers) {
                attrs.extend_from_slice(&[
                    names[3],
                    (m & 0xffff_ffff) as u32 as i32,
                    names[4],
                    (m >> 32) as u32 as i32,
                ]);
            }
        }
        attrs.push(EGL_NONE);
        let (egl, gl, image_api) = (&self.api.egl, &self.api.gl, &self.api.image);
        // SAFETY: GL and EGL calls on the current context; the image and
        // texture made here are freed before returning.
        unsafe {
            let image = (image_api.eglCreateImageKHR)(
                self.display,
                std::ptr::null_mut(),
                EGL_LINUX_DMA_BUF_EXT,
                std::ptr::null_mut(),
                attrs.as_ptr(),
            );
            ensure!(
                !image.is_null(),
                "The graphics card would not import its screen buffer ({:#x}, format {:#x}, modifier {:#x})",
                (egl.eglGetError)(),
                buf.fourcc,
                buf.modifier.unwrap_or(super::kms::MOD_INVALID)
            );
            while (gl.glGetError)() != 0 {}
            let mut tex = 0;
            (gl.glGenTextures)(1, &mut tex);
            (gl.glActiveTexture)(GL_TEXTURE0);
            (gl.glBindTexture)(self.target, tex);
            (image_api.glEGLImageTargetTexture2DOES)(self.target, image);
            for (k, v) in [
                (GL_TEXTURE_MIN_FILTER, GL_NEAREST),
                (GL_TEXTURE_MAG_FILTER, GL_NEAREST),
                (GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE),
                (GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE),
            ] {
                (gl.glTexParameteri)(self.target, k, v);
            }
            let result = self.draw(buf, region);
            (gl.glDeleteTextures)(1, &tex);
            (image_api.eglDestroyImageKHR)(self.display, image);
            result
        }
    }

    unsafe fn draw(&mut self, buf: &DmaBuf, r: Region) -> Result<Vec<u8>> {
        // SAFETY: GL calls on the current context, the texture bound.
        unsafe {
            self.canvas(r.w, r.h)?;
            let gl = &self.api.gl;
            (gl.glViewport)(0, 0, r.w as i32, r.h as i32);
            (gl.glUseProgram)(self.program);
            (gl.glUniform1i)((gl.glGetUniformLocation)(self.program, c"s".as_ptr()), 0);
            let (bw, bh) = (buf.width as f32, buf.height as f32);
            (gl.glUniform4f)(
                self.rect,
                r.x as f32 / bw,
                r.y as f32 / bh,
                r.w as f32 / bw,
                r.h as f32 / bh,
            );
            // Row 0 of the picture is window row 0 and texture row 0, so
            // glReadPixels hands it back top row first.
            let quad: [f32; 8] = [-1.0, -1.0, 1.0, -1.0, -1.0, 1.0, 1.0, 1.0];
            (gl.glBindBuffer)(GL_ARRAY_BUFFER, 0);
            (gl.glVertexAttribPointer)(0, 2, GL_FLOAT, 0, 0, quad.as_ptr().cast());
            (gl.glEnableVertexAttribArray)(0);
            (gl.glDrawArrays)(GL_TRIANGLE_STRIP, 0, 4);
            let mut rgba = vec![0u8; r.w as usize * r.h as usize * 4];
            (gl.glPixelStorei)(GL_PACK_ALIGNMENT, 1);
            (gl.glReadPixels)(
                0,
                0,
                r.w as i32,
                r.h as i32,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                rgba.as_mut_ptr().cast(),
            );
            let error = (gl.glGetError)();
            ensure!(
                error == 0,
                "The graphics card could not read its screen buffer (GL error {error:#x})"
            );
            Ok(rgba)
        }
    }
}

impl Drop for Gpu {
    fn drop(&mut self) {
        // The display is shared by every context on the device, so it is
        // left initialised; only this context goes.
        // SAFETY: objects this made, on its own context.
        unsafe {
            if self.current().is_ok() {
                let gl = &self.api.gl;
                if let Some((fbo, tex, _, _)) = self.canvas.take() {
                    (gl.glDeleteFramebuffers)(1, &fbo);
                    (gl.glDeleteTextures)(1, &tex);
                }
                if self.program != 0 {
                    (gl.glDeleteProgram)(self.program);
                }
            }
            let egl = &self.api.egl;
            (egl.eglMakeCurrent)(
                self.display,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            (egl.eglDestroyContext)(self.display, self.context);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    type ExportQuery = unsafe extern "C" fn(Ptr, Ptr, *mut i32, *mut i32, *mut u64) -> u32;
    type Export = unsafe extern "C" fn(Ptr, Ptr, *mut i32, *mut i32, *mut i32) -> u32;
    const EGL_GL_TEXTURE_2D_KHR: u32 = 0x30B1;

    /// A picture no two pixels of which are alike nearby, so a wrongly
    /// untiled buffer cannot pass.
    pub fn pattern(w: u32, h: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                out.extend_from_slice(&[
                    (x * 7 + y * 3) as u8,
                    (y * 5) as u8 ^ (x as u8),
                    ((x ^ y) * 11) as u8,
                    255,
                ]);
            }
        }
        out
    }

    /// The card puts a picture in a texture in its own layout, which is
    /// tiled on Intel and AMD; exported as a dma-buf, with the modifier the
    /// driver chose, and read back through `Gpu::read`, it is the same
    /// picture. Skipped where there is no EGL that can export, which says
    /// why on stderr.
    #[test]
    fn a_buffer_in_the_cards_own_layout_reads_back_plain() {
        let card = std::env::var("DESKVNC_TEST_CARD").unwrap_or_else(|_| {
            (0..8)
                .map(|n| format!("/dev/dri/card{n}"))
                .find(|p| std::path::Path::new(p).exists())
                .unwrap_or_default()
        });
        let mut gpu = match Gpu::new(&card) {
            Ok(gpu) => gpu,
            Err(error) => {
                eprintln!("skipped: no EGL here ({error:#})");
                return;
            }
        };
        let (w, h) = (333u32, 217u32);
        let want = pattern(w, h);
        // SAFETY: GL and EGL calls on the context `gpu` made current.
        let exported = unsafe {
            let api = gpu.api;
            let get = |n: &CStr| (api.egl.eglGetProcAddress)(n.as_ptr());
            let (q, e) = (
                get(c"eglExportDMABUFImageQueryMESA"),
                get(c"eglExportDMABUFImageMESA"),
            );
            if q.is_null() || e.is_null() {
                eprintln!("skipped: this EGL cannot export a buffer");
                return;
            }
            let query = std::mem::transmute::<Ptr, ExportQuery>(q);
            let export = std::mem::transmute::<Ptr, Export>(e);
            gpu.current().unwrap();
            let gl = &api.gl;
            let mut tex = 0;
            (gl.glGenTextures)(1, &mut tex);
            (gl.glBindTexture)(GL_TEXTURE_2D, tex);
            (gl.glTexImage2D)(
                GL_TEXTURE_2D,
                0,
                GL_RGBA as i32,
                w as i32,
                h as i32,
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                want.as_ptr().cast(),
            );
            let image = (api.image.eglCreateImageKHR)(
                gpu.display,
                gpu.context,
                EGL_GL_TEXTURE_2D_KHR,
                tex as usize as Ptr,
                [EGL_NONE].as_ptr(),
            );
            assert!(!image.is_null(), "no image of the texture");
            let (mut fourcc, mut planes, mut modifier) = (0, 0, 0u64);
            if query(gpu.display, image, &mut fourcc, &mut planes, &mut modifier) == 0 {
                eprintln!("skipped: the driver would not export this texture");
                return;
            }
            let (mut fds, mut strides, mut offsets) = ([-1; 4], [0; 4], [0; 4]);
            assert!(
                export(
                    gpu.display,
                    image,
                    fds.as_mut_ptr(),
                    strides.as_mut_ptr(),
                    offsets.as_mut_ptr()
                ) != 0
            );
            (api.image.eglDestroyImageKHR)(gpu.display, image);
            (gl.glDeleteTextures)(1, &tex);
            if fds[0] < 0 {
                // A software renderer can say yes and hand back nothing.
                eprintln!("skipped: {} exported no buffer", gpu.name);
                return;
            }
            eprintln!(
                "exported {w}x{h} as {:?} with modifier {modifier:#x} in {planes} plane(s) on {}",
                fourcc.to_le_bytes().map(|b| b as char),
                gpu.name
            );
            let buf = DmaBuf {
                width: w,
                height: h,
                fourcc: fourcc as u32,
                modifier: Some(modifier),
                planes: (0..planes.clamp(1, 4) as usize)
                    .map(|i| DmaPlane {
                        // A plane may share the first one's descriptor.
                        fd: OwnedFd::from_raw_fd(libc::dup(if fds[i] >= 0 {
                            fds[i]
                        } else {
                            fds[0]
                        })),
                        offset: offsets[i] as u32,
                        pitch: strides[i] as u32,
                    })
                    .collect(),
            };
            for fd in fds.into_iter().filter(|&fd| fd >= 0) {
                libc::close(fd);
            }
            buf
        };
        let got = gpu.read(&exported, Region { x: 0, y: 0, w, h }).unwrap();
        assert!(got == want, "the picture came back changed");
        // And a region of it, as a screen's source rectangle crops.
        let r = Region {
            x: 10,
            y: 20,
            w: 100,
            h: 50,
        };
        let part = gpu.read(&exported, r).unwrap();
        for row in 0..r.h {
            let a = ((row + r.y) * w + r.x) as usize * 4;
            let b = (row * r.w) as usize * 4;
            assert_eq!(
                &part[b..b + r.w as usize * 4],
                &want[a..a + r.w as usize * 4],
                "row {row} of the region"
            );
        }
    }
}
