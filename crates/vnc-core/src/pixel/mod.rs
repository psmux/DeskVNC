//! Framebuffer, pixel conversion and thumbnail generation.
//!
//! Conversion, the pixel format and the downscaler moved to `remote-pixel`
//! and are re-exported here at their old paths, so every `crate::pixel::` call
//! site is unchanged (PRDRDP/02 §13 commit 1b). [`Framebuffer`] stayed: it
//! decodes JPEG rects through `crate::encodings`, which would be two
//! dependencies a crate that is meant to have none.
//!
//! Public surface (consumed by `session/` and the Tauri shell):
//! - [`Framebuffer`], RGBA8888 client-side framebuffer with rect application
//! - [`convert_to_rgba`], wire pixels -> RGBA8888
//! - [`ColourMap`], indexed-colour palette state (SetColourMapEntries)

pub mod framebuffer;

pub use framebuffer::Framebuffer;
pub use remote_pixel::{convert, thumbnail};
pub use remote_pixel::{convert_to_rgba, convert_to_rgba_mapped, downscale_rgba, ColourMap};
