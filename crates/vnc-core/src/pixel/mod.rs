//! Framebuffer, pixel conversion and thumbnail generation.
//!
//! Public surface (consumed by `session/` and the Tauri shell):
//! - [`Framebuffer`], RGBA8888 client-side framebuffer with rect application
//! - [`convert_to_rgba`], wire pixels -> RGBA8888
//! - [`ColourMap`], indexed-colour palette state (SetColourMapEntries)

pub mod convert;
pub mod framebuffer;
pub mod thumbnail;

pub use convert::{convert_to_rgba, convert_to_rgba_mapped, ColourMap};
pub use framebuffer::Framebuffer;
pub use thumbnail::downscale_rgba;
