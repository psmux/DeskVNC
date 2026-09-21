#![forbid(unsafe_code)]

mod session;
mod wire;
use anyhow::{Result, ensure};
use image::{ImageDecoder, ImageEncoder};
pub use session::{
    Approval, Connectivity, Event, HostOptions, Route, Session, host, validate_relay_url, viewer,
};
use std::io::Cursor;
pub use wire::{Button, Input, Invitation, Key};

/// Implemented by a local platform backend, created only after consent.
pub trait Desktop {
    fn capture(&mut self) -> Result<Frame>;
    fn input(&mut self, input: Input) -> Result<()>;
    fn release(&mut self);
}
#[derive(Clone, Debug)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}
impl Frame {
    pub fn validate(&self) -> Result<()> {
        dimensions(self.width, self.height)?;
        ensure!(
            self.rgba.len() as u64 == self.width as u64 * self.height as u64 * 4,
            "Invalid frame buffer"
        );
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new_with_quality(
            &mut bytes,
            image::codecs::png::CompressionType::Fast,
            image::codecs::png::FilterType::Adaptive,
        )
        .write_image(
            &self.rgba,
            self.width,
            self.height,
            image::ExtendedColorType::Rgba8,
        )?;
        ensure!(
            bytes.len() <= wire::MAX_FRAME,
            "Encoded screen is too large"
        );
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= wire::MAX_FRAME, "Screen packet is too large");
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(wire::MAX_SIDE);
        limits.max_image_height = Some(wire::MAX_SIDE);
        limits.max_alloc = Some(64 * 1024 * 1024);
        let decoder = image::codecs::png::PngDecoder::with_limits(Cursor::new(bytes), limits)?;
        let (width, height) = decoder.dimensions();
        dimensions(width, height)?;
        let rgba = image::DynamicImage::from_decoder(decoder)?
            .into_rgba8()
            .into_raw();
        Ok(Self {
            width,
            height,
            rgba,
        })
    }
}
fn dimensions(width: u32, height: u32) -> Result<()> {
    ensure!(
        width > 0
            && height > 0
            && width <= wire::MAX_SIDE
            && height <= wire::MAX_SIDE
            && width as u64 * height as u64 <= wire::MAX_PIXELS,
        "Screen dimensions exceed limits"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_are_lossless_and_bounded() {
        let frame = Frame {
            width: 2,
            height: 1,
            rgba: vec![12, 34, 56, 255, 7, 8, 9, 255],
        };
        assert_eq!(
            Frame::decode(&frame.encode().unwrap()).unwrap().rgba,
            frame.rgba
        );
        assert!(
            Frame {
                width: u32::MAX,
                height: 1,
                rgba: vec![]
            }
            .encode()
            .is_err()
        );
        assert!(Frame::decode(b"untrusted bytes").is_err());
    }
}
