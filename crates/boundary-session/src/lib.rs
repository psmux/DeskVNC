#![forbid(unsafe_code)]

mod dns;
mod session;
pub mod tools;
pub mod unattended;
mod wire;
use anyhow::{Result, ensure};
use image::{ImageDecoder, ImageEncoder};
pub use session::{
    Approval, Connectivity, Event, HostOptions, Route, Session, host, validate_relay_url, viewer,
    viewer_as, viewer_with_tools,
};
use std::io::Cursor;

/// JPEG quality for screens: small enough for a cellular uplink, sharp
/// enough to read text.
const JPEG_QUALITY: u8 = 70;
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
    /// The screen as JPEG, for a helper that said it takes one. A whole
    /// screen is a tenth the size of the PNG, which is what keeps the picture
    /// moving on a slow uplink. Text stays readable at this quality.
    pub fn encode_jpeg(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let rgb: Vec<u8> = self
            .rgba
            .as_chunks::<4>()
            .0
            .iter()
            .flat_map(|p| [p[0], p[1], p[2]])
            .collect();
        let mut bytes = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, JPEG_QUALITY).write_image(
            &rgb,
            self.width,
            self.height,
            image::ExtendedColorType::Rgb8,
        )?;
        ensure!(
            bytes.len() <= wire::MAX_FRAME,
            "Encoded screen is too large"
        );
        Ok(bytes)
    }
    /// A PNG or a JPEG screen, told apart by its first bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= wire::MAX_FRAME, "Screen packet is too large");
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(wire::MAX_SIDE);
        limits.max_image_height = Some(wire::MAX_SIDE);
        limits.max_alloc = Some(64 * 1024 * 1024);
        let image = if bytes.starts_with(&[0xff, 0xd8]) {
            let mut decoder = image::codecs::jpeg::JpegDecoder::new(Cursor::new(bytes))?;
            decoder.set_limits(limits)?;
            let (width, height) = decoder.dimensions();
            dimensions(width, height)?;
            image::DynamicImage::from_decoder(decoder)?
        } else {
            let decoder = image::codecs::png::PngDecoder::with_limits(Cursor::new(bytes), limits)?;
            let (width, height) = decoder.dimensions();
            dimensions(width, height)?;
            image::DynamicImage::from_decoder(decoder)?
        };
        let (width, height) = (image.width(), image.height());
        let rgba = image.into_rgba8().into_raw();
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

#[cfg(test)]
mod screen_tests {
    use super::*;
    #[test]
    fn jpeg_screens_are_smaller_and_decode_like_png_ones() {
        // A busy screen: a gradient with text-like noise, not a flat colour.
        let (width, height) = (640u32, 360u32);
        let rgba: Vec<u8> = (0..width * height)
            .flat_map(|i| {
                let (x, y) = (i % width, i / width);
                let v = ((x * 7 + y * 13) ^ (x * y)) as u8;
                [v, v.wrapping_add(40), (x as u8).wrapping_mul(3), 255]
            })
            .collect();
        let frame = Frame {
            width,
            height,
            rgba,
        };
        let png = frame.encode().unwrap();
        let jpeg = frame.encode_jpeg().unwrap();
        assert!(
            jpeg.len() * 3 < png.len(),
            "jpeg {} png {}",
            jpeg.len(),
            png.len()
        );
        for bytes in [png, jpeg] {
            let back = Frame::decode(&bytes).unwrap();
            assert_eq!((back.width, back.height), (width, height));
            assert_eq!(back.rgba.len(), frame.rgba.len());
        }
    }
}
