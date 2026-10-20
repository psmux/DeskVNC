//! The Mac's answer to the media offer.
//!
//! The answer says what the encoder settled on: the canvas it will render,
//! and how many tiles it is using. The offer asked for a picture of a given
//! size, and the answer is the truth about what arrived.
//!
//! The answer arrives as a framebuffer-update-shaped body with a binary
//! property list inside it. The property list holds a compressed media
//! description, and the description's top level field 5 is the video
//! configuration: field 4 the canvas width, field 5 the height, and field 6
//! the number of tiles.

use flate2::read::ZlibDecoder;
use std::io::Read;

/// What the Mac answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MediaAnswer {
    /// The canvas the encoder will render, in pixels.
    pub canvas_width: u32,
    pub canvas_height: u32,
    /// How many tile streams the video is split into.
    pub tiles: u32,
}

impl MediaAnswer {
    /// Whether the answer describes a canvas that can be streamed.
    ///
    /// The Mac sometimes answers with an empty canvas while its encoder is
    /// still warming up, and that is not an answer worth acting on: the
    /// offer is asked again instead.
    pub fn is_usable(&self) -> bool {
        self.canvas_width > 0 && self.canvas_height > 0
    }
}

/// Find the answer in a control message.
///
/// The message is a framebuffer update with a property list inside it, and
/// the property list is not at a fixed place: the search is for the plist
/// marker itself.
pub fn parse(body: &[u8]) -> Option<MediaAnswer> {
    let start = body.windows(6).position(|window| window == b"bplist")?;
    // The plist runs to the end of the message, but the message may carry
    // more after it, so the reader is given what is left and stops when the
    // plist is complete.
    let slice = &body[start..];
    let value = crate::plist::parse(slice)?;
    let blob = crate::plist::value_for(&value, "avcMediaStreamNegotiatorMediaBlob")?.as_data()?;
    let mut decompressed = Vec::new();
    ZlibDecoder::new(blob).read_to_end(&mut decompressed).ok()?;
    parse_description(&decompressed)
}

/// Read the canvas and the tile count out of the media description.
fn parse_description(blob: &[u8]) -> Option<MediaAnswer> {
    let mut answer = MediaAnswer::default();
    if blob.is_empty() {
        return None;
    }
    let mut pos = 0usize;
    while pos < blob.len() {
        let (tag, next) = read_varint(blob, pos)?;
        pos = next;
        let field = tag >> 3;
        let wire = tag & 7;
        match wire {
            0 => {
                let (_, next) = read_varint(blob, pos)?;
                pos = next;
            }
            1 => pos += 8,
            2 => {
                let (len, next) = read_varint(blob, pos)?;
                pos = next;
                let bytes = blob.get(pos..pos + len as usize)?;
                pos += len as usize;
                // The video configuration is the top level field 5.
                if field == 5 {
                    read_video_config(bytes, &mut answer);
                }
            }
            5 => pos += 4,
            _ => return None,
        }
    }
    Some(answer)
}

/// The video configuration: the canvas and the number of tiles.
fn read_video_config(bytes: &[u8], answer: &mut MediaAnswer) {
    let mut pos = 0usize;
    while pos < bytes.len() {
        let Some((tag, next)) = read_varint(bytes, pos) else {
            break;
        };
        pos = next;
        let field = tag >> 3;
        let wire = tag & 7;
        match wire {
            0 => {
                let Some((value, next)) = read_varint(bytes, pos) else {
                    break;
                };
                pos = next;
                match field {
                    4 => answer.canvas_width = value as u32,
                    5 => answer.canvas_height = value as u32,
                    6 => answer.tiles = value as u32,
                    _ => {}
                }
            }
            1 => pos += 8,
            2 => {
                let Some((len, next)) = read_varint(bytes, pos) else {
                    break;
                };
                pos = next + len as usize;
            }
            5 => pos += 4,
            _ => return,
        }
    }
}

/// A protobuf varint.
fn read_varint(bytes: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(pos)?;
        pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, pos));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut value = value;
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return out;
            }
        }
    }

    /// A media description with a video configuration in the top level
    /// field 5.
    fn description(width: u32, height: u32, tiles: u32) -> Vec<u8> {
        let mut config = Vec::new();
        config.push(0x20); // field 4, varint
        config.extend(varint(u64::from(width)));
        config.push(0x28); // field 5, varint
        config.extend(varint(u64::from(height)));
        config.push(0x30); // field 6, varint
        config.extend(varint(u64::from(tiles)));
        let mut blob = Vec::new();
        blob.push(0x2a); // field 5, length delimited
        blob.extend(varint(config.len() as u64));
        blob.extend(config);
        blob
    }

    #[test]
    fn the_canvas_and_the_tiles_are_read() {
        let answer =
            parse_description(&description(2216, 1440, 1)).expect("the description parsed");
        assert_eq!(answer.canvas_width, 2216);
        assert_eq!(answer.canvas_height, 1440);
        assert_eq!(answer.tiles, 1);
        assert!(answer.is_usable());
    }

    #[test]
    fn an_empty_canvas_is_not_usable() {
        let answer = parse_description(&description(0, 0, 0)).expect("the description parsed");
        assert!(!answer.is_usable());
    }

    #[test]
    fn rubbish_does_not_parse() {
        assert!(parse_description(b"not a protobuf").is_none());
        assert!(parse_description(&[]).is_none());
    }
}
