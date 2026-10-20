//! A small binary property list reader.
//!
//! The Mac's answer to the media offer is a binary plist with one thing in
//! it that matters: the compressed media description, which says what
//! canvas the encoder settled on and how many tiles it is using.
//!
//! Only the part of the format that is needed to find that one value is
//! implemented: dictionaries, their ASCII keys, and their data values.

/// The bytes of one value from a property list.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    Real(f64),
    Data(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Dict(Vec<(Value, Value)>),
}

impl Value {
    /// The data of a value, if it is data.
    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Value::Data(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// The text of a value, if it is text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }
}

/// Parse a binary property list.
pub fn parse(bytes: &[u8]) -> Option<Value> {
    if bytes.len() < 8 + 32 || !bytes.starts_with(b"bplist00") {
        return None;
    }
    let trailer = &bytes[bytes.len() - 32..];
    let offset_size = trailer[6] as usize;
    let ref_size = trailer[7] as usize;
    let object_count = read_uint(&trailer[8..16])? as usize;
    let top_object = read_uint(&trailer[16..24])? as usize;
    let table_offset = read_uint(&trailer[24..32])? as usize;
    if offset_size == 0 || ref_size == 0 || object_count == 0 {
        return None;
    }
    let table_end = table_offset + object_count * offset_size;
    if table_end > bytes.len() {
        return None;
    }
    let reader = Reader {
        bytes,
        offset_size,
        ref_size,
        table_offset,
    };
    // The objects are read on demand; a list can point at itself.
    let mut cache: Vec<Option<Value>> = vec![None; object_count];
    reader.object(top_object, &mut cache, 0)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset_size: usize,
    ref_size: usize,
    table_offset: usize,
}

impl<'a> Reader<'a> {
    /// The byte offset of an object.
    fn offset_of(&self, index: usize) -> Option<usize> {
        let at = self.table_offset + index * self.offset_size;
        let raw = self.bytes.get(at..at + self.offset_size)?;
        read_uint(raw).map(|value| value as usize)
    }

    /// The object reference stored at a position.
    fn reference_at(&self, at: usize) -> Option<usize> {
        let raw = self.bytes.get(at..at + self.ref_size)?;
        read_uint(raw).map(|value| value as usize)
    }

    fn object(&self, index: usize, cache: &mut Vec<Option<Value>>, depth: u32) -> Option<Value> {
        if depth > 16 || index >= cache.len() {
            return None;
        }
        if let Some(value) = &cache[index] {
            return Some(value.clone());
        }
        let at = self.offset_of(index)?;
        let marker = *self.bytes.get(at)?;
        // The high nibble says what the object is, the low nibble says how
        // long it is (or which of the few fixed shapes it is).
        let n = (marker & 0x0f) as usize;
        let (kind, length, data_at) = match marker >> 4 {
            0x0 => {
                return Some(match marker {
                    0x08 => Value::Bool(false),
                    0x09 => Value::Bool(true),
                    _ => Value::Null,
                })
            }
            0x1 => (1u8, 1usize << n, at + 1),
            0x2 => (2u8, 1usize << n, at + 1),
            0x3 => match marker {
                0x33 => (3u8, 8, at + 1),
                // Data: a length, then the bytes.
                0x34 => {
                    let (len, start) = self.count_after(at + 1)?;
                    (4u8, len, start)
                }
                _ => return None,
            },
            // Data and strings: the length is in the low nibble, unless it
            // is fifteen, which means an int with the length follows.
            0x4 => {
                let (len, start) = self.sized(at + 1, n)?;
                (4u8, len, start)
            }
            0x5 => {
                let (len, start) = self.sized(at + 1, n)?;
                (5u8, len, start)
            }
            0x6 => {
                let (len, start) = self.sized(at + 1, n)?;
                (6u8, len * 2, start)
            }
            0x8 => (8u8, n + 1, at + 1),
            0xa | 0xc => {
                let (len, start) = self.count(at + 1, n)?;
                (marker >> 4, len, start)
            }
            0xd => {
                let (len, start) = self.count(at + 1, n)?;
                (0x0d, len, start)
            }
            _ => return None,
        };
        let value = match kind {
            1 => {
                let raw = self.bytes.get(data_at..data_at + length)?;
                Value::Integer(read_signed(raw)?)
            }
            2 => {
                let raw = self.bytes.get(data_at..data_at + length)?;
                Value::Real(f64::from_be_bytes(raw.try_into().ok()?))
            }
            3 => {
                // A date: seconds since 2001. The value is not used here.
                let raw = self.bytes.get(data_at..data_at + length)?;
                Value::Real(f64::from_be_bytes(raw.try_into().ok()?))
            }
            4 => {
                let raw = self.bytes.get(data_at..data_at + length)?;
                Value::Data(raw.to_vec())
            }
            5 => {
                // An ASCII string.
                let raw = self.bytes.get(data_at..data_at + length)?;
                Value::Text(String::from_utf8_lossy(raw).into_owned())
            }
            6 => {
                // A UTF-16 string.
                let raw = self.bytes.get(data_at..data_at + length)?;
                let units: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                    .collect();
                Value::Text(String::from_utf16_lossy(&units))
            }
            8 => {
                let raw = self.bytes.get(data_at..data_at + length)?;
                Value::Integer(read_uint(raw)? as i64 + 1)
            }
            0x0a | 0x0c => {
                let mut items = Vec::new();
                for i in 0..length {
                    let item = self.reference_at(data_at + i * self.ref_size)?;
                    items.push(self.object(item, cache, depth + 1)?);
                }
                Value::Array(items)
            }
            _ => {
                // A dictionary: the keys and the values, one after the other.
                let mut pairs = Vec::new();
                for i in 0..length {
                    let key_index = self.reference_at(data_at + i * self.ref_size)?;
                    let value_index = self.reference_at(data_at + (length + i) * self.ref_size)?;
                    let key = self.object(key_index, cache, depth + 1)?;
                    let value = self.object(value_index, cache, depth + 1)?;
                    pairs.push((key, value));
                }
                Value::Dict(pairs)
            }
        };
        cache[index] = Some(value.clone());
        Some(value)
    }

    /// A count that follows a marker: a byte, or fifteen and then an int.
    fn count_after(&self, at: usize) -> Option<(usize, usize)> {
        let marker = *self.bytes.get(at)?;
        if marker & 0x0f != 0x0f {
            return Some((marker as usize, at + 1));
        }
        // The count is an int, and the int's own marker says how many bytes
        // it has: 0x1n is one byte, 0x2n is two, and so on.
        let (value, next) = self.int_after(at + 1)?;
        Some((value as usize, next))
    }

    /// An int that follows a marker.
    fn int_after(&self, at: usize) -> Option<(u64, usize)> {
        let marker = *self.bytes.get(at)?;
        let width = 1usize << (marker & 0x0f);
        let raw = self.bytes.get(at + 1..at + 1 + width)?;
        Some((read_uint(raw)?, at + 1 + width))
    }

    /// The size of a data object or a string: the count in the low nibble,
    /// or an int that follows when the nibble is fifteen.
    fn sized(&self, at: usize, nibble: usize) -> Option<(usize, usize)> {
        if nibble != 0x0f {
            return Some((nibble, at));
        }
        let (value, next) = self.int_after(at)?;
        Some((value as usize, next))
    }

    /// How many entries a collection has. The count is in the marker's low
    /// nibble, and only a count of fifteen means "an int follows".
    fn count(&self, at: usize, nibble: usize) -> Option<(usize, usize)> {
        if nibble != 0x0f {
            return Some((nibble, at));
        }
        let (value, next) = self.int_after(at)?;
        Some((value as usize, next))
    }
}

fn read_uint(raw: &[u8]) -> Option<u64> {
    if raw.is_empty() || raw.len() > 8 {
        return None;
    }
    let mut value = 0u64;
    for byte in raw {
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}

fn read_signed(raw: &[u8]) -> Option<i64> {
    if raw.is_empty() || raw.len() > 8 {
        return None;
    }
    if raw.len() == 8 {
        return Some(i64::from_be_bytes(raw.try_into().ok()?));
    }
    let mut value = 0i64;
    for byte in raw {
        value = (value << 8) | i64::from(*byte);
    }
    // A short integer is signed.
    let bits = 8 * raw.len();
    if bits < 64 && value & (1 << (bits - 1)) != 0 {
        value -= 1 << bits;
    }
    Some(value)
}

/// Find a value in a property list by its key.
pub fn value_for<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Dict(pairs) => pairs
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small binary plist built by hand: a dictionary with one text key
    /// and one data value.
    fn plist_with(key: &str, value: &[u8]) -> Vec<u8> {
        let mut objects: Vec<Vec<u8>> = Vec::new();
        // An ASCII string: 0x5n, or 0x5F and a count for a long one.
        let mut text = Vec::new();
        if key.len() < 15 {
            text.push(0x50 | key.len() as u8);
        } else {
            text.push(0x5f);
            text.push(0x10); // a one byte int
            text.push(key.len() as u8);
        }
        text.extend_from_slice(key.as_bytes());
        objects.push(text);
        // Data: 0x4n, or 0x4F and a count for a long one.
        let mut data = Vec::new();
        if value.len() < 15 {
            data.push(0x40 | value.len() as u8);
        } else {
            data.push(0x4f);
            // The count is an int, and its marker says how many bytes it has.
            if value.len() <= 0xff {
                data.push(0x10);
                data.push(value.len() as u8);
            } else {
                data.push(0x11);
                data.extend_from_slice(&(value.len() as u16).to_be_bytes());
            }
        }
        data.extend_from_slice(value);
        objects.push(data);
        // A dictionary of one pair: the key is object 0 and the value is
        // object 1.
        objects.push(vec![0xd1, 0x00, 0x01]);
        let mut bytes = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for object in &objects {
            offsets.push(bytes.len());
            bytes.extend_from_slice(object);
        }
        let table_at = bytes.len();
        for offset in offsets {
            bytes.extend_from_slice(&(offset as u16).to_be_bytes());
        }
        bytes.extend_from_slice(&[0u8; 5]);
        bytes.push(0); // sort version
        bytes.push(2); // offset int size
        bytes.push(1); // object ref size
        bytes.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&(objects.len() as u64 - 1).to_be_bytes()); // the top object
        bytes.extend_from_slice(&(table_at as u64).to_be_bytes());
        bytes
    }

    #[test]
    fn a_plist_round_trips() {
        let bytes = plist_with("avcMediaStreamNegotiatorMediaBlob", b"the blob");
        let value = parse(&bytes).expect("the plist parsed");
        let blob = value_for(&value, "avcMediaStreamNegotiatorMediaBlob").expect("the key");
        assert_eq!(blob.as_data(), Some(&b"the blob"[..]));
    }

    #[test]
    fn a_plist_with_a_long_value_round_trips() {
        let long = vec![7u8; 300];
        let bytes = plist_with("avcMediaStreamNegotiatorMediaBlob", &long);
        let value = parse(&bytes).expect("the plist parsed");
        let blob = value_for(&value, "avcMediaStreamNegotiatorMediaBlob").expect("the key");
        assert_eq!(blob.as_data(), Some(&long[..]));
    }

    #[test]
    fn rubbish_is_not_a_plist() {
        assert!(parse(b"not a plist at all").is_none());
        assert!(parse(b"").is_none());
    }
}
