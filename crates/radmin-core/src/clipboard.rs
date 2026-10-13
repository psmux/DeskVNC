use super::desktop::{tlv, word};
use anyhow::{ensure, Result};
pub const MAX_TEXT: usize = 1024 * 1024;
pub fn send(text: &str) -> Result<Vec<u8>> {
    ensure!(
        text.len() <= MAX_TEXT && !text.contains('\0'),
        "Radmin clipboard text is too large or contains NUL"
    );
    let mut data: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    data.extend_from_slice(&[0, 0]);
    let mut record = (data.len() as u32).to_be_bytes().to_vec();
    record.extend_from_slice(&0x20000000u32.to_be_bytes());
    record.extend(data);
    Ok(tlv(0x60000000, &record))
}
pub fn receive(mut data: &[u8]) -> Result<Option<String>> {
    ensure!(
        data.len() <= 16 * 1024 * 1024,
        "Radmin clipboard payload is too large"
    );
    let mut text = None;
    while !data.is_empty() {
        ensure!(data.len() >= 8, "Truncated Radmin clipboard record");
        let (len, format) = (word(data, 0)? as usize, word(data, 4)?);
        ensure!(
            len > 0 && len <= data.len() - 8,
            "Invalid Radmin clipboard record length"
        );
        let value = &data[8..8 + len];
        if format == 0x20000000 && text.is_none() {
            ensure!(
                len >= 2 && len % 2 == 0 && value.ends_with(&[0, 0]) && len <= MAX_TEXT * 2 + 2,
                "Invalid Radmin Unicode clipboard extent"
            );
            let units: Vec<u16> = value[..len - 2]
                .chunks_exact(2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .collect();
            let decoded = String::from_utf16(&units)?;
            ensure!(
                !decoded.contains('\0') && decoded.len() <= MAX_TEXT,
                "Invalid Radmin clipboard text"
            );
            text = Some(decoded);
        }
        data = &data[8 + len..];
    }
    Ok(text)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_and_unicode_clipboard() {
        assert_eq!(
            hex::encode(send("A").unwrap()),
            "6000000c000000042000000000410000"
        );
        let data = send("hello שלום 😀").unwrap();
        assert_eq!(
            receive(&data[4..]).unwrap().as_deref(),
            Some("hello שלום 😀")
        );
        assert!(send("a\0b").is_err());
        assert!(receive(&[0, 0, 0, 4, 0x20, 0, 0, 0, 0]).is_err());
    }
}
