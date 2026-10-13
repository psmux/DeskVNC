//! Stateful AES-256-CBC records with Radmin's native padding/checksum.
use aes::Aes256;
use anyhow::{ensure, Result};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md4::{Digest, Md4};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_RECORD: usize = 16 * 1024 * 1024;

fn checksum(data: &[u8]) -> [u8; 8] {
    let mut sum = 0u64;
    for chunk in data.chunks(8) {
        let mut word = [0; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        sum = sum.wrapping_add(u64::from_le_bytes(word));
    }
    let digest = Md4::digest(sum.to_le_bytes());
    std::array::from_fn(|i| digest[i].wrapping_add(digest[i + 8]))
}

pub(crate) fn pad(data: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !data.is_empty() && data.len() <= MAX_RECORD - 24,
        "Invalid Radmin record payload size"
    );
    let size = ((data.len() + 24) / 16) * 16;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(data);
    out.resize(size - 9, 0xcc);
    out.extend_from_slice(&checksum(&out));
    out.push((size - data.len()) as u8);
    Ok(out)
}

fn unpad(mut data: Vec<u8>) -> Result<Vec<u8>> {
    ensure!(
        !data.is_empty() && data.len() <= MAX_RECORD && data.len().is_multiple_of(16),
        "Invalid encrypted Radmin record length"
    );
    let padding = data[data.len() - 1] as usize;
    ensure!(
        (9..=24).contains(&padding) && padding < data.len(),
        "Invalid Radmin record padding"
    );
    ensure!(
        bool::from(checksum(&data[..data.len() - 9]).ct_eq(&data[data.len() - 9..data.len() - 1])),
        "Radmin record checksum mismatch"
    );
    data.truncate(data.len() - padding);
    Ok(data)
}

pub struct CipherState {
    encryptor: cbc::Encryptor<Aes256>,
    decryptor: cbc::Decryptor<Aes256>,
}
impl CipherState {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        ensure!(
            key.len() == 32 && iv.len() == 16,
            "Invalid Radmin cipher parameters"
        );
        Ok(Self {
            encryptor: cbc::Encryptor::new_from_slices(key, iv)?,
            decryptor: cbc::Decryptor::new_from_slices(key, iv)?,
        })
    }
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = pad(data)?;
        for block in out.chunks_exact_mut(16) {
            self.encryptor.encrypt_block_mut(block.into());
        }
        Ok(out)
    }
    pub fn decrypt(&mut self, mut data: Vec<u8>) -> Result<Vec<u8>> {
        ensure!(
            !data.is_empty() && data.len() <= MAX_RECORD && data.len().is_multiple_of(16),
            "Invalid Radmin ciphertext length"
        );
        for block in data.chunks_exact_mut(16) {
            self.decryptor.decrypt_block_mut(block.into());
        }
        unpad(data)
    }
}

pub async fn read_record<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let length = reader.read_u32().await? as usize;
    ensure!(
        (1..=MAX_RECORD).contains(&length),
        "Invalid Radmin record size"
    );
    let mut data = vec![0; length];
    reader.read_exact(&mut data).await?;
    Ok(data)
}
pub async fn write_record<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    ensure!(
        !data.is_empty() && data.len() <= MAX_RECORD,
        "Invalid Radmin outgoing record size"
    );
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aes_cbc_matches_nist_sp800_38a_first_block() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let ciphertext = CipherState::new(&key, &iv)
            .unwrap()
            .encrypt(&plaintext)
            .unwrap();
        assert_eq!(
            hex::encode(&ciphertext[..16]),
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
        );
    }
    #[test]
    fn native_padding_vectors_and_corruption() {
        for (plain, encoded) in [
            ("00", "00ccccccccccccc508283e781d39ee0f"),
            ("001f3e5d7c", "001f3e5d7cccccb4932804e1aa3bb40b"),
            (
                "001f3e5d7c9bbad9",
                "001f3e5d7c9bbad9ccccccccccccccccccccccccccccccc0faa7475889eb7d18",
            ),
        ] {
            let plain = hex::decode(plain).unwrap();
            let mut encoded = hex::decode(encoded).unwrap();
            assert_eq!(pad(&plain).unwrap(), encoded);
            assert_eq!(unpad(encoded.clone()).unwrap(), plain);
            encoded[0] ^= 1;
            assert!(unpad(encoded).is_err());
        }
    }
    #[test]
    fn cbc_continuity_across_records() {
        let mut send = CipherState::new(&[3; 32], &[5; 16]).unwrap();
        let mut receive = CipherState::new(&[3; 32], &[5; 16]).unwrap();
        let first = send.encrypt(b"hello").unwrap();
        let second = send.encrypt(b"hello").unwrap();
        assert_ne!(first, second);
        assert_eq!(receive.decrypt(first).unwrap(), b"hello");
        assert_eq!(receive.decrypt(second).unwrap(), b"hello");
    }
}
