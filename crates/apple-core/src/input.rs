//! Apple's encrypted pointer event (0x10), inside a control record.
use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit};

pub fn pointer(key: &[u8; 16], x: u16, y: u16, buttons: u16) -> [u8; 18] {
    let mut block = [0u8; 16];
    block[10] = 0xff;
    // RFB middle/right are reversed in Apple's HID button mask.
    let buttons = buttons as u8;
    block[11] = (buttons & !6) | ((buttons & 2) << 1) | ((buttons & 4) >> 1);
    block[12..14].copy_from_slice(&x.to_be_bytes());
    block[14..16].copy_from_slice(&y.to_be_bytes());
    let mut block = cipher::generic_array::GenericArray::from(block);
    Aes128::new(key.into()).encrypt_block(&mut block);
    let mut message = [0u8; 18];
    message[0] = 0x10;
    message[2..].copy_from_slice(&block);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::BlockDecrypt;

    #[test]
    fn encrypted_pointer_preserves_coordinates_and_button_edges() {
        let key = [9; 16];
        for (rfb, apple) in [(0, 0), (1, 1), (2, 4), (4, 2), (8, 8), (16, 16)] {
            let message = pointer(&key, 1234, 567, rfb);
            assert_eq!(message[..2], [0x10, 0]);
            let mut block = cipher::generic_array::GenericArray::clone_from_slice(&message[2..]);
            Aes128::new((&key).into()).decrypt_block(&mut block);
            assert_eq!(block[10], 0xff);
            assert_eq!(block[11], apple);
            assert_eq!(&block[12..14], &1234u16.to_be_bytes());
            assert_eq!(&block[14..16], &567u16.to_be_bytes());
        }
    }
}
