//! The `0x1c` media offer.
//!
//! The Mac will not start the H.264 stream until it receives a binary plist
//! whose media blob asks for one H.264 picture per frame. The layout matches
//! the offer Screen Sharing sends: a version-3 header, four 46-byte SRTP
//! key blobs, and a video plist plus an audio plist (audio is requested below
//! the server's bitrate floor, so nothing is sent).

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::write::ZlibEncoder;
use flate2::Compression;
use rand::{Rng, RngExt};

const HEVC_PARAMS_NO_LTR: &[u8] =
    b"FLS;MS:-1;LF:-1;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;";

/// `(message, server-to-viewer video key, viewer-to-server video key)`.
///
/// The first key decrypts the UDP stream. The second encrypts the feedback
/// we send back: without it there is no way to ask the Mac for a fresh
/// picture when one is lost.
pub fn media_offer() -> (Vec<u8>, [u8; 46], [u8; 46]) {
    let audio_v = random_46();
    let audio_s = random_46();
    let video_v = random_46();
    let video_s = random_46();
    let audio = plist(8, &media_blob(8));
    let video = plist(7, &media_blob(7));
    let ms = (audio.len() + video.len() + 0xd8) as u16;
    let mut buf = vec![0u8; ms as usize + 4];
    buf[0] = 0x1c;
    buf[2..4].copy_from_slice(&ms.to_be_bytes());
    buf[4..6].copy_from_slice(&3u16.to_be_bytes());
    // 60 fps on both tiers, and do not bake the cursor into the picture.
    //
    // BIG ENDIAN, and that is deliberate. The protocol notes describe this
    // word as host-endian, and "correcting" it to little-endian is a trap
    // that has been walked into before: the host loads the word
    // un-byteswapped and hands it to the streaming agent, where the byte
    // order is the other way round. Big-endian `00 00 00 07` is what makes
    // the host honour "do not send the cursor in the picture". With
    // little-endian the cursor is baked into the video and the viewer
    // draws a second one on top of it.
    buf[6..10].copy_from_slice(&7u32.to_be_bytes());
    buf[10..12].copy_from_slice(&(audio.len() as u16).to_be_bytes());
    buf[12..14].copy_from_slice(&(video.len() as u16).to_be_bytes());
    buf[0x14..0x24].copy_from_slice(&random_16());
    buf[0x24..0x52].copy_from_slice(&audio_v);
    buf[0x52..0x80].copy_from_slice(&audio_s);
    let vo = 0x80 + audio.len();
    buf[0x80..vo].copy_from_slice(&audio);
    buf[vo..vo + 0x2e].copy_from_slice(&video_v);
    buf[vo + 0x2e..vo + 0x5c].copy_from_slice(&video_s);
    buf[vo + 0x5c..].copy_from_slice(&video);
    (buf, video_s, video_v)
}

fn media_blob(mode: u64) -> Vec<u8> {
    let session_id = rand::rng().random::<u32>() as u64;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let desc = if mode == 7 {
        let mut d = field_varint(1, session_id);
        d.extend(field_varint(2, 0));
        d.extend(field_bytes(3, &h264_bank()));
        d.extend(field_varint(6, 1)); // one picture per frame
        d.extend(field_varint(7, 0));
        d.extend(field_varint(8, 63));
        d.extend(field_varint(9, 1));
        d.extend(field_varint(12, 1));
        field_bytes(5, &d)
    } else {
        // Field 4 below the audio tier floor, so the Mac sends no audio.
        let mut d = field_varint(1, session_id);
        d.extend(field_varint(2, 0));
        d.extend(field_varint(3, 0));
        d.extend(field_varint(4, 1000));
        d.extend(field_varint(5, 0));
        d.extend(field_varint(6, 0));
        field_bytes(3, &d)
    };
    let mut blob = field_varint(1, 1);
    blob.extend(field_varint(2, 1));
    blob.extend(desc);
    blob.extend(field_bytes(6, b"DeskVNC"));
    blob.extend(field_varint(8, 0));
    blob.extend(audio_f9());
    blob.extend(field_varint(13, timestamp));
    blob.extend(field_varint(14, 2));
    blob.extend(field_varint(16, 0));
    blob.extend(field_varint(18, 1));
    blob
}

/// Codec bank 123. The Mac answers this bank with H.264 4:2:0.
fn h264_bank() -> Vec<u8> {
    let res = |kind: u64| {
        let mut e = field_varint(1, 1);
        e.extend(field_varint(2, kind));
        e.extend(field_varint(3, 50115));
        e.extend(field_varint(4, 0));
        e
    };
    let mut bank = field_varint(1, 123);
    for kind in [1u64, 2, 1, 2] {
        bank.extend(field_bytes(2, &res(kind)));
    }
    bank.extend(field_bytes(3, HEVC_PARAMS_NO_LTR));
    bank.extend(field_varint(4, 1));
    bank
}

fn audio_f9() -> Vec<u8> {
    const TIERS: &[(u64, u64, Option<u64>)] = &[
        (0, 40_000_000, Some(12_288)),
        (0, 6_000_000, Some(131_072)),
        (4074, 0, Some(16_384)),
        (16, 4100, None),
        (0, 75_000_000, Some(524_288)),
        (0, 20_000_000, Some(98_304)),
        (4, 6500, None),
        (0, 60_000_000, Some(262_144)),
        (1, 299, None),
        (0, 100_000_000, Some(1_048_576)),
    ];
    let mut out = Vec::new();
    for &(f1, f2, f3) in TIERS {
        let mut body = Vec::new();
        body.push(0x08);
        body.extend(varint(f1));
        body.push(0x10);
        body.extend(varint(f2));
        if let Some(f3) = f3 {
            body.push(0x18);
            body.extend(varint(f3));
        }
        out.push(0x4a);
        out.extend(varint(body.len() as u64));
        out.extend(body);
    }
    out
}

fn plist(mode: u64, blob: &[u8]) -> Vec<u8> {
    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib.write_all(blob).ok();
    let compressed = zlib.finish().unwrap_or_default();
    let endpoint = remote_endpoint();
    let call = uuid_upper();
    let objects = [
        Vec::new(), // dict, filled once the other objects exist
        plist_ascii("avcMediaStreamNegotiatorMediaBlob"),
        plist_ascii("avcMediaStreamNegotiatorMode"),
        plist_ascii("avcMediaStreamOptionCallID"),
        plist_ascii("avcMediaStreamOptionRemoteEndpointInfo"),
        plist_data(&compressed),
        plist_int(mode),
        plist_ascii(&call),
        plist_data(&endpoint),
    ];
    let mut objects: Vec<Vec<u8>> = objects.into();
    objects[0] = plist_dict(&[(1, 5), (2, 6), (3, 7), (4, 8)]);
    let mut bytes = b"bplist00".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for obj in &objects {
        offsets.push(bytes.len());
        bytes.extend(obj);
    }
    let table_at = bytes.len();
    for off in offsets {
        bytes.extend_from_slice(&(off as u16).to_be_bytes());
    }
    bytes.extend_from_slice(&[0; 6]);
    bytes.push(2); // offset integers are 2 bytes
    bytes.push(1); // object refs are 1 byte
    bytes.extend_from_slice(&9u64.to_be_bytes());
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.extend_from_slice(&(table_at as u64).to_be_bytes());
    bytes
}

fn remote_endpoint() -> Vec<u8> {
    let mut e = vec![0x08, 0x00, 0x10, 0x01];
    e.extend(proto_str(0x1a, b"Linux-x86_64"));
    e.extend(proto_str(0x22, b"1.0.0"));
    e.extend(proto_str(0x2a, b"0"));
    e
}

fn proto_str(tag: u8, s: &[u8]) -> Vec<u8> {
    let mut o = vec![tag, s.len() as u8];
    o.extend(s);
    o
}

fn plist_dict(pairs: &[(u8, u8)]) -> Vec<u8> {
    let mut o = vec![0xD0 | pairs.len() as u8];
    for (k, _) in pairs {
        o.push(*k);
    }
    for (_, v) in pairs {
        o.push(*v);
    }
    o
}

fn plist_ascii(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut o = Vec::new();
    if b.len() < 15 {
        o.push(0x50 | b.len() as u8);
    } else {
        o.push(0x5F);
        o.extend(plist_int(b.len() as u64));
    }
    o.extend(b);
    o
}

fn plist_data(b: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    if b.len() < 15 {
        o.push(0x40 | b.len() as u8);
    } else {
        o.push(0x4F);
        o.extend(plist_int(b.len() as u64));
    }
    o.extend(b);
    o
}

fn plist_int(v: u64) -> Vec<u8> {
    if v <= 0xff {
        vec![0x10, v as u8]
    } else if v <= 0xffff {
        let mut o = vec![0x11];
        o.extend_from_slice(&(v as u16).to_be_bytes());
        o
    } else if v <= 0xffff_ffff {
        let mut o = vec![0x12];
        o.extend_from_slice(&(v as u32).to_be_bytes());
        o
    } else {
        let mut o = vec![0x13];
        o.extend_from_slice(&v.to_be_bytes());
        o
    }
}

fn field_varint(field: u32, value: u64) -> Vec<u8> {
    let mut o = varint(u64::from(field) << 3);
    o.extend(varint(value));
    o
}

fn field_bytes(field: u32, value: &[u8]) -> Vec<u8> {
    let mut o = varint((u64::from(field) << 3) | 2);
    o.extend(varint(value.len() as u64));
    o.extend(value);
    o
}

fn varint(mut v: u64) -> Vec<u8> {
    let mut o = Vec::new();
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        o.push(b);
        if v == 0 {
            break;
        }
    }
    o
}

fn random_46() -> [u8; 46] {
    let mut b = [0u8; 46];
    rand::rng().fill_bytes(&mut b);
    b
}

fn random_16() -> [u8; 16] {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b
}

fn uuid_upper() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn offer_plist_loads() {
        let (msg, key, feedback_key) = media_offer();
        assert_eq!(msg[0], 0x1c);
        assert_eq!(key.len(), 46);
        assert_eq!(feedback_key.len(), 46);
        assert_ne!(key, feedback_key, "the two directions must not share a key");
        assert!(msg.len() < 60_000, "offer is {} bytes", msg.len());
        let path =
            std::env::temp_dir().join(format!("apple-offer-test-{}.bin", std::process::id()));
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&msg).unwrap();
        let check = std::process::Command::new("python3")
            .arg("-c")
            .arg(
                "import plistlib,sys,zlib\n\
                 m=open(sys.argv[1],'rb').read()\n\
                 assert m[0]==0x1c and int.from_bytes(m[4:6],'big')==3\n\
                 vs=int.from_bytes(m[12:14],'big'); a=int.from_bytes(m[10:12],'big')\n\
                 vo=0x80+a+0x5c\n\
                 p=plistlib.loads(m[vo:vo+vs])\n\
                 assert p['avcMediaStreamNegotiatorMode']==7\n\
                 b=zlib.decompress(p['avcMediaStreamNegotiatorMediaBlob'])\n\
                 assert b'DeskVNC' in b\n",
            )
            .arg(&path)
            .output()
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(
            check.status.success(),
            "stdout {} stderr {}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        );
    }
}
