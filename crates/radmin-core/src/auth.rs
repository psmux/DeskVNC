//! Radmin-security SRP-6a/MGF1 variant. Windows/NTLM is not negotiated.
use anyhow::{ensure, Result};
use num_bigint_dig::BigUint;
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub const PREAMBLE: &[u8] = &hex_literal_preamble();
const fn hex_literal_preamble() -> [u8; 14] {
    [1, 0, 0, 0, 5, 0, 0, 2, 0x27, 0x27, 2, 0, 0, 0]
}
const ACK: &[u8] = &[1, 0, 0, 0, 5, 0, 0, 0, 0x27, 0x27, 0, 0, 0, 0];
const MODULUS_HEX: &str = concat!(
    "9847fc7e0f891dfd5d02f19d587d8f77aec0b980d4304b0113b406f23e2cec58",
    "cafca04a53e36fb68e0c3bff92cf335786b0dbe60dfe4178ef2fcd2a4dd09947",
    "ffd8df96fd0f9e2981a32da95503342eca9f08062cbdd4ac2d7cdf810db4db96d",
    "b70102266261cd3f8bdd56a102fc6ceedbba5eae99e6127bdd952f7a0d18a7902",
    "1c881ae63ec4b3590387f548598f2cb8f90dea36fc4f80c5473fdb6b0c6bdb0fd",
    "baf4601f560dd149167ea125db8ad34fd0fd45350dec72cfb3b528ba2332d6091",
    "acea89dfd06c9c4d18f697245bd2ac9278b92bfe7dbafaa0c43b40a71f1930eb",
    "c4fd24c9e5a2e5a4ccf5d7f51544d70b2bca4af5b8d37b379fd7740a682f"
);
pub(crate) fn modulus() -> Vec<u8> {
    hex::decode(MODULUS_HEX).expect("constant SRP group")
}
pub(crate) fn hash(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = Sha1::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().to_vec()
}
pub(crate) fn padded(number: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 256];
    data[256 - number.len()..].copy_from_slice(number);
    data
}
pub(crate) fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub(crate) fn tlvs(data: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut rest = data;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        ensure!(rest.len() >= 4, "Truncated Radmin authentication TLV");
        let tag = u16::from_le_bytes(rest[..2].try_into()?);
        let len = u16::from_be_bytes(rest[2..4].try_into()?) as usize;
        ensure!(
            len <= rest.len() - 4,
            "Truncated Radmin authentication value"
        );
        ensure!(
            !fields.iter().any(|(t, _)| *t == tag),
            "Duplicate Radmin authentication field"
        );
        fields.push((tag, &rest[4..4 + len]));
        rest = &rest[4 + len..];
    }
    Ok(fields)
}

pub(crate) fn packet(step: u32, fields: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = vec![0x10, 0, 0, 4];
    body.extend_from_slice(&step.to_be_bytes());
    for (tag, value) in fields {
        body.extend_from_slice(&tag.to_le_bytes());
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
    }
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend(body);
    frame
}

async fn receive<S: AsyncRead + Unpin>(
    stream: &mut S,
    step: u32,
    expected: &[u16],
) -> Result<Vec<Vec<u8>>> {
    let len = stream.read_u32().await? as usize;
    ensure!(
        (8..=4096).contains(&len),
        "Invalid Radmin authentication length"
    );
    let mut data = vec![0; len];
    stream.read_exact(&mut data).await?;
    let fields = tlvs(&data)?;
    ensure!(
        fields.len() == expected.len() + 1,
        "Unexpected Radmin authentication fields"
    );
    ensure!(
        fields.iter().find(|(t, _)| *t == 0x10).map(|(_, v)| *v)
            == Some(step.to_be_bytes().as_slice()),
        "Unexpected Radmin authentication step"
    );
    expected
        .iter()
        .map(|tag| {
            fields
                .iter()
                .find(|(t, _)| t == tag)
                .map(|(_, v)| v.to_vec())
                .ok_or_else(|| anyhow::anyhow!("Missing Radmin authentication field"))
        })
        .collect()
}

type SrpProofs = (Vec<u8>, Vec<u8>, Zeroizing<Vec<u8>>);

fn proofs(
    user: &str,
    password: &str,
    salt: &[u8],
    a: &BigUint,
    public_a: &[u8],
    public_b: &[u8],
) -> Result<SrpProofs> {
    let group = modulus();
    let n = BigUint::from_bytes_be(&group);
    let b = BigUint::from_bytes_be(public_b);
    ensure!(
        !public_b.is_empty() && public_b.len() <= group.len() && b != BigUint::from(0u32) && b < n,
        "Invalid Radmin SRP server public value"
    );
    let user = utf16le(user);
    let password = Zeroizing::new(utf16le(password));
    let inner = Zeroizing::new(hash(&[&user, b":", &password]));
    let x = BigUint::from_bytes_be(&hash(&[salt, &inner]));
    let g = BigUint::from(5u32);
    let k = BigUint::from_bytes_be(&hash(&[&group, &padded(&[5])]));
    let u = BigUint::from_bytes_be(&hash(&[&padded(public_a), &padded(public_b)]));
    ensure!(
        u != BigUint::from(0u32),
        "Invalid Radmin SRP scrambling parameter"
    );
    let base = (b + &n - (k * g.modpow(&x, &n)) % &n) % &n;
    ensure!(
        base != BigUint::from(0u32),
        "Invalid Radmin SRP shared-secret base"
    );
    let secret = Zeroizing::new(base.modpow(&(a + u * x), &n).to_bytes_be());
    let mut key = Zeroizing::new(hash(&[&secret, &[0, 0, 0, 0]]));
    key.extend(hash(&[&secret, &[0, 0, 0, 1]]));
    let xor: Vec<u8> = hash(&[&group])
        .iter()
        .zip(hash(&[&[5]]))
        .map(|(x, y)| x ^ y)
        .collect();
    let m1 = hash(&[&xor, &hash(&[&user]), salt, public_a, public_b, &key]);
    let m2 = hash(&[public_a, &m1, &key]);
    Ok((m1, m2, key))
}

pub async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    user: &str,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        !user.is_empty() && !user.contains('\0') && !password.contains('\0'),
        "A valid Radmin-security user name and password are required"
    );
    let username: Vec<u8> = user.encode_utf16().flat_map(u16::to_be_bytes).collect();
    ensure!(
        username.len() <= 512,
        "Radmin user name exceeds the supported length"
    );
    stream.write_all(PREAMBLE).await?;
    let mut ack = [0; 14];
    stream.read_exact(&mut ack).await?;
    ensure!(ack == ACK, "Unsupported Radmin server negotiation");
    stream.write_all(&packet(1, &[(0x20, &username)])).await?;
    let challenge = receive(stream, 2, &[0x30, 0x40, 0x50]).await?;
    ensure!(
        challenge[0] == modulus() && challenge[1] == [5],
        "Unsupported Radmin SRP group; Windows authentication is not supported"
    );
    ensure!(challenge[2].len() == 32, "Invalid Radmin SRP salt");
    let mut random = Zeroizing::new([0u8; 32]);
    getrandom::fill(random.as_mut())
        .map_err(|_| anyhow::anyhow!("Cannot obtain secure randomness"))?;
    let a = BigUint::from_bytes_be(random.as_ref()) + BigUint::from(2048u32);
    let public_a = BigUint::from(5u32)
        .modpow(&a, &BigUint::from_bytes_be(&modulus()))
        .to_bytes_be();
    stream.write_all(&packet(3, &[(0x60, &public_a)])).await?;
    let public_b = receive(stream, 4, &[0x60]).await?.remove(0);
    let (m1, m2, key) = proofs(user, password, &challenge[2], &a, &public_a, &public_b)?;
    stream.write_all(&packet(5, &[(0x70, &m1)])).await?;
    let proof = receive(stream, 6, &[0x70]).await?.remove(0);
    ensure!(
        bool::from(proof.ct_eq(&m2)),
        "Radmin authentication failed: server proof did not verify"
    );
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_existing_python_engine_fixed_srp_transcript() {
        // Synthetic test credentials; generated once using the existing engine
        // as an independent cross-language oracle. No Python runs in this test.
        let a = BigUint::parse_bytes(b"123456789abcdef123456789abcdef", 16).unwrap();
        let public_a = BigUint::from(5u32)
            .modpow(&a, &BigUint::from_bytes_be(&modulus()))
            .to_bytes_be();
        let public_b = hex::decode(
            "20d060892d795fec80d72c5136a377df93c97327765cdbdef6f0800d0c08751a1f03ff4ecf9a0c2880245f8293a55ac1642c948f1cb46e8f06b149c5f6a12ac66c0b32a78a5bb80370c00aa9c4c0032cd227a1ca895229a418809edae6af259e6595488b61f7a5bf98d9c95e40f436e4ac10035770825f4b3ddc31459af062418fa708cf52b8ddcdc1df37f150a10b45f95c760d45994ef5ffce4b31cd3065cd789dabf7b7ce62527d3e9eb5487d93783e699243c72f95f62533e6b69509026ebc8350a3d8b53c53dd8d103daa5a115e49f42a314c5ac63450e7e4615c21e811936d119ae80273141dff22ac6f72a1d7dc51924ed0005a8a0b4edca43f79a49e"
        ).unwrap();
        let salt: Vec<u8> = (0..32).collect();
        let (m1, m2, key) = proofs(
            "fixture-é",
            "synthetic test password",
            &salt,
            &a,
            &public_a,
            &public_b,
        )
        .unwrap();
        assert_eq!(hex::encode(m1), "a6a9aa4cf3d3fc0e19fb151764f09eac61d47582");
        assert_eq!(hex::encode(m2), "67215ec036cb838daf597730815e022ce8c794d5");
        assert_eq!(
            hex::encode(key.as_slice()),
            "688a52032487009636f3018f02d743d1b73a1dfc9ad4c5b1415d0a99d81cf54cb77ee9d6474c4841"
        );
        assert!(proofs(
            "fixture-é",
            "synthetic test password",
            &salt,
            &a,
            &public_a,
            &[0]
        )
        .is_err());
    }
    #[test]
    fn auth_tags_use_mixed_endianness_and_reject_duplicates() {
        assert_eq!(
            hex::encode(packet(1, &[(0x20, &[0, 65])])),
            "0000000e1000000400000001200000020041"
        );
        assert!(tlvs(&[0x10, 0, 0, 1, 1, 0x10, 0, 0, 1, 2]).is_err());
        assert!(tlvs(&[0x10, 0, 0, 2, 1]).is_err());
    }
}
