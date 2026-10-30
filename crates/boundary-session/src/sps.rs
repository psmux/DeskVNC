//! Telling a helper's decoder it may show each picture at once.
//!
//! An H.264 sequence parameter set that does not say how many pictures may
//! come out of order leaves the decoder to assume as many as its level
//! allows, and it holds that many back before showing the first. Apple's
//! software encoder on the Intel i5 iMac wrote Main profile at level 4.0
//! with no such count, and WebKit's decoder held four 1920 by 1080 pictures:
//! the window waited half a second for each picture and drew none of them.
//! The hosts here never reorder, so the count is written as nought.

/// `sps` with its VUI's bitstream restriction saying no picture is
/// reordered, or `None` when it already says so or cannot be read. `sps` is
/// one NAL unit with its header byte and without a start code.
pub fn no_reordering(sps: &[u8]) -> Option<Vec<u8>> {
    if sps.first()? & 31 != 7 {
        return None;
    }
    let rbsp = unescape(&sps[1..]);
    let mut r = Reader { data: &rbsp, at: 0 };
    let refs = read_to_vui(&mut r)?;
    let keep = if r.bit()? {
        let at = vui_to_restriction(&mut r)?;
        if r.bit()? {
            r.bit()?;
            for _ in 0..4 {
                r.ue()?;
            }
            if r.ue()? == 0 {
                return None;
            }
        }
        at
    } else {
        // No VUI: write one that has only the restriction in it.
        let at = r.at - 1;
        let mut w = Writer::default();
        w.copy(&rbsp, at);
        w.bit(true);
        // Aspect ratio, overscan, video signal, chroma location, timing,
        // NAL HRD, VCL HRD and fixed picture structure: all absent.
        for _ in 0..8 {
            w.bit(false);
        }
        return Some(finish(sps[0], w, refs));
    };
    let mut w = Writer::default();
    w.copy(&rbsp, keep);
    Some(finish(sps[0], w, refs))
}

/// The restriction, then the trailing bits, then the NAL unit around them.
fn finish(header: u8, mut w: Writer, refs: u32) -> Vec<u8> {
    w.bit(true);
    // Motion vectors over picture edges allowed, and the defaults for the
    // byte and bit limits and the motion vector lengths.
    w.bit(true);
    w.ue(2);
    w.ue(1);
    w.ue(15);
    w.ue(15);
    // No reordering, and a buffer as deep as the references.
    w.ue(0);
    w.ue(refs.max(1));
    w.bit(true);
    while !w.bits.is_multiple_of(8) {
        w.bit(false);
    }
    let mut out = vec![header];
    out.extend(escape(&w.bytes));
    out
}

/// Reads the sequence parameter set up to and including the VUI present
/// flag's position (left before it), returning the reference count.
fn read_to_vui(r: &mut Reader) -> Option<u32> {
    let profile = r.bits(8)?;
    r.bits(16)?;
    r.ue()?;
    if matches!(
        profile,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        let chroma = r.ue()?;
        if chroma == 3 {
            r.bit()?;
        }
        r.ue()?;
        r.ue()?;
        r.bit()?;
        if r.bit()? {
            let lists = if chroma == 3 { 12 } else { 8 };
            for i in 0..lists {
                if r.bit()? {
                    skip_scaling_list(r, if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    r.ue()?;
    match r.ue()? {
        0 => {
            r.ue()?;
        }
        1 => {
            r.bit()?;
            r.se()?;
            r.se()?;
            for _ in 0..r.ue()? {
                r.se()?;
            }
        }
        _ => {}
    }
    let refs = r.ue()?;
    r.bit()?;
    r.ue()?;
    r.ue()?;
    if !r.bit()? {
        r.bit()?;
    }
    r.bit()?;
    if r.bit()? {
        for _ in 0..4 {
            r.ue()?;
        }
    }
    Some(refs)
}

fn skip_scaling_list(r: &mut Reader, size: usize) -> Option<()> {
    let (mut last, mut next) = (8i64, 8i64);
    for _ in 0..size {
        if next != 0 {
            next = (last + r.se()? + 256) % 256;
        }
        if next != 0 {
            last = next;
        }
    }
    Some(())
}

/// Reads the VUI up to its bitstream restriction flag, returning that
/// flag's position.
fn vui_to_restriction(r: &mut Reader) -> Option<usize> {
    if r.bit()? && r.bits(8)? == 255 {
        r.bits(32)?;
    }
    if r.bit()? {
        r.bit()?;
    }
    if r.bit()? {
        r.bits(4)?;
        if r.bit()? {
            r.bits(24)?;
        }
    }
    if r.bit()? {
        r.ue()?;
        r.ue()?;
    }
    if r.bit()? {
        r.bits(32)?;
        r.bits(32)?;
        r.bit()?;
    }
    let nal = r.bit()?;
    if nal {
        hrd(r)?;
    }
    let vcl = r.bit()?;
    if vcl {
        hrd(r)?;
    }
    if nal || vcl {
        r.bit()?;
    }
    r.bit()?;
    Some(r.at)
}

fn hrd(r: &mut Reader) -> Option<()> {
    let count = r.ue()? + 1;
    r.bits(8)?;
    for _ in 0..count {
        r.ue()?;
        r.ue()?;
        r.bit()?;
    }
    r.bits(20)?;
    Some(())
}

/// The raw bytes of a NAL unit's payload, without emulation prevention.
fn unescape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut zeros = 0;
    for &b in data {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
    out
}

/// Emulation prevention put back, so no start code appears inside.
fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    let mut zeros = 0;
    for &b in data {
        if zeros >= 2 && b <= 3 {
            out.push(3);
            zeros = 0;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
    out
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn bit(&mut self) -> Option<bool> {
        let byte = self.data.get(self.at / 8)?;
        let bit = byte >> (7 - self.at % 8) & 1 == 1;
        self.at += 1;
        Some(bit)
    }
    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0;
        for _ in 0..n {
            v = v << 1 | self.bit()? as u32;
        }
        Some(v)
    }
    fn ue(&mut self) -> Option<u32> {
        let mut zeros = 0;
        while !self.bit()? {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        Some((1u32 << zeros) - 1 + self.bits(zeros)?)
    }
    fn se(&mut self) -> Option<i64> {
        let k = self.ue()? as i64;
        Some(if k & 1 == 1 { (k + 1) / 2 } else { -(k / 2) })
    }
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
    bits: usize,
}

impl Writer {
    fn bit(&mut self, on: bool) {
        if self.bits.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if on {
            *self.bytes.last_mut().unwrap() |= 1 << (7 - self.bits % 8);
        }
        self.bits += 1;
    }
    /// The first `count` bits of `data`.
    fn copy(&mut self, data: &[u8], count: usize) {
        for i in 0..count {
            self.bit(data[i / 8] >> (7 - i % 8) & 1 == 1);
        }
    }
    fn ue(&mut self, v: u32) {
        let v = v as u64 + 1;
        let len = 64 - v.leading_zeros();
        for _ in 1..len {
            self.bit(false);
        }
        for i in (0..len).rev() {
            self.bit(v >> i & 1 == 1);
        }
    }
}

/// Every sequence parameter set in an Annex B picture said to show each
/// picture at once; the rest unchanged.
pub fn annex_b_no_reordering(data: &[u8]) -> Option<Vec<u8>> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut out = Vec::with_capacity(data.len() + 16);
    let mut changed = false;
    let mut copied = 0;
    for (n, &start) in starts.iter().enumerate() {
        let mut end = starts.get(n + 1).map_or(data.len(), |&next| next - 3);
        // The zero before a four byte start code belongs to the next one.
        while n + 1 < starts.len() && end > start && data[end - 1] == 0 {
            end -= 1;
        }
        if data.get(start).is_some_and(|b| b & 31 == 7)
            && let Some(sps) = no_reordering(&data[start..end])
        {
            out.extend_from_slice(&data[copied..start]);
            out.extend_from_slice(&sps);
            copied = end;
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    out.extend_from_slice(&data[copied..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Apple's software encoder on the i5: Main profile, VUI with an HRD and
    /// no restriction.
    const I5: &str = "274d4028a9180f0044fcb80b501010130ad7bdf010";
    /// Apple silicon's low latency encoder: already says nought.
    const M1: &str = "27640c28ac1314501e0089f966a0202020f0804258";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn reorder_count(sps: &[u8]) -> Option<u32> {
        let rbsp = unescape(&sps[1..]);
        let mut r = Reader { data: &rbsp, at: 0 };
        read_to_vui(&mut r)?;
        if !r.bit()? {
            return None;
        }
        vui_to_restriction(&mut r)?;
        if !r.bit()? {
            return None;
        }
        r.bit()?;
        for _ in 0..4 {
            r.ue()?;
        }
        r.ue()
    }

    #[test]
    fn the_i5_stream_is_told_nothing_is_reordered() {
        let sps = hex(I5);
        assert_eq!(reorder_count(&sps), None);
        let fixed = no_reordering(&sps).unwrap();
        assert_eq!(reorder_count(&fixed), Some(0));
        // Everything before the restriction is as it was.
        assert_eq!(fixed[..18], sps[..18]);
        assert_eq!(no_reordering(&fixed), None);
    }

    #[test]
    fn a_stream_without_a_vui_gets_one() {
        // The i5's parameter set cut off at its VUI flag, which says none.
        let sps = hex(I5);
        let rbsp = unescape(&sps[1..]);
        let mut r = Reader { data: &rbsp, at: 0 };
        read_to_vui(&mut r).unwrap();
        let mut w = Writer::default();
        w.copy(&rbsp, r.at);
        w.bit(false);
        w.bit(true);
        while !w.bits.is_multiple_of(8) {
            w.bit(false);
        }
        let mut bare = vec![sps[0]];
        bare.extend(escape(&w.bytes));
        assert_eq!(reorder_count(&bare), None);
        let fixed = no_reordering(&bare).unwrap();
        assert_eq!(reorder_count(&fixed), Some(0));
    }

    #[test]
    fn other_units_and_short_ones_are_left_alone() {
        assert_eq!(no_reordering(&hex("28fe09c8")), None);
        assert_eq!(no_reordering(&hex(M1)), None);
    }

    #[test]
    fn a_picture_keeps_its_other_units() {
        let mut data = vec![0, 0, 0, 1];
        data.extend(hex(I5));
        data.extend([
            0, 0, 0, 1, 0x28, 0xfe, 0x09, 0xc8, 0, 0, 1, 0x65, 0x88, 0x84,
        ]);
        let fixed = annex_b_no_reordering(&data).unwrap();
        assert!(fixed.ends_with(&[
            0, 0, 0, 1, 0x28, 0xfe, 0x09, 0xc8, 0, 0, 1, 0x65, 0x88, 0x84
        ]));
        assert!(fixed.starts_with(&[0, 0, 0, 1, 0x27, 0x4d]));
    }
}
