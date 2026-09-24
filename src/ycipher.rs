fn utf8_bytes_string(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

pub fn y_digest(input: &str, key: &str) -> String {
    let o = utf8_bytes_string(input);
    let a_len = o.len();
    let m = key.len();
    if m == 0 {
        return String::new();
    }
    let key_b = key.as_bytes();

    let mut e = [0u32; 16];
    for (i, v) in e.iter_mut().enumerate() {
        *v = ((i as u32) << 4) + (i as u32 % 16);
    }
    let f = 16u32;
    let mask = f - 1;

    let mut ka = 0u32;
    for ko in 0..f as usize {
        ka = ((ko as u32)
            .wrapping_add(ka)
            .wrapping_add(e[ko])
            .wrapping_add(e[ka as usize])
            >> 1)
            .wrapping_add(key_b[ko % m] as u32)
            & mask;
        let c = e[ko];
        e[ko] = e[ka as usize];
        e[ka as usize] = c;
    }

    let mut m2: usize = 0;
    let mut n2: usize = 0;
    for r2 in 0..a_len {
        n2 = (((m2 ^ n2) as u32).wrapping_add(e[m2] ^ e[n2]) as usize) & mask as usize;
        let c = e[m2];
        e[m2] = e[n2];
        e[n2] = c;
        let mut cc = o[r2] as u32;
        cc = cc.wrapping_add(m2 as u32).wrapping_add(n2 as u32);
        cc = cc ^ e[m2] ^ e[n2];
        cc &= 255;
        e[m2] = cc;
        m2 = (m2 + 1) & mask as usize;
    }

    for o3 in 0..(f << 1) as usize {
        let r3 = o3 % f as usize;
        if r3 != 0 {
            e[r3] ^= e[r3 - 1];
        } else {
            e[0] ^= e[f as usize - 1];
        }
    }

    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for v in e.iter() {
        out.push(H[(*v >> 4) as usize & 15] as char);
        out.push(H[(*v & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_shape() {
        let d1 = y_digest("{\"TrackList\":{}}", "0000");
        assert_eq!(d1.len(), 32);
        assert!(d1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(d1, y_digest("{\"TrackList\":{}}", "0000"));
        assert_ne!(d1, y_digest("{\"TrackList\":{} ", "0000"));
        assert_ne!(d1, y_digest("{\"TrackList\":{}}", "0001"));
    }

    #[test]
    fn utf8_preprocessing() {
        let d = y_digest("µ", "0000");
        assert_eq!(d.len(), 32);
    }
}
