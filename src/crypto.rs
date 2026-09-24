use aws_lc_rs::cipher::{
    PaddedBlockDecryptingKey, PaddedBlockEncryptingKey, UnboundCipherKey, DecryptionContext,
    EncryptionContext, AES_128,
};
use aws_lc_rs::digest;
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rand;

pub const IV_LEN: usize = 16;
pub const SHA1_LEN: usize = 20;
pub const MD5_LEN: usize = 16;

pub fn aes128_cbc_encrypt(key: &[u8; IV_LEN], iv: &[u8; IV_LEN], plain: &[u8]) -> Vec<u8> {
    let ubk = UnboundCipherKey::new(&AES_128, key).expect("aes128 key");
    let ek = PaddedBlockEncryptingKey::cbc_pkcs7(ubk).expect("cbc pkcs7 key");
    let mut buf = plain.to_vec();
    let ctx = EncryptionContext::Iv128(FixedLength::<IV_LEN>::from(iv));
    ek.less_safe_encrypt(&mut buf, ctx).expect("aes-cbc encrypt");
    buf
}

pub fn aes128_cbc_decrypt(key: &[u8; IV_LEN], iv: &[u8; IV_LEN], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.is_empty() || ct.len() % IV_LEN != 0 {
        return None;
    }
    let ubk = UnboundCipherKey::new(&AES_128, key).ok()?;
    let dk = PaddedBlockDecryptingKey::cbc_pkcs7(ubk).ok()?;
    let mut buf = ct.to_vec();
    let ctx = DecryptionContext::Iv128(FixedLength::<IV_LEN>::from(iv));
    let plain = dk.decrypt(&mut buf, ctx).ok()?;
    Some(plain.to_vec())
}

pub fn sha1(data: &[u8]) -> [u8; SHA1_LEN] {
    let d = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    let mut out = [0u8; SHA1_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; SHA1_LEN] {
    let k = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let tag = hmac::sign(&k, msg);
    let mut out = [0u8; SHA1_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

pub fn md5(data: &[u8]) -> [u8; MD5_LEN] {
    use md5::Digest;
    let mut h = md5::Md5::new();
    h.update(data);
    let out = h.finalize();
    let mut b = [0u8; MD5_LEN];
    b.copy_from_slice(&out);
    b
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn md5_hex(data: &[u8]) -> String {
    hex_lower(&md5(data))
}

pub fn hex_lower(d: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(d.len() * 2);
    for &b in d {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut chunks = data.chunks_exact(3);
    for c in &mut chunks {
        let v = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.push(B64[(v >> 18) as usize & 63] as char);
        out.push(B64[(v >> 12) as usize & 63] as char);
        out.push(B64[(v >> 6) as usize & 63] as char);
        out.push(B64[v as usize & 63] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let v = u32::from(rem[0]) << 16;
            out.push(B64[(v >> 18) as usize & 63] as char);
            out.push(B64[(v >> 12) as usize & 63] as char);
            out.push_str("==");
        }
        2 => {
            let v = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(B64[(v >> 18) as usize & 63] as char);
            out.push(B64[(v >> 12) as usize & 63] as char);
            out.push(B64[(v >> 6) as usize & 63] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut lookup = [255u8; 256];
    for (i, &c) in B64.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &c in b {
        if c == b'=' {
            break;
        }
        let v = lookup[c as usize];
        if v == 255 {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

pub fn b64s(data: &[u8]) -> String {
    b64_encode(data)
}

pub fn pct_encode(s: &str, out: &mut String) {
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 15) as usize] as char);
            }
        }
    }
}

pub fn pct_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(core::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

pub struct Rng {
    buf: [u8; 64],
    pos: usize,
}

impl Rng {
    pub fn new() -> Self {
        Rng { buf: [0; 64], pos: 64 }
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            if self.pos == 64 {
                rand::fill(&mut self.buf).expect("system rand");
                self.pos = 0;
            }
            let take = (out.len() - i).min(64 - self.pos);
            out[i..i + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            i += take;
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let zone = u64::MAX - (u64::MAX % n) - 1;
        loop {
            let v = self.next_u64();
            if v <= zone {
                return v % n;
            }
        }
    }

    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + self.unit() * (hi - lo)
    }

    pub fn uuid_v4(&mut self) -> String {
        let mut b = [0u8; 16];
        self.fill(&mut b);
        uuid::Builder::from_random_bytes(b).into_uuid().to_string()
    }

    pub fn hex32(&mut self) -> String {
        let mut b = [0u8; 16];
        self.fill(&mut b);
        b.iter().map(|v| format!("{:02x}", v)).collect()
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis() as u64
}
