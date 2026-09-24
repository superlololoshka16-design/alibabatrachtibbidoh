use crate::crypto::{b64_encode, hmac_sha1, pct_encode, now_ms, Rng};

pub struct Form {
    keys: Vec<&'static str>,
    vals: Vec<String>,
    secret: Vec<u8>,
}

impl Form {
    pub fn new(secret: &[u8]) -> Self {
        Form { keys: Vec::new(), vals: Vec::new(), secret: secret.to_vec() }
    }

    pub fn push(&mut self, k: &'static str, v: String) {
        self.keys.push(k);
        self.vals.push(v);
    }

    fn canonical(&self) -> String {
        let mut idx: Vec<usize> = (0..self.keys.len()).collect();
        idx.sort_by(|&a, &b| self.keys[a].cmp(self.keys[b]));
        let mut q = String::with_capacity(256);
        for (n, &i) in idx.iter().enumerate() {
            if n > 0 {
                q.push('&');
            }
            pct_encode(self.keys[i], &mut q);
            q.push('=');
            pct_encode(&self.vals[i], &mut q);
        }
        q
    }

    pub fn string_to_sign(&self) -> String {
        let c = self.canonical();
        let mut sts = String::with_capacity(c.len() + 16);
        sts.push_str("POST&%2F&");
        pct_encode(&c, &mut sts);
        sts
    }

    pub fn sign(&self) -> String {
        let sts = self.string_to_sign();
        let mut key = self.secret.clone();
        key.push(b'&');
        let mac = hmac_sha1(&key, sts.as_bytes());
        b64_encode(&mac)
    }

    pub fn body(&self) -> String {
        let mut b = String::with_capacity(512);
        for (n, i) in (0..self.keys.len()).enumerate() {
            if n > 0 {
                b.push('&');
            }
            b.push_str(self.keys[i]);
            b.push('=');
            for &c in self.vals[i].as_bytes() {
                match c {
                    b' ' => b.push('+'),
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        b.push(c as char)
                    }
                    _ => {
                        const HEX: &[u8; 16] = b"0123456789ABCDEF";
                        b.push('%');
                        b.push(HEX[(c >> 4) as usize] as char);
                        b.push(HEX[(c & 15) as usize] as char);
                    }
                }
            }
        }
        b
    }
}

pub fn iso_now_utc() -> String {
    iso_from_ms(now_ms())
}

pub fn iso_from_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let civil = civil_from_days(days as i64);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", civil.0, civil.1, civil.2, h, m, s)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn nonce(rng: &mut Rng) -> String {
    rng.uuid_v4()
}
