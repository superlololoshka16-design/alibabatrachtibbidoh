use crate::crypto::{aes128_cbc_decrypt, b64_decode};

#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct SessionKeys {
    pub vr: [u8; 16],
    pub hr: [u8; 16],
    pub flag: [u8; 16],
    pub upload: [u8; 16],
    pub preid: [u8; 16],
    pub web: [u8; 16],
}

pub fn derive_key(blob: &str, access_sec: &[u8; 16], iv: &[u8; 16]) -> Option<[u8; 16]> {
    let raw = b64_decode(blob)?;
    if raw.len() != 32 {
        return None;
    }
    let out = aes128_cbc_decrypt(access_sec, iv, &raw)?;
    if out.len() != 16 {
        return None;
    }
    let mut k = [0u8; 16];
    k.copy_from_slice(&out);
    Some(k)
}

impl SessionKeys {
    pub fn vr_str(&self) -> &str {
        core::str::from_utf8(&self.vr).unwrap_or("")
    }
    pub fn hr_str(&self) -> &str {
        core::str::from_utf8(&self.hr).unwrap_or("")
    }
    pub fn flag_str(&self) -> &str {
        core::str::from_utf8(&self.flag).unwrap_or("")
    }
    pub fn upload_str(&self) -> &str {
        core::str::from_utf8(&self.upload).unwrap_or("")
    }
}
