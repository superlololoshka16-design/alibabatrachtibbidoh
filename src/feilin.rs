use crate::crypto::{aes128_cbc_decrypt, aes128_cbc_encrypt, b64_decode, b64_encode, md5, md5_hex, Rng};

pub const FEILIN_PLATFORM: &str = "W.10054";
pub const CAPTURE_CODE: u32 = 501;

pub const TOKEN_SALT: &str = "daye,raolewoba!";

pub struct DeviceRegistration {
    pub secret_key: String,
    pub device_id: String,
    pub server_blob: String,
    pub feilin_version: String,
    pub timestamp_ms: u64,
    pub client_ip: String,
    pub raw: String,
}

pub fn parse_device_config(k_hr: &[u8; 16], iv: &[u8; 16], dc_b64: &str) -> Option<DeviceRegistration> {
    let raw = b64_decode(dc_b64)?;
    let out = aes128_cbc_decrypt(k_hr, iv, &raw)?;
    let text = String::from_utf8(out).ok()?;
    let parts: Vec<&str> = text.split('#').collect();
    if parts.len() < 9 {
        return None;
    }
    let secret_key = b64_decode(parts[0])
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    let ts: u64 = parts.get(7).and_then(|v| v.parse().ok()).unwrap_or(0);
    Some(DeviceRegistration {
        secret_key,
        device_id: parts[2].to_string(),
        server_blob: parts.get(4).unwrap_or(&"").to_string(),
        feilin_version: parts[3].to_string(),
        timestamp_ms: ts,
        client_ip: parts.get(8).unwrap_or(&"").to_string(),
        raw: text,
    })
}

fn session_key(reg: &DeviceRegistration) -> [u8; 16] {
    let mut k = [0u8; 16];
    let b = reg.secret_key.as_bytes();
    let n = b.len().min(16);
    k[..n].copy_from_slice(&b[..n]);
    k
}

fn seal_enc(session: &[u8; 16], iv: &[u8; 16], payload: &str) -> String {
    b64_encode(&aes128_cbc_encrypt(session, iv, payload.as_bytes()))
}

fn seal_token(session: &[u8; 16], iv: &[u8; 16], value: &str) -> String {
    b64_encode(&aes128_cbc_encrypt(session, iv, value.as_bytes()))
}

pub struct SealedDevice {
    pub container: String,
    pub payload_len: usize,
}

pub fn seal_device(
    reg: &DeviceRegistration,
    iv: &[u8; 16],
    payload: &str,
    ts_ms: u64,
) -> SealedDevice {
    let session = session_key(reg);
    let enc = seal_enc(&session, iv, payload);
    let h1 = seal_token(&session, iv, "saf-captcha");
    let h2 = seal_token(&session, iv, FEILIN_PLATFORM);
    let h3 = seal_token(&session, iv, &ts_ms.to_string());
    SealedDevice {
        container: format!("{}#{}#{}#{}##{}", reg.device_id, enc, h1, h2, h3),
        payload_len: payload.len(),
    }
}

fn log_inner(reg: &DeviceRegistration, iv: &[u8; 16], scene: &str) -> String {
    let session = session_key(reg);
    let plain = format!("{}#saf-captcha#{}", FEILIN_PLATFORM, scene);
    b64_encode(&aes128_cbc_encrypt(&session, iv, plain.as_bytes()))
}

pub fn log2_data(
    upload_key: &[u8; 16],
    iv: &[u8; 16],
    app_key: &str,
    app_version: &str,
    reg: &DeviceRegistration,
    scene: &str,
    sealed: &str,
    gather_cost_ms: u32,
) -> String {
    let inner = log_inner(reg, iv, scene);
    let inner_b64 = b64_encode(sealed.as_bytes());
    let plain = format!(
        "{}#W#{}#{}#CLOUD#{}#{}#{}",
        app_key, inner, app_version, gather_cost_ms, CAPTURE_CODE, inner_b64
    );
    b64_encode(&aes128_cbc_encrypt(upload_key, iv, plain.as_bytes()))
}

pub fn log3_data(
    upload_key: &[u8; 16],
    iv: &[u8; 16],
    app_key: &str,
    app_version: &str,
    reg: &DeviceRegistration,
    scene: &str,
    spec_vector_plain: &str,
) -> String {
    let session = session_key(reg);
    let inner = log_inner(reg, iv, scene);
    let spec_enc = b64_encode(&aes128_cbc_encrypt(&session, iv, spec_vector_plain.as_bytes()));
    let record = format!(
        "511#{}",
        b64_encode(format!("{}#{}", reg.device_id, spec_enc).as_bytes())
    );
    let plain = format!(
        "{}#W#{}#{}#CLOUD#59#{}",
        app_key,
        inner,
        app_version,
        b64_encode(record.as_bytes())
    );
    b64_encode(&aes128_cbc_encrypt(upload_key, iv, plain.as_bytes()))
}

pub fn device_token(
    reg: &DeviceRegistration,
    iv: &[u8; 16],
    mini: &str,
    gather_cost: u32,
) -> String {
    let session = session_key(reg);
    let blob = b64_encode(&aes128_cbc_encrypt(&session, iv, mini.as_bytes()));
    let base = format!(
        "SG_WEB#{}#{}#{}#{}",
        reg.device_id, blob, gather_cost, TOKEN_SALT
    );
    format!(
        "SG_WEB#{}#{}#{}#{}",
        reg.device_id,
        blob,
        gather_cost,
        md5_hex(base.as_bytes())
    )
}

pub fn spec_vector(uptime_ms: u64) -> String {
    let flags = "11111110111111111111111111";
    let plain = format!(
        "0#0#0#0#0#0#0#0#{}#0#0#0#0#0#0#0#0#0#0#0#1#1#{}",
        uptime_ms, flags
    );
    b64_encode(plain.as_bytes())
}

pub fn timing_log(entries: &[(u32, u64)]) -> String {
    entries
        .iter()
        .map(|(code, ms)| format!("{}-{}", code, ms))
        .collect::<Vec<_>>()
        .join("|")
}

#[allow(dead_code)]
pub fn hash_png_target(data: &[u8], w: u32, h: u32) -> String {
    format!("[{},{},{}]", md5_hex(data), w, h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_vector_layout() {
        let sv = spec_vector(1790976);
        let plain = String::from_utf8(b64_decode(&sv).unwrap()).unwrap();
        let parts: Vec<&str> = plain.split('#').collect();
        assert_eq!(parts.len(), 23);
        assert_eq!(parts[8], "1790976");
        assert_eq!(parts[20], "1");
        assert_eq!(parts[21], "1");
        assert_eq!(parts[22].len(), 26);

        assert_eq!(
            sv,
            "MCMwIzAjMCMwIzAjMCMwIzE3OTA5NzYjMCMwIzAjMCMwIzAjMCMwIzAjMCMwIzEjMSMxMTExMTExMDExMTExMTExMTExMTExMTExMQ=="
        );
    }

    #[test]
    fn token_format() {
        let reg = DeviceRegistration {
            secret_key: "a9d7c921e7e7f6dd".into(),
            device_id: "dev".into(),
            server_blob: String::new(),
            feilin_version: String::new(),
            timestamp_ms: 0,
            client_ip: String::new(),
            raw: String::new(),
        };
        let iv = *b"0123456789ABCDEF";
        let t = device_token(&reg, &iv, "mini", 298);
        let parts: Vec<&str> = t.split('#').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "SG_WEB");
        assert_eq!(parts[3], "298");
        assert_eq!(parts[4].len(), 32);
    }

    #[test]
    fn md5_probe() {
        assert_eq!(md5_hex(b"abc").len(), 32);
        assert_eq!(crate::crypto::b64_encode(&md5(b"abc")), "kAFQmDzST7DWlj99KOF/cg==");
    }
}
