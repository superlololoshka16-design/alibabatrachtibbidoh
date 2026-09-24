use zaic::feilin::*;
use zaic::crypto::{b64_encode, b64_decode, md5, md5_hex};

use zaic::feilin::*;

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
    assert_eq!(b64_encode(&md5(b"abc")), "kAFQmDzST7DWlj99KOF/cg==");
}
