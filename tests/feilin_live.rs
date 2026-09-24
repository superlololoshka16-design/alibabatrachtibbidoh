use zaic::crypto::{aes128_cbc_decrypt, b64_decode, b64_encode};
use zaic::feilin::{self, DeviceRegistration};
use zaic::profile::{self, SessionCtx};
use zaic::rt;

const DEVICE_ID: &str = "3795d28242a11619bc25f786f84e53d4-h-1789740566060-dc1c638dcc054da0b2ea5aeab58f7848";

const SK: &[u8; 16] = b"5f76907e801e17f0";

fn bundle_iv() -> [u8; 16] {
    bundle_keys().iv
}

fn reg() -> DeviceRegistration {
    DeviceRegistration {
        secret_key: String::from_utf8(SK.to_vec()).unwrap(),
        device_id: DEVICE_ID.to_string(),
        server_blob: String::new(),
        feilin_version: "1.5.1".into(),
        timestamp_ms: 1789740566791,
        client_ip: "47.57.232.232".into(),
        raw: String::new(),
    }
}

fn bundle_keys() -> zaic::rt::AliyunIntel {
    let aliyun = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bundles/aliyun.js"),
    )
    .expect("bundles/aliyun.js");
    rt::extract_aliyun(&aliyun).expect("ключи из бандла")
}

#[test]
fn live_h1_saf_captcha() {
    let iv = bundle_iv();
    let ct = zaic::crypto::aes128_cbc_encrypt(SK, &iv, b"saf-captcha");
    assert_eq!(b64_encode(&ct), "xordkoNFGjX4qY5d2i8i7A==", "h1 из живого захвата Log2");
}

#[test]
fn live_h2_platform() {
    let iv = bundle_iv();
    let ct = zaic::crypto::aes128_cbc_encrypt(SK, &iv, b"W.10054");
    assert_eq!(b64_encode(&ct), "UfDK8l3eZLR0n0aRINQttg==", "h2 из живого захвата Log2");
}

#[test]
fn live_h3_timestamp() {
    let iv = bundle_iv();
    let ct = zaic::crypto::aes128_cbc_encrypt(SK, &iv, b"1789740566791");
    assert_eq!(b64_encode(&ct), "j5e6etoA6mdNZQuNGbNcZA==", "h3 из живого захвата Log2");
}

#[test]
fn seal_roundtrip_restores_payload() {
    let iv = bundle_iv();
    let payload = "W.10054#1.5#11##Blink#probe#payload#with#hashes#and#fields";
    let sealed = feilin::seal_device(&reg(), &iv, payload, 1789740566791);
    let parts: Vec<&str> = sealed.container.split('#').collect();
    assert_eq!(parts.len(), 6, "id#ENC#h1#h2##h3");
    assert_eq!(parts[0], DEVICE_ID);
    let raw = b64_decode(parts[1]).unwrap();

    let plain = aes128_cbc_decrypt(SK, &iv, &raw).unwrap();
    assert_eq!(
        String::from_utf8(plain).unwrap(),
        payload,
        "ENC = b64(IV16||AES(sk,IV,payload))"
    );
    assert_eq!(parts[2], "xordkoNFGjX4qY5d2i8i7A==");
    assert_eq!(parts[3], "UfDK8l3eZLR0n0aRINQttg==");
    assert_eq!(parts[5], "j5e6etoA6mdNZQuNGbNcZA==");
}

#[test]
fn log2_container_structure() {
    let al = bundle_keys();
    let iv = al.iv;
    let upload = al.keys.upload;
    let data = feilin::log2_data(
        &upload, &iv, "3795d28242a11619bc25f786f84e53d4", "W20220202",
        &reg(), "didk33e0", "SEALED", 388,
    );
    let raw = b64_decode(&data).unwrap();
    let plain = aes128_cbc_decrypt(&upload, &iv, &raw).unwrap();
    let text = String::from_utf8(plain).unwrap();
    let parts: Vec<&str> = text.split('#').collect();
    assert_eq!(parts.len(), 8, "appKey#W#enc#W20220202#CLOUD#cost#501#b64");
    assert_eq!(parts[1], "W");
    assert_eq!(parts[3], "W20220202");
    assert_eq!(parts[4], "CLOUD");
    assert_eq!(parts[5], "388");
    assert_eq!(parts[6], "501");
    assert_eq!(parts[7], b64_encode(b"SEALED"));
}

#[test]
fn log3_container_structure() {
    let al = bundle_keys();
    let iv = al.iv;
    let upload = al.keys.upload;
    let data = feilin::log3_data(
        &upload, &iv, "3795d28242a11619bc25f786f84e53d4", "W20220202",
        &reg(), "didk33e0", "1#1#1",
    );
    let raw = b64_decode(&data).unwrap();
    let plain = aes128_cbc_decrypt(&upload, &iv, &raw).unwrap();
    let text = String::from_utf8(plain).unwrap();
    let parts: Vec<&str> = text.split('#').collect();
    assert_eq!(parts.len(), 7, "appKey#W#enc#W20220202#CLOUD#59#b64 — 7 полей");
    assert_eq!(parts[4], "CLOUD");
    assert_eq!(parts[5], "59");
}

#[test]
fn device_config_format() {
    let iv = bundle_iv();
    let al = bundle_keys();

    assert_eq!(al.keys.vr.len(), 16);
    assert_eq!(al.keys.hr.len(), 16);
    assert_ne!(al.keys.vr, al.keys.hr);
    assert_eq!(String::from_utf8_lossy(&iv).len(), 16);
}

fn make_ctx<'a>(rng: &'a mut zaic::crypto::Rng, ip: &'a str, timing: &'a String) -> SessionCtx<'a> {
    SessionCtx {
        rng,
        now_ms: 1789741347892,
        init_ms: 1789741348050,
        verify_ms: 1789741352000,
        client_ip: ip,
        uptime_ms: 1790976,
        timing_log: timing,
        feilin_url: "https://g.alicdn.com/captcha-frontend/FeiLin/1.5.1/feilin024.83fc951d16ef1ca92c6468a2649738e3cd20cb85f650a80686ba863bc3803fd2.js",
        feilin_load_ms: (581232 % 1000) as f64,
        feilin_size: 581232,
        piece_render: "[ec4ac200cecad4988a0bc32890e39073,122,110]",
        strip_render: "[d8eda6282f6717eb17ee66402af7623e,240,60]",
        tok21: "tok21aa",
        tok71: "tok71-40-char-token-aaaaaaaaaaaaaaaaa",
        tok73: "tok73-42-char-token-bbbbbbbbbbbbbbbbbbb",
    }
}

#[test]
fn all_profiles_build_full_payload() {
    let timing = "10-0|11-203|20-204|23-446|30-448|40-458|41-981|70-981".to_string();
    for p in (0..10).map(zaic::gen::snap) {
        let mut rng = zaic::crypto::Rng::new();
        let mut ctx = make_ctx(&mut rng, "47.57.232.232", &timing);
        let payload = profile::build_payload(&p, &mut ctx);
        let fields: Vec<&str> = payload.split('#').collect();
        assert_eq!(fields.len(), 142, "snap#{}: число полей", p.idx);
        assert_eq!(fields[0], "W.10054");
        assert!(payload.contains(&p.gpu_angle), "snap#{}: GPU в payload", p.idx);
        assert!(payload.contains(p.tz), "snap#{}: таймзона в payload", p.idx);
        assert!(
            payload.contains(&format!("{}*{}", p.screen.1, p.screen.0)),
            "snap#{}: экран в payload",
            p.idx
        );
        assert!(payload.contains(&p.os.ua()), "snap#{}: UA в payload", p.idx);
        assert!(payload.contains(&p.tzo.to_string()), "snap#{}: tz-offset", p.idx);
    }
}

#[test]
fn all_profiles_build_mini_payload() {
    let timing = "10-0|11-203|20-204".to_string();
    for p in (0..10).map(zaic::gen::snap) {
        let mut rng = zaic::crypto::Rng::new();
        let mut ctx = make_ctx(&mut rng, "47.57.232.232", &timing);
        let mini = profile::build_mini(&p, &mut ctx, 298, "CERT");
        let fields: Vec<&str> = mini.split('#').collect();
        assert_eq!(fields.len(), 142, "snap#{}: мини 142 слота", p.idx);
        assert_eq!(fields[0], "W.10054");
        assert_eq!(fields[47], format!("{}*{}", p.screen.1, p.screen.0));
    }
}

#[test]
fn profiles_are_heterogeneous() {
    use std::collections::HashSet;
    let snaps: Vec<_> = (0..10).map(zaic::gen::snap).collect();
    let gpus: HashSet<String> = snaps.iter().map(|p| p.gpu_model.to_string()).collect();
    assert_eq!(gpus.len(), 10, "10 строго разных GPU");
    let tzs: HashSet<String> = snaps.iter().map(|p| p.tz.to_string()).collect();
    assert_eq!(tzs.len(), 10, "10 строго разных таймзон");
    let screens: HashSet<(u32, u32)> = snaps.iter().map(|p| p.screen).collect();
    assert_eq!(screens.len(), 10, "10 строго разных экранов");
}
