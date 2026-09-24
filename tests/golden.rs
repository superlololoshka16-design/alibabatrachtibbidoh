use zaic::crypto::Rng;
use zaic::rt;
use zaic::{feilin, flow, gen, profile, track, verify};

fn read(name: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bundles").join(name)).unwrap()
}

fn intel() -> rt::Intel {
    let al = rt::extract_aliyun(&read("aliyun.js")).expect("aliyun");
    let (duane, secret) = rt::extract_feilin(&read("feilin.js"), &al.access_sec, &al.iv).expect("feilin");
    let r_table = rt::extract_r_table(&read("pe.js")).expect("pe");
    rt::Intel {
        access_sec: al.access_sec,
        iv: al.iv,
        keys: al.keys,
        aaduane_id: al.aaduane_id,
        ak_secret: al.ak_secret,
        cloudauth_duane: duane,
        cloudauth_secret: secret,
        cloudauth_version: al.cloudauth_version,
        app_key: al.app_key,
        app_version: al.app_version,
        api_version: al.api_version,
        platform: al.platform,
        app_name: al.app_name,
        r_table,
        web_key: al.web_key,
        feilin_version: String::new(),
        feilin_url: String::new(),
    }
}

fn reg_fixture() -> feilin::DeviceRegistration {
    feilin::DeviceRegistration {
        secret_key: "5f76907e801e17f0".into(),
        device_id: "3795d28242a11619bc25f786f84e53d4-h-1789740566060-dc1c638dcc054da0b2ea5aeab58f7848".into(),
        server_blob: String::new(),
        feilin_version: String::new(),
        timestamp_ms: 1789740566060,
        client_ip: "47.57.232.232".into(),
        raw: String::new(),
    }
}

#[test]
fn init_captcha_signature_live_vector() {
    let intel = intel();
    let cfg = flow::FlowCfg::from_intel(&intel, "36qgs6xb", "didk33e0", "no8xfe", "sgp");
    let dd = flow::build_device_data(&intel.keys, &intel.iv, &cfg, "36qgs6xb");
    assert_eq!(
        dd,
        "TEQYvgJq1LrMqFaBybfIzPxz2ygFyAct7X/w+LacfXWd9rGSwE/x6ZCONucD1fehMi9xkGJSDbTdPgjkaTUmYDT6EN6zdoexJK8eJmPkTnSnQnNbVZcECxA7/g3O8NBHGxYmbw5uUCb4kavONtnIkkQy94qIIiHc86XsPjRq/17AtDuAXzeAOfYKdvnT8fV8"
    );
    let mut f = zaic::pop::Form::new(cfg.ak_secret.as_slice());
    f.push("AaduaneId", cfg.aaduane_id.clone());
    f.push("SignatureMethod", "HMAC-SHA1".into());
    f.push("SignatureVersion", "1.0".into());
    f.push("Format", "JSON".into());
    f.push("Timestamp", "2026-09-11T21:35:40Z".into());
    f.push("Version", cfg.api_version.clone());
    f.push("Action", "InitCaptchaV3".into());
    f.push("SceneId", "36qgs6xb".into());
    f.push("Language", "en".into());
    f.push("Mode", "embed".into());
    f.push("UpLang", "true".into());
    f.push("DeviceData", dd);
    f.push("SignatureNonce", "8a546b19-702f-43ba-986a-f34efd335dd2".into());
    assert_eq!(f.sign(), "KE3hzE96Sf/wPZxXE4Za/0vLxLU=");
}

#[test]
fn device_config_live_vector() {
    let intel = intel();
    let reg = feilin::parse_device_config(
        &intel.keys.hr,
        &intel.iv,
        "TroZ9ZN9wTNtNVp6KAAST9i/E+Tc8tpSF3DjCnZDlwAJcLjyJSxaEzElnxrRqvnnxieVc4xYfM5Cdlg1n16VHT87JUKNfsr2L49wP8KrC+nC/x9+NboG0wW9fZtmOHIEHoSyw23BRaOMW+zaN4oNYq1cvLPbnSDbLSydKBbPhw5NWhriOi6TilJq3pYDtaoKBBJ7MProngVYwSc+oq5mGD4/44tSOOjPJUdEo0Z2eBXHzMQvYyA7fLjAFJSu39XJM7qCYiVZOS41GqHEDA3SqOX8+fufDqq5g2QP1gkR7NjfInm40s/sB5ZWwDiifw7e",
    )
    .expect("живой DeviceConfig");
    assert_eq!(reg.secret_key, "5f76907e801e17f0");
    assert!(reg.device_id.starts_with("3795d28242a11619bc25f786f84e53d4-h-"));
    assert_eq!(reg.client_ip, "47.57.232.232");
    assert!(reg.feilin_version.starts_with("1.5.1/feilin021"));
}

#[test]
fn r_cipher_live_vector_runtime_table() {
    let intel = intel();
    assert_eq!(&intel.keys.web, b"3e627e1b4c63f913");
    let deflate_b64 = "eJx1j0GLwkAMhf/KknOQZCYmM4LXZRUPguKea7d1ixSWtros4n932q6HHrzkJfkeL4RIHBVePDkRUTMqA2vhv7JgR47+Bvsmy8+bqu1gcYM6hwUEhzyPKGaKb8iA0PXrpPVlgu2Ji3/8M8FuhPV1pOd21LJKOoTzYGi7rOn2VZ1C2ELU6JSUjBLpnewCYSDCebo3DH1jjlDTUv1MoiP1zyqDB+44PrZ7GX4omqr8myKmIBEha07p8Mc7tevP/HfF4Xt7Wi7h/gBeKVDH";
    let expected_b64 = "JRMlgg1EDAVARgILRQRNM0T0U3gZByN+b34ZFFpTIx86iEWM63Z7Hy0WEYJf2uMVMrdifmqNKnC06LHur5J1JXcnCGcQW21iGTbtfQ8ybKYjdT8cD8tPdO5rc0h8GWb2qx5RPsJVTfIZYWhCeIok2Aykj3x1nyVg+A2sdHs1aslOhCALFDUoYQAVWzhHsjUANnUB3yewejx4ER5gISeLMVtzbD0XnwxbMXNdf2IjCCAUckhBUTGdA/GPrTULa2A2WSx8OGNlBjBOShsHNQ8+JwlzDztcGxw5sulZtTUZS81LTXVHtN05TU2Awxlxc2aeHENvjFs8GS99Ot92ZnBRRXU8KDVWCD4wU2cUb0VdNi0=";
    let got = verify::r_cipher(deflate_b64, &intel.keys.web, &intel.r_table);
    let expected = zaic::crypto::b64_decode(expected_b64).unwrap();
    assert_eq!(got, expected, "R-шифр с рантайм-таблицей — байт-в-байт с живым захватом");
}

#[test]
fn sealed_container_six_fields() {
    let intel = intel();
    let reg = reg_fixture();
    let payload = "W.10054#1.5#11##Blink#Windows#Chrome#143.0.0.0";
    let sealed = feilin::seal_device(&reg, &intel.iv, payload, 1789741347892);
    let parts: Vec<&str> = sealed.container.split('#').collect();
    assert_eq!(parts.len(), 6);
    assert_eq!(parts[0], reg.device_id);

    assert_eq!(parts[2].len(), 24);

    assert_eq!(parts[3].len(), 24);

    assert_eq!(parts[5].len(), 24);
    assert_eq!(parts[4], "");

    let sealed2 = feilin::seal_device(&reg, &intel.iv, payload, 1789741347892);
    assert_eq!(sealed.container, sealed2.container);
}

#[test]
fn token_formula_shape() {
    let intel = intel();
    let reg = reg_fixture();
    let t = feilin::device_token(&reg, &intel.iv, "mini-payload", 388);
    let parts: Vec<&str> = t.split('#').collect();
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0], "SG_WEB");
    assert_eq!(parts[1], reg.device_id);
    assert_eq!(parts[3], "388");

    let expect = zaic::crypto::md5_hex(
        format!("SG_WEB#{}#{}#{}#{}", reg.device_id, parts[2], 388, feilin::TOKEN_SALT).as_bytes(),
    );
    assert_eq!(parts[4], expect);
}

#[test]
fn log_containers_shape() {
    let intel = intel();
    let reg = reg_fixture();
    let spec = feilin::spec_vector(1790976);
    let d2 = feilin::log2_data(
        &intel.keys.upload, &intel.iv, &intel.app_key, &intel.app_version,
        &reg, "didk33e0", "SEALED", 388,
    );
    let plain2 = open_aes(&intel.keys.upload, &intel.iv, &d2);
    let p2: Vec<&str> = plain2.split('#').collect();
    assert_eq!(p2[0], intel.app_key.as_str());
    assert_eq!(p2[1], "W");
    assert_eq!(p2[3], intel.app_version.as_str());
    assert_eq!(p2[4], "CLOUD");
    assert_eq!(p2[5], "388");
    assert_eq!(p2[6], "501");

    let d3 = feilin::log3_data(
        &intel.keys.upload, &intel.iv, &intel.app_key, &intel.app_version,
        &reg, "didk33e0", &spec,
    );
    let plain3 = open_aes(&intel.keys.upload, &intel.iv, &d3);
    let p3: Vec<&str> = plain3.split('#').collect();
    assert_eq!(p3[4], "CLOUD");
    assert_eq!(p3[5], "59");

    let rec_b64 = p3[6];
    let rec = String::from_utf8(zaic::crypto::b64_decode(rec_b64).unwrap()).unwrap();
    assert!(rec.starts_with("511#"));
    let inner = String::from_utf8(
        zaic::crypto::b64_decode(rec.strip_prefix("511#").unwrap()).unwrap(),
    )
    .unwrap();
    assert!(inner.starts_with(&reg.device_id));

    let blob = inner.split('#').nth(1).unwrap();
    let dec = zaic::crypto::aes128_cbc_decrypt(
        reg.secret_key.as_bytes().try_into().unwrap(),
        &intel.iv,
        &zaic::crypto::b64_decode(blob).unwrap(),
    )
    .unwrap();
    assert_eq!(String::from_utf8(dec).unwrap(), spec);

    let inner_dec = zaic::crypto::aes128_cbc_decrypt(
        reg.secret_key.as_bytes().try_into().unwrap(),
        &intel.iv,
        &zaic::crypto::b64_decode(p3[2]).unwrap(),
    )
    .unwrap();
    assert_eq!(String::from_utf8(inner_dec).unwrap(), "W.10054#saf-captcha#didk33e0");
}

fn open_aes(key: &[u8; 16], iv: &[u8; 16], b64: &str) -> String {
    let raw = zaic::crypto::b64_decode(b64).unwrap();
    let dec = zaic::crypto::aes128_cbc_decrypt(key, iv, &raw).unwrap();
    String::from_utf8(dec).unwrap()
}

#[test]
fn payload_exact_map_142() {
    use zaic::profile::{self, SessionCtx};
    let mut rng = Rng::new();
    let timing = "10-0|11-233|20-237|23-416|30-417|40-424|41-762|70-763";
    let p = &gen::snap(0);
    let mut ctx = SessionCtx {
        rng: &mut rng,
        now_ms: 1789741347892,
        init_ms: 1789741348050,
        verify_ms: 0,
        client_ip: "47.57.232.232",
        uptime_ms: 1790976,
        timing_log: timing,
        feilin_url: "https://g.alicdn.com/captcha-frontend/FeiLin/1.5.1/feilin021.da034b8e79ba3ff2916416654f42a33d46f25cfe2ca711735ac83a0fe9acd916.js",
        feilin_load_ms: 46.6,
        feilin_size: 581232,
        piece_render: "[ec4ac200cecad4988a0bc32890e39073,122,110]",
        strip_render: "[d8eda6282f6717eb17ee66402af7623e,240,60]",
        tok21: "Z2hjNmloaWY=",
        tok71: "0CPj01gy1gAT7oL5VmpkNnjonqrzwffyRur6htkt",
        tok73: "AtwzKtPOFZyZbfPSA1wVrr8sTfYIHkpubCQrG14P0W",
    };
    let payload = profile::build_payload(p, &mut ctx);
    let fields: Vec<&str> = payload.split('#').collect();
    assert_eq!(fields.len(), 142);
    assert_eq!(fields[0], "W.10054");
    assert_eq!(fields[1], "1.5");
    assert_eq!(fields[8], "504");
    assert_eq!(fields[20], "5");
    assert_eq!(fields[92], "1");
    assert_eq!(fields[108], "1");
    assert_eq!(fields[109], "0");
    assert_eq!(fields[110], "[Chromium,Google Chrome,Not_A Brand]");
    assert!(fields[111].split('|').count() == 36);
    assert_eq!(fields[113], "[0,a]");
    assert_eq!(fields[133], "https");
    assert_eq!(fields[135], "c:");
    assert_eq!(fields[139], "[ec4ac200cecad4988a0bc32890e39073,122,110]");
    assert_eq!(fields[140], "[d8eda6282f6717eb17ee66402af7623e,240,60]");
    assert_eq!(fields[141], "1");
    assert_eq!(fields[71].len(), 40);
    assert_eq!(fields[73].len(), 42);

    assert!(fields[52].starts_with("de26") && fields[52].contains("7f42"));
    assert_eq!(profile::empty_json_md5(), "99914b932bd37a50b983c5e7c90ae93b");
}

#[test]
fn mini_exact_map_142() {
    use zaic::profile::{self, SessionCtx};
    let mut rng = Rng::new();
    let timing = "10-0|11-233|20-237|23-416|30-417|40-424|41-762|70-763|71-859|80-859";
    let p = &gen::snap(0);
    let mut ctx = SessionCtx {
        rng: &mut rng,
        now_ms: 1789741348900,
        init_ms: 1789741348050,
        verify_ms: 1789741348953,
        client_ip: "47.57.232.232",
        uptime_ms: 1790976,
        timing_log: timing,
        feilin_url: "",
        feilin_load_ms: 0.0,
        feilin_size: 0,
        piece_render: "",
        strip_render: "",
        tok21: "Z2hjNmloaWY=",
        tok71: "0CPj01gy1gAT7oL5VmpkNnjonqrzwffyRur6htkt",
        tok73: "AtwzKtPOFZyZbfPSA1wVrr8sTfYIHkpubCQrG14P0W",
    };
    let mini = profile::build_mini(p, &mut ctx, 388, "CERTIFYID1");
    let fields: Vec<&str> = mini.split('#').collect();
    assert_eq!(fields.len(), 142);
    assert_eq!(fields[3], "388");
    assert_eq!(fields[8], "0");
    assert_eq!(fields[20], "7");
    assert_eq!(fields[76], "false");
    assert_eq!(fields[77], "CERTIFYID1");
    assert_eq!(fields[71].len(), 40);
    assert_eq!(fields[73].len(), 42);
    assert_eq!(fields[109], "0");
}

#[test]
fn y_digest_and_data_pipeline() {
    let intel = intel();
    let tk = "{\"TrackList\":{\"mc\":\"100,200,300, ,1\",\"tc\":\"\",\"mu\":\"100,200,400, ,1\",\"te\":\"\",\"mp\":\"90,190,50,1|95,195,90,1\",\"tmv\":\"\",\"ks\":\"\",\"fi\":\"\",\"startTime\":1789741348000,\"si\":\"1920,1920,969,1920,969,1048,1080,59.88,1936\"},\"TrackStartTime\":1789741348000,\"VerifyTime\":1789741348900,\"arg\":\"QUJD\"}";
    let data = verify::build_data(&intel.keys.web, &intel.r_table, tk);
    assert!(!data.is_empty());

    let enc = zaic::crypto::b64_decode(&data).unwrap();

    let data2 = verify::build_data(&intel.keys.web, &intel.r_table, tk);
    assert_eq!(data, data2, "data детерминирован");

    let y = zaic::ycipher::y_digest(tk, "0000");
    assert_eq!(y.len(), 32);
}

#[test]
fn click_tk_shape() {
    let mut rng = Rng::new();
    let geom = verify::ClickGeom { btn_x: 640, btn_y: 500, approach_from: (800, 300) };
    let tk = verify::tk_json_click(&mut rng, &geom, 1789741348050, 1789741354000, "1920,1920,969,1920,969,1048,1080,59.88,1936");
    assert!(tk.starts_with("{\"TrackList\":{\"mc\":\"640,500,"));
    assert!(tk.contains(", ,1\",\"tc\":\"\""));
    assert!(tk.contains("\"mp\":\""));
    assert!(tk.contains("\"si\":\"1920,1920,969,1920,969,1048,1080,59.88,1936\""));
    assert!(tk.contains("\"arg\":\""));
    assert!(tk.ends_with("}"));
}

#[test]
fn drag_track_still_sane() {
    let mut rng = Rng::new();
    let pts = track::generate_track(&mut rng, 260.0, 18.0);
    assert!(pts.len() >= 20);
    let total = pts.last().unwrap().t_ms;
    assert!((1000..=3200).contains(&total));
}

#[test]
fn probe_roundtrip_and_targets() {
    use zaic::probe;
    let rgba = probe::raster_piece_probe();
    let png = probe::encode_png_chrome(&rgba, probe::PIECE_W, probe::PIECE_H).expect("PNG");
    let field = probe::render_field(&png, probe::PIECE_W, probe::PIECE_H);
    assert_ne!(field, probe::TARGET_PIECE_RENDER);
    assert_eq!(probe::TARGET_PIECE_RENDER, "[ec4ac200cecad4988a0bc32890e39073,122,110]");
    assert_eq!(probe::TARGET_STRIP_RENDER, "[d8eda6282f6717eb17ee66402af7623e,240,60]");
}

#[test]
fn golden_png_roundtrip_byte_exact() {
    use zaic::probe;
    for (name, w, h) in [
        ("probe_piece_golden.png", probe::PIECE_W, probe::PIECE_H),
        ("probe_strip_golden.png", probe::STRIP_W, probe::STRIP_H),
    ] {
        let raw = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bundles").join(name)).unwrap();
        let rgba = probe::decode_rgba(&raw).expect(name);
        let re = probe::encode_png_chrome(&rgba.px, w, h).expect("re-encode");
        assert_eq!(re, raw, "{}: decode→encode байт-в-байт", name);
    }
}

#[test]
fn session_cross_consistency_payload_mini() {
    use zaic::profile::{self, SessionCtx};
    let mut rng = Rng::new();
    let timing_l2 = "10-0|11-233|20-237|23-416|30-417|40-424|41-762|70-763";
    let timing_mini = "10-0|11-233|20-237|23-416|30-417|40-424|41-762|70-763|71-859|80-859";
    let tok21 = "Z2hjNmloaWY=";
    let tok71 = "0CPj01gy1gAT7oL5VmpkNnjonqrzwffyRur6htkt";
    let tok73 = "AtwzKtPOFZyZbfPSA1wVrr8sTfYIHkpubCQrG14P0W";
    let p = &gen::snap(3);
    let mut ctx = SessionCtx {
        rng: &mut rng,
        now_ms: 1789741350000,
        init_ms: 1789741348050,
        verify_ms: 0,
        client_ip: "47.57.242.119",
        uptime_ms: 2_100_000,
        timing_log: timing_l2,
        feilin_url: "https://g.alicdn.com/captcha-frontend/FeiLin/1.5.1/feilin022.js",
        feilin_load_ms: 46.6,
        feilin_size: 581232,
        piece_render: "",
        strip_render: "",
        tok21,
        tok71,
        tok73,
    };
    let payload = profile::build_payload(p, &mut ctx);
    let mut ctx2 = SessionCtx {
        rng: &mut rng,
        now_ms: 1789741356000,
        init_ms: 1789741348050,
        verify_ms: 1789741356400,
        client_ip: "47.57.242.119",
        uptime_ms: 2_100_000,
        timing_log: timing_mini,
        feilin_url: "",
        feilin_load_ms: 0.0,
        feilin_size: 0,
        piece_render: "",
        strip_render: "",
        tok21,
        tok71,
        tok73,
    };
    let mini = profile::build_mini(p, &mut ctx2, 298, "CERT01");
    let pf: Vec<&str> = payload.split('#').collect();
    let mf: Vec<&str> = mini.split('#').collect();
    assert_eq!(pf[21], mf[21], "[21] сессионный токен");
    assert_eq!(pf[71], mf[71], "[71] сессионный токен");
    assert_eq!(pf[73], mf[73], "[73] сессионный токен");
    assert_eq!(pf[72], mf[72], "[72] init-момент");
    assert_eq!(pf[88], mf[88], "[88] spec_vector");
    assert_eq!(pf[47], mf[47], "[47] экран");
    assert_eq!(pf[32], mf[32], "[32] audio");
    assert_eq!(pf[78], mf[78], "[78] font");
    assert_eq!(pf[42], mf[42], "[42] ip");

    assert!(mf[43].starts_with(&pf[43]), "мини-тайминг extends Log2-тайминга");
    assert!(mf[43].len() > pf[43].len());

    assert!(pf[74].parse::<u64>().unwrap() > pf[72].parse::<u64>().unwrap());
    assert!(mf[74].parse::<u64>().unwrap() > mf[72].parse::<u64>().unwrap());
}
