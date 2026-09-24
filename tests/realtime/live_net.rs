use zaic::net::{BrowserHeaders, Engine};
use zaic::rt;
use zaic::{feilin, flow, profile, verify};

const ALIYUN_CDN: &str = "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js";

fn read(name: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bundles").join(name)).unwrap()
}

async fn engine() -> Engine {
    Engine::new().expect("wreq движок")
}

fn json_field(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":\"", key);
    let start = body.find(&pat)? + pat.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[tokio::test]
async fn live_init_captcha_with_runtime_keys() {
    let engine = engine().await;
    let bh = BrowserHeaders::default();
    let rep = engine.get_bytes(&bh, ALIYUN_CDN).await.expect("aliyun.js CDN");
    let live = String::from_utf8_lossy(&rep.body).to_string();
    let al = rt::extract_aliyun(&live).expect("ключи из живого CDN-бандла");

    let page = engine.get_bytes(&bh, "https://chat.z.ai/auth").await.expect("страница");
    let html = String::from_utf8_lossy(&page.body).to_string();
    assert!(html.contains("chat.z.ai"));
    let cfg = flow::FlowCfg::from_intel(
        &rt::Intel {
            access_sec: al.access_sec,
            iv: al.iv,
            keys: al.keys,
            aaduane_id: al.aaduane_id.clone(),
            ak_secret: al.ak_secret.clone(),
            cloudauth_duane: String::new(),
            cloudauth_secret: String::new(),
            cloudauth_version: al.cloudauth_version.clone(),
            app_key: al.app_key.clone(),
            app_version: al.app_version.clone(),
            api_version: al.api_version.clone(),
            platform: al.platform.clone(),
            app_name: al.app_name.clone(),
            r_table: [0u8; 64],
            web_key: al.web_key,
            feilin_version: String::new(),
            feilin_url: String::new(),
        },
        "36qgs6xb",
        "didk33e0",
        "no8xfe",
        "sgp",
    );
    let mut rng = zaic::crypto::Rng::new();

    let dd = flow::build_device_data(&al.keys, &al.iv, &cfg, "didk33e0");
    let mut f = flow::init_form(&mut rng, &cfg, "didk33e0", dd);
    let sig = f.sign();
    f.push("Signature", sig);
    let rep = engine.post_form(&bh, &cfg.api_url(), &f.body()).await.expect("init сеть");
    assert_eq!(rep.status, 200);
    assert!(rep.version.contains("2"), "h2");
    let body = String::from_utf8_lossy(&rep.body).to_string();
    assert!(body.contains("CertifyId"), "init не выдал капчу: {}", &body[..body.len().min(200)]);
    let certify = json_field(&body, "CertifyId");
    assert!(certify.as_deref().map(|c| !c.is_empty()).unwrap_or(false));
    if let Some(dc) = json_field(&body, "DeviceConfig") {
        let reg = feilin::parse_device_config(&al.keys.hr, &al.iv, &dc).expect("DeviceConfig живым hr-ключом");
        assert!(reg.device_id.starts_with(&al.app_key));
    }
}

#[tokio::test]
async fn live_rtable_from_static_path() {
    let engine = engine().await;
    let bh = BrowserHeaders::default();
    let aliyun = engine.get_bytes(&bh, ALIYUN_CDN).await.expect("CDN");
    let live = String::from_utf8_lossy(&aliyun.body).to_string();
    let al = rt::extract_aliyun(&live).expect("алиюн");
    let cfg = flow::FlowCfg::from_intel(
        &rt::Intel {
            access_sec: al.access_sec,
            iv: al.iv,
            keys: al.keys,
            aaduane_id: al.aaduane_id.clone(),
            ak_secret: al.ak_secret.clone(),
            cloudauth_duane: String::new(),
            cloudauth_secret: String::new(),
            cloudauth_version: al.cloudauth_version.clone(),
            app_key: al.app_key.clone(),
            app_version: al.app_version.clone(),
            api_version: al.api_version.clone(),
            platform: al.platform.clone(),
            app_name: al.app_name.clone(),
            r_table: [0u8; 64],
            web_key: al.web_key,
            feilin_version: String::new(),
            feilin_url: String::new(),
        },
        "36qgs6xb",
        "didk33e0",
        "no8xfe",
        "sgp",
    );
    let mut rng = zaic::crypto::Rng::new();
    let dd = flow::build_device_data(&al.keys, &al.iv, &cfg, "didk33e0");
    let mut f = flow::init_form(&mut rng, &cfg, "didk33e0", dd);
    let sig = f.sign();
    f.push("Signature", sig);
    let rep = engine.post_form(&bh, &cfg.api_url(), &f.body()).await.expect("init");
    let body = String::from_utf8_lossy(&rep.body).to_string();
    let sp = json_field(&body, "StaticPath").expect("StaticPath");
    let url = format!("https://g.alicdn.com/captcha-frontend/dynamicJS/{}.js", sp);
    let pe = engine.get_bytes(&bh, &url).await.expect("живой pe.js");
    let src = String::from_utf8_lossy(&pe.body).to_string();
    let table = rt::extract_r_table(&src).expect("R-таблица из живого байткода");
    let uniq: std::collections::HashSet<u8> = table.iter().copied().collect();
    assert_eq!(uniq.len(), 64, "перестановка 0..63");
}

#[tokio::test]
async fn live_full_round_profile_zero() {
    let engine = engine().await;
    let bh = BrowserHeaders::default();
    let aliyun = engine.get_bytes(&bh, ALIYUN_CDN).await.expect("CDN");
    let live = String::from_utf8_lossy(&aliyun.body).to_string();
    let al = rt::extract_aliyun(&live).expect("алиюн");
    let feilin_src = read("feilin.js");
    let (duane, secret) = rt::extract_feilin(&feilin_src, &al.access_sec, &al.iv).expect("дуаны");
    let intel = rt::Intel {
        access_sec: al.access_sec,
        iv: al.iv,
        keys: al.keys,
        aaduane_id: al.aaduane_id,
        ak_secret: al.ak_secret,
        cloudauth_duane: duane,
        cloudauth_secret: secret,
        cloudauth_version: al.cloudauth_version,
        app_key: al.app_key.clone(),
        app_version: al.app_version.clone(),
        api_version: al.api_version.clone(),
        platform: al.platform.clone(),
        app_name: al.app_name.clone(),
        r_table: [0u8; 64],
        web_key: al.web_key,
        feilin_version: String::new(),
        feilin_url: String::new(),
    };
    let cfg = flow::FlowCfg::from_intel(&intel, "36qgs6xb", "didk33e0", "no8xfe", "sgp");
    let scene = "didk33e0";
    let prof = &zaic::gen::snap(0);

    let mut rng = zaic::crypto::Rng::new();
    let dd = flow::build_device_data(&intel.keys, &intel.iv, &cfg, scene);
    let mut f = flow::init_form(&mut rng, &cfg, scene, dd);
    let sig = f.sign();
    f.push("Signature", sig);
    let rep = engine.post_form(&bh, &cfg.api_url(), &f.body()).await.expect("init");
    assert_eq!(rep.status, 200);
    let body = String::from_utf8_lossy(&rep.body).to_string();
    let certify = json_field(&body, "CertifyId").expect("CertifyId");
    let static_path = json_field(&body, "StaticPath").unwrap_or_default();
    let reg = json_field(&body, "DeviceConfig")
        .and_then(|d| feilin::parse_device_config(&intel.keys.hr, &intel.iv, &d))
        .expect("DeviceConfig");

    let pe_url = format!("https://g.alicdn.com/captcha-frontend/dynamicJS/{}.js", static_path);
    let pe = engine.get_bytes(&bh, &pe_url).await.expect("pe.js");
    let r_table = rt::extract_r_table(&String::from_utf8_lossy(&pe.body)).expect("R-таблица");

    let mut ul = flow::upload_log_form(&mut rng, &cfg, &certify, &reg.client_ip, zaic::crypto::now_ms(), 210, 170, 15);
    let usig = ul.sign();
    ul.push("Signature", usig);
    let rep = engine.post_form(&bh, &cfg.upload_url(), &ul.body()).await.expect("UploadLog");
    assert_eq!(rep.status, 200);

    let gather_cost = 280u32;
    let timing = feilin::timing_log(&[
        (10, 0), (11, 203), (20, 205), (23, 410), (30, 412), (40, 420), (41, 760), (70, 761),
    ]);
    let feilin_url = "https://g.alicdn.com/captcha-frontend/FeiLin/1.5.1/feilin021.da034b8e79ba3ff2916416654f42a33d46f25cfe2ca711735ac83a0fe9acd916.js";
    let mut sctx = profile::SessionCtx {
        rng: &mut rng,
        now_ms: zaic::crypto::now_ms(),
        init_ms: reg.timestamp_ms,
        verify_ms: 0,
        client_ip: &reg.client_ip,
        uptime_ms: 1_790_976,
        timing_log: &timing,
        feilin_url,
        feilin_load_ms: 150.0,
        feilin_size: 581232,
        piece_render: "",
        strip_render: "",
        tok21: "Z2hjNmloaWY=",
        tok71: "0CPj01gy1gAT7oL5VmpkNnjonqrzwffyRur6htkt",
        tok73: "AtwzKtPOFZyZbfPSA1wVrr8sTfYIHkpubCQrG14P0W",
    };
    let payload = profile::build_payload(prof, &mut sctx);
    assert_eq!(payload.split('#').count(), 142);
    let sealed = feilin::seal_device(&reg, &intel.iv, &payload, zaic::crypto::now_ms());
    let data2 = feilin::log2_data(
        &intel.keys.upload, &intel.iv, &cfg.app_key, &cfg.app_version,
        &reg, scene, &sealed.container, gather_cost,
    );
    let mut lf2 = zaic::telemetry::cloudauth_form(&intel, &mut rng, "Log2", data2);
    let lsig2 = lf2.sign();
    lf2.push("Signature", lsig2);
    let rep = engine.post_form(&bh, "https://cloudauth-device-dualstack.ap-southeast-1.aliyuncs.com/", &lf2.body()).await.expect("Log2");
    let body = String::from_utf8_lossy(&rep.body).to_string();
    assert!(body.contains("\"ResultObject\":true"), "Log2 отклонён: {}", &body[..body.len().min(200)]);

    let spec = feilin::spec_vector(1_790_976);
    let data3 = feilin::log3_data(
        &intel.keys.upload, &intel.iv, &cfg.app_key, &cfg.app_version,
        &reg, scene, &spec,
    );
    let mut lf3 = zaic::telemetry::cloudauth_form(&intel, &mut rng, "Log3", data3);
    let lsig3 = lf3.sign();
    lf3.push("Signature", lsig3);
    let rep = engine.post_form(&bh, "https://cloudauth-device-dualstack.ap-southeast-1.aliyuncs.com/", &lf3.body()).await.expect("Log3");
    assert_eq!(rep.status, 200);

    let verify_ms = zaic::crypto::now_ms();
    let mini_timing = feilin::timing_log(&[
        (10, 0), (11, 203), (20, 205), (23, 410), (30, 412), (40, 420),
        (41, 760), (70, 761), (71, 855), (80, 856),
    ]);
    let mut mctx = profile::SessionCtx {
        rng: &mut rng,
        now_ms: verify_ms,
        init_ms: reg.timestamp_ms,
        verify_ms,
        client_ip: &reg.client_ip,
        uptime_ms: 1_790_976,
        timing_log: &mini_timing,
        feilin_url: "",
        feilin_load_ms: 0.0,
        feilin_size: 0,
        piece_render: "",
        strip_render: "",
        tok21: "Z2hjNmloaWY=",
        tok71: "0CPj01gy1gAT7oL5VmpkNnjonqrzwffyRur6htkt",
        tok73: "AtwzKtPOFZyZbfPSA1wVrr8sTfYIHkpubCQrG14P0W",
    };
    let mini = profile::build_mini(prof, &mut mctx, gather_cost, &certify);
    let token = feilin::device_token(&reg, &intel.iv, &mini, gather_cost);
    let geom = verify::ClickGeom { btn_x: 640, btn_y: 500, approach_from: (820, 320) };
    let si = verify::si_csv(
            prof.inner.0,
            prof.screen.0,
            prof.inner.1,
            prof.inner.0,
            prof.inner.1,
            prof.outer.1,
            prof.screen.1,
            59.9,
            prof.outer.0,
        );
    let tk = verify::tk_json_click(&mut rng, &geom, reg.timestamp_ms, verify_ms, &si);
    let data = verify::build_data(&intel.web_key, &r_table, &tk);
    let cvp = flow::captcha_verify_param_json(scene, &certify, &zaic::crypto::b64_encode(token.as_bytes()), &data);
    let mut vf = flow::verify_form(&mut rng, &cfg, scene, &certify, &cvp);
    let vsig = vf.sign();
    vf.push("Signature", vsig);
    let rep = engine.post_form(&bh, &cfg.verify_url(), &vf.body()).await.expect("verify");
    assert_eq!(rep.status, 200, "verify HTTP");
    let body = String::from_utf8_lossy(&rep.body).to_string();

    let code = json_field(&body, "VerifyCode").unwrap_or_default();
    assert!(
        body.contains("VerifyCode") || body.contains("ResultObject"),
        "verify ответ без вердикта: {}",
        &body[..body.len().min(200)]
    );
    assert!(code != "F002" && code != "F003", "формат verify отклонён: {}", code);
}
