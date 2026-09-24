use crate::crypto::{aes128_cbc_decrypt, aes128_cbc_encrypt, b64_decode, b64_encode, Rng};
use crate::keys::SessionKeys;
use crate::pop::{iso_now_utc, Form};
use crate::rt::Intel;
pub struct FlowCfg {
    pub scene_id: String,
    pub scene_zai: String,
    pub prefix: String,
    pub region_api: String,
    pub region_sig: String,
    pub app_key: String,
    pub app_version: String,
    pub api_version: String,
    pub platform: String,
    pub app_name: String,
    pub aaduane_id: String,
    pub ak_secret: Vec<u8>,
    pub api_host: String,
    pub verify_host: String,
    pub upload_host: String,
    pub static_cdn: String,
}

pub const FEILIN_PLATFORM: &str = "W.10054";
pub const FEILIN_VERSION: &str = "1.5";

impl FlowCfg {
    pub fn from_intel(intel: &Intel, scene_id: &str, scene_zai: &str, prefix: &str, region_sig: &str) -> FlowCfg {
        let region_api = match region_sig {
            "cn" => "cn-hangzhou".to_string(),
            _ => "southeast".to_string(),
        };
        let api_host = format!("{}.captcha-open-{}.aliyuncs.com", prefix, region_api);
        let verify_host = format!("{}-verify.captcha-open-{}.aliyuncs.com", prefix, region_api);
        let upload_host = format!("upload.captcha-open-{}.aliyuncs.com", region_api);
        FlowCfg {
            scene_id: scene_id.to_string(),
            scene_zai: scene_zai.to_string(),
            prefix: prefix.to_string(),
            region_api,
            region_sig: region_sig.to_string(),
            app_key: intel.app_key.clone(),
            app_version: intel.app_version.clone(),
            api_version: intel.api_version.clone(),
            platform: intel.platform.clone(),
            app_name: intel.app_name.clone(),
            aaduane_id: intel.aaduane_id.clone(),
            ak_secret: intel.ak_secret.as_bytes().to_vec(),
            api_host,
            verify_host,
            upload_host,
            static_cdn: "https://static-captcha-sgp.aliyuncs.com/".to_string(),
        }
    }

    pub fn api_url(&self) -> String {
        format!("https://{}/", self.api_host)
    }
    pub fn verify_url(&self) -> String {
        format!("https://{}/", self.verify_host)
    }
    pub fn upload_url(&self) -> String {
        format!("https://{}/", self.upload_host)
    }
}

pub fn sig_string_init(cfg: &FlowCfg, scene: &str) -> String {
    format!(
        "{}#{}#{}#captcha-normal#{}#{}",
        cfg.platform, cfg.app_name, scene, cfg.prefix, cfg.region_sig
    )
}

pub fn build_device_data(k: &SessionKeys, iv: &[u8; 16], cfg: &FlowCfg, scene: &str) -> String {
    let inner = b64_encode(&aes128_cbc_encrypt(&k.flag, iv, sig_string_init(cfg, scene).as_bytes()));
    let plain = format!("{}#W#{}#{}#CLOUD#", cfg.app_key, inner, cfg.app_version);
    b64_encode(&aes128_cbc_encrypt(&k.vr, iv, plain.as_bytes()))
}

pub fn open_device_data(k: &SessionKeys, iv: &[u8; 16], dd_b64: &str) -> Option<String> {
    let raw = b64_decode(dd_b64)?;
    let out = aes128_cbc_decrypt(&k.vr, iv, &raw)?;
    String::from_utf8(out).ok()
}

pub struct DeviceConfig {
    pub secret_key: String,
    pub device_id: String,
    pub feilin_version: String,
    pub timestamp_ms: u64,
    pub client_ip: String,
    pub raw: String,
}

pub fn parse_device_config(k: &SessionKeys, iv: &[u8; 16], dc_b64: &str) -> Option<DeviceConfig> {
    let raw = b64_decode(dc_b64)?;
    let out = aes128_cbc_decrypt(&k.hr, iv, &raw)?;
    let text = String::from_utf8(out).ok()?;
    let parts: Vec<&str> = text.split('#').collect();
    if parts.len() < 9 {
        return None;
    }
    let sk = b64_decode(parts[0])
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    let ts: u64 = parts.get(7).and_then(|v| v.parse().ok()).unwrap_or(0);
    Some(DeviceConfig {
        secret_key: sk,
        device_id: parts[2].to_string(),
        feilin_version: parts[3].to_string(),
        timestamp_ms: ts,
        client_ip: parts.get(8).unwrap_or(&"").to_string(),
        raw: text,
    })
}

pub fn init_form(rng: &mut Rng, cfg: &FlowCfg, scene: &str, dd: String) -> Form {
    let mut f = Form::new(&cfg.ak_secret);
    f.push("AaduaneId", cfg.aaduane_id.clone());
    f.push("SignatureMethod", "HMAC-SHA1".into());
    f.push("SignatureVersion", "1.0".into());
    f.push("Format", "JSON".into());
    f.push("Timestamp", iso_now_utc());
    f.push("Version", cfg.api_version.clone());
    f.push("Action", "InitCaptchaV3".into());
    f.push("SceneId", scene.into());
    f.push("Language", "en".into());
    f.push("Mode", "popup".into());
    f.push("DeviceData", dd);
    f.push("SignatureNonce", rng.uuid_v4());
    f
}

pub fn upload_log_form(
    rng: &mut Rng,
    cfg: &FlowCfg,
    certify_id: &str,
    client_ip: &str,
    now_ms: u64,
    init_rt_ms: u64,
    js_rt_ms: u64,
    img_rt_ms: u64,
) -> Form {
    let log = format!(
        "{{\"sId\":\"{}\",\"pfx\":\"{}\",\"mInit\":{{\"t\":{},\"s\":true,\"msg\":\"INIT_SUCCESS\",\"rt\":{}}},\"hst\":\"captcha-open-{}.aliyuncs.com\",\"cId\":\"{}\",\"ip\":\"{}\",\"js\":{{\"t\":{},\"s\":true,\"msg\":\"DYNAMICJS_LOADED\",\"rt\":{}}},\"pImg\":{{\"t\":{},\"s\":true,\"msg\":\"IMAGE_LOADED\",\"rt\":{}}},\"rt\":{}}}",
        cfg.scene_id, cfg.prefix,
        now_ms - init_rt_ms, init_rt_ms,
        cfg.region_api,
        certify_id, client_ip,
        now_ms - js_rt_ms, js_rt_ms,
        now_ms - img_rt_ms, img_rt_ms,
        init_rt_ms + js_rt_ms + img_rt_ms + 40,
    );
    let mut f = Form::new(&cfg.ak_secret);
    f.push("AaduaneId", cfg.aaduane_id.clone());
    f.push("SignatureMethod", "HMAC-SHA1".into());
    f.push("SignatureVersion", "1.0".into());
    f.push("Format", "JSON".into());
    f.push("Timestamp", iso_now_utc());
    f.push("Version", cfg.api_version.clone());
    f.push("Action", "UploadLog".into());
    f.push("log", log);
    f.push("SignatureNonce", rng.uuid_v4());
    f
}

pub fn verify_form(rng: &mut Rng, cfg: &FlowCfg, scene: &str, certify_id: &str, cvp_json: &str) -> Form {
    let mut f = Form::new(&cfg.ak_secret);
    f.push("AaduaneId", cfg.aaduane_id.clone());
    f.push("SignatureMethod", "HMAC-SHA1".into());
    f.push("SignatureVersion", "1.0".into());
    f.push("Format", "JSON".into());
    f.push("Timestamp", iso_now_utc());
    f.push("Version", cfg.api_version.clone());
    f.push("Action", "VerifyCaptchaV3".into());
    f.push("SceneId", scene.into());
    f.push("CertifyId", certify_id.into());
    f.push("CaptchaVerifyParam", cvp_json.into());
    f.push("SignatureNonce", rng.uuid_v4());
    f
}

pub fn captcha_verify_param_json(scene: &str, certify_id: &str, device_token: &str, data: &str) -> String {
    format!(
        "{{\"sceneId\":\"{}\",\"certifyId\":\"{}\",\"deviceToken\":\"{}\",\"data\":\"{}\"}}",
        scene, certify_id, device_token, data
    )
}
