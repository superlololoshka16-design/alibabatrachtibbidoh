use wreq::header::{HeaderMap, HeaderName, HeaderValue};
use wreq::Client;

pub const EMULATED: &str = "Chrome/149.0.0.0";

pub struct Engine {
    client: Client,
}

pub struct Reply {
    pub status: u16,
    pub version: String,
    pub body: Vec<u8>,
}

pub struct BrowserHeaders {
    pub ua: String,
    pub sec_ch_ua: String,
    pub sec_ch_ua_platform: String,
    pub accept_language: String,
}

impl BrowserHeaders {
    pub fn new(ua: &str, brands: &[&str], major: &str, platform: &str) -> BrowserHeaders {
        let sec_ch_ua = brands
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if i == brands.len() - 1 {
                    format!("\"{}\";v=\"8\"", b)
                } else {
                    format!("\"{}\";v=\"{}\"", b, major)
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        BrowserHeaders {
            ua: ua.to_string(),
            sec_ch_ua,
            sec_ch_ua_platform: platform.to_string(),
            accept_language: "en-US,en;q=0.9".to_string(),
        }
    }

    fn apply(&self, h: &mut HeaderMap) {
        if let Ok(v) = HeaderValue::from_str(&self.ua) {
            h.insert("User-Agent", v);
        }
        if let (n1, Ok(v1)) = (HeaderName::from_static("sec-ch-ua"), HeaderValue::from_str(&self.sec_ch_ua)) {
            h.insert(n1, v1);
        }
        if let (n2, v2) = (HeaderName::from_static("sec-ch-ua-mobile"), HeaderValue::from_static("?0")) {
            h.insert(n2, v2);
        }
        if let (n3, Ok(v3)) = (
            HeaderName::from_static("sec-ch-ua-platform"),
            HeaderValue::from_str(&self.sec_ch_ua_platform),
        ) {
            h.insert(n3, v3);
        }
        if let Ok(v4) = HeaderValue::from_str(&self.accept_language) {
            h.insert("Accept-Language", v4);
        }
    }
}

impl Default for BrowserHeaders {
    fn default() -> Self {
        BrowserHeaders::new(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
            &["Chromium", "Google Chrome", "Not_A Brand"],
            "149",
            "Windows",
        )
    }
}

impl Engine {
    pub fn new() -> Result<Engine, String> {
        let emu = wreq_util::Emulation::builder()
            .profile(wreq_util::Profile::Chrome149)
            .platform(wreq_util::Platform::Windows)
            .build();
        let client = Client::builder()
            .emulation(emu)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Engine { client })
    }

    fn site_headers(bh: &BrowserHeaders) -> HeaderMap {
        let mut h = HeaderMap::new();
        bh.apply(&mut h);
        h.insert("Accept", HeaderValue::from_static("*/*"));
        h.insert("Origin", HeaderValue::from_static("https://chat.z.ai"));
        h.insert("Referer", HeaderValue::from_static("https://chat.z.ai/auth"));
        h
    }

    pub async fn post_form(&self, bh: &BrowserHeaders, url: &str, body: &str) -> Result<Reply, String> {
        let mut h = Self::site_headers(bh);
        h.insert("Content-Type", HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"));
        self.send(url, h, Some(body.as_bytes().to_vec())).await
    }

    pub async fn post_json(&self, bh: &BrowserHeaders, url: &str, body: &str) -> Result<Reply, String> {
        let mut h = Self::site_headers(bh);
        h.insert("Content-Type", HeaderValue::from_static("application/json"));
        self.send(url, h, Some(body.as_bytes().to_vec())).await
    }

    pub async fn post_json_zai(&self, bh: &BrowserHeaders, url: &str, body: &str, device_id: &str) -> Result<Reply, String> {
        let mut h = HeaderMap::new();
        bh.apply(&mut h);
        h.insert("Accept", HeaderValue::from_static("*/*"));
        h.insert("Content-Type", HeaderValue::from_static("application/json"));
        h.insert("Origin", HeaderValue::from_static("https://chat.z.ai"));
        h.insert("Referer", HeaderValue::from_static("https://chat.z.ai/auth"));
        if let Ok(v) = HeaderValue::from_str(device_id) {
            h.insert("X-Device-ID", v);
        }
        self.send(url, h, Some(body.as_bytes().to_vec())).await
    }

    pub async fn get_bytes(&self, bh: &BrowserHeaders, url: &str) -> Result<Reply, String> {
        let mut h = HeaderMap::new();
        bh.apply(&mut h);
        h.insert("Accept", HeaderValue::from_static("image/avif,image/webp,image/apng,image/*,*/*;q=0.8"));
        h.insert("Referer", HeaderValue::from_static("https://chat.z.ai/auth"));
        self.send(url, h, None).await
    }

    pub async fn get_with(&self, url: &str, extra: &[(&str, &str)]) -> Result<Reply, String> {
        let mut h = HeaderMap::new();
        for (k, v) in extra {
            if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
                h.insert(name, val);
            }
        }
        self.send(url, h, None).await
    }

    async fn send(&self, url: &str, headers: HeaderMap, body: Option<Vec<u8>>) -> Result<Reply, String> {
        let mut req = self.client.post(url);
        if body.is_none() {
            req = self.client.get(url);
        }
        let req = req.headers(headers);
        let req = if let Some(b) = body {
            req.body(wreq::Body::from(b))
        } else {
            req
        };
        let resp = req.send().await.map_err(|e| format!("{}: {}", url, e))?;
        let status = resp.status().as_u16();
        let version = format!("{:?}", resp.version());
        let body = resp.bytes().await.map_err(|e| e.to_string())?;
        Ok(Reply { status, version, body: body.to_vec() })
    }
}
