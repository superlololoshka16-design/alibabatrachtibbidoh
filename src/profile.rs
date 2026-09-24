use crate::crypto::{b64_encode, md5, Rng};
use crate::gen::{self, Snap};

pub struct SessionCtx<'a> {
    pub rng: &'a mut Rng,
    pub now_ms: u64,
    pub init_ms: u64,
    pub verify_ms: u64,
    pub client_ip: &'a str,
    pub uptime_ms: u64,
    pub timing_log: &'a str,
    pub feilin_url: &'a str,
    pub feilin_load_ms: f64,
    pub feilin_size: u64,
    pub piece_render: &'a str,
    pub strip_render: &'a str,

    pub tok21: &'a str,
    pub tok71: &'a str,
    pub tok73: &'a str,
}

pub fn hash31(s: &str) -> i64 {
    let mut w: i64 = 0;
    for b in s.bytes() {
        w = (((w as i32) << 5).wrapping_sub(w as i32) as i64).wrapping_add(b as i64);
    }
    w
}

fn hex(d: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(d.len() * 2);
    for &b in d {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

pub fn session_token(rng: &mut Rng, now_ms: u64, salt_tail: u64) -> String {
    let tc = now_ms.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(salt_tail);
    let tn = (now_ms ^ rng.next_u64()) % 0xFFFF_FFFF;
    let body = format!("9eb33e062dc7fae1-h-{}-{}", tc, tn);
    let body = if body.len() > 4 {
        body[..body.len() - 4].to_string()
    } else {
        body
    };

    let abs = hash31(&body).abs();
    let tail = format!("{:04}", abs % 10000);
    format!("{}{}", body, tail)
}

pub fn canvas_render(p: &Snap) -> String {
    let hw = format!(
        "cr|{}|{}|{}|{}|{}",
        p.screen.0, p.screen.1, p.dpr, p.gpu_angle, p.fonts_count
    );
    hex(&md5(hw.as_bytes()))
}

pub fn audio_render(p: &Snap) -> String {
    let hw = format!("ar|{}|{}|{}", p.cores, p.mem, p.os.name());
    hex(&md5(hw.as_bytes()))
}

pub fn webgl_target(p: &Snap) -> String {
    let hw = format!("wt|{}|{}|{}", p.gpu_vendor, p.gpu_model, p.max_tex);
    hex(&md5(hw.as_bytes()))
}

pub fn font_render(p: &Snap) -> String {
    let hw = format!("fr|{}|{}", p.os.name(), p.fonts_count);
    hex(&md5(hw.as_bytes()))
}

pub fn webgl_pack(p: &Snap) -> String {
    let core = &webgl_target(p);
    let mid = hex(&md5(
        format!("wp|{}|{}", p.gpu_angle, p.seed).as_bytes(),
    ));
    format!("de26{}7f42{}", &mid[..16.min(mid.len())], &core[..26.min(core.len())])
}

pub fn empty_json_md5() -> String {
    hex(&md5(b"{}"))
}

pub fn nav_platform(p: &Snap) -> String {
    p.os.platform().to_string()
}

fn rnd_alnum(rng: &mut Rng, len: usize) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        s.push(A[rng.below(A.len() as u64) as usize] as char);
    }
    s
}

fn perf_array(rng: &mut Rng) -> String {
    let vals: Vec<String> = (0..14)
        .map(|i| {
            let v = match i {
                0 => 2.6 + rng.unit() * 5.0,
                1 => rng.unit(),
                2 => 0.2 + rng.unit() * 0.6,
                3 => rng.unit() * 12.5,
                4 => 0.2 + rng.unit() * 2.5,
                5 => rng.unit() * 0.2,
                6 => 5.0 + rng.unit() * 8.5,
                7 => 4.1 + rng.unit() * 20.7,
                8 => 4.0 + rng.unit(),
                9 => 15.0 + rng.unit() * 9.0,
                13 => 4.1,
                _ => 4.0 + rng.unit() * 0.5,
            };
            format!("{:.1}", v)
        })
        .collect();
    format!("[{}]", vals.join(","))
}

fn perf_pair_array(rng: &mut Rng) -> String {
    let v = 500.0 + rng.unit() * 1500.0;
    let d = 15.0 + rng.unit() * 4.0;
    format!("[{:.1},{:.1},{:.1}]", v, v, v + d)
}

pub fn build_payload(p: &Snap, ctx: &mut SessionCtx) -> String {
    let rand8 = ctx.tok21.to_string();
    let rand40 = ctx.tok71.to_string();
    let rand42 = ctx.tok73.to_string();
    let ts1 = ctx.init_ms;
    let ts2 = ctx.init_ms + 700 + ctx.rng.below(200);
    let spec = crate::feilin::spec_vector(ctx.uptime_ms);
    let webgl = webgl_pack(p);
    let canvas = canvas_render(p);
    let audio = audio_render(p);
    let font = font_render(p);
    let dims_screen = format!("{}*{}", p.screen.1, p.screen.0);
    let dims_inner = format!("{}*{}", p.inner.1, p.inner.0);
    let dims_outer = format!("{}*{}", p.outer.1, p.outer.0);
    let dims_avail = format!("{}*{}", p.avail.1, p.avail.0);
    let perf = perf_array(ctx.rng);
    let perf2 = perf_pair_array(ctx.rng);
    let nav_platform = nav_platform(p);
    let touch_pack = if p.touch { "1*1*1*1" } else { "0*0*0*0" };
    let mem_pack = mem_pack_of(p.mem);
    let f: Vec<String> = vec![
        "W.10054".into(),
        "1.5".into(),
        "11".into(),
        String::new(),
        "Blink".into(),
        nav_platform,
        "Chrome".into(),
        "149.0.0.0".into(),
        "504".into(),
        "[application/pdf,text/pdf]".into(),
        "false".into(),
        "1".into(),
        p.gpu_vendor.into(),
        p.gpu_angle.clone(),
        String::new(),
        String::new(),
        "0".into(),
        "0".into(),
        "0".into(),
        canvas,
        "5".into(),
        b64_encode(rand8.as_bytes()),
        "4".into(),
        touch_pack.into(),
        p.depth.to_string(),
        p.depth.to_string(),
        "srgb".into(),
        "false".into(),
        "false".into(),
        "false".into(),
        "0".into(),
        "0".into(),
        audio,
        String::new(),
        p.cores.to_string(),
        "[]".into(),
        p.os.name().into(),
        p.os.version().into(),
        "1".into(),
        "true".into(),
        p.lang.into(),
        p.tz.into(),
        ctx.client_ip.into(),
        ctx.timing_log.into(),
        "true".into(),
        "true".into(),
        "true".into(),
        dims_screen,
        "true".into(),
        "0".into(),
        "false".into(),
        "false".into(),
        webgl,
        "https://chat.z.ai/auth".into(),
        String::new(),
        dims_inner.clone(),
        dims_outer,
        dims_avail,
        "10".into(),
        dims_inner,
        "true".into(),
        String::new(),
        "false".into(),
        "149.0.0.0".into(),
        p.os.ua(),
        "unspecified".into(),
        "false".into(),
        "saf-captcha".into(),
        "0".into(),
        "[PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF]".into(),
        p.tzo.to_string(),
        rand40,
        ts1.to_string(),
        rand42,
        ts2.to_string(),
        "desktop".into(),
        "true".into(),
        String::new(),
        font,
        empty_json_md5(),
        "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36".into(),
        "Mozilla".into(),
        "64".into(),
        "149.0.8000.0".into(),
        String::new(),
        "0".into(),
        "0".into(),
        ctx.init_ms.to_string(),
        spec,
        "1".into(),
        "1".into(),
        "true".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "1".into(),
        "0".into(),
        "[Chromium,Google Chrome,Not_A Brand]".into(),
        mem_pack.into(),
        "0".into(),
        "[0,a]".into(),
        "false".into(),
        String::new(),
        "true".into(),
        ctx.feilin_url.into(),
        format!("[{},{},{}]]", &ctx.feilin_url[1..], ctx.feilin_load_ms, ctx.feilin_size),
        "false".into(),
        "false".into(),
        "true".into(),
        "false".into(),
        "false".into(),
        "false".into(),
        "[true,true,true,true,true]".into(),
        "false".into(),
        String::new(),
        String::new(),
        "1".into(),
        String::new(),
        String::new(),
        String::new(),
        "https".into(),
        "false".into(),
        "c:".into(),
        perf,
        perf2,
        "0".into(),
        ctx.piece_render.into(),
        ctx.strip_render.into(),
        "1".into(),
    ];
    debug_assert_eq!(f.len(), 142, "payload карта = 142 поля");
    f.join("#")
}

fn mem_pack_of(mem: u32) -> String {
    let head: [&str; 6] = if mem >= 64 {
        ["1", "1", "0", "0", "0", "0"]
    } else {
        ["0", "0", "0", "0", "0", "0"]
    };
    let mut parts: Vec<&str> = head.to_vec();
    for _ in 0..10 {
        parts.extend_from_slice(&["1", "1", "0"]);
    }
    parts.join("|")
}

pub fn build_mini(
    p: &Snap,
    ctx: &mut SessionCtx,
    gather_cost: u32,
    certify_id: &str,
) -> String {
    let rand8 = ctx.tok21.to_string();
    let rand40 = ctx.tok71.to_string();
    let rand42 = ctx.tok73.to_string();
    let audio = audio_render(p);
    let font = font_render(p);
    let dims_screen = format!("{}*{}", p.screen.1, p.screen.0);
    let spec = crate::feilin::spec_vector(ctx.uptime_ms);
    let nav_platform = nav_platform(p);
    let mut f: Vec<String> = vec![String::new(); 142];
    f[0] = "W.10054".into();
    f[3] = gather_cost.to_string();
    f[5] = nav_platform;
    f[6] = "Chrome".into();
    f[7] = "149.0.0.0".into();
    f[8] = "0".into();
    f[20] = "7".into();
    f[21] = b64_encode(rand8.as_bytes());
    f[22] = "4".into();
    f[32] = audio;
    f[34] = p.cores.to_string();
    f[36] = p.os.name().into();
    f[37] = p.os.version().into();
    f[42] = ctx.client_ip.into();
    f[43] = ctx.timing_log.into();
    f[44] = "true".into();
    f[47] = dims_screen;
    f[67] = "saf-captcha".into();
    f[68] = "0".into();
    f[71] = rand40;
    f[72] = ctx.init_ms.to_string();
    f[73] = rand42;
    f[74] = ctx.verify_ms.to_string();
    f[75] = "desktop".into();
    f[76] = "false".into();
    f[77] = certify_id.into();
    f[78] = font;
    f[85] = "0".into();
    f[86] = "0".into();
    f[87] = ctx.init_ms.to_string();
    f[88] = spec;
    f[89] = "1".into();
    f[90] = "1".into();
    f[91] = "true".into();
    f[109] = "0".into();
    f.join("#")
}

pub struct HeadAsk {
    pub ua: String,
    pub brands: Vec<&'static str>,
    pub major: &'static str,
    pub platform: &'static str,
}

pub fn head_ask(p: &Snap) -> HeadAsk {
    HeadAsk {
        ua: p.os.ua(),
        brands: vec!["Chromium", "Google Chrome", "Not_A Brand"],
        major: "149",
        platform: match p.os {
            gen::Os::Win => "Windows",
            gen::Os::Mac => "macOS",
            gen::Os::Linux => "Linux",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(rng: &'a mut Rng) -> SessionCtx<'a> {
        SessionCtx {
            rng,
            now_ms: 1_790_000_000_000,
            init_ms: 1_790_000_000_000,
            verify_ms: 1_790_000_004_500,
            client_ip: "8.212.10.159",
            uptime_ms: 2_500_000,
            timing_log: "10-0|11-200|20-205",
            feilin_url: "https://g.alicdn.com/x.js",
            feilin_load_ms: 250.0,
            feilin_size: 580984,
            piece_render: "",
            strip_render: "",
            tok21: "abcdefgh",
            tok71: "40-char-token-aaaaaaaaaaaaaaaaaaaaaaaaa",
            tok73: "42-char-token-bbbbbbbbbbbbbbbbbbbbbbbb",
        }
    }

    #[test]
    fn payload_is_142_hash_joined() {
        let mut rng = Rng::new();
        let p = gen::snap(0);
        let mut c = ctx(&mut rng);
        let s = build_payload(&p, &mut c);
        assert_eq!(s.split('#').count(), 142);

        assert!(!s.contains("\""));
    }

    #[test]
    fn mini_is_142_sparse() {
        let mut rng = Rng::new();
        let p = gen::snap(3);
        let mut c = ctx(&mut rng);
        let s = build_mini(&p, &mut c, 313, "CERT1");
        assert_eq!(s.split('#').count(), 142);
        assert_eq!(s.split('#').nth(77).unwrap(), "CERT1");
        assert_eq!(s.split('#').nth(3).unwrap(), "313");
    }

    #[test]
    fn token_shape() {
        let mut rng = Rng::new();
        let t = session_token(&mut rng, 1_790_000_000_000, 7);
        assert!(t.starts_with("9eb33e062dc7fae1-h-"));
        assert!(t.len() >= 20);
    }

    #[test]
    fn renders_stable_per_profile() {
        let p = gen::snap(1);
        assert_eq!(canvas_render(&p), canvas_render(&p));
        assert_ne!(canvas_render(&gen::snap(2)), canvas_render(&gen::snap(5)));
    }
}
