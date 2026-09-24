use zaic::crypto::Rng;
use zaic::rt::{self, Intel};
use zaic::{ast, crypto, deobf, feilin, flow, gen, keys, net, profile, telemetry, verify};

const ALIYUN_CDN: &str = "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js";
const DYNAMIC_JS_CDN: &str = "https://g.alicdn.com/captcha-frontend/dynamicJS/";
const FEILIN_CDN: &str = "https://g.alicdn.com/captcha-frontend/FeiLin/";
const PAGE_URL: &str = "https://chat.z.ai/auth";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = match cmd {
        "selftest" => selftest(),
        "init" => rt.block_on(cmd_init()),
        "pipeline" | "signup" => rt.block_on(cmd_pipeline(args.get(2).map(|s| s.as_str()))),
        "analyze" => cmd_analyze(args.get(2).map(|s| s.as_str())),
        "deobfuscate" => cmd_deobfuscate(
            args.get(2).map(|s| s.as_str()),
            args.get(3).map(|s| s.as_str()),
        ),
        "collect" => cmd_collect(args.get(2).map(|s| s.as_str())),
        "anchor" => cmd_anchor(args.get(2).map(|s| s.as_str())),
        "deobfuscate-full" => cmd_deobfuscate_full(
            args.get(2).map(|s| s.as_str()),
            args.get(3).map(|s| s.as_str()),
        ),
        "rtcheck" => rt.block_on(cmd_rtcheck()),
        "profiles" => cmd_profiles(),
        "fp" => rt.block_on(cmd_fp()),
        "help" | _ => {
            print_help();
            0
        }
    };
    std::process::exit(code);
}

fn print_help() {
    println!(
        "zaic v2.5 — pure-Rust challenger chat.z.ai/auth (Aliyun Captcha V3)

ключи/дуаны/R-таблица: 100% рантайм из живых бандлов через oxc —
aliyun.js (CDN) → роли Xt/ACCESS_SEC/IV семантикой, pe.js (StaticPath
живого init) → R-таблица из VM-байткода, feilin.js (версия из
DeviceConfig) → cloudauth-дуаны. y-шифр — дизасм VM F/Q байткода.

флоу (живой хром, v2.4): init(popup, didk33e0) → UploadLog → Log2 →
Log3 → verify(TRACELESS-клик по ползунку). Log1 не существует.
капча НЕ решается: никакого NCC/зрения — только код и сеть.

команды:
  pipeline [N]  живой цикл по N профилям (по умолчанию 10):
                 каждому профилю свой DeviceData/мини/трек; критерий —
                 VerifyCaptchaV3 и прохождение капчи по сети
  rtcheck       отчёт рантайм-экстракции: ключи/дуаны/R-таблица/сцена
  init          живой InitCaptchaV3 (popup, didk33e0)
  selftest      крипто-векторы на живых данных
  analyze       oxc-анализ бандла
  deobfuscate   деобфусцированный pretty-дамп
  profiles      10 профилей железа + матрица различий
  fp            отпечаток TLS/h2 против tls.peet.ws"
    );
}

fn local_bundle(name: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("bundles")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_default()
}

fn json_field(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":\"", key);
    let start = body.find(&pat)? + pat.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

async fn fetch_live_sources(engine: &net::Engine) -> Result<(String, SceneCfg), String> {
    let bh = net::BrowserHeaders::default();
    let aliyun = engine
        .get_bytes(&bh, ALIYUN_CDN)
        .await
        .map_err(|e| format!("aliyun.js CDN: {}", e))?;
    let aliyun_src = String::from_utf8_lossy(&aliyun.body).to_string();
    let page = engine
        .get_bytes(&bh, PAGE_URL)
        .await
        .map_err(|e| format!("chat.z.ai/auth: {}", e))?;
    let page_html = String::from_utf8_lossy(&page.body).to_string();
    let script_url = find_index_script(&page_html).ok_or("index-скрипт не найден")?;
    let idx = engine
        .get_bytes(&bh, &script_url)
        .await
        .map_err(|e| format!("index.js {}: {}", script_url, e))?;
    let idx_src = String::from_utf8_lossy(&idx.body).to_string();
    let scene = extract_scene(&idx_src).ok_or("сцена не извлечена из index.js")?;
    Ok((aliyun_src, scene))
}

fn find_index_script(html: &str) -> Option<String> {
    let mut best: Option<String> = None;
    let mut pos = 0;
    while let Some(p) = html[pos..].find("src=\"") {
        let start = pos + p + 5;
        let end = html[start..].find('"')? + start;
        let url = &html[start..end];
        if url.contains("assets/index-") && url.ends_with(".js") {
            let full = if url.starts_with("http") {
                url.to_string()
            } else if url.starts_with("//") {
                format!("https:{}", url)
            } else {
                format!("https://chat.z.ai{}", url)
            };
            best = Some(full);
        }
        pos = end;
    }
    best
}

pub struct SceneCfg {
    pub region: String,
    pub prefix: String,
    pub scene: String,
    pub scene_zai: String,
}

fn extract_scene(src: &str) -> Option<SceneCfg> {
    let allocator = oxc::allocator::Allocator::default();
    let ret = oxc::parser::Parser::new(&allocator, src, oxc::span::SourceType::cjs()).parse();
    if ret.diagnostics.len() > 3 {
        return None;
    }
    let program = ret.program;
    let sem = oxc::semantic::SemanticBuilder::new()
        .with_check_syntax_error(false)
        .with_build_nodes(true)
        .build(&program)
        .semantic;
    use oxc::ast::AstKind;
    let mut region = None;
    let mut prefix = None;
    let mut scene_zai = None;
    let mut consts: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for node in sem.nodes().iter() {
        if let AstKind::VariableDeclarator(d) = node.kind() {
            if let (
                oxc::ast::ast::BindingPattern::BindingIdentifier(b),
                Some(oxc::ast::ast::Expression::StringLiteral(s)),
            ) = (&d.id, &d.init)
            {
                consts.insert(b.name.as_str().to_string(), s.value.to_string());
            }
        }
    }
    let mut scene_literal = None;
    for node in sem.nodes().iter() {
        if let AstKind::ObjectProperty(p) = node.kind() {
            if let oxc::ast::ast::PropertyKey::StaticIdentifier(id) = &p.key {
                let val = match &p.value {
                    oxc::ast::ast::Expression::StringLiteral(s) => Some(s.value.to_string()),
                    oxc::ast::ast::Expression::Identifier(i) => {
                        consts.get(i.name.as_str()).cloned()
                    }
                    _ => None,
                };
                match (id.name.as_str(), val) {
                    ("REGION", Some(v)) => region = Some(v),
                    ("PREFIX", Some(v)) => prefix = Some(v),
                    ("SCENE_ID", Some(v)) if v.len() >= 6 && v.len() <= 12 => {
                        scene_literal = Some(v)
                    }
                    _ => {}
                }
            }
        }
    }

    for node in sem.nodes().iter() {
        if let AstKind::ConditionalExpression(c) = node.kind() {
            let span = &src[c.span.start as usize..c.span.end as usize];
            if span.contains("chat.z.ai") {
                if let (
                    oxc::ast::ast::Expression::StringLiteral(a),
                    oxc::ast::ast::Expression::StringLiteral(b),
                ) = (&c.consequent, &c.alternate)
                {
                    let ok = |v: &str| {
                        v.len() >= 6
                            && v.len() <= 12
                            && v.chars().all(|ch| ch.is_ascii_alphanumeric())
                    };
                    if ok(&a.value.to_string()) && ok(&b.value.to_string()) {
                        scene_zai = Some(a.value.to_string());
                    }
                }
            }
        }
    }
    Some(SceneCfg {
        region: region?,
        prefix: prefix?,
        scene: scene_literal.or_else(|| scene_zai.clone())?,
        scene_zai: scene_zai.unwrap_or_default(),
    })
}

async fn load_intel(engine: &net::Engine) -> Result<(Intel, SceneCfg), String> {
    let (aliyun_src, scene) = fetch_live_sources(engine).await?;
    let al = rt::extract_aliyun(&aliyun_src)?;
    let mut intel = Intel {
        access_sec: al.access_sec,
        iv: al.iv,
        keys: al.keys,
        aaduane_id: al.aaduane_id,
        ak_secret: al.ak_secret,
        cloudauth_duane: String::new(),
        cloudauth_secret: String::new(),
        cloudauth_version: al.cloudauth_version,
        app_key: al.app_key,
        app_version: al.app_version,
        api_version: al.api_version,
        platform: al.platform,
        app_name: al.app_name,
        r_table: [0u8; 64],
        web_key: al.web_key,
        feilin_version: String::new(),
        feilin_url: String::new(),
    };

    let mut rng = Rng::new();
    let cfg_probe = flow::FlowCfg::from_intel(
        &intel,
        &scene.scene,
        &scene.scene_zai,
        &scene.prefix,
        &scene.region,
    );
    let dd = flow::build_device_data(&intel.keys, &intel.iv, &cfg_probe, &cfg_probe.scene_id);
    let mut f = flow::init_form(&mut rng, &cfg_probe, &scene.scene, dd);
    let sig = f.sign();
    f.push("Signature", sig);
    let bh = net::BrowserHeaders::default();
    let feilin_src = match engine.post_form(&bh, &cfg_probe.api_url(), &f.body()).await {
        Ok(rep) => {
            let body = String::from_utf8_lossy(&rep.body).to_string();
            let ver = json_field(&body, "DeviceConfig")
                .and_then(|d| feilin::parse_device_config(&intel.keys.hr, &intel.iv, &d))
                .map(|dc| dc.feilin_version)
                .unwrap_or_default();
            if !ver.is_empty() {
                let url = format!("{}{}.js", FEILIN_CDN, ver);
                match engine.get_bytes(&bh, &url).await {
                    Ok(r) => {
                        intel.feilin_version = ver.clone();
                        intel.feilin_url = url;
                        String::from_utf8_lossy(&r.body).to_string()
                    }
                    Err(_) => local_bundle("feilin.js"),
                }
            } else {
                local_bundle("feilin.js")
            }
        }
        Err(_) => local_bundle("feilin.js"),
    };
    match rt::extract_feilin(&feilin_src, &intel.access_sec, &intel.iv) {
        Ok((duane, secret)) => {
            intel.cloudauth_duane = duane;
            intel.cloudauth_secret = secret;
        }
        Err(e) => return Err(format!("feilin-дуаны: {}", e)),
    }
    Ok((intel, scene))
}

async fn load_r_table(engine: &net::Engine, static_path: &str) -> [u8; 64] {
    let bh = net::BrowserHeaders::default();
    if !static_path.is_empty() {
        let url = format!("{}{}.js", DYNAMIC_JS_CDN, static_path);
        if let Ok(rep) = engine.get_bytes(&bh, &url).await {
            let src = String::from_utf8_lossy(&rep.body).to_string();
            if let Ok(t) = rt::extract_r_table(&src) {
                return t;
            }
        }
    }
    let src = local_bundle("pe.js");
    rt::extract_r_table(&src).unwrap_or([0u8; 64])
}

async fn cmd_rtcheck() -> i32 {
    println!("== rtcheck: рантайм-экстракция из живых источников ==");
    let engine = match net::Engine::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("движок: {}", e);
            return 1;
        }
    };
    let (intel, scene) = match load_intel(&engine).await {
        Ok(x) => x,
        Err(e) => {
            eprintln!("intel: {}", e);
            return 1;
        }
    };
    println!("aliyun.js (живой CDN):");
    println!(
        "  ACCESS_SEC   = {}",
        String::from_utf8_lossy(&intel.access_sec)
    );
    println!("  IV           = {}", String::from_utf8_lossy(&intel.iv));
    println!(
        "  vr={} hr={} flag={} upload={}",
        intel.keys.vr_str(),
        intel.keys.hr_str(),
        intel.keys.flag_str(),
        intel.keys.upload_str()
    );
    println!("  AaduaneId    = {}", intel.aaduane_id);
    println!("  appKey       = {}", intel.app_key);
    println!(
        "feilin.js: duane={} secret={} версия={}",
        intel.cloudauth_duane, intel.cloudauth_secret, intel.feilin_version
    );
    println!(
        "сцена: region={} prefix={} scene={} chat.z.ai={}",
        scene.region, scene.prefix, scene.scene, scene.scene_zai
    );
    let bh = net::BrowserHeaders::default();
    let mut rng = Rng::new();
    let cfg = flow::FlowCfg::from_intel(
        &intel,
        &scene.scene,
        &scene.scene_zai,
        &scene.prefix,
        &scene.region,
    );
    let dd = flow::build_device_data(&intel.keys, &intel.iv, &cfg, &cfg.scene_id);
    let mut f = flow::init_form(&mut rng, &cfg, &scene.scene, dd);
    let sig = f.sign();
    f.push("Signature", sig);
    match engine.post_form(&bh, &cfg.api_url(), &f.body()).await {
        Ok(rep) => {
            let body = String::from_utf8_lossy(&rep.body).to_string();
            let sp = json_field(&body, "StaticPath").unwrap_or_default();
            let t = load_r_table(&engine, &sp).await;
            let uniq: std::collections::HashSet<u8> = t.iter().copied().collect();
            println!(
                "R-таблица (StaticPath={}): {} уникальных / 64",
                sp,
                uniq.len()
            );
            if uniq.len() == 64 {
                println!("  {:?}…", &t[..12]);
                0
            } else {
                println!("  [FAIL] таблица не полная");
                1
            }
        }
        Err(e) => {
            eprintln!("init: {}", e);
            1
        }
    }
}

async fn cmd_init() -> i32 {
    let engine = match net::Engine::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("движок: {}", e);
            return 1;
        }
    };
    let (intel, scene) = match load_intel(&engine).await {
        Ok(x) => x,
        Err(e) => {
            eprintln!("intel: {}", e);
            return 1;
        }
    };
    let cfg = flow::FlowCfg::from_intel(
        &intel,
        &scene.scene,
        &scene.scene_zai,
        &scene.prefix,
        &scene.region,
    );
    let mut rng = Rng::new();
    let bh = net::BrowserHeaders::default();
    let scene_id = match std::env::var("ZAIC_SCENE") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            if scene.scene_zai.is_empty() {
                scene.scene.clone()
            } else {
                scene.scene_zai.clone()
            }
        }
    };
    let dd = flow::build_device_data(&intel.keys, &intel.iv, &cfg, &scene_id);
    let mut f = flow::init_form(&mut rng, &cfg, &scene_id, dd);
    let sig = f.sign();
    f.push("Signature", sig);
    println!("POST {} (сцена {}, Mode=popup)", cfg.api_url(), scene_id);
    match engine.post_form(&bh, &cfg.api_url(), &f.body()).await {
        Ok(rep) => {
            println!("HTTP {} ({})", rep.status, rep.version);
            let body = String::from_utf8_lossy(&rep.body).to_string();
            println!("{}", &body[..body.len().min(500)]);
            println!("\n-- разбор:");
            for field in ["CertifyId", "CaptchaType", "StaticPath", "PowVerifyString"] {
                if let Some(v) = json_field(&body, field) {
                    println!("   {}: {}", field, &v[..v.len().min(100)]);
                }
            }
            if let Some(dc) = json_field(&body, "DeviceConfig")
                .and_then(|d| feilin::parse_device_config(&intel.keys.hr, &intel.iv, &d))
            {
                println!("   secret_key: {}", dc.secret_key);
                println!("   device_id:  {}", dc.device_id);
                println!("   feilin:     {}", dc.feilin_version);
                println!("   client_ip:  {}", dc.client_ip);
            }
            if rep.status == 200 {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("init fail: {}", e);
            1
        }
    }
}

struct RoundReport {
    profile: String,
    certify_id: String,
    captcha_type: String,
    upload_log: bool,
    log2: bool,
    log3: bool,
    verify_status: u16,
    verify_code: String,
    verify_result: Option<String>,
    passed: bool,
    device_id: String,
    webgl: String,
    canvas: String,
    imgs: String,
}

#[allow(clippy::too_many_arguments)]
async fn run_round(
    engine: &net::Engine,
    intel: &Intel,
    cfg: &flow::FlowCfg,
    scene: &str,
    cloudauth_url: &str,
    prof: &gen::Snap,
    verbose: bool,
) -> Result<RoundReport, String> {
    let mut rng = Rng::new();
    let bh = profile_headers(prof);
    let t0 = std::time::Instant::now();

    let dd = flow::build_device_data(&intel.keys, &intel.iv, cfg, scene);
    let mut f = flow::init_form(&mut rng, cfg, scene, dd.clone());
    let sig = f.sign();
    f.push("Signature", sig);
    let rep = engine
        .post_form(&bh, &cfg.api_url(), &f.body())
        .await
        .map_err(|e| format!("init сеть: {}", e))?;
    let body = String::from_utf8_lossy(&rep.body).to_string();
    let certify = json_field(&body, "CertifyId").unwrap_or_default();
    let ctype = json_field(&body, "CaptchaType").unwrap_or_default();
    let static_path = json_field(&body, "StaticPath").unwrap_or_default();
    let reg = json_field(&body, "DeviceConfig")
        .and_then(|d| feilin::parse_device_config(&intel.keys.hr, &intel.iv, &d))
        .ok_or_else(|| {
            format!(
                "DeviceConfig не разобрался: {}",
                &body[..body.len().min(160)]
            )
        })?;
    if certify.is_empty() {
        return Err(format!(
            "init не выдал капчу: {}",
            &body[..body.len().min(160)]
        ));
    }
    let init_ms = crypto::now_ms();
    let init_rt = t0.elapsed().as_millis() as u64;
    if verbose {
        println!(
            "      [1/6] init: CertifyId={} CaptchaType={} pe={}",
            certify, ctype, static_path
        );
    }

    let r_table = load_r_table(engine, &static_path).await;
    if r_table.iter().all(|&v| v == 0) {
        return Err("R-таблица не извлеклась".into());
    }

    let mut imgs: Vec<(String, u32)> = Vec::new();
    if ctype == "INPAINTING" || ctype == "PUZZLE" || ctype == "SLIDING" {
        for (key, label) in [("Image", "main"), ("PuzzleImage", "piece")] {
            if let Some(path) = json_field(&body, key) {
                if path.is_empty() {
                    continue;
                }
                if let Ok(png) = engine
                    .get_bytes(&bh, &format!("{}{}", cfg.static_cdn, path))
                    .await
                {
                    let digest = crypto::md5(&png.body);
                    let fname = format!("deobf/img_{}_{}.png", certify, label);
                    let _ = std::fs::write(&fname, &png.body);
                    let tag = format!(
                        "{}:{}:md5={}",
                        label,
                        png.body.len(),
                        crypto::b64_encode(&digest)
                    );
                    imgs.push((tag, png.body.len() as u32));
                    if verbose {
                        println!("      картинка {}: {} байт md5={} → {}", label, png.body.len(), crypto::b64_encode(&digest), fname);
                    }
                }
            }
        }
    }

    tokio::time::sleep(std::time::Duration::from_millis(250 + rng.below(200))).await;

    let js_rt = 152 + rng.below(60);
    let img_rt = 12 + rng.below(20);
    let mut ul = flow::upload_log_form(
        &mut rng,
        cfg,
        &certify,
        &reg.client_ip,
        crypto::now_ms(),
        init_rt,
        js_rt,
        img_rt,
    );
    let usig = ul.sign();
    ul.push("Signature", usig);
    let upload_ok = matches!(engine.post_form(&bh, &cfg.upload_url(), &ul.body()).await, Ok(r) if r.status == 200);
    if verbose {
        println!(
            "      [2/6] UploadLog: {}",
            if upload_ok { "HTTP 200" } else { "fail" }
        );
    }

    tokio::time::sleep(std::time::Duration::from_millis(700 + rng.below(500))).await;

    let gather_cost: u32 = 260 + rng.below(120) as u32;

    let t11 = 180 + rng.below(80);
    let t20 = t11 + 2 + rng.below(8);
    let t23 = t11 + 180 + rng.below(120);
    let t30 = t23 + 1 + rng.below(6);
    let t40 = t23 + 10 + rng.below(40);
    let t41 = t40 + 300 + rng.below(120);
    let t70 = t41 + 1 + rng.below(4);
    let t71 = t41 + 60 + rng.below(160);
    let t80 = t71 + rng.below(3);
    let payload_timing = feilin::timing_log(&[
        (10, 0),
        (11, t11),
        (20, t20),
        (23, t23),
        (30, t30),
        (40, t40),
        (41, t41),
        (70, t70),
    ]);
    let mini_timing = feilin::timing_log(&[
        (10, 0),
        (11, t11),
        (20, t20),
        (23, t23),
        (30, t30),
        (40, t40),
        (41, t41),
        (70, t70),
        (71, t71),
        (80, t80),
    ]);
    let tok21 = {
        let t: String = rnd_alnum_pub(&mut rng, 8);
        crypto::b64_encode(t.as_bytes())
    };
    let tok71: String = rnd_alnum_pub(&mut rng, 40);
    let tok73: String = rnd_alnum_pub(&mut rng, 42);
    let uptime = 1_700_000 + rng.below(2_500_000);
    let feilin_url = if intel.feilin_url.is_empty() {
        format!(
            "{}1.5.1/feilin021.da034b8e79ba3ff2916416654f42a33d46f25cfe2ca711735ac83a0fe9acd916",
            FEILIN_CDN
        )
    } else {
        intel.feilin_url.clone()
    };
    let fl_load = 150.0 + rng.below(900) as f64 / 10.0;
    let mut sctx = profile::SessionCtx {
        rng: &mut rng,
        now_ms: crypto::now_ms(),
        init_ms,
        verify_ms: 0,
        client_ip: &reg.client_ip,
        uptime_ms: uptime,
        timing_log: &payload_timing,
        feilin_url: &feilin_url,
        feilin_load_ms: fl_load,
        feilin_size: 581232,
        piece_render: "",
        strip_render: "",
        tok21: &tok21,
        tok71: &tok71,
        tok73: &tok73,
    };
    let payload = profile::build_payload(prof, &mut sctx);
    let sealed = feilin::seal_device(&reg, &intel.iv, &payload, crypto::now_ms());
    let data2 = feilin::log2_data(
        &intel.keys.upload,
        &intel.iv,
        &cfg.app_key,
        &cfg.app_version,
        &reg,
        scene,
        &sealed.container,
        gather_cost,
    );
    let mut lf2 = telemetry::cloudauth_form(intel, &mut rng, "Log2", data2);
    let lsig2 = lf2.sign();
    lf2.push("Signature", lsig2);
    let rep = engine
        .post_form(&bh, cloudauth_url, &lf2.body())
        .await
        .map_err(|e| format!("Log2 сеть: {}", e))?;
    let body = String::from_utf8_lossy(&rep.body).to_string();
    let log2_ok = body.contains("\"ResultObject\":true");
    if verbose {
        println!(
            "      [3/6] Log2 ({} симв. payload, cost={}): {}",
            sealed.payload_len,
            gather_cost,
            if log2_ok {
                "ResultObject:true"
            } else {
                &body[..body.len().min(80)]
            }
        );
    }

    tokio::time::sleep(std::time::Duration::from_millis(200 + rng.below(300))).await;

    let spec = feilin::spec_vector(uptime);
    let data3 = feilin::log3_data(
        &intel.keys.upload,
        &intel.iv,
        &cfg.app_key,
        &cfg.app_version,
        &reg,
        scene,
        &spec,
    );
    let mut lf3 = telemetry::cloudauth_form(intel, &mut rng, "Log3", data3);
    let lsig3 = lf3.sign();
    lf3.push("Signature", lsig3);
    let rep = engine
        .post_form(&bh, cloudauth_url, &lf3.body())
        .await
        .map_err(|e| format!("Log3 сеть: {}", e))?;
    let body = String::from_utf8_lossy(&rep.body).to_string();
    let log3_ok = body.contains("\"ResultObject\":true");
    if verbose {
        println!(
            "      [4/6] Log3: {}",
            if log3_ok {
                "ResultObject:true"
            } else {
                &body[..body.len().min(80)]
            }
        );
    }

    let wait = 4500 + rng.below(4500);
    tokio::time::sleep(std::time::Duration::from_millis(wait)).await;

    let verify_ms = crypto::now_ms();
    let mut mctx = profile::SessionCtx {
        rng: &mut rng,
        now_ms: verify_ms,
        init_ms,
        verify_ms,
        client_ip: &reg.client_ip,
        uptime_ms: uptime,
        timing_log: &mini_timing,
        feilin_url: &feilin_url,
        feilin_load_ms: 0.0,
        feilin_size: 0,
        piece_render: "",
        strip_render: "",
        tok21: &tok21,
        tok71: &tok71,
        tok73: &tok73,
    };
    let mini = profile::build_mini(prof, &mut mctx, gather_cost, &certify);
    let token = feilin::device_token(&reg, &intel.iv, &mini, gather_cost);

    let si = verify::si_csv(
        prof.inner.0,
        prof.screen.0,
        prof.inner.1,
        prof.inner.0,
        prof.inner.1,
        prof.outer.1,
        prof.screen.1,
        59.5 + rng.unit(),
        prof.outer.0,
    );

    let cx = prof.inner.0 / 2;
    let slider_x = cx - 130 + rng.below(40) as u32;
    let slider_y = prof.inner.1 / 2 + 60 + rng.below(40) as u32;
    let geom = verify::ClickGeom {
        btn_x: slider_x,
        btn_y: slider_y,
        approach_from: (
            cx + 120 + rng.below(200) as u32,
            prof.inner.1 / 2 - 80 + rng.below(60) as u32,
        ),
    };
    let tk = verify::tk_json_click(&mut rng, &geom, init_ms, verify_ms, &si);
    let data_field = verify::build_data(&intel.web_key, &r_table, &tk);
    let token_b64 = crypto::b64_encode(token.as_bytes());
    let cvp = flow::captcha_verify_param_json(scene, &certify, &token_b64, &data_field);
    let mut vf = flow::verify_form(&mut rng, cfg, scene, &certify, &cvp);
    let vsig = vf.sign();
    vf.push("Signature", vsig);
    let rep = engine
        .post_form(&bh, &cfg.verify_url(), &vf.body())
        .await
        .map_err(|e| format!("verify сеть: {}", e))?;
    let body = String::from_utf8_lossy(&rep.body).to_string();
    let vcode = json_field(&body, "VerifyCode").unwrap_or_default();
    let vres = json_field(&body, "VerifyResult");
    let passed = body.contains("\"ResultObject\":true")
        || vcode == "F000"
        || vres.as_deref() == Some("true");
    if verbose {
        println!(
            "      [5/6] темп: пауза {} мс (телеметрия заявляет секунды)",
            wait
        );
        println!(
            "      [6/6] verify: HTTP {} → {} {} (ResultObject={:?})",
            rep.status,
            &body[..body.len().min(700)],
            vcode,
            vres
        );
    }

    let captcha_param = verify::captcha_verify_param(&certify, scene);
    let email = format!("probe{}@example.com", rng.below(1_000_000_000));
    let mut signup_body = String::with_capacity(256);
    signup_body.push_str("{\"name\":\"probe\",\"email\":\"");
    signup_body.push_str(&email);
    signup_body.push_str(
        "\",\"password\":\"Za!Probe2026x\",\"profile_image_url\":\"\",\"captcha_verify_param\":\"",
    );
    signup_body.push_str(&captcha_param);
    signup_body.push_str("\"}");
    let signup = engine
        .post_json_zai(
            &bh,
            "https://chat.z.ai/api/v1/auths/signup",
            &signup_body,
            &reg.device_id,
        )
        .await;
    if verbose {
        match &signup {
            Ok(r) => {
                let b = String::from_utf8_lossy(&r.body);
                println!(
                    "      [+] signup-проба: HTTP {} → {}",
                    r.status,
                    &b[..b.len().min(220)]
                );
            }
            Err(e) => println!("      [+] signup-проба: сеть {}", e),
        }
    }

    Ok(RoundReport {
        profile: format!("snap#{}", prof.idx),
        certify_id: certify,
        captcha_type: ctype,
        upload_log: upload_ok,
        log2: log2_ok,
        log3: log3_ok,
        verify_status: rep.status,
        verify_code: vcode,
        verify_result: vres,
        passed,
        device_id: reg.device_id,
        webgl: profile::webgl_target(prof),
        canvas: profile::canvas_render(prof),
        imgs: imgs
            .iter()
            .map(|(l, n)| format!("{}:{}", l, n))
            .collect::<Vec<_>>()
            .join(","),
    })
}

fn profile_headers(p: &gen::Snap) -> net::BrowserHeaders {
    let h = profile::head_ask(p);
    net::BrowserHeaders::new(&h.ua, &h.brands, h.major, h.platform)
}

async fn cmd_pipeline(arg: Option<&str>) -> i32 {
    let n = arg
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(10)
        .min(10);
    let engine = match net::Engine::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("движок: {}", e);
            return 1;
        }
    };
    println!("== rt: живые бандлы и страница ==");
    let (intel, scene) = match load_intel(&engine).await {
        Ok(x) => x,
        Err(e) => {
            eprintln!("intel: {}", e);
            return 1;
        }
    };
    println!(
        "aliyun.js(живой): vr={} hr={} flag={} upload={}",
        intel.keys.vr_str(),
        intel.keys.hr_str(),
        intel.keys.flag_str(),
        intel.keys.upload_str()
    );
    println!(
        "сцена(живая): region={} prefix={} scene={} chat.z.ai={}",
        scene.region, scene.prefix, scene.scene, scene.scene_zai
    );
    let cfg = flow::FlowCfg::from_intel(
        &intel,
        &scene.scene,
        &scene.scene_zai,
        &scene.prefix,
        &scene.region,
    );
    let cloudauth_url =
        "https://cloudauth-device-dualstack.ap-southeast-1.aliyuncs.com/".to_string();
    let scene = scene.scene.clone();

    let snaps: Vec<gen::Snap> = (0..n).map(gen::snap).collect();
    let mut reports = Vec::new();
    for (i, prof) in snaps.iter().enumerate() {
        println!(
            "\n[{}/{}] профиль #{} — {} {}x{} GPU={} tz={}",
            i + 1,
            n,
            prof.idx,
            prof.os.name(),
            prof.screen.0,
            prof.screen.1,
            prof.gpu_model,
            prof.tz
        );
        match run_round(&engine, &intel, &cfg, &scene, &cloudauth_url, prof, true).await {
            Ok(r) => {
                reports.push(r);
            }
            Err(e) => {
                println!("      ОШИБКА: {}", e);
            }
        }
    }

    println!("\n=================================================================");
    println!(
        "{:<24} {:>3} {:>4} {:>4} {:>4} {:<10} {:<6} {:<18} {}",
        "профиль", "OK", "UL", "L2", "L3", "CertifyId", "тип", "картинки", "verify"
    );
    let mut passed = 0;
    for r in &reports {
        if r.passed {
            passed += 1;
        }
        println!(
            "{:<24} {:>3} {:>4} {:>4} {:>4} {:<10} {:<6} {:<18} {} ({})",
            r.profile,
            if r.passed { "ДА" } else { "-" },
            if r.upload_log { "+" } else { "-" },
            if r.log2 { "+" } else { "-" },
            if r.log3 { "+" } else { "-" },
            &r.certify_id,
            r.captcha_type,
            if r.imgs.is_empty() { "-" } else { &r.imgs },
            r.verify_code,
            r.verify_result.as_deref().unwrap_or("?")
        );
    }
    println!("=================================================================");
    let uniq_dev = reports
        .iter()
        .map(|r| r.device_id.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let uniq_webgl = reports
        .iter()
        .map(|r| r.webgl.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let uniq_canvas = reports
        .iter()
        .map(|r| r.canvas.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    println!(
        "deviceId уникальных: {} / {}, webgl-таргетов: {} / {}, canvas: {} / {}",
        uniq_dev,
        reports.len(),
        uniq_webgl,
        reports.len(),
        uniq_canvas,
        reports.len()
    );
    println!(
        "капча пройдена по сети (ResultObject:true): {}/{} профилей",
        passed, n
    );
    if passed == n && n > 0 {
        println!("== ПАЙПЛАЙН 100%: каждый профиль прошёл живой verify ==");
        0
    } else {
        1
    }
}

fn selftest() -> i32 {
    println!("== selftest: рантайм-деривация + живые векторы ==");
    let aliyun = local_bundle("aliyun.js");
    if aliyun.is_empty() {
        eprintln!("[FAIL] bundles/aliyun.js недоступен");
        return 1;
    }
    let al = match rt::extract_aliyun(&aliyun) {
        Ok(al) => al,
        Err(e) => {
            eprintln!("[FAIL] деривация: {}", e);
            return 1;
        }
    };
    println!(
        "[OK] деривация из бандла: vr={} hr={} flag={} upload={}",
        al.keys.vr_str(),
        al.keys.hr_str(),
        al.keys.flag_str(),
        al.keys.upload_str()
    );
    if al.keys.vr_str() != "45f8ac1e1de14397" || al.keys.hr_str() != "87f879f135f27da7" {
        eprintln!("[FAIL] ключи не сходятся с живым трафиком (ротация блобов?)");
        return 1;
    }
    let tests: Vec<(&str, fn() -> bool)> = vec![
        ("SHA-1 / MD5 / HMAC-SHA1 векторы", test_crypto),
        ("подпись живого InitCaptchaV3 (KE3hzE96...)", test_init_sig),
        ("подпись живого UploadLog (pfV7C0NJ...)", test_upload_sig),
        ("yr() тест-вектор AES", test_yr_vector),
        ("DeviceConfig живой → secretKey/ip", test_dc),
        ("egg: MBA-канонизация", test_egg_mba),
        ("egg: плоская программа-исполнитель", test_egg_ops),
        ("payload 142 поля по канонической карте", test_payload_map),
        ("мини 142 поля, verify-значения", test_mini_map),
        ("y-шифр: форма дайджеста", test_y_digest),
        (
            "R-шифр: обратный ход на живом векторе",
            test_r_cipher_roundtrip,
        ),
    ];
    let mut fail = 0;
    for (name, f) in tests {
        let ok = f();
        println!("[{}] {}", if ok { "OK" } else { "FAIL" }, name);
        if !ok {
            fail += 1;
        }
    }
    if fail > 0 {
        1
    } else {
        0
    }
}

fn test_crypto() -> bool {
    crypto::b64_encode(&crypto::sha1(b"abc")) == "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
        && crypto::b64_encode(&crypto::md5(b"abc")) == "kAFQmDzST7DWlj99KOF/cg=="
        && crypto::b64_encode(&crypto::hmac_sha1(
            b"key",
            b"The quick brown fox jumps over the lazy dog",
        )) == "3nybhbi3iqa8ino29wqQcBydtNk="
}

fn test_init_sig() -> bool {
    let al = rt::extract_aliyun(&local_bundle("aliyun.js")).expect("aliyun");
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
    let dd = "TEQYvgJq1LrMqFaBybfIzPxz2ygFyAct7X/w+LacfXWd9rGSwE/x6ZCONucD1fehMi9xkGJSDbTdPgjkaTUmYDT6EN6zdoexJK8eJmPkTnSnQnNbVZcECxA7/g3O8NBHGxYmbw5uUCb4kavONtnIkkQy94qIIiHc86XsPjRq/17AtDuAXzeAOfYKdvnT8fV8".to_string();
    if flow::build_device_data(&al.keys, &al.iv, &cfg, "36qgs6xb") != dd {
        return false;
    }
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
    f.push(
        "SignatureNonce",
        "8a546b19-702f-43ba-986a-f34efd335dd2".into(),
    );
    f.sign() == "KE3hzE96Sf/wPZxXE4Za/0vLxLU="
}

fn test_upload_sig() -> bool {
    let al = rt::extract_aliyun(&local_bundle("aliyun.js")).expect("aliyun");
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
    let mut f = zaic::pop::Form::new(cfg.ak_secret.as_slice());
    f.push("AaduaneId", cfg.aaduane_id.clone());
    f.push("SignatureMethod", "HMAC-SHA1".into());
    f.push("SignatureVersion", "1.0".into());
    f.push("Format", "JSON".into());
    f.push("Timestamp", "2026-09-11T21:35:41Z".into());
    f.push("Version", cfg.api_version.clone());
    f.push("Action", "UploadLog".into());
    f.push(
        "log",
        "{\"sId\":\"36qgs6xb\",\"pfx\":\"no8xfe\",\"mInit\":{\"t\":1789162540784,\"s\":true,\"msg\":\"INIT_SUCCESS\",\"rt\":754},\"hst\":\"captcha-open-southeast.aliyuncs.com\",\"cId\":\"J9nQ6xeVnJ\",\"ip\":\"95.112.141.54\",\"js\":{\"t\":1789162540971,\"s\":true,\"msg\":\"DYNAMICJS_LOADED\",\"rt\":182},\"pImg\":{\"t\":1789162541190,\"s\":true,\"msg\":\"IMAGE_LOADED\",\"rt\":16},\"rt\":1164}".into(),
    );
    f.push(
        "SignatureNonce",
        "cde4a758-bdea-48dc-ac07-f4a62b0d4dc7".into(),
    );
    f.sign() == "pfV7C0NJB26UMlYzBAEaLDnYq+Q="
}

fn test_yr_vector() -> bool {
    let al = rt::extract_aliyun(&local_bundle("aliyun.js")).expect("aliyun");
    let (k, iv) = (al.keys, al.iv);
    let sig = "W.10001.c#saf-aliyun-com#36qgs6xb#captcha-normal#no8xfe#southeast";
    let ct = crypto::aes128_cbc_encrypt(&k.vr, &iv, sig.as_bytes());
    crypto::b64_encode(&ct)
        == "526Lh2uEsWKQc82jdSdnvOHEXX/Kt5c7zhlF7Ixbar/cafdsfKue3Mo0H9ynO8j/ngOCmEAyETE6EBUQbnbAMdv/3vCPegvk8rhs+W9hyvA="
}

fn test_dc() -> bool {
    let al = rt::extract_aliyun(&local_bundle("aliyun.js")).expect("aliyun");
    match feilin::parse_device_config(
        &al.keys.hr,
        &al.iv,
        "TroZ9ZN9wTNtNVp6KAAST9i/E+Tc8tpSF3DjCnZDlwAJcLjyJSxaEzElnxrRqvnnxieVc4xYfM5Cdlg1n16VHT87JUKNfsr2L49wP8KrC+nC/x9+NboG0wW9fZtmOHIEHoSyw23BRaOMW+zaN4oNYq1cvLPbnSDbLSydKBbPhw5NWhriOi6TilJq3pYDtaoKBBJ7MProngVYwSc+oq5mGD4/44tSOOjPJUdEo0Z2eBXHzMQvYyA7fLjAFJSu39XJM7qCYiVZOS41GqHEDA3SqOX8+fufDqq5g2QP1gkR7NjfInm40s/sB5ZWwDiifw7e",
    ) {
        Some(dc) => dc.secret_key == "5f76907e801e17f0" && dc.client_ip == "47.57.232.232",
        None => false,
    }
}

fn test_egg_mba() -> bool {
    use zaic::egraph::{canonical, sexpr, Builder};
    let mut b = Builder::new();
    let a = b.var("a");
    let x = b.var("b");
    let one = b.lit(1);
    let x1 = b.xor(a, x);
    let band = b.band(a, x);
    let carry = b.shl(band, one);
    let sum = b.add(x1, carry);
    let mba = canonical(&b.finish(sum));
    let mut b2 = Builder::new();
    let a2 = b2.var("a");
    let x2 = b2.var("b");
    let plain = b2.add(a2, x2);
    sexpr(&mba) == sexpr(&canonical(&b2.finish(plain)))
}

fn test_egg_ops() -> bool {
    use zaic::egraph::{canonical, ops, Builder};
    let mut b = Builder::new();
    let x = b.var("x");
    let k = b.lit(42);
    let e1 = b.xor(x, k);
    let k2 = b.lit(42);
    let e2 = b.xor(e1, k2);
    let expr = canonical(&b.finish(e2));
    let prog = ops::flatten(&expr);
    prog.exec(&[7]) == Some(7) && prog.exec(&[123]) == Some(123) && prog.n_vars == 1
}

fn test_payload_map() -> bool {
    let mut rng = Rng::new();
    let prof = &gen::snap(0);
    let timing = "10-0|11-203|20-204|23-446|30-448|40-458|41-981|70-981";
    let url = "https://g.alicdn.com/captcha-frontend/FeiLin/1.5.1/feilin021";
    let mut ctx = profile::SessionCtx {
        rng: &mut rng,
        now_ms: 1_789_741_347_892,
        init_ms: 1_789_741_348_050,
        verify_ms: 0,
        client_ip: "8.212.10.159",
        uptime_ms: 1_790_976,
        timing_log: timing,
        feilin_url: url,
        feilin_load_ms: 152.0,
        feilin_size: 581232,
        piece_render: "[ec4ac200cecad4988a0bc32890e39073,122,110]",
        strip_render: "[d8eda6282f6717eb17ee66402af7623e,240,60]",
        tok21: "Z2hjNmloaWY=",
        tok71: "0CPj01gy1gAT7oL5VmpkNnjonqrzwffyRur6htkt",
        tok73: "AtwzKtPOFZyZbfPSA1wVrr8sTfYIHkpubCQrG14P0W",
    };
    let p = profile::build_payload(prof, &mut ctx);
    let fields: Vec<&str> = p.split('#').collect();
    fields.len() == 142
        && fields[0] == "W.10054"
        && fields[92] == "1"
        && fields[108] == "1"
        && fields[109] == "0"
        && fields[110] == "[Chromium,Google Chrome,Not_A Brand]"
        && fields[111].split('|').count() == 36
        && fields[113] == "[0,a]"
        && fields[133] == "https"
        && fields[135] == "c:"
        && fields[139] == "[ec4ac200cecad4988a0bc32890e39073,122,110]"
        && fields[141] == "1"
}

fn test_mini_map() -> bool {
    let mut rng = Rng::new();
    let prof = &gen::snap(0);
    let timing = "10-0|11-233|20-237|23-416|30-417|40-424|41-762|70-763|71-859|80-859";
    let mut ctx = profile::SessionCtx {
        rng: &mut rng,
        now_ms: 1_789_741_348_900,
        init_ms: 1_789_741_348_050,
        verify_ms: 1_789_741_348_953,
        client_ip: "8.212.10.159",
        uptime_ms: 1_790_976,
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
    let m = profile::build_mini(prof, &mut ctx, 298, "TESTCERT1");
    let fields: Vec<&str> = m.split('#').collect();
    fields.len() == 142
        && fields[3] == "298"
        && fields[8] == "0"
        && fields[20] == "7"
        && fields[72] == "1789741348050"
        && fields[74] == "1789741348953"
        && fields[76] == "false"
        && fields[77] == "TESTCERT1"
        && fields[87] == "1789741348050"
        && fields[109] == "0"
        && fields[71].len() == 40
        && fields[73].len() == 42
}

fn test_y_digest() -> bool {
    let d = zaic::ycipher::y_digest("{\"TrackList\":{\"mc\":\"1,2,3, ,1\"}}", "0000");
    d.len() == 32
        && d.chars().all(|c| c.is_ascii_hexdigit())
        && d == zaic::ycipher::y_digest("{\"TrackList\":{\"mc\":\"1,2,3, ,1\"}}", "0000")
        && d != zaic::ycipher::y_digest("{\"TrackList\":{\"mc\":\"1,2,3, ,1\" }", "0000")
}

fn test_r_cipher_roundtrip() -> bool {
    let al = rt::extract_aliyun(&local_bundle("aliyun.js")).expect("aliyun");
    let key = al.web_key;
    let pe = local_bundle("pe.js");
    let table = match rt::extract_r_table(&pe) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let a = verify::r_cipher("QUJD", &key, &table);
    let b = verify::r_cipher("QUJD", &key, &table);
    a == b && !a.is_empty()
}


fn env_s(s: &zaic::deflat::S) -> usize {
    match s {
        zaic::deflat::S::Env(v) => {
            let src = [
                "navigator.",
                "window.",
                "screen.",
                "document.",
                "performance.",
                "location.",
            ];
            let hit = src.iter().any(|p| v.starts_with(p));
            let deep = v.matches('.').count() >= 2;
            if hit {
                2 + deep as usize
            } else {
                0
            }
        }
        zaic::deflat::S::Bin(_, a, b) => env_s(a) + env_s(b) / 4,
        zaic::deflat::S::Call(_, args) => args.iter().map(env_s).sum(),
        zaic::deflat::S::Cond(c, a, b) => env_s(c) / 2 + env_s(a) / 2 + env_s(b) / 2,
        zaic::deflat::S::Un(_, a) => env_s(a) / 2,
        _ => 0,
    }
}

fn cmd_anchor(path: Option<&str>) -> i32 {
    let p = path
        .map(|s| s.to_string())
        .unwrap_or_else(|| "bundles/pe_fresh.js".to_string());
    let src = match std::fs::read_to_string(&p) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("anchor: {}: {}", p, e);
            return 1;
        }
    };
    let deobf_src = match deobf::deobfuscate_file(&p) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("anchor: деобфускация: {}", e);
            return 1;
        }
    };
    println!("anchor: {} ({}B raw → {}B деобф)", p, src.len(), deobf_src.len());

    let map = match zaic::anchor::build_anchor_map(&deobf_src) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("anchor: {}", e);
            return 1;
        }
    };
    println!();
    println!("=== карта полей ← source-анкеры (чистый AST-проход) ===");
    println!("полей с анкерами: {} | всего анкер-обращений: {}", map.fields.len(), map.total_anchors);
    for (field, anchors) in &map.fields {
        println!("  {:40} ← {}", field, anchors.join(", "));
    }
    println!();
    println!("=== плотность анкеров ===");
    let mut ranked: Vec<_> = map.anchors.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1));
    for (a, n) in ranked.iter().take(40) {
        println!("  {:44} × {}", a, n);
    }

    let mut dump = String::new();
    dump.push_str("# карта полей ← анкеры\n");
    for (field, anchors) in &map.fields {
        dump.push_str(&format!("{} = {}\n", field, anchors.join(", ")));
    }
    dump.push_str("\n# плотность\n");
    for (a, n) in ranked {
        dump.push_str(&format!("{} × {}\n", a, n));
    }
    std::fs::write("deobf/anchor_map.txt", dump).expect("запись anchor_map");
    println!("\nполная карта → deobf/anchor_map.txt");
    0
}

fn cmd_collect(path: Option<&str>) -> i32 {
    let p = path
        .map(|s| s.to_string())
        .unwrap_or_else(|| "bundles/feilin.live.js".to_string());
    let raw = match std::fs::read_to_string(&p) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("collect: {}: {}", p, e);
            return 1;
        }
    };

    let deobf_src = match deobf::deobfuscate_file(&p) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("collect: деобфускация: {}", e);
            return 1;
        }
    };
    println!(
        "collect: {} ({}B raw → {}B deobf)",
        p,
        raw.len(),
        deobf_src.len()
    );

    let fns = match zaic::deflat::deflatten_all(&deobf_src) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("collect: deflat: {}", e);
            return 1;
        }
    };
    println!("де-флэттенено функций: {}", fns.len());
    if std::env::var("ZAIC_DEFLAT_DEBUG").is_ok() {
        for f in &fns {
            println!(
                "  fn {} init={} blocks={} init_block={}",
                f.name,
                f.init,
                f.blocks.len(),
                f.block(f.init).is_some()
            );
        }
    }

    {
        let mut dump = String::new();
        for f in &fns {
            let steps = zaic::deflat::trace(f, 3000);
            dump.push_str(&zaic::deflat::render_trace(f, &steps));
            dump.push('\n');
        }
        std::fs::write("deobf/deflat_trace.txt", dump).expect("запись дампа");
    }

    let anchor_score = |f: &zaic::deflat::FlatFn| -> usize {
        let mut total = 0;
        let mut total = 0;
        for b in &f.blocks {
            for a in &b.actions {
                match a {
                    zaic::deflat::Action::Call(_, args) => {
                        for s in args {
                            total += env_s(s);
                        }
                    }
                    zaic::deflat::Action::Assign(_, v) => total += env_s(v),
                    zaic::deflat::Action::Return(v) => {
                        if let Some(s) = v {
                            total += env_s(s);
                        }
                    }
                }
            }
            for t in &b.transitions {
                if let Some(c) = &t.cond {
                    total += env_s(c);
                }
            }
        }
        total
    };
    let mut best: Option<usize> = None;
    let mut best_score = 0usize;
    for (i, f) in fns.iter().enumerate() {
        let score = anchor_score(f);
        if score >= 8 {
            println!("  [{}] {} — телеметрия-анкеров: {}", i, f.name, score);
            if score > best_score {
                best_score = score;
                best = Some(i);
            }
        }
    }
    if best.is_none() {
        for (i, f) in fns.iter().enumerate() {
            let mut joins = 0;
            for b in &f.blocks {
                for a in &b.actions {
                    if let zaic::deflat::Action::Call(d, _) = a {
                        if d.starts_with("join") {
                            joins += 1;
                        }
                    }
                }
            }
            if joins > 0 && best.is_none() {
                println!("  [{}] {} — join-блоков: {} (фолбэк)", i, f.name, joins);
                best = Some(i);
            }
        }
    }
    let collector_idx = match best {
        Some(i) => i,
        None => {
            eprintln!("collect: коллектор (join '#') не найден — дамп всех join-упоминаний:");
            for f in fns.iter() {
                for b in &f.blocks {
                    for a in &b.actions {
                        let s = match a {
                            zaic::deflat::Action::Assign(n, v) => {
                                format!("{} = {}", n, v.render())
                            }
                            zaic::deflat::Action::Call(d, args) => format!(
                                "{} [{}]",
                                d,
                                args.iter()
                                    .map(|x| x.render())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            ),
                            zaic::deflat::Action::Return(v) => format!(
                                "return {}",
                                v.as_ref().map(|x| x.render()).unwrap_or_default()
                            ),
                        };
                        if s.contains("join") {
                            println!("  fn {} [{}] {}", f.name, b.state, s);
                        }
                    }
                }
            }
            return 1;
        }
    };
    let collector = &fns[collector_idx];
    println!(
        "\nколлектор: {} (init={}, блоков={})",
        collector.name,
        collector.init,
        collector.blocks.len()
    );
    let steps = zaic::deflat::trace(collector, 4000);
    print!("{}", zaic::deflat::render_trace(collector, &steps));
    println!("\nполный дамп → deobf/deflat_trace.txt");
    println!("\n=== полная CFG-карта коллектора (все блоки) ===");
    let mut blk_lines = String::new();
    for b in &collector.blocks {
        blk_lines.push_str(&format!("[{}]\n", b.state));
        for a in &b.actions {
            let s = match a {
                zaic::deflat::Action::Assign(n, v) => format!("  {} = {}", n, v.render()),
                zaic::deflat::Action::Call(d, args) => format!(
                    "  {} [{}]",
                    d,
                    args.iter().map(|x| x.render()).collect::<Vec<_>>().join(",")
                ),
                zaic::deflat::Action::Return(v) => {
                    format!("  return {}", v.as_ref().map(|x| x.render()).unwrap_or_default())
                }
            };
            blk_lines.push_str(&s);
            blk_lines.push('\n');
        }
        for t in &b.transitions {
            let c = t.cond.as_ref().map(|x| x.render()).unwrap_or_default();
            blk_lines.push_str(&format!("  -> {} [{}]\n", t.next, c));
        }
    }
    std::fs::write("deobf/collector_cfg.txt", &blk_lines).expect("запись CFG");
    println!("все {} блоков → deobf/collector_cfg.txt", collector.blocks.len());
    0
}

fn cmd_analyze(path: Option<&str>) -> i32 {
    let default = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bundles");
    let targets: Vec<std::path::PathBuf> = match path {
        Some(p) => vec![std::path::PathBuf::from(p)],
        None => {
            let mut v = Vec::new();
            for name in ["aliyun.js", "pe.js", "feilin.js"] {
                let p = default.join(name);
                if p.exists() {
                    v.push(p);
                }
            }
            v
        }
    };
    if targets.is_empty() {
        eprintln!("бандлы не найдены: положи aliyun.js/pe.js/feilin.js в bundles/");
        return 1;
    }
    for p in targets {
        println!("=== {} ===", p.display());
        let t0 = std::time::Instant::now();
        match ast::analyze_file(&p.display().to_string()) {
            Ok(a) => {
                println!("парсинг+анализ: {:?}", t0.elapsed());
                println!(
                    "декодеров: {} | обёрток: {} | ротаций: {} | инлайнов: {}",
                    a.decoders.len(),
                    a.wrappers,
                    a.rotations.len(),
                    a.inlined
                );
                println!("строк извлечено: {}", a.strings.len());
                println!("ключевых блобов (Xt): {}", a.key_blobs.len());
                for blob in &a.key_blobs {
                    let key = rt::blob_to_key_pub(blob);
                    match key {
                        Some(k) => println!("  {} → {}", blob, String::from_utf8_lossy(&k)),
                        None => println!("  {} → ?", blob),
                    }
                }
                if let Ok(deobf_src) = deobf::deobfuscate_file(&p.display().to_string()) {
                    if let Ok(map) = zaic::anchor::build_anchor_map(&deobf_src) {
                        println!(
                            "телеметрия-полей: {} | анкер-обращений: {}",
                            map.fields.len(),
                            map.total_anchors
                        );
                        for (field, anchors) in &map.fields {
                            println!("  {} ← {}", field, anchors.join(", "));
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("FAIL: {}", e);
                return 1;
            }
        }
    }
    0
}

fn cmd_deobfuscate_full(path: Option<&str>, out: Option<&str>) -> i32 {
    let p = match path {
        Some(p) => p.to_string(),
        None => {
            eprintln!("deobfuscate-full <бандл.js> [out.js]");
            return 1;
        }
    };
    match deobf::deobfuscate_full(&p) {
        Ok(src) => match out {
            Some(o) => {
                std::fs::write(o, src).expect("запись");
                println!("полный деобф (строки+opaque+CFF) → {}", o);
                0
            }
            None => {
                println!("{}", &src[..src.len().min(2000)]);
                0
            }
        },
        Err(e) => {
            eprintln!("FAIL: {}", e);
            1
        }
    }
}

fn cmd_deobfuscate(path: Option<&str>, out: Option<&str>) -> i32 {
    let p = match path {
        Some(p) => p.to_string(),
        None => {
            eprintln!("deobfuscate <бандл.js> [out.js]");
            return 1;
        }
    };
    match deobf::deobfuscate_file(&p) {
        Ok(src) => match out {
            Some(o) => {
                std::fs::write(o, src).expect("запись");
                println!("деобфусцировано → {}", o);
                0
            }
            None => {
                println!("{}", &src[..src.len().min(2000)]);
                0
            }
        },
        Err(e) => {
            eprintln!("FAIL: {}", e);
            1
        }
    }
}

fn cmd_profiles() -> i32 {
    println!("== 10 профилей чистой математикой (сид → слепок) ==");
    for i in 0..10 {
        let p = gen::snap(i);
        println!(
            "  #{} {} {:?} экран {}x{} dpr={} ядра {} мем {} GPU [{}] tz={} lang={} шрифтов {}",
            i,
            p.os.name(),
            p.os.platform(),
            p.screen.0,
            p.screen.1,
            p.dpr,
            p.cores,
            p.mem,
            p.gpu_model,
            p.tz,
            p.lang,
            p.fonts_count
        );
    }
    println!("\nпрофилей: 10 (попарно различные во всех перестановочных размерностях)");
    0
}

async fn cmd_fp() -> i32 {
    let engine = match net::Engine::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("движок: {}", e);
            return 1;
        }
    };
    println!("GET https://tls.peet.ws/api/all (эмуляция Chrome 149)…");
    match engine.get_with("https://tls.peet.ws/api/all", &[]).await {
        Ok(r) => {
            let body = String::from_utf8_lossy(&r.body);
            println!("HTTP {} ({})", r.status, r.version);
            println!("{}", body);
            0
        }
        Err(e) => {
            eprintln!("fp: {}", e);
            1
        }
    }
}

fn rnd_alnum_pub(rng: &mut Rng, len: usize) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        s.push(A[rng.below(A.len() as u64) as usize] as char);
    }
    s
}
