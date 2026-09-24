use std::collections::HashMap;
use std::path::PathBuf;

use zaic::ast;
use zaic::rt;

fn bundle(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundles").join(name)
}

fn read(name: &str) -> String {
    std::fs::read_to_string(bundle(name)).unwrap()
}

#[test]
fn bundles_yield_live_keys_runtime() {
    let aliyun = read("aliyun.js");
    let intel = rt::extract_aliyun(&aliyun).expect("алиюн: рантайм-экстракция");
    let key = |hex: &str| -> [u8; 16] {
        let mut k = [0u8; 16];
        k.copy_from_slice(hex.as_bytes());
        k
    };
    assert_eq!(intel.keys.vr, key("45f8ac1e1de14397"), "vr (REQ)");
    assert_eq!(intel.keys.hr, key("87f879f135f27da7"), "hr (RES)");
    assert_eq!(intel.keys.flag, key("c175a358550d02e2"), "flag");
    assert_eq!(intel.keys.upload, key("a549a55c60a39aa0"), "upload");
    assert_eq!(intel.keys.preid, key("75ae5c150d235802"), "preid");
    assert_eq!(intel.keys.web, key("3e627e1b4c63f913"), "web (comma-фрагменты)");
    assert_eq!(intel.access_sec, *b"FqJB6iRNVYdEGpwb");
    assert_eq!(intel.iv, *b"0123456789ABCDEF");
    assert_eq!(intel.aaduane_id, "111jdk439dJJIjd023823201");
    assert_eq!(intel.ak_secret, "222aiJodos2938JDdosko2djd82sf0");
    assert_eq!(intel.app_key, "3795d28242a11619bc25f786f84e53d4");
    assert_eq!(intel.api_version, "2023-03-05");
    assert_eq!(intel.cloudauth_version, "2020-10-15");
    assert_eq!(intel.platform, "W.10001.c");
    assert_eq!(intel.app_name, "saf-captcha");

    let a = ast::analyze_file(bundle("aliyun.js").to_str().unwrap()).expect("aliyun.js анализ");
    assert!(a.decoders.len() >= 3, "aliyun: мало декодеров: {}", a.decoders.len());
    assert!(a.inlined > 500, "aliyun: мало инлайнов: {}", a.inlined);
    for anchor in ["InitCaptchaV3", "AES", "__ALIYUN", "captcha-front", "FqJB6iRN"] {
        assert!(a.strings.iter().any(|s| s.contains(anchor)), "aliyun: якорь {:?} не декодирован", anchor);
    }
}

#[test]
fn feilin_yields_cloudauth_creds_runtime() {
    let al = rt::extract_aliyun(&read("aliyun.js")).expect("aliyun");
    let (duane, secret) = rt::extract_feilin(&read("feilin.js"), &al.access_sec, &al.iv)
        .expect("feilin: дуаны рантаймом");
    assert_eq!(duane, "DuaneAprqkYsF3nt1yjK29Bf");
    assert_eq!(secret, "DuanemHmyeE6LXCC46sJEDUw5DTlSZ");

    let f = ast::analyze_file(bundle("feilin.js").to_str().unwrap()).expect("feilin.js анализ");
    assert!(f.decoders.len() >= 10, "feilin: мало декодеров: {}", f.decoders.len());
    assert!(f.wrappers >= 50, "feilin: мало обёрток: {}", f.wrappers);
    assert!(f.inlined >= 500, "feilin: мало инлайнов: {}", f.inlined);
    let map: HashMap<String, ()> = f.config_pairs.iter().map(|(k, _)| (k.clone(), ())).collect();
    for key in ["REQ", "RES", "FLAG", "UPLOAD", "PREID", "ID", "SECRET", "AES_IV", "ACCESS_SEC", "APP_KEY"] {
        assert!(map.contains_key(key), "feilin: конфиг-ключ {} не сложился", key);
    }
}

#[test]
fn r_table_extracted_from_vm_both_generations() {
    let dump = rt::extract_r_table(&read("pe.js")).expect("R-таблица из дампа pe.js");
    let expected: [u8; 64] = [
        32, 50, 10, 51, 6, 44, 37, 16, 46, 11, 62, 19, 43, 25, 23, 30, 60, 33, 53, 34, 7, 26, 12, 48,
        5, 2, 20, 4, 61, 13, 47, 49, 18, 29, 27, 22, 1, 17, 39, 56, 41, 38, 55, 31, 15, 58, 52, 40,
        8, 57, 45, 35, 59, 36, 42, 54, 63, 3, 24, 28, 14, 9, 0, 21,
    ];
    assert_eq!(dump, expected, "R-таблица дампа должна совпадать с живым вектором побайтово");
}

#[test]
fn egg_mba_and_ops() {
    use zaic::egraph::{canonical, ops, sexpr, Builder};
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
    assert_eq!(sexpr(&mba), sexpr(&canonical(&b2.finish(plain))), "MBA (a^b)+((a&b)<<1) обязан канонизироваться в a+b");

    let mut b3 = Builder::new();
    let v = b3.var("x");
    let k = b3.lit(42);
    let e1 = b3.xor(v, k);
    let k2 = b3.lit(42);
    let e2 = b3.xor(e1, k2);
    let expr = canonical(&b3.finish(e2));
    let prog = ops::flatten(&expr);
    assert_eq!(prog.exec(&[7]), Some(7));
    assert_eq!(prog.exec(&[123]), Some(123));
    assert_eq!(prog.n_vars, 1);
}

#[test]
fn profiles_heterogeneous_payloads() {
    use zaic::crypto::Rng;
    use zaic::profile::{self, SessionCtx};
    use zaic::gen;
    let mut rng = Rng::new();
    let timing = "10-0|11-12|20-14|23-220|30-224|40-231|90-300";
    let mut canvas_set = std::collections::HashSet::new();
    let mut webgl_set = std::collections::HashSet::new();
    let mut font_set = std::collections::HashSet::new();
    for p in (0..10).map(gen::snap) {
        let mut ctx = SessionCtx {
            rng: &mut rng,
            now_ms: 1789741347892,
            init_ms: 1789741348050,
            verify_ms: 0,
            client_ip: "47.57.232.232",
            uptime_ms: 1790976,
            timing_log: timing,
            feilin_url: "https://g.alicdn.com/x.js",
            feilin_load_ms: 42.5,
            feilin_size: 581232,
            piece_render: "[ec4ac200cecad4988a0bc32890e39073,122,110]",
            strip_render: "[d8eda6282f6717eb17ee66402af7623e,240,60]",
            tok21: "Z2hjNmloaWY=",
            tok71: "0CPj01gy1gAT7oL5VmpkNnjonqrzwffyRur6htkt",
            tok73: "AtwzKtPOFZyZbfPSA1wVrr8sTfYIHkpubCQrG14P0W",
        };
        let payload = profile::build_payload(&p, &mut ctx);
        let fields: Vec<&str> = payload.split('#').collect();
        assert_eq!(fields.len(), 142, "snap#{}: полей {}", p.idx, fields.len());
        canvas_set.insert(profile::canvas_render(&p));
        webgl_set.insert(profile::webgl_target(&p));
        font_set.insert(profile::font_render(&p));
    }
        assert!(font_set.len() >= 3, "шрифтовые рендеры — по семействам ОС+счёту шрифтов (ранее 4 фиксированных таблиц)");
    assert_eq!(canvas_set.len(), 10);
    assert_eq!(webgl_set.len(), 10);
}
