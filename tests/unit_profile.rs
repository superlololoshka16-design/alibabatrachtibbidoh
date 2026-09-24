use zaic::profile::*;
use zaic::crypto::Rng;
use zaic::gen;

use zaic::profile::*;

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
