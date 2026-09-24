pub const CRYPTO_CONSTANTS: &[(i64, &str)] = &[
    (1732584193, "md5/sha1 init a"),
    (4023233417, "md5 init b"),
    (2562383102, "md5 init c"),
    (271733878, "md5 init d"),
    (-271733879, "md5 init d (neg)"),
    (1518500249, "sha1 k1"),
    (1859775393, "sha1 k2"),
    (2400959708, "sha1 k3"),
    (3395469782, "sha1 k4"),
    (1779033703, "sha256 init a"),
    (3144134277, "sha256 init b"),
    (1013904242, "sha256 init c"),
    (2773480762, "sha256 init d"),
    (4294967295, "u32 mask"),
    (4294967296, "2^32 (sin-table init)"),
    (1518744757, "rc5/sha const"),
    (1549556828, "hmac opad"),
    (909522486, "hmac ipad"),
    (3355582781, "xxh prime"),
    (668265263, "xxh prime"),
    (374761393, "xxh prime"),
    (2246822519, "xxh prime"),
    (3266489917, "xxh prime"),
    (6682652630, "xxh prime64"),
];

pub const AES_SBOX_HEAD: [u8; 8] = [99, 124, 119, 123, 242, 107, 111, 56];

pub fn is_aes_sbox(table: &[i64]) -> bool {
    if table.len() < 16 {
        return false;
    }
    AES_SBOX_HEAD.iter().zip(table.iter()).all(|(a, b)| *a as u8 == *b as u8)
}

pub fn is_sin_table_gen(expr_src: &str) -> bool {
    expr_src.contains("4294967296") && expr_src.contains("sin")
}

pub const HASH_ROUND_PATTERNS: &[&str] = &[
    "(<<< (+ (+ ?a (?f ?b ?c ?d)) (+ ?m ?k)) ?s)",
    "(+ ?a (<<< (+ (+ ?a (?f ?b ?c ?d)) (+ ?m ?k)) ?s))",
    "(<<< (+ (+ ?a (^ ?b (^ ?c ?d))) (+ ?m ?k)) ?s)",
    "(<<< (+ (+ ?a (^ ?b (& ?c ?d))) (+ ?m ?k)) ?s)",
];

pub fn md5_round_canonical() -> String {
    HASH_ROUND_PATTERNS[1].to_string()
}
