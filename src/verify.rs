use crate::crypto::{b64_encode, Rng};
use crate::ycipher::y_digest;
use std::io::Write;

pub fn r_cipher(data_b64: &str, key: &[u8; 16], table: &[u8; 64]) -> Vec<u8> {
    let mut r = *table;
    let mut t: usize = 0;
    for i in 0..64usize {
        t = (((i + t + r[i] as usize + r[t] as usize) >> 1) + key[i % key.len()] as usize) & 63;
        if i != t {
            r[i] ^= r[t];
            r[t] ^= r[i];
            r[i] ^= r[t];
        }
    }
    let mut out = Vec::with_capacity(data_b64.len());
    let mut e: usize = 0;
    let mut a: usize = 0;
    for &ch in data_b64.as_bytes() {
        a = ((e ^ a).wrapping_add((r[e] ^ r[a]) as usize)) & 63;
        if e != a {
            r[e] ^= r[a];
            r[a] ^= r[e];
            r[e] ^= r[a];
        }
        let mut m = ch as i64;
        m += e as i64 + r[e] as i64;
        m -= a as i64 + r[a] as i64;
        m ^= r[e] as i64 + r[a] as i64;
        m ^= r[(r[e] as usize).wrapping_add(r[a] as usize) & 63] as i64;
        out.push((m & 0xff) as u8);
        e = (e + 1) & 63;
    }
    out
}

pub fn zlib_deflate(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    let mut enc = ZlibEncoder::new(Vec::with_capacity(data.len() / 2 + 64), Compression::new(6));
    enc.write_all(data).expect("deflate");
    enc.finish().expect("deflate finish")
}

pub fn build_data(key: &[u8; 16], table: &[u8; 64], tk_plain: &str) -> String {
    let prefix = y_digest(tk_plain, "0000");
    let mut payload = Vec::with_capacity(tk_plain.len() + 32);
    payload.extend_from_slice(prefix.as_bytes());
    payload.extend_from_slice(tk_plain.as_bytes());
    let b64s = b64_encode(&zlib_deflate(&payload));
    b64_encode(&r_cipher(&b64s, key, table))
}

fn arg_b64(rng: &mut Rng) -> String {
    let mut b = [0u8; 10];
    rng.fill(&mut b);
    b64_encode(&b)
}

pub struct ClickGeom {
    pub btn_x: u32,
    pub btn_y: u32,
    pub approach_from: (u32, u32),
}

#[allow(clippy::too_many_arguments)]
pub fn tk_json_click(
    rng: &mut Rng,
    geom: &ClickGeom,
    init_ms: u64,
    verify_ms: u64,
    si_csv: &str,
) -> String {
    let elapsed = verify_ms.saturating_sub(init_ms);
    let click_at = elapsed.saturating_sub(180 + rng.below(500)).max(600);

    let n = 3 + rng.below(5);
    let (sx, sy) = geom.approach_from;
    let mut mp = String::with_capacity(64 * n as usize);
    let step = 40 + rng.below(25);
    let start_t = click_at - (n as u64) * step - rng.below(150);
    for i in 0..=n {
        if i > 0 {
            mp.push('|');
        }
        let p = i as f64 / n as f64;
        let x = sx as f64 + (geom.btn_x as f64 - sx as f64) * p;
        let y = sy as f64 + (geom.btn_y as f64 - sy as f64) * p;
        mp.push_str(&format!("{:.0},{:.0},{},1", x, y, start_t + i as u64 * step));
    }
    let mc_t = click_at;
    let mu_t = mc_t + 70 + rng.below(70);
    let track_start = init_ms + start_t;
    format!(
        "{{\"TrackList\":{{\"mc\":\"{},{},{}, ,1\",\"tc\":\"\",\"mu\":\"{},{},{}, ,1\",\"te\":\"\",\"mp\":\"{}\",\"tmv\":\"\",\"ks\":\"\",\"fi\":\"\",\"startTime\":{},\"si\":\"{}\"}},\"TrackStartTime\":{},\"VerifyTime\":{},\"arg\":\"{}\"}}",
        geom.btn_x, geom.btn_y, mc_t,
        geom.btn_x, geom.btn_y + rng.below(2) as u32, mu_t,
        mp,
        track_start, si_csv,
        track_start, verify_ms,
        arg_b64(rng),
    )
}

pub fn si_csv(inner_w: u32, screen_w: u32, inner_h: u32, client_w: u32, client_h: u32, outer_h: u32, screen_h: u32, fps: f64, outer_w: u32) -> String {
    format!("{},{},{},{},{},{},{},{:.2},{}", inner_w, screen_w, inner_h, client_w, client_h, outer_h, screen_h, fps, outer_w)
}

pub fn captcha_verify_param(certify_id: &str, scene_id: &str) -> String {
    b64_encode(
        format!(
            "{{\"certifyId\":\"{}\",\"sceneId\":\"{}\",\"isSign\":true}}",
            certify_id, scene_id
        )
        .as_bytes(),
    )
}

pub fn tk_json_drag(
    rng: &mut Rng,
    slider_x: u32,
    slider_y: u32,
    drag: u32,
    hole_x: u32,
    init_ms: u64,
    verify_ms: u64,
    si_csv: &str,
) -> String {
    let n = 12 + rng.below(9);
    let elapsed = verify_ms.saturating_sub(init_ms);
    let click_at = elapsed.saturating_sub(400 + rng.below(600)).max(900);
    let step = 45 + rng.below(20);
    let start_t = click_at.saturating_sub((n as u64) * step / 2);
    let mut pts: Vec<(f64, u64)> = Vec::with_capacity(n as usize + 2);
    let mut prev_x = 0.0f64;
    for i in 0..=n {
        let p = i as f64 / n as f64;
        let eased = if p < 0.5 { 4.0 * p * p * p } else { 1.0 - (-2.0 * p + 2.0).powi(3) / 2.0 };
        let mut x = eased * drag as f64;
        let jitter = (rng.below(5) as i64) - 2;
        x = (x + jitter as f64).max(0.0).min(drag as f64 + 2.0);
        if x < prev_x - 3.0 {
            x = prev_x - 3.0;
        }
        prev_x = x;
        pts.push((x, start_t + i as u64 * step));
    }

    let end_t = pts.last().map(|p| p.1).unwrap_or(click_at);
    pts.push((drag as f64, end_t + 60 + rng.below(80)));
    pts.push((drag as f64, end_t + 180 + rng.below(200)));

    let mut mp = String::with_capacity(24 * pts.len());
    for (i, (dx, t)) in pts.iter().enumerate() {
        if i > 0 {
            mp.push('|');
        }
        mp.push_str(&format!("{:.0},{},{},1", slider_x as f64 + dx, slider_y, t));
    }

    let (lx, lt) = pts[pts.len() - 2];
    let post_x = slider_x as f64 + drag as f64 + 120.0 + rng.below(60) as f64;
    let post_y = slider_y as f64 - 60.0 - rng.below(40) as f64;
    let mut mm = format!("{},{},{},1", slider_x, slider_y, pts[0].1);
    for (dx, t) in &pts {
        mm.push('|');
        mm.push_str(&format!("{:.0},{},{},1", slider_x as f64 + dx, slider_y, t));
    }
    mm.push_str(&format!(
        "|{:.0},{},{},1|{:.0},{:.0},{},1",
        slider_x as f64 + lx,
        slider_y,
        lt + 1,
        post_x,
        post_y,
        lt + 40 + rng.below(60)
    ));

    let mc_t = pts[0].1;
    let mu_t = lt;
    let track_start = init_ms + start_t;
    let mut out = String::with_capacity(mp.len() * 2 + 512);
    out.push_str("{\"TrackList\":{\"mc\":\"");
    out.push_str(&format!("{},{},{}, ,1", slider_x, slider_y, mc_t));
    out.push_str("\",\"tc\":\"\",\"mu\":\"");
    out.push_str(&format!("{:.0},{},{}, ,1", slider_x as f64 + lx, slider_y, mu_t));
    out.push_str("\",\"te\":\"\",\"mp\":\"");
    out.push_str(&mp);
    out.push_str("\",\"tmv\":\"\",\"ks\":\"\",\"fi\":\"\",\"mm\":\"");
    out.push_str(&mm);
    out.push_str("\",\"startTime\":");
    out.push_str(&track_start.to_string());
    out.push_str(",\"si\":\"");
    out.push_str(si_csv);
    out.push_str("\"},\"TrackStartTime\":");
    out.push_str(&track_start.to_string());
    out.push_str(",\"VerifyTime\":");
    out.push_str(&verify_ms.to_string());
    out.push_str(",\"xPos\":\"");
    out.push_str(&hole_x.to_string());
    out.push_str("\",\"slidePos\":\"");
    out.push_str(&drag.to_string());
    out.push_str("\",\"arg\":\"");
    out.push_str(&arg_b64(rng));
    out.push_str("\"}");
    out
}
