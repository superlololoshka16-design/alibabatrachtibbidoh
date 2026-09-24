use crate::crypto::{b64_encode, md5};

pub const PIECE_W: u32 = 122;
pub const PIECE_H: u32 = 110;
pub const STRIP_W: u32 = 240;
pub const STRIP_H: u32 = 60;

pub const TARGET_PIECE_RENDER: &str = "[ec4ac200cecad4988a0bc32890e39073,122,110]";
pub const TARGET_STRIP_RENDER: &str = "[d8eda6282f6717eb17ee66402af7623e,240,60]";

pub fn render_field(png_bytes: &[u8], w: u32, h: u32) -> String {
    let data_url = data_url(png_bytes);
    format!("[{},{},{}]", hex(&md5(data_url.as_bytes())), w, h)
}

pub fn data_url(png_bytes: &[u8]) -> String {
    format!("data:image/png;base64,{}", b64_encode(png_bytes))
}

pub fn encode_png_chrome(rgba: &[u8], w: u32, h: u32) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let tmp = std::env::temp_dir().join(format!("zaic_probe_{}.png", std::process::id()));
    {
        let file = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        let mut enc = png::Encoder::new(file, w, h);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_deflate_compression(png::DeflateCompression::Level(1));
        enc.set_filter(png::Filter::Up);
        let mut sw = enc
            .write_header()
            .map_err(|e| e.to_string())?
            .into_stream_writer()
            .map_err(|e| e.to_string())?;
        let rowlen = w as usize * 4;
        for row in rgba.chunks(rowlen) {
            sw.write_all(row).map_err(|e| e.to_string())?;
        }
        sw.finish().map_err(|e| e.to_string())?;
    }
    std::fs::read(&tmp).map_err(|e| e.to_string())
}

pub fn raster_piece_probe() -> Vec<u8> {
    const W: usize = PIECE_W as usize;
    const H: usize = PIECE_H as usize;
    let mut buf = vec![Px { r: 0.0, g: 0.0, b: 0.0, a: 0.0 }; W * H];
    let fills: [(f64, f64, f64, (f64, f64, f64)); 3] = [
        (40.0, 40.0, 40.0, (1.0, 34.0 / 255.0, 1.0)),
        (80.0, 40.0, 40.0, (34.0 / 255.0, 1.0, 1.0)),
        (60.0, 80.0, 40.0, (1.0, 1.0, 34.0 / 255.0)),
    ];
    for (cx, cy, r, col) in fills {
        for y in 0..H {
            for x in 0..W {
                let cov = circle_coverage(x as f64, y as f64, cx, cy, r);
                if cov > 0.0 {
                    blend_multiply(&mut buf[y * W + x], col, cov);
                }
            }
        }
    }

    for y in 0..H {
        for x in 0..W {
            let co = circle_coverage(x as f64, y as f64, 60.0, 60.0, 60.0);
            let ci = circle_coverage(x as f64, y as f64, 60.0, 60.0, 20.0);
            let cov = (co - ci).clamp(0.0, 1.0);
            if cov > 0.0 {
                blend_multiply(&mut buf[y * W + x], (1.0, 153.0 / 255.0, 204.0 / 255.0), cov);
            }
        }
    }
    let mut out = Vec::with_capacity(W * H * 4);
    for p in &buf {
        if p.a <= 0.0 {
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        let q = |v: f64| ((v / p.a * 255.0) + 0.5).floor().clamp(0.0, 255.0) as u8;
        let a = ((p.a * 255.0) + 0.5).floor().clamp(0.0, 255.0) as u8;
        out.extend_from_slice(&[q(p.r), q(p.g), q(p.b), a]);
    }
    out
}

#[derive(Clone, Copy)]
struct Px {
    r: f64,
    g: f64,
    b: f64,
    a: f64,
}

fn blend_multiply(dst: &mut Px, col: (f64, f64, f64), asrc: f64) {
    let ab = dst.a;
    if ab <= 0.0 {
        dst.r = col.0 * asrc;
        dst.g = col.1 * asrc;
        dst.b = col.2 * asrc;
        dst.a = asrc;
        return;
    }
    let ao = asrc + ab * (1.0 - asrc);
    if ao <= 0.0 {
        return;
    }
    let cb_r = dst.r / ab;
    let cb_g = dst.g / ab;
    let cb_b = dst.b / ab;
    dst.r = asrc * (1.0 - ab) * col.0 + asrc * ab * cb_r * col.0 + (1.0 - asrc) * ab * cb_r;
    dst.g = asrc * (1.0 - ab) * col.1 + asrc * ab * cb_g * col.1 + (1.0 - asrc) * ab * cb_g;
    dst.b = asrc * (1.0 - ab) * col.2 + asrc * ab * cb_b * col.2 + (1.0 - asrc) * ab * cb_b;
    dst.a = ao;
}

fn circle_coverage(x: f64, y: f64, cx: f64, cy: f64, r: f64) -> f64 {
    let x0 = x;
    let x1 = x + 1.0;
    let lo = y - cy;
    let hi = y + 1.0 - cy;
    if lo >= r || hi <= -r {
        return 0.0;
    }

    let mut pts = vec![x0, x1];
    for &yy in &[lo, -lo, hi, -hi] {
        let a = yy.abs();
        if a < r {
            let s = (r * r - a * a).sqrt();
            for xx in [cx - s, cx + s] {
                if xx > x0 && xx < x1 {
                    pts.push(xx);
                }
            }
        }
    }
    pts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    pts.dedup();
    let mut area = 0.0;
    for w in pts.windows(2) {
        let (xa, xb) = (w[0], w[1]);
        let xm = (xa + xb) / 2.0;
        let d2 = r * r - (xm - cx) * (xm - cx);
        if d2 <= 0.0 {
            continue;
        }
        let hw = (xb - xa) / 2.0;
        if hw <= 0.0 {
            continue;
        }

        const GX: [f64; 4] = [
            0.1834346424956498,
            0.5255324099163290,
            0.7966664774136267,
            0.9602898564975363,
        ];
        const GW: [f64; 4] = [
            0.3626837833783620,
            0.3137066458778872,
            0.2223810344533745,
            0.1012285362903763,
        ];
        let mut s = 0.0;
        for i in 0..4 {
            let t = GX[i];
            for sign in [-1.0, 1.0] {
                let xx = xm + sign * hw * t;
                let d = r * r - (xx - cx) * (xx - cx);
                if d <= 0.0 {
                    continue;
                }
                let h = d.sqrt();
                let top = hi.min(h);
                let bot = lo.max(-h);
                if top > bot {
                    s += GW[i] * (top - bot);
                }
            }
        }
        area += s * hw;
    }
    area.clamp(0.0, 1.0)
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

pub struct Rgba {
    pub px: Vec<u8>,
    pub w: u32,
    pub h: u32,
}

pub fn decode_rgba(raw: &[u8]) -> Result<Rgba, String> {
    let dec = png::Decoder::new(std::io::Cursor::new(raw));
    let mut reader = dec.read_info().map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; reader.output_buffer_size().unwrap_or(0)];
    let info = reader.next_frame(&mut buf).map_err(|e| e.to_string())?;
    let n = info.buffer_size();
    buf.truncate(n);
    Ok(Rgba { px: buf, w: info.width, h: info.height })
}
