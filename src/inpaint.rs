use crate::probe::decode_rgba;

pub struct Rgba {
    pub px: Vec<u8>,
    pub w: u32,
    pub h: u32,
}

pub fn decode(png_bytes: &[u8]) -> Result<Rgba, String> {
    let r = decode_rgba(png_bytes)?;
    Ok(Rgba {
        px: r.px,
        w: r.w,
        h: r.h,
    })
}

pub struct Hole {
    pub x0: usize,
    pub y0: usize,
    pub y1: usize,
    pub width: usize,
}

fn lum(img: &Rgba, x: usize, y: usize) -> f64 {
    let o = (y * img.w as usize + x) * 4;
    (img.px[o] as f64 + img.px[o + 1] as f64 + img.px[o + 2] as f64) / 3.0
}

fn alpha(img: &Rgba, x: usize, y: usize) -> u8 {
    img.px[(y * img.w as usize + x) * 4 + 3]
}

fn piece_geometry(piece: &Rgba) -> Option<(usize, usize, usize)> {
    let mut y0 = usize::MAX;
    let mut y1 = 0usize;
    for y in 0..piece.h as usize {
        for x in 0..piece.w as usize {
            if alpha(piece, x, y) > 0 {
                y0 = y0.min(y);
                y1 = y1.max(y);
            }
        }
    }
    if y0 == usize::MAX || y1 < y0 {
        return None;
    }
    let mut cols = vec![false; piece.w as usize];
    for x in 0..piece.w as usize {
        for y in y0..=y1 {
            if alpha(piece, x, y) > 0 {
                cols[x] = true;
                break;
            }
        }
    }
    let pw = cols.iter().filter(|c| **c).count();
    if pw == 0 {
        return None;
    }
    Some((y0, y1, pw))
}

pub fn detect(main: &Rgba, piece: &Rgba) -> Option<Hole> {
    let (py0, py1, pw) = piece_geometry(piece)?;
    let band_h = py1 - py0 + 1;
    if band_h < 4 || pw == 0 || main.w as usize <= pw + 2 || main.h as usize <= py1 + 1 {
        return None;
    }
    let mw = main.w as usize;
    let mh = main.h as usize;

    let ncc = |x0: usize, y0: usize, tmpl: &[(usize, usize, f64)], tmean: f64, tstd: f64| -> f64 {
        let n = tmpl.len() as f64;
        let mut s = 0f64;
        let mut s2 = 0f64;
        let mut cross = 0f64;
        for &(dx, dy, tv) in tmpl {
            let v = lum(main, x0 + dx, y0 + dy);
            s += v;
            s2 += v * v;
            cross += v * tv;
        }
        let mean = s / n;
        let var = (s2 - mean * mean * n) / n;
        if var <= 0.0 {
            return 0.0;
        }
        let std = var.sqrt();
        (cross / n - mean * tmean) / (std * tstd)
    };

    let mut tmpl: Vec<(usize, usize, f64)> = Vec::new();
    let mut tsum = 0f64;
    for dy in 0..band_h {
        for dx in 0..pw {
            if alpha(piece, dx, py0 + dy) > 0 {
                let v = lum(piece, dx, py0 + dy);
                tmpl.push((dx, dy, v));
                tsum += v;
            }
        }
    }
    if tmpl.is_empty() {
        return None;
    }
    let tn = tmpl.len() as f64;
    let tmean = tsum / tn;
    let mut tvar = 0f64;
    for &(_, _, v) in &tmpl {
        tvar += (v - tmean) * (v - tmean);
    }
    let tstd = ((tvar / tn).sqrt()).max(1e-9);

    let step = 2;
    let mut best: Option<(f64, usize, usize)> = None;
    let mut y0 = 0usize;
    while y0 + band_h <= mh {
        let mut x0 = 1usize;
        while x0 + pw <= mw - 1 {
            let score = ncc(x0, y0, &tmpl, tmean, tstd);
            match best {
                Some((bs, _, _)) if score <= bs => {}
                _ => best = Some((score, x0, y0)),
            }
            x0 += step;
        }
        y0 += step;
    }
    let (score, x0, y0) = best?;
    if score < 0.25 {
        return None;
    }

    let mut bx0 = x0;
    let mut bsc = score;
    let mut dx = 1usize;
    while dx < step {
        if x0 + dx + pw <= mw - 1 {
            let s = ncc(x0 + dx, y0, &tmpl, tmean, tstd);
            if s > bsc {
                bsc = s;
                bx0 = x0 + dx;
            }
        }
        if x0 >= dx {
            let s = ncc(x0 - dx, y0, &tmpl, tmean, tstd);
            if s > bsc {
                bsc = s;
                bx0 = x0 - dx;
            }
        }
        dx += 1;
    }
    let mut by0 = y0;
    if y0 >= step {
        let s = ncc(bx0, y0 - step, &tmpl, tmean, tstd);
        if s > bsc {
            by0 = y0 - step;
        }
    }
    if y0 + step + band_h <= mh {
        let s = ncc(bx0, y0 + step, &tmpl, tmean, tstd);
        if s > bsc {
            by0 = y0 + step;
        }
    }
    Some(Hole {
        x0: bx0,
        y0: by0,
        y1: by0 + band_h - 1,
        width: pw,
    })
}

pub fn drag_distance_for(hole_x: usize) -> usize {
    let a = 0.0035503f64;
    let b = 0.07692f64;
    let d = b * b + 4.0 * a * hole_x as f64;
    let m = (-b + d.sqrt()) / (2.0 * a);
    m.round().max(1.0) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drag_inverse() {
        assert_eq!(drag_distance_for(103), 160);

        let h = drag_distance_for(258);
        assert!((255..=262).contains(&h));
    }

    #[test]
    fn dark_slot_found() {
        let w = 300usize;
        let h = 300usize;
        let pw = 20usize;
        let ph = 110usize;
        let mut px = vec![200u8; w * h * 4];
        for y in 0..h {
            for x in 0..w {
                let o = (y * w + x) * 4 + 3;
                px[o] = 255;
            }
        }
        for y in 0..ph {
            for x in 140..150 {
                let o = (y * w + x) * 4;
                px[o] = 30;
                px[o + 1] = 30;
                px[o + 2] = 30;
            }
        }
        let main = Rgba {
            px,
            w: w as u32,
            h: h as u32,
        };

        let mut pp = vec![0u8; pw * ph * 4];
        for y in 0..ph {
            for x in 0..pw {
                let o = (y * pw + x) * 4;
                pp[o] = 120;
                pp[o + 1] = 120;
                pp[o + 2] = 120;
                pp[o + 3] = if (8..18).contains(&x) { 255 } else { 0 };
            }
        }
        let piece = Rgba {
            px: pp,
            w: pw as u32,
            h: ph as u32,
        };
        let hole = detect(&main, &piece).expect("слот найден");
        assert!((138..=150).contains(&hole.x0), "x0={}", hole.x0);
        let h = drag_distance_for(hole.x0);
        assert!((180..=196).contains(&h), "drag={}", h);
    }
}
