use flate2::read::ZlibDecoder;
use std::io::Read;

pub struct Rgba {
    pub w: usize,
    pub h: usize,

    pub px: Vec<u8>,
}

#[derive(Debug)]
pub enum PngErr {
    NotPng,
    BadChunk,
    Unsupported(String),
    Decode,
}

fn be32(b: &[u8]) -> usize {
    ((b[0] as usize) << 24) | ((b[1] as usize) << 16) | ((b[2] as usize) << 8) | b[3] as usize
}

pub fn decode(data: &[u8]) -> Result<Rgba, PngErr> {
    if data.len() < 8 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(PngErr::NotPng);
    }
    let mut pos = 8usize;
    let mut w = 0usize;
    let mut h = 0usize;
    let mut ctype = 0u8;
    let mut depth = 0u8;
    let mut interlace = 0u8;
    let mut idat: Vec<u8> = Vec::new();
    while pos + 8 <= data.len() {
        let len = be32(&data[pos..pos + 4]);
        let typ = &data[pos + 4..pos + 8];
        let body = &data[pos + 8..(pos + 8 + len).min(data.len())];
        match typ {
            b"IHDR" => {
                if body.len() < 13 {
                    return Err(PngErr::BadChunk);
                }
                w = be32(&body[0..4]);
                h = be32(&body[4..8]);
                depth = body[8];
                ctype = body[9];
                interlace = body[12];
            }
            b"IDAT" => idat.extend_from_slice(body),
            b"IEND" => break,
            _ => {}
        }
        pos += 12 + len;
    }
    if interlace != 0 {
        return Err(PngErr::Unsupported("interlace".into()));
    }
    if depth != 8 || !matches!(ctype, 2 | 6) {
        return Err(PngErr::Unsupported(format!("type {} depth {}", ctype, depth)));
    }
    let bpp = if ctype == 6 { 4 } else { 3 };
    if w == 0 || h == 0 || w > 4096 || h > 4096 {
        return Err(PngErr::Unsupported("size".into()));
    }
    let mut z = ZlibDecoder::new(&idat[..]);
    let mut raw = vec![0u8; (w * bpp + 1) * h];
    z.read_exact(&mut raw).map_err(|_| PngErr::Decode)?;

    let mut px = Vec::with_capacity(w * h * 4);
    let mut prev = vec![0u8; w * bpp];
    for y in 0..h {
        let row_off = y * (w * bpp + 1);
        let filter = raw[row_off];
        let line = &mut raw[row_off + 1..row_off + 1 + w * bpp];
        match filter {
            0 => {}
            1 => {
                for i in bpp..line.len() {
                    line[i] = line[i].wrapping_add(line[i - bpp]);
                }
            }
            2 => {
                for i in 0..line.len() {
                    line[i] = line[i].wrapping_add(prev[i]);
                }
            }
            3 => {
                for i in 0..line.len() {
                    let left = if i >= bpp { line[i - bpp] as u32 } else { 0 };
                    line[i] = line[i].wrapping_add(((left + prev[i] as u32) / 2) as u8);
                }
            }
            4 => {
                for i in 0..line.len() {
                    let a = if i >= bpp { line[i - bpp] as i32 } else { 0 };
                    let b = prev[i] as i32;
                    let c = if i >= bpp { prev[i - bpp] as i32 } else { 0 };
                    let p = a + b - c;
                    let pa = (p - a).abs();
                    let pb = (p - b).abs();
                    let pc = (p - c).abs();
                    let pred = if pa <= pb && pa <= pc { a } else if pb <= pc { b } else { c };
                    line[i] = line[i].wrapping_add(pred as u8);
                }
            }
            _ => return Err(PngErr::Decode),
        }
        prev.copy_from_slice(line);
        for x in 0..w {
            let o = x * bpp;
            if ctype == 6 {
                px.extend_from_slice(&line[o..o + 4]);
            } else {
                px.extend_from_slice(&[line[o], line[o + 1], line[o + 2], 255]);
            }
        }
    }
    Ok(Rgba { w, h, px })
}
