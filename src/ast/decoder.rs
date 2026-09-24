use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
pub struct Decoder {
    pub name: String,
    pub table: Rc<RefCell<Vec<String>>>,
    pub shift: i64,

    pub lookup: [i8; 256],

    pub xor_out: bool,
}

impl Decoder {
    pub fn decode(&self, n: i64, xor: Option<i64>) -> Option<String> {
        let idx = n.checked_sub(self.shift)?;
        if idx < 0 {
            return None;
        }
        let table = self.table.borrow();
        let s = table.get(idx as usize)?;
        let x = match (self.xor_out, xor) {
            (false, _) => 0i64,
            (true, Some(v)) => v,
            (true, None) => 0,
        };
        let mut e: u64 = 0;
        let mut o: u32 = 0;
        let mut out: Vec<u8> = Vec::with_capacity(s.len() * 3 / 4 + 4);
        for &b in s.as_bytes() {
            let v = self.lookup[b as usize];
            if v < 0 {
                continue;
            }
            let v = v as u64;
            if o % 4 != 0 {
                e = e.wrapping_mul(64).wrapping_add(v);
            } else {
                e = v;
            }
            let o_before = o;
            o += 1;
            if o_before % 4 != 0 {
                let shift = match o_before % 4 {
                    1 => 4,
                    2 => 2,
                    _ => 0,
                };
                out.push((((e >> shift) & 0xff) as u8) ^ x as u8);
            }
        }
        String::from_utf8(out).ok()
    }

    pub fn rotate_table(&self) {
        let mut t = self.table.borrow_mut();
        if t.len() > 1 {
            t.rotate_left(1);
        }
    }

    pub fn decodes_text(&self) -> bool {
        let table = self.table.borrow();
        let mut hits = 0usize;
        for i in 0..table.len() {
            let n = i as i64 + self.shift;
            let ok = if self.xor_out {
                (0..=255u32).any(|x| {
                    matches!(&self.decode(n, Some(x as i64)), Some(s) if textlike(s))
                })
            } else {
                matches!(&self.decode(n, None), Some(s) if textlike(s))
            };
            if ok {
                hits += 1;
            }
        }
        let need = if table.len() < 4 { 1 } else { 2 };
        hits >= need
    }
}

fn textlike(s: &str) -> bool {
    !s.is_empty() && s.chars().any(|c| c.is_ascii_alphanumeric())
}

pub fn lookup_from_alphabet(alphabet: &str) -> [i8; 256] {
    let mut l = [-1i8; 256];
    for (pos, b) in alphabet.bytes().enumerate() {
        if l[b as usize] == -1 {
            l[b as usize] = pos as i8;
        }
    }
    l
}

pub fn lookup_from_hex(hex: &str, k: u8) -> Option<[i8; 256]> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut l = [-1i8; 256];
    let b = hex.as_bytes();
    let mut pos: i8 = 0;
    let mut i = 0;
    while i + 1 < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        let byte = ((hi * 16 + lo) as u8) ^ k;
        if l[byte as usize] == -1 {
            l[byte as usize] = pos;
        }
        pos += 1;
        i += 2;
    }
    if pos < 48 {
        return None;
    }
    Some(l)
}
