use zaic::inpaint::*;

use zaic::inpaint::*;

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
