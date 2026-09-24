use crate::crypto::Rng;

pub struct TrackPoint {
    pub x: f64,
    pub y: f64,
    pub t_ms: u64,
}

pub fn generate_track(rng: &mut Rng, distance: f64, base_y: f64) -> Vec<TrackPoint> {
    let total_ms: u64 = 1000 + rng.below(1400);
    let frames = (total_ms / 16).max(20);
    let mut pts = Vec::with_capacity(frames as usize + 4);
    pts.push(TrackPoint { x: 0.0, y: base_y, t_ms: 0 });
    let mut prev_x = 0.0f64;
    let mut f_idx = 1u64;
    let mut time_shift = 0u64;
    while f_idx < frames {
        let p = f_idx as f64 / frames as f64;
        let eased = if p < 0.5 { 4.0 * p * p * p } else { 1.0 - (-2.0 * p + 2.0).powi(3) / 2.0 };
        let mut x = eased * distance;
        let jitter = (rng.below(5) as i64) - 2;
        x = (x + jitter as f64).max(0.0).min(distance + 2.0);
        if x < prev_x - 3.0 {
            x = prev_x - 3.0;
        }
        let t = f_idx * 16 + rng.below(9) + time_shift;
        let y = base_y + (rng.below(3) as i64 - 1) as f64;
        pts.push(TrackPoint { x, y, t_ms: t });
        if rng.below(40) == 0 && p > 0.4 && p < 0.7 {
            let hold = 90 + rng.below(120);
            pts.push(TrackPoint { x, y: base_y, t_ms: t + hold });
            time_shift += hold;
        }
        prev_x = x;
        f_idx += 1;
    }
    let end_t = pts.last().map(|p| p.t_ms).unwrap_or(total_ms);
    pts.push(TrackPoint { x: distance, y: base_y, t_ms: end_t + 30 + rng.below(60) });
    pts.push(TrackPoint { x: distance, y: base_y, t_ms: end_t + 200 + rng.below(300) });
    pts
}

pub fn segment_speed(a: &TrackPoint, b: &TrackPoint) -> f64 {
    if b.t_ms <= a.t_ms {
        return 0.0;
    }
    (b.x - a.x).abs() / ((b.t_ms - a.t_ms) as f64 / 1000.0)
}

pub fn track_json(pts: &[TrackPoint]) -> String {
    let mut s = String::with_capacity(pts.len() * 24 + 2);
    s.push('[');
    for (i, p) in pts.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('[');
        s.push_str(&format!("{:.1},{:.1},{}", p.x, p.y, p.t_ms));
        s.push(']');
    }
    s.push(']');
    s
}
