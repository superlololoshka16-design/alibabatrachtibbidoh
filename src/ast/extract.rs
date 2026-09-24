use super::{Ctx, Val};

pub fn extract_keys(ctx: &Ctx) -> (Vec<String>, Vec<String>) {
    let mut strings: Vec<String> = Vec::new();
    for v in ctx.folded.values() {
        if let Val::Str(s) = v {
            if !s.is_empty() {
                strings.push(s.clone());
            }
        }
    }
    strings.sort();
    strings.dedup();
    let blobs = strings
        .iter()
        .filter(|s| s.len() == 44 && crate::crypto::b64_decode(s).map(|b| b.len() == 32).unwrap_or(false))
        .cloned()
        .collect();
    (strings, blobs)
}
