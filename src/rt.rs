use crate::ast;
use crate::crypto::{aes128_cbc_decrypt, b64_decode};
use crate::keys::SessionKeys;
use oxc::allocator::Allocator;
use oxc::ast::AstKind;
use oxc::ast::ast::ArrayExpressionElement;
use oxc::ast::ast::{AssignmentOperator, BinaryOperator, CallExpression, ConditionalExpression, Expression, Statement, SimpleAssignmentTarget, UpdateExpression};
use oxc::parser::Parser;
use oxc::semantic::Semantic;
use oxc::span::SourceType;

pub struct Intel {
    pub access_sec: [u8; 16],
    pub iv: [u8; 16],
    pub keys: SessionKeys,
    pub aaduane_id: String,
    pub ak_secret: String,
    pub cloudauth_duane: String,
    pub cloudauth_secret: String,
    pub cloudauth_version: String,
    pub app_key: String,
    pub app_version: String,
    pub api_version: String,
    pub platform: String,
    pub app_name: String,
    pub r_table: [u8; 64],
    pub web_key: [u8; 16],
    pub feilin_version: String,
    pub feilin_url: String,
}

fn is_hex16(s: &[u8]) -> bool {
    s.len() == 16 && s.iter().all(|b| b.is_ascii_hexdigit())
}

fn blob_to_key(blob: &str, sec: &[u8; 16], iv: &[u8; 16]) -> Option<[u8; 16]> {
    let raw = b64_decode(blob)?;
    if raw.len() != 32 {
        return None;
    }
    let out = aes128_cbc_decrypt(sec, iv, &raw)?;
    if !is_hex16(&out) {
        return None;
    }
    let mut k = [0u8; 16];
    k.copy_from_slice(&out);
    Some(k)
}

pub fn blob_to_key_pub(blob: &str) -> Option<[u8; 16]> {
    let aliyun = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bundles/aliyun.js"),
    )
    .ok()?;
    let a = ast::analyze_src(&aliyun).ok()?;
    let iv = {
        let hex = a.config_pairs.iter().find(|(k, _)| k == "AES_IV")?.1.clone();
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        let hb = hex.as_bytes();
        let mut i = 0;
        while i + 1 < hb.len() {
            let hi = (hb[i] as char).to_digit(16)?;
            let lo = (hb[i + 1] as char).to_digit(16)?;
            bytes.push((hi * 16 + lo) as u8);
            i += 2;
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(crate::crypto::b64_encode(&bytes).as_bytes());
        k
    };
    blob_to_key(blob, &access_sec_of(&a)?, &iv)
}

fn access_sec_of(a: &crate::ast::Analysis) -> Option<[u8; 16]> {
    let mut blobs: Vec<String> = a.strings.iter().filter(|s| shape_blob(s)).cloned().collect();
    blobs.sort();
    blobs.dedup();
    let iv = a
        .config_pairs
        .iter()
        .find(|(k, _)| k == "AES_IV")
        .map(|(_, v)| v.clone())?;
    let iv = {
        let mut bytes = Vec::with_capacity(iv.len() / 2);
        let hb = iv.as_bytes();
        let mut i = 0;
        while i + 1 < hb.len() {
            let hi = (hb[i] as char).to_digit(16)?;
            let lo = (hb[i + 1] as char).to_digit(16)?;
            bytes.push((hi * 16 + lo) as u8);
            i += 2;
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(crate::crypto::b64_encode(&bytes).as_bytes());
        k
    };
    let mut best: Option<([u8; 16], usize)> = None;
    for s in &a.strings {
        let b = s.as_bytes();
        if b.len() == 16 && b.iter().all(|c| c.is_ascii_graphic()) {
            let mut k = [0u8; 16];
            k.copy_from_slice(b);
            let n = blobs.iter().filter(|b| blob_to_key(b, &k, &iv).is_some()).count();
            if n >= 4 && best.as_ref().map(|(_, m)| n > *m).unwrap_or(true) {
                best = Some((k, n));
            }
        }
    }
    best.map(|(k, _)| k)
}

fn shape_blob(s: &str) -> bool {
    s.len() == 44 && b64_decode(s).map(|b| b.len() == 32).unwrap_or(false)
}

fn cred_blob(s: &str, sec: &[u8; 16], iv: &[u8; 16]) -> Option<String> {
    let raw = b64_decode(s)?;
    if raw.len() < 16 || raw.len() > 64 {
        return None;
    }
    let out = aes128_cbc_decrypt(sec, iv, &raw)?;
    if out.len() < 8 {
        return None;
    }
    if !out.iter().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    String::from_utf8(out).ok()
}

pub struct AliyunIntel {
    pub keys: SessionKeys,
    pub access_sec: [u8; 16],
    pub iv: [u8; 16],
    pub aaduane_id: String,
    pub ak_secret: String,
    pub web_key: [u8; 16],
    pub app_key: String,
    pub app_version: String,
    pub api_version: String,
    pub cloudauth_version: String,
    pub platform: String,
    pub app_name: String,
}

pub fn extract_aliyun(src: &str) -> Result<AliyunIntel, String> {
    let a = ast::analyze_src(src).map_err(|e| format!("aliyun: {}", e))?;
    let mut blobs: Vec<String> = a
        .strings
        .iter()
        .filter(|s| shape_blob(s))
        .cloned()
        .collect();
    blobs.sort();
    blobs.dedup();
    if blobs.len() < 5 {
        return Err(format!("aliyun: блобов {}, надо >=5", blobs.len()));
    }

    let aes_iv_hex = a
        .config_pairs
        .iter()
        .find(|(k, _)| k == "AES_IV")
        .map(|(_, v)| v.clone())
        .ok_or("aliyun: AES_IV не найден в конфиге")?;
    let iv = {
        let mut bytes = Vec::with_capacity(aes_iv_hex.len() / 2);
        let hb = aes_iv_hex.as_bytes();
        let mut i = 0;
        while i + 1 < hb.len() {
            let hi = (hb[i] as char).to_digit(16).ok_or("aliyun: AES_IV не hex")?;
            let lo = (hb[i + 1] as char).to_digit(16).ok_or("aliyun: AES_IV не hex")?;
            bytes.push((hi * 16 + lo) as u8);
            i += 2;
        }
        let iv_b64 = crate::crypto::b64_encode(&bytes);
        let ib = iv_b64.as_bytes();
        if ib.len() != 16 {
            return Err("aliyun: AES_IV даёт IV != 16 байт".into());
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(ib);
        k
    };

    let mut sec_cands: Vec<[u8; 16]> = Vec::new();
    for s in &a.strings {
        let b = s.as_bytes();
        if b.len() == 16 && b.iter().all(|c| c.is_ascii_graphic()) {
            let mut k = [0u8; 16];
            k.copy_from_slice(b);
            sec_cands.push(k);
        }
    }

    let mut best: Option<([u8; 16], usize)> = None;
    for sec in &sec_cands {
        let n = blobs.iter().filter(|b| blob_to_key(b, sec, &iv).is_some()).count();
        if n >= 4 && best.as_ref().map(|(_, m)| n > *m).unwrap_or(true) {
            best = Some((*sec, n));
        }
    }
    let (sec, _n) = best.ok_or("aliyun: ACCESS_SEC не найден семантически")?;

    let mut roles: Vec<(String, [u8; 16])> = Vec::new();
    for (k, v) in &a.config_pairs {
        if matches!(k.as_str(), "REQ" | "RES" | "FLAG" | "UPLOAD" | "PREID") {
            if let Some(key) = blob_to_key(v, &sec, &iv) {
                roles.push((k.clone(), key));
            }
        }
    }
    let role = |name: &str| -> Option<[u8; 16]> {
        roles.iter().find(|(k, _)| k == name).map(|(_, v)| *v)
    };
    let vr = role("REQ").ok_or("aliyun: REQ")?;
    let hr = role("RES").ok_or("aliyun: RES")?;
    let flag = role("FLAG").ok_or("aliyun: FLAG")?;
    let upload = role("UPLOAD").ok_or("aliyun: UPLOAD")?;
    let preid = role("PREID").ok_or("aliyun: PREID")?;

    let mut web_key = None;
    for frags in &a.fragments {
        let joined: String = frags.iter().take(frags.len().saturating_sub(1)).cloned().collect();
        if let Some(k) = blob_to_key(&joined, &sec, &iv) {
            let known = roles.iter().any(|(_, v)| *v == k);
            if !known {
                web_key = Some(k);
            }
        }
    }
    let web_key = web_key.ok_or("aliyun: web-блоб (comma-фрагменты) не найден")?;

    let mut creds: Vec<(String, String)> = Vec::new();
    for (k, v) in &a.config_pairs {
        if (k == "ID" || k == "SECRET") && v.len() >= 40 && v.len() <= 80 {
            if let Some(plain) = cred_blob(v, &sec, &iv) {
                if plain.len() >= 16 && plain.len() <= 48 {
                    creds.push((k.clone(), plain));
                }
            }
        }
    }
    let aaduane_id = creds
        .iter()
        .find(|(k, _)| k == "ID")
        .map(|(_, v)| v.clone())
        .ok_or("aliyun: AaduaneId не расшифрован")?;
    let ak_secret = creds
        .iter()
        .find(|(k, _)| k == "SECRET")
        .map(|(_, v)| v.clone())
        .ok_or("aliyun: AccessKeySecret не расшифрован")?;

    let cfg = |name: &str| -> Option<String> {
        a.config_pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let cloudauth_version = cfg("API_VERSION").ok_or("aliyun: API_VERSION")?;
    let is_date = |v: &str| {
        v.len() == 10
            && v.as_bytes()[4] == b'-'
            && v.as_bytes()[7] == b'-'
            && v.bytes().filter(|b| *b == b'-').count() == 2
            && v.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    };
    let api_version = a
        .strings
        .iter()
        .filter(|s| is_date(s) && s.as_str() != cloudauth_version.as_str())
        .cloned()
        .next()
        .ok_or("aliyun: captcha API version (дата, отличная от cloudauth)")?;
    let _ = &api_version;
    let app_version = cfg("APP_VERSION").ok_or("aliyun: APP_VERSION")?;
    let platform = cfg("PLATFORM").ok_or("aliyun: PLATFORM")?;

    let mut app_key = None;
    for (k, v) in &a.config_pairs {
        if (k == "sgp" || k == "ga") && v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
            app_key = Some(v.clone());
        }
    }
    let app_key = app_key.ok_or("aliyun: appKey sgp не найден")?;
    let app_name = cfg("3.0")
        .or_else(|| cfg("2.0"))
        .ok_or("aliyun: appName (2.0/3.0) не найден")?;
    let app_name = if app_name == "saf-captcha" {
        app_name
    } else {
        cfg("APP_NAME").ok_or("aliyun: APP_NAME не найден")?
    };

    Ok(AliyunIntel {
        keys: SessionKeys { vr, hr, flag, upload, preid, web: web_key },
        access_sec: sec,
        iv,
        aaduane_id,
        ak_secret,
        web_key,
        app_key,
        app_version,
        api_version,
        cloudauth_version,
        platform,
        app_name,
    })
}

pub fn extract_feilin(src: &str, sec: &[u8; 16], iv: &[u8; 16]) -> Result<(String, String), String> {
    let a = ast::analyze_src(src).map_err(|e| format!("feilin: {}", e))?;
    let mut duanes: Vec<(String, String)> = Vec::new();
    for (k, v) in &a.config_pairs {
        if (k == "ID" || k == "SECRET") && v.len() >= 40 && v.len() <= 80 {
            if let Some(plain) = cred_blob(v, sec, iv) {
                if plain.len() >= 16 && plain.len() <= 48 {
                    duanes.push((k.clone(), plain));
                }
            }
        }
    }
    let duane = duanes
        .iter()
        .find(|(k, _)| k == "ID")
        .map(|(_, v)| v.clone())
        .ok_or("feilin: cloudauth AaduaneId не расшифрован")?;
    let secret = duanes
        .iter()
        .find(|(k, _)| k == "SECRET")
        .map(|(_, v)| v.clone())
        .ok_or("feilin: cloudauth secret не расшифрован")?;
    Ok((duane, secret))
}

enum PoolVal {
    Num(f64),
    Other,
}

fn array_values<'a>(arr: &oxc::ast::ast::ArrayExpression<'a>) -> Option<Vec<PoolVal>> {
    let mut out = Vec::with_capacity(arr.elements.len());
    for el in &arr.elements {
        match el {
            ArrayExpressionElement::NumericLiteral(n) => out.push(PoolVal::Num(n.value)),
            ArrayExpressionElement::StringLiteral(_) => out.push(PoolVal::Other),
            ArrayExpressionElement::NullLiteral(_) => out.push(PoolVal::Other),
            _ => return None,
        }
    }
    Some(out)
}

fn opcode_of_cond(semantic: &Semantic, c: &ConditionalExpression<'_>) -> Option<i64> {
    let t = match &c.test {
        Expression::BinaryExpression(b) => b,
        _ => return None,
    };
    if !matches!(
        t.operator,
        BinaryOperator::StrictEquality | BinaryOperator::Equality
    ) {
        return None;
    }
    match (&t.left, &t.right) {
        (Expression::NumericLiteral(n), Expression::Identifier(_)) => Some(n.value as i64),
        (Expression::Identifier(_), Expression::NumericLiteral(n)) => Some(n.value as i64),
        _ => None,
    }
}

pub fn has_load_marker_pub(e: &Expression<'_>) -> bool {
    fn is_postfix_member(u: &UpdateExpression<'_>) -> bool {
        !u.prefix
            && matches!(
                &u.argument,
                SimpleAssignmentTarget::AssignmentTargetIdentifier(_)
                    | SimpleAssignmentTarget::ComputedMemberExpression(_)
            )
    }
    fn walk(e: &Expression<'_>) -> bool {
        match e {
            Expression::ParenthesizedExpression(p) => walk(&p.expression),
            Expression::SequenceExpression(s) => {
                if s.expressions.len() < 2 {
                    return false;
                }
                let cursor = s.expressions.iter().any(|x| match x {
                    Expression::AssignmentExpression(a) => {
                        a.operator == AssignmentOperator::Assign
                            && match &a.right {
                                Expression::UpdateExpression(u) => is_postfix_member(u),
                                Expression::ComputedMemberExpression(cm) => {
                                    matches!(&cm.expression, Expression::UpdateExpression(u) if is_postfix_member(u))
                                }
                                _ => false,
                            }
                    }
                    _ => false,
                });
                if !cursor {
                    return false;
                }
                s.expressions.iter().any(|x| match x {
                    Expression::CallExpression(c) => {
                        if let Expression::StaticMemberExpression(m) = &c.callee {
                            if m.property.name.as_str() == "push" {
                                return c.arguments.iter().any(|a| {
                                    a.as_expression()
                                        .map(|g| matches!(g, Expression::ComputedMemberExpression(_)))
                                        .unwrap_or(false)
                                });
                            }
                        }
                        false
                    }
                    _ => false,
                })
            }
            Expression::ConditionalExpression(c) => {
                walk(&c.test) || walk(&c.consequent) || walk(&c.alternate)
            }
            _ => false,
        }
    }
    walk(e)
}

pub fn has_buildarr_marker_pub(e: &Expression<'_>) -> bool {
    fn unshift_pop(callee: &Expression<'_>) -> bool {
        match callee {
            Expression::StaticMemberExpression(m) => m.property.name.as_str() == "unshift",
            _ => false,
        }
    }
    fn walk(e: &Expression<'_>) -> bool {
        match e {
            Expression::ParenthesizedExpression(p) => walk(&p.expression),
            Expression::SequenceExpression(s) => s.expressions.iter().any(walk),
            Expression::CallExpression(c) => {
                if let Expression::StaticMemberExpression(m) = &c.callee {
                    if m.property.name.as_str() == "forEach" {
                        for a in &c.arguments {
                            if let Some(fe) = a.as_expression() {
                                if let Expression::FunctionExpression(f) = fe {
                                    if let Some(body) = &f.body {
                                        for st in &body.statements {
                                            if let Statement::ExpressionStatement(es) = st {
                                                if let Expression::CallExpression(ic) =
                                                    &es.expression
                                                {
                                                    if unshift_pop(&ic.callee) {
                                                        return true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                walk(&c.callee)
                    || c
                        .arguments
                        .iter()
                        .any(|a| a.as_expression().map(walk).unwrap_or(false))
            }
            Expression::ConditionalExpression(c) => {
                walk(&c.test) || walk(&c.consequent) || walk(&c.alternate)
            }
            _ => false,
        }
    }
    walk(e)
}

#[derive(Clone)]
struct VmOpcodes {
    load: i64,
    buildarr: i64,
}

fn bytecode_of(semantic: &Semantic) -> Vec<i64> {
    let mut best: Vec<i64> = Vec::new();
    for node in semantic.nodes().iter() {
        if let AstKind::ArrayExpression(arr) = node.kind() {
            if arr.elements.len() <= best.len() {
                continue;
            }
            let mut ops = Vec::with_capacity(arr.elements.len());
            let mut ok = true;
            for el in &arr.elements {
                match el {
                    ArrayExpressionElement::NumericLiteral(n) => {
                        if n.value.fract() != 0.0 {
                            ok = false;
                            break;
                        }
                        ops.push(n.value as i64);
                    }
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok && ops.len() > best.len() {
                best = ops;
            }
        }
    }
    best
}
fn vm_all_pairs(semantic: &Semantic) -> Vec<VmOpcodes> {
    let nodes: Vec<AstKind> = semantic.nodes().iter().map(|n| n.kind()).collect();
    let mut roots: Vec<(u32, u32)> = Vec::new();
    for n in &nodes {
        if let AstKind::ConditionalExpression(c) = n {
            if has_buildarr_marker_pub(&c.consequent) {
                roots.push((c.span.start, c.span.end));
            }
        }
    }
    let mut out: Vec<VmOpcodes> = Vec::new();
    for (rs, re) in roots {
        let mut best_root = (rs, re);
        for n in &nodes {
            if let AstKind::ConditionalExpression(c) = n {
                if c.span.start < rs && c.span.end > re {
                    best_root = (c.span.start, c.span.end);
                }
            }
        }
        let (bs, be) = best_root;
        let mut load_op: Option<i64> = None;
        let mut barr_op: Option<i64> = None;
        let mut count = 0usize;
        for n in &nodes {
            if let AstKind::ConditionalExpression(c) = n {
                if c.span.start >= bs && c.span.end <= be {
                    count += 1;
                    if let Some(op) = opcode_of_cond(semantic, c) {
                        if has_load_marker_pub(&c.consequent) && load_op.is_none() {
                            load_op = Some(op);
                        }
                        if has_buildarr_marker_pub(&c.consequent) && barr_op.is_none() {
                            barr_op = Some(op);
                        }
                    }
                }
            }
        }
        if let (Some(l), Some(b)) = (load_op, barr_op) {
            if l != b && count >= 8 {
                out.push(VmOpcodes { load: l, buildarr: b });
            }
        }
    }
    out
}

fn pool_min_len(bytecode: &[i64], load: i64, buildarr: i64) -> Option<usize> {
    let n = bytecode.len();
    let mut best: Option<usize> = None;
    let mut i = 0usize;
    while i + 1 < n {
        if bytecode[i] == buildarr {
            let cnt = bytecode[i + 1];
            if cnt >= 2 && (cnt as usize) * 2 <= i {
                let mut c = 0usize;
                let mut j = i;
                while j >= 2 && c < cnt as usize && bytecode[j - 2] == load {
                    c += 1;
                    j -= 2;
                }
                if c == cnt as usize {
                    match best {
                        Some(b) if b >= c => {}
                        _ => best = Some(c),
                    }
                }
            }
        }
        i += 1;
    }
    best
}

pub fn extract_r_table(src: &str) -> Result<[u8; 64], String> {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, src, SourceType::cjs()).parse();
    if ret.diagnostics.len() > 3 {
        return Err("pe: parse".into());
    }
    let program = ret.program;
    let sem = oxc::semantic::SemanticBuilder::new()
        .with_check_syntax_error(false)
        .with_build_nodes(true)
        .build(&program)
        .semantic;
    let bc = bytecode_of(&sem);
    let pairs = vm_all_pairs(&sem);
    let vm = pairs
        .iter()
        .filter_map(|p| pool_min_len(&bc, p.load, p.buildarr).map(|l| (l, p)))
        .max_by_key(|(l, _)| *l)
        .map(|(_, p)| p.clone())
        .ok_or("pe: VM-пара с run в байткоде не найдена")?;
    let arr_len = pool_min_len(&bc, vm.load, vm.buildarr)
        .ok_or("pe: run load+buildarr в байткоде не найден")?;
    let mut pools: Vec<Vec<PoolVal>> = Vec::new();
    let mut codes: Vec<Vec<i64>> = Vec::new();
    for node in sem.nodes().iter() {
        if let AstKind::ArrayExpression(arr) = node.kind() {
            if arr.elements.len() < 30 {
                continue;
            }
            let Some(vals) = array_values(arr) else {
                continue;
            };
            let all_num = vals.iter().all(|v| matches!(v, PoolVal::Num(_)));
            if all_num {
                let ops: Vec<i64> = vals
                    .iter()
                    .filter_map(|v| match v {
                        PoolVal::Num(n) if n.fract() == 0.0 => Some(*n as i64),
                        _ => None,
                    })
                    .collect();
                if ops.len() >= 30 {
                    codes.push(ops);
                }
            } else {
                pools.push(vals);
            }
        }
    }
    let load = |v: &PoolVal| -> Option<i64> {
        match v {
            PoolVal::Num(n) if n.fract() == 0.0 => Some(*n as i64),
            _ => None,
        }
    };
    for code in &codes {
        let ops = code;
        let n = ops.len();
        let mut i = 0usize;
        while i + 1 < n {
            if ops[i] == vm.buildarr {
                let cnt = ops[i + 1];
                if cnt >= arr_len as i64 && cnt as usize <= i / 2 + 1 {
                    let mut loads: Vec<i64> = Vec::with_capacity(cnt as usize);
                    let mut j = i;
                    while j >= 2 && loads.len() < cnt as usize && ops[j - 2] == vm.load {
                        loads.push(ops[j - 1]);
                        j -= 2;
                    }
                    if loads.len() == cnt as usize {
                        loads.reverse();
                        for pool in &pools {
                            if loads
                                .iter()
                                .any(|&ix| ix < 0 || ix as usize >= pool.len())
                            {
                                continue;
                            }
                            let table: Vec<i64> = loads
                                .iter()
                                .filter_map(|&ix| load(&pool[ix as usize]))
                                .collect();
                            if table.len() == loads.len()
                                && table
                                    .iter()
                                    .all(|&v| (0..=255).contains(&v))
                                && table
                                    .iter()
                                    .collect::<std::collections::HashSet<_>>()
                                    .len()
                                    == table.len()
                                && table.len() >= arr_len
                            {
                                let mut out = [0u8; 64];
                                let l = table.len().min(64);
                                for (o, t) in out.iter_mut().take(l).zip(table.iter()) {
                                    *o = *t as u8;
                                }
                                return Ok(out);
                            }
                        }
                    }
                }
            }
            i += 1;
        }
    }
    Err("pe: R-таблица (структурный run load+buildarr) не найдена".into())
}

pub struct IntelLoad {
    pub aliyun: String,
    pub pe: String,
    pub feilin: String,
}

pub fn extract(load: &IntelLoad) -> Result<Intel, String> {
    let al = extract_aliyun(&load.aliyun)?;
    let (cloudauth_duane, cloudauth_secret) = extract_feilin(&load.feilin, &al.access_sec, &al.iv)?;
    let r_table = extract_r_table(&load.pe)?;
    Ok(Intel {
        access_sec: al.access_sec,
        iv: al.iv,
        keys: al.keys,
        aaduane_id: al.aaduane_id,
        ak_secret: al.ak_secret,
        cloudauth_duane,
        cloudauth_secret,
        cloudauth_version: al.cloudauth_version,
        app_key: al.app_key,
        app_version: al.app_version,
        api_version: al.api_version,
        platform: al.platform,
        app_name: al.app_name,
        r_table,
        web_key: al.web_key,
        feilin_version: String::new(),
        feilin_url: String::new(),
    })
}
