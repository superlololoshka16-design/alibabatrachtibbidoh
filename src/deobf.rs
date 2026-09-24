use crate::ast;
use oxc::allocator::Allocator;
use oxc::ast::ast::*;
use oxc::ast::AstKind;
use oxc::parser::Parser;
use oxc::semantic::{Semantic, SemanticBuilder};
use oxc::span::GetSpan;
use std::collections::HashMap;

fn strip_p<'a, 'e>(e: &'e Expression<'a>) -> &'e Expression<'a> {
    match e {
        Expression::ParenthesizedExpression(p) => strip_p(&p.expression),
        _ => e,
    }
}

fn truthy_js(v: &f64) -> bool {
    *v != 0.0 && !v.is_nan()
}

fn num_lit(e: &Expression) -> Option<f64> {
    match strip_p(e) {
        Expression::NumericLiteral(n) => Some(n.value),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            match strip_p(&u.argument) {
                Expression::NumericLiteral(n) => Some(-n.value),
                _ => None,
            }
        }
        _ => None,
    }
}

fn bin_eval(op: BinaryOperator, a: f64, b: f64) -> Option<f64> {
    use BinaryOperator::*;
    Some(match op {
        Addition => a + b,
        Subtraction => a - b,
        Multiplication => a * b,
        Division => a / b,
        Remainder => a % b,
        Exponential => a.powf(b),
        BitwiseAnd => ((a as i32) & (b as i32)) as f64,
        BitwiseOR => ((a as i32) | (b as i32)) as f64,
        BitwiseXOR => ((a as i32) ^ (b as i32)) as f64,
        ShiftLeft => ((a as i32).wrapping_shl(b as u32 & 31)) as f64,
        ShiftRight => ((a as i32).wrapping_shr(b as u32 & 31)) as f64,
        ShiftRightZeroFill => ((a as u32).wrapping_shr(b as u32 & 31)) as f64,
        Equality => ((a == b) || (a.is_nan() && b.is_nan())) as i32 as f64,
        Inequality => !((a == b) || (a.is_nan() && b.is_nan())) as i32 as f64,
        StrictEquality => (a == b) as i32 as f64,
        StrictInequality => (a != b) as i32 as f64,
        LessThan => (a < b) as i32 as f64,
        LessEqualThan => (a <= b) as i32 as f64,
        GreaterThan => (a > b) as i32 as f64,
        GreaterEqualThan => (a >= b) as i32 as f64,
        _ => return None,
    })
}

fn bin_str(op: BinaryOperator, a: &str, b: &str) -> Option<f64> {
    use BinaryOperator::*;
    Some(match op {
        Addition => return None,
        Equality => (a == b) as i32 as f64,
        Inequality => (a != b) as i32 as f64,
        StrictEquality => (a == b) as i32 as f64,
        StrictInequality => (a != b) as i32 as f64,
        LessThan => (a < b) as i32 as f64,
        LessEqualThan => (a <= b) as i32 as f64,
        GreaterThan => (a > b) as i32 as f64,
        GreaterEqualThan => (a >= b) as i32 as f64,
        _ => return None,
    })
}

fn bin_bool(op: BinaryOperator, a: bool, b: bool) -> Option<f64> {
    use BinaryOperator::*;
    Some(match op {
        Equality => (a == b) as i32 as f64,
        Inequality => (a != b) as i32 as f64,
        StrictEquality => (a == b) as i32 as f64,
        StrictInequality => (a != b) as i32 as f64,
        _ => return None,
    })
}

#[derive(Clone, Debug)]
enum JVal {
    Num(f64),
    Str(String),
    Bool(bool),
}

fn eval_pure(e: &Expression) -> Option<JVal> {
    match strip_p(e) {
        Expression::NumericLiteral(n) => Some(JVal::Num(n.value)),
        Expression::StringLiteral(s) => Some(JVal::Str(s.value.to_string())),
        Expression::BooleanLiteral(b) => Some(JVal::Bool(b.value)),
        Expression::NullLiteral(_) => None,
        Expression::UnaryExpression(u) => {
            let a = eval_pure(&u.argument)?;
            match u.operator {
                UnaryOperator::LogicalNot => Some(JVal::Bool(match a {
                    JVal::Num(v) => !truthy_js(&v),
                    JVal::Str(s) => s.is_empty(),
                    JVal::Bool(b) => !b,
                })),
                UnaryOperator::UnaryNegation => Some(JVal::Num(match a {
                    JVal::Num(v) => -v,
                    _ => return None,
                })),
                UnaryOperator::UnaryPlus => Some(JVal::Num(match a {
                    JVal::Num(v) => v,
                    JVal::Bool(b) => if b { 1.0 } else { 0.0 },
                    _ => return None,
                })),
                UnaryOperator::BitwiseNot => Some(JVal::Num(match a {
                    JVal::Num(v) => !(v as i32) as f64,
                    _ => return None,
                })),
                _ => None,
            }
        }
        Expression::BinaryExpression(b) => {
            let l = eval_pure(&b.left)?;
            let r = eval_pure(&b.right)?;
            match (l, r) {
                (JVal::Num(a), JVal::Num(c)) => bin_eval(b.operator, a, c).map(JVal::Num),
                (JVal::Str(a), JVal::Str(c)) => {
                    if matches!(b.operator, BinaryOperator::Addition) {
                        return None;
                    }
                    bin_str(b.operator, &a, &c).map(JVal::Num)
                }
                (JVal::Bool(a), JVal::Bool(c)) => bin_bool(b.operator, a, c).map(JVal::Num),
                _ => None,
            }
        }
        Expression::LogicalExpression(l) => {
            let lv = eval_pure(&l.left)?;
            let lt = match &lv {
                JVal::Num(v) => truthy_js(v),
                JVal::Str(s) => !s.is_empty(),
                JVal::Bool(b) => *b,
            };
            match l.operator {
                LogicalOperator::And => {
                    if lt {
                        eval_pure(&l.right)
                    } else {
                        Some(lv)
                    }
                }
                LogicalOperator::Or => {
                    if lt {
                        Some(lv)
                    } else {
                        eval_pure(&l.right)
                    }
                }
                _ => None,
            }
        }
        Expression::ConditionalExpression(c) => {
            let t = eval_pure(&c.test)?;
            let truth = match t {
                JVal::Num(v) => truthy_js(&v),
                JVal::Str(s) => !s.is_empty(),
                JVal::Bool(b) => b,
            };
            if truth {
                eval_pure(&c.consequent)
            } else {
                eval_pure(&c.alternate)
            }
        }
        Expression::SequenceExpression(s) => s.expressions.last().and_then(eval_pure),
        Expression::CallExpression(c) => eval_call_pure(c),
        _ => None,
    }
}

fn eval_call_pure(c: &CallExpression) -> Option<JVal> {
    if let Expression::StaticMemberExpression(m) = strip_p(&c.callee) {
        if let Expression::Identifier(idf) = strip_p(&m.object) {
            if idf.name.as_str() == "Math" {
                let num_of = |e: &Expression| -> Option<f64> {
                    match eval_pure(e)? {
                        JVal::Num(n) => Some(n),
                        JVal::Bool(b) => Some(if b { 1.0 } else { 0.0 }),
                        JVal::Str(_) => None,
                    }
                };
                let e0 = c.arguments.first().and_then(|a| a.as_expression()).map(num_of).flatten();
                let e1 = c.arguments.get(1).and_then(|a| a.as_expression()).map(num_of).flatten();
                let r = match m.property.name.as_str() {
                    "abs" => e0?.abs(),
                    "round" => e0?.round(),
                    "floor" => e0?.floor(),
                    "ceil" => e0?.ceil(),
                    "sqrt" => e0?.sqrt(),
                    "trunc" => e0?.trunc(),
                    "pow" => e0?.powf(e1?),
                    _ => return None,
                };
                return Some(JVal::Num(r));
            }

        }
    }
    if let Expression::Identifier(idf) = strip_p(&c.callee) {
        if idf.name.as_str() == "isNaN" {
            let v = match eval_pure(c.arguments.first()?.as_expression()?)? {
                JVal::Num(n) => n,
                JVal::Bool(b) => if b { 1.0 } else { 0.0 },
                JVal::Str(_) => return None,
            };
            return Some(JVal::Bool(v.is_nan()));
        }
    }
    None
}

fn render_val(v: &JVal) -> String {
    match v {
        JVal::Num(n) => {
            if *n == n.trunc() && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                format!("{}", n)
            }
        }
        JVal::Str(s) => format!("{:?}", s),
        JVal::Bool(b) => format!("{}", b),
    }
}

fn neg_mul(a: &Expression, b: &Expression) -> bool {
    // !x * !y или x*y где один !обёрнут
    let is_neg = |e: &Expression| matches!(strip_p(e), Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot);
    is_neg(a) || is_neg(b) || (is_neg(a) && is_neg(b))
}


fn is_isnan_not_arg(e: &Expression) -> Option<bool> {
    if let Expression::CallExpression(c) = strip_p(e) {
        let callee = match strip_p(&c.callee) {
            Expression::Identifier(idf) => idf.name.as_str() == "isNaN",
            Expression::StaticMemberExpression(m) => {
                let base_ok = matches!(strip_p(&m.object), Expression::Identifier(i) if i.name.as_str() == "Math");
                base_ok && m.property.name.as_str() == "isNaN"
            }
            _ => false,
        };
        if callee {
            let arg = c.arguments.first().and_then(|a| a.as_expression())?;
            let not_arg = matches!(strip_p(arg), Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot);
            if not_arg {
                return Some(false);
            }
            if let Expression::BinaryExpression(ib) = strip_p(arg) {
                if ib.operator == BinaryOperator::Multiplication {
                    let l_not = matches!(strip_p(&ib.left), Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot);
                    let r_not = matches!(strip_p(&ib.right), Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot);
                    if l_not && r_not {
                        return Some(false);
                    }
                }
            }
        }
    }
    None
}

fn is_pow_zero(e: &Expression) -> Option<bool> {
    if let Expression::CallExpression(c) = strip_p(e) {
        if let Expression::StaticMemberExpression(m) = strip_p(&c.callee) {
            if let Expression::Identifier(idf) = strip_p(&m.object) {
                if idf.name.as_str() == "Math" && m.property.name.as_str() == "pow" {
                    return num_lit(c.arguments.get(1)?.as_expression()?).map(|v| v == 0.0);
                }
            }
        }
    }
    None
}

fn is_opaque_true(e: &Expression) -> Option<bool> {
    // 1) Math.pow(<любое>, 0) → 1 → true
    if is_pow_zero(e) == Some(true) {
        return Some(true);
    }
    // 2) Math.abs(<произведение с !>) >= 0 → true
    if let Expression::BinaryExpression(b) = strip_p(e) {
        if matches!(b.operator, BinaryOperator::GreaterEqualThan | BinaryOperator::GreaterThan) {
            let ge = matches!(b.operator, BinaryOperator::GreaterEqualThan);
            let left_zero = num_lit(&b.left) == Some(0.0);
            let right_zero = num_lit(&b.right) == Some(0.0);
            if left_zero || right_zero {
                let other = if left_zero { &b.right } else { &b.left };
                if let Expression::CallExpression(c) = strip_p(other) {
                    if let Expression::StaticMemberExpression(m) = strip_p(&c.callee) {
                        if let Expression::Identifier(idf) = strip_p(&m.object) {
                            if idf.name.as_str() == "Math" && m.property.name.as_str() == "abs" {
                                let arg = c.arguments.first().and_then(|a| a.as_expression())?;
                                let is_mul = matches!(strip_p(arg), Expression::BinaryExpression(ib) if ib.operator == BinaryOperator::Multiplication);
                                let is_not = matches!(strip_p(arg), Expression::UnaryExpression(iu) if iu.operator == UnaryOperator::LogicalNot);
                                if is_mul || is_not {
                                    if left_zero {
                                        return Some(ge);
                                    } else if right_zero {
                                        return Some(ge);
                                    } else {
                                        return Some(true);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if matches!(b.operator, BinaryOperator::GreaterEqualThan) {
            if num_lit(&b.right) == Some(0.0) {
                if let Expression::CallExpression(c) = strip_p(&b.left) {
                    if let Expression::StaticMemberExpression(m) = strip_p(&c.callee) {
                        if let Expression::Identifier(idf) = strip_p(&m.object) {
                            if idf.name.as_str() == "Math" && m.property.name.as_str() == "abs" {
                                let arg = c.arguments.first().and_then(|a| a.as_expression())?;
                                if let Expression::BinaryExpression(inner) = strip_p(arg) {
                                    if inner.operator == BinaryOperator::Multiplication {
                                        return Some(true);
                                    }
                                }
                                if matches!(strip_p(arg), Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot) {
                                    return Some(true);
                                }
                            }
                        }
                    }
                }
            }
        }
        // 3a) <expr> / 0 == <не-ноль> → false (inf/nan никогда не равно числу)
        if matches!(b.operator, BinaryOperator::Equality | BinaryOperator::StrictEquality) {
            if num_lit(&b.right).is_some() && num_lit(&b.right) != Some(0.0) {
                if let Expression::BinaryExpression(inner) = strip_p(&b.left) {
                    if inner.operator == BinaryOperator::Division && num_lit(&inner.right) == Some(0.0) {
                        return Some(false);
                    }
                }
            }
        }
        // 3) 0 * <что угодно> == <не-ноль> → false
        if matches!(b.operator, BinaryOperator::Equality | BinaryOperator::StrictEquality) {
            if num_lit(&b.right).is_some() && num_lit(&b.right) != Some(0.0) {
                if let Expression::BinaryExpression(inner) = strip_p(&b.left) {
                    if inner.operator == BinaryOperator::Multiplication && num_lit(&inner.left) == Some(0.0) {
                        return Some(false);
                    }
                }
            }
        }
    }
    // 4) isNaN(!x) / isNaN(!x*!y) → false
    if let Some(v) = is_isnan_not_arg(e) {
        return Some(v);
    }
    // 5) isNaN(x/x) || x/x == 1 → true (обфускаторская тавтология)
    if let Expression::LogicalExpression(l) = strip_p(e) {
        if l.operator == LogicalOperator::Or {
            let lt = is_opaque_true(&l.left);
            if lt == Some(false) {
                return is_opaque_true(&l.right);
            }
            return lt;
        }
        if l.operator == LogicalOperator::And {
            let lt = is_opaque_true(&l.left);
            if lt == Some(true) {
                return is_opaque_true(&l.right);
            }
            return lt;
        }
    }
    // чистая математика над константами
    let v = eval_pure(e)?;
    match v {
        JVal::Num(n) => Some(truthy_js(&n)),
        JVal::Bool(b) => Some(b),
        JVal::Str(s) => Some(!s.is_empty()),
    }
}

pub fn rewrite_cff(source: &str) -> Result<(String, usize, usize), String> {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, SourceType::cjs()).parse();
    if ret.diagnostics.len() > 3 {
        return Err(format!("parse errors: {}", ret.diagnostics.len()));
    }
    let program = ret.program;
    let sem_ret = SemanticBuilder::new()
        .with_check_syntax_error(false)
        .with_build_nodes(true)
        .build(&program);
    let semantic = sem_ret.semantic;

    let mut opaque_removed = 0usize;
    let mut cff_removed = 0usize;
    let mut edits: Vec<(u32, u32, String)> = Vec::new();

    // 1) opaque-предикаты: ConditionalExpression с константным тестом
    for node in semantic.nodes().iter() {
        if let AstKind::ConditionalExpression(c) = node.kind() {
            if let Some(t) = is_opaque_true(&c.test) {
                let pick = if t { &c.consequent } else { &c.alternate };
                let ps = pick.span();
                if (ps.end as usize) <= source.len() {
                    let txt = source[ps.start as usize..ps.end as usize].to_string();
                    let sp = c.span;
                    edits.push((sp.start, sp.end, txt));
                    opaque_removed += 1;
                }
            }
        }
        if let AstKind::LogicalExpression(l) = node.kind() {
            if let Some(lt) = is_opaque_true(&l.left) {
                // left константно-истинно/ложно: OR берёт left/right, AND аналогично
                let pick = match l.operator {
                    LogicalOperator::Or => {
                        if lt { &l.left } else { &l.right }
                    }
                    LogicalOperator::And => {
                        if lt { &l.right } else { &l.left }
                    }
                    _ => continue,
                };
                let ps = pick.span();
                if (ps.end as usize) <= source.len() {
                    let txt = source[ps.start as usize..ps.end as usize].to_string();
                    let sp = l.span;
                    edits.push((sp.start, sp.end, txt));
                    opaque_removed += 1;
                }
            }
        }
    }

    // CFF-фаза вынесена отдельно: rewrite_cff_pass
    edits.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    let mut out = source.to_string();
    let mut applied_start: Option<u32> = None;
    for (s, e, r) in edits {
        if s > e {
            continue;
        }
        if let Some(as_) = applied_start {
            if e > as_ {
                continue;
            }
        }
        if (e as usize) <= out.len() && (s as usize) <= out.len() {
            out.replace_range(s as usize..e as usize, r.as_str());
            applied_start = Some(s);
        }
    }
    Ok((out, opaque_removed, cff_removed))
}


pub fn rewrite_fixpoint(source: &str, rounds: usize) -> Result<(String, usize, usize), String> {
    let mut cur = source.to_string();
    let mut total_opaque = 0usize;
    let mut total_cff = 0usize;
    for _ in 0..rounds {
        let (next, o) = crate::emit::opaque_fold_pass(&cur)?;
        let (next2, c) = crate::emit::cff_emit_pass(&next)?;
        if o == 0 && c == 0 {
            break;
        }
        total_opaque += o;
        total_cff += c;
        cur = next2;
    }
    Ok((cur, total_opaque, total_cff))
}
pub fn deobfuscate_full(path: &str) -> Result<String, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
    let analysis = ast::analyze_src(&src)?;
    let patched = apply_edits(&src, &analysis.edits);
    let pretty = pretty_print(&patched)?;
    if std::env::var("ZAIC_DEOBF_DEBUG").is_ok() {
        eprintln!("[full] после строк: {}B", pretty.len());
    }
    let (full, o, c) = rewrite_fixpoint(&pretty, 8)?;
    if std::env::var("ZAIC_DEOBF_DEBUG").is_ok() {
        eprintln!("[full] после rewrite: {}B (opaque={}, cff={})", full.len(), o, c);
    }
    // подстановка лямбда-таблиц ep.X(a,b) → (a OP b)
    let (subst, n_sub) = crate::subst::substitute_lambdas_fixpoint(&full, 12)?;
    if std::env::var("ZAIC_DEOBF_DEBUG").is_ok() {
        eprintln!("[full] после subst: {}B (лямбд={})", subst.len(), n_sub);
    }
    let full_pretty = pretty_print(&subst)?;
    let full_pretty = if full_pretty.is_empty() { pretty_print(&full)? } else { full_pretty };
    Ok(full_pretty)
}

pub fn apply_edits(source: &str, edits: &[(u32, u32, String)]) -> String {
    let mut out = source.to_string();
    let mut es: Vec<&(u32, u32, String)> = edits.iter().collect();
    es.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    let mut applied_start: Option<u32> = None;
    for (s, e, r) in es {
        if s > e {
            continue;
        }
        if let Some(as_) = applied_start {
            if *e > as_ {
                continue;
            }
        }
        if (*e as usize) <= out.len() && (*s as usize) <= out.len() {
            out.replace_range(*s as usize..*e as usize, r);
            applied_start = Some(*s);
        }
    }
    fix_joins(&mut out);
    out
}

fn fix_joins(s: &mut String) {
    const KW: [&str; 27] = [
        "function", "var", "let", "const", "if", "for", "while", "do", "switch", "try", "return",
        "throw", "class", "new", "typeof", "void", "delete", "this", "null", "true", "false", "in",
        "of", "instanceof", "async", "await", "yield",
    ];
    for kw in KW {
        let pats: [(&str, usize); 2] = [("0", 1), ("[]", 2)];
        for (prefix, plen) in pats {
            let p = format!("{}{}", prefix, kw);
            let mut from = 0usize;
            while let Some(pos) = s[from..].find(&p) {
                let at = from + pos;
                let after = at + p.len();
                let next_ok = s[after..]
                    .chars()
                    .next()
                    .map(|c| !(c.is_alphanumeric() || c == '_' || c == '$'))
                    .unwrap_or(true);
                if next_ok {
                    s.insert_str(at + plen, ";");
                    from = at + p.len() + 1;
                } else {
                    from = at + 1;
                }
            }
        }
    }
}

pub fn pretty_print(src: &str) -> Result<String, String> {
    let allocator = oxc::allocator::Allocator::default();
    let ret = oxc::parser::Parser::new(&allocator, src, oxc::span::SourceType::cjs()).parse();
    if !ret.diagnostics.is_empty() {
        if std::env::var("ZAIC_DEOBF_DEBUG").is_ok() {
            for d in ret.diagnostics.iter().take(5) {
                eprintln!("[pretty] diag: {:?}", d);
            }
        }
        // 2 известных диагностик-хвоста от dead-code вставок — пропускаем если правки малы
    }
    let program = ret.program;
    let printed = oxc::codegen::Codegen::new()
        .with_options(oxc::codegen::CodegenOptions {
            minify: false,
            ..Default::default()
        })
        .build(&program);
    if printed.code.is_empty() && !src.is_empty() {
        return Ok(src.to_string());
    }
    Ok(printed.code)
}

pub fn deobfuscate_file(path: &str) -> Result<String, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
    let analysis = ast::analyze_src(&src)?;
    let patched = apply_edits(&src, &analysis.edits);
    let pretty = pretty_print(&patched)?;
    Ok(pretty)
}
