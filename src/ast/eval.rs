use oxc::ast::ast::*;
use oxc::ast::AstKind;
use oxc::syntax::node::NodeId;
use oxc::syntax::symbol::SymbolId;

use super::{ref_symbol, Ctx, Target, Val};

enum Callable {
    Target(Target),
    BindFn(Target, Vec<Val>),
    ParseInt,
    Number,
    Round,
    Floor,
    Ceil,
    Abs,
    Pow,
    ValueOf(Val),
}

pub fn eval_test(ctx: &Ctx, e: &Expression) -> Val {
    eval_expr(ctx, e)
}

pub fn eval_call_node(ctx: &Ctx, call: &CallExpression) -> Option<Val> {
    if std::env::var("ZAIC_TRACE").is_ok() && call.span.start >= 172400 && call.span.start <= 172700 {
        eprintln!("[trace] вызов @{}: {}", call.span.start, &ctx.source[call.span.start as usize..(call.span.end as usize).min(ctx.source.len()).min(call.span.start as usize + 60)]);
        if call.span.start == 172635 {
            let resolved = resolve_callable_and_args(ctx, &call.callee, &call.arguments);
            let name = match &call.callee { e => format!("{:?}", std::mem::discriminant(e)) };
            eprintln!("[trace] @172635 variant={} resolved={}", name, resolved.is_some());
        }
    }
    if let Val::BoundFn { target, pre } = eval_expr(ctx, &call.callee) {
        let mut args = pre;
        for a in &call.arguments {
            if let Some(e) = a.as_expression() {
                args.push(eval_expr(ctx, e));
            }
        }
        return dispatch_target(ctx, &target, &args, 0);
    }
    let (c, args) = match resolve_callable_and_args(ctx, &call.callee, &call.arguments) {
        Some(x) => x,
        None => (resolve_member_base(ctx, &call.callee)?, eval_args(ctx, &call.arguments)),
    };
    dispatch(ctx, c, &args)
}

fn eval_args(ctx: &Ctx, args: &[Argument]) -> Vec<Val> {
    args.iter()
        .filter_map(|a| a.as_expression().map(|e| eval_expr(ctx, e)))
        .collect()
}

fn resolve_callable_and_args(
    ctx: &Ctx,
    callee: &Expression,
    args: &[Argument],
) -> Option<(Callable, Vec<Val>)> {
    match callee {
        Expression::Identifier(idf) => {
            if let Some(sym) = ref_symbol(ctx, idf.reference_id.get()) {
                if let Some(p) = ctx.builtin_paths.get(&sym) {
                    if let Some(c) = builtin_callable(p) {
                        return Some((c, eval_args(ctx, args)));
                    }
                }
                let t = super::scan::symbol_target(ctx, sym)?;
                return Some((Callable::Target(t), eval_args(ctx, args)));
            }
            match idf.name.as_str() {
                "parseInt" => Some((Callable::ParseInt, eval_args(ctx, args))),
                "Number" => Some((Callable::Number, eval_args(ctx, args))),
                _ => None,
            }
        }
        Expression::SequenceExpression(s) => {
            let last = s.expressions.last()?;
            resolve_callable_and_args(ctx, last, args)
        }
        Expression::ConditionalExpression(c) => {
            let t = eval_expr(ctx, &c.test).truthy()?;
            let pick = if t { &c.consequent } else { &c.alternate };
            resolve_callable_and_args(ctx, pick, args)
        }
        Expression::LogicalExpression(l) => {
            let lt = eval_expr(ctx, &l.left).truthy()?;
            let pick = if lt { &l.right } else { &l.left };
            resolve_callable_and_args(ctx, pick, args)
        }
        Expression::ParenthesizedExpression(p) => {
            resolve_callable_and_args(ctx, &p.expression, args)
        }
        Expression::StaticMemberExpression(m) => match m.property.name.as_str() {
            "call" => {
                let base = resolve_member_base(ctx, &m.object)?;
                let vals: Vec<Val> = args
                    .iter()
                    .skip(1)
                    .filter_map(|a| a.as_expression().map(|e| eval_expr(ctx, e)))
                    .collect();
                Some((base, vals))
            }
            "apply" => {
                let base = resolve_member_base(ctx, &m.object)?;
                let mut vals = Vec::new();
                if let Some(Argument::ArrayExpression(arr)) = args.get(1) {
                    for el in &arr.elements {
                        if let Some(e) = el.as_expression() {
                            vals.push(eval_expr(ctx, e));
                        }
                    }
                }
                Some((base, vals))
            }
            "bind" => {
                let base = resolve_member_base(ctx, &m.object)?;
                let target = match base {
                    Callable::Target(t) => t,
                    _ => return None,
                };
                let pre: Vec<Val> = args
                    .iter()
                    .skip(1)
                    .filter_map(|a| a.as_expression().map(|e| eval_expr(ctx, e)))
                    .collect();
                Some((Callable::BindFn(target, pre), Vec::new()))
            }
            "valueOf" => {
                let v = eval_expr(ctx, &m.object);
                if matches!(v, Val::Num(_) | Val::Str(_)) {
                    Some((Callable::ValueOf(v), Vec::new()))
                } else {
                    None
                }
            }
            _ => None,
        },
        Expression::ComputedMemberExpression(cm) => {
            let obj = match &cm.object {
                Expression::ParenthesizedExpression(p) => &p.expression,
                o => o,
            };
            let idx = match &cm.expression {
                Expression::ParenthesizedExpression(p) => &p.expression,
                i => i,
            };
            let pick = match obj {
                Expression::ObjectExpression(o) => {
                    let mut hit = None;
                    for p in &o.properties {
                        if let ObjectPropertyKind::ObjectProperty(prop) = p {
                            let k0 = match &prop.key {
                                PropertyKey::NumericLiteral(n) => n.value as i64 == 0,
                                PropertyKey::StringLiteral(s) => s.value == "0",
                                _ => false,
                            };
                            if k0 {
                                hit = Some(&prop.value);
                                break;
                            }
                        }
                    }
                    hit
                }
                Expression::ArrayExpression(arr) => {
                    let mut hit = None;
                    for el in &arr.elements {
                        if let Some(e) = el.as_expression() {
                            hit = Some(e);
                            break;
                        }
                    }
                    hit
                }
                _ => None,
            };
            let idx_ok = matches!(idx, Expression::NumericLiteral(_))
                || match super::eval::eval_expr(ctx, idx) {
                    Val::Num(n) if n.fract() == 0.0 => true,
                    _ => false,
                };
            match (pick, idx_ok) {
                (Some(e), true) => resolve_callable_and_args(ctx, e, args),
                _ => None,
            }
        }
        _ => None,
    }
}

fn resolve_member_base(ctx: &Ctx, obj: &Expression) -> Option<Callable> {
    match obj {
        Expression::Identifier(idf) => {
            if let Some(sym) = ref_symbol(ctx, idf.reference_id.get()) {
                if let Some(p) = ctx.builtin_paths.get(&sym) {
                    if let Some(c) = builtin_callable(p) {
                        return Some(c);
                    }
                }
                let t = super::scan::symbol_target(ctx, sym)?;
                return Some(Callable::Target(t));
            }
            match idf.name.as_str() {
                "parseInt" => Some(Callable::ParseInt),
                "Number" => Some(Callable::Number),
                _ => None,
            }
        }
        Expression::StaticMemberExpression(m) => {
            if let Expression::Identifier(idf) = &m.object {
                if idf.name.as_str() == "Math" {
                    return match m.property.name.as_str() {
                        "round" => Some(Callable::Round),
                        "floor" => Some(Callable::Floor),
                        "ceil" => Some(Callable::Ceil),
                        "abs" => Some(Callable::Abs),
                        "pow" => Some(Callable::Pow),
                        _ => None,
                    };
                }
            }
            resolve_member_base(ctx, &m.object)
        }
        Expression::SequenceExpression(s) => resolve_member_base(ctx, s.expressions.last()?),
        Expression::ConditionalExpression(c) => {
            let t = eval_expr(ctx, &c.test).truthy()?;
            let pick = if t { &c.consequent } else { &c.alternate };
            resolve_member_base(ctx, pick)
        }
        Expression::LogicalExpression(l) => {
            let lt = eval_expr(ctx, &l.left).truthy()?;
            let pick = if lt { &l.right } else { &l.left };
            resolve_member_base(ctx, pick)
        }
        Expression::ParenthesizedExpression(p) => resolve_member_base(ctx, &p.expression),
        _ => None,
    }
}

fn dispatch(ctx: &Ctx, c: Callable, args: &[Val]) -> Option<Val> {
    match c {
        Callable::Target(t) => dispatch_target(ctx, &t, args, 0),
        Callable::BindFn(t, pre) => Some(Val::BoundFn { target: t, pre }),
        Callable::ParseInt => {
            let s = args.first()?.as_str()?;
            Some(Val::Num(js_parse_int(s)))
        }
        Callable::Number => Some(Val::Num(args.first().map(|v| v.to_num()).unwrap_or(0.0))),
        Callable::Round => Some(Val::Num(args.first()?.to_num().round())),
        Callable::Floor => Some(Val::Num(args.first()?.to_num().floor())),
        Callable::Ceil => Some(Val::Num(args.first()?.to_num().ceil())),
        Callable::Abs => Some(Val::Num(args.first()?.to_num().abs())),
        Callable::Pow => Some(Val::Num(args.first()?.to_num().powf(args.get(1)?.to_num()))),
        Callable::ValueOf(v) => Some(v),
    }
}

fn dispatch_target(ctx: &Ctx, target: &Target, args: &[Val], depth: u32) -> Option<Val> {
    if depth > 16 {
        return None;
    }
    match target {
        Target::Dec(idx) => {
            let d = ctx.decoders.get(*idx)?;
            let n = args.first()?.to_num();
            if !n.is_finite() {
                return None;
            }
            let xor = if d.xor_out {
                args.get(1).map(|v| v.to_num().trunc() as i64)
            } else {
                None
            };
            match d.decode(n.trunc() as i64, xor) {
                Some(v) => Some(Val::Str(v)),
                None => {
                    if std::env::var("ZAIC_DEBUG").is_ok() && (n.trunc() as i64) == 88 {
                        let idx = n.trunc() as i64 - d.shift;
                        let ent = d.table.borrow().get(idx as usize).cloned();
                        eprintln!("[dbg-decode] n={} xor={:?} idx={} запись={:?} alph_head={:?}", n, xor, idx, ent, d.lookup.iter().filter(|v| **v >= 0).count());
                    }
                    None
                }
            }
        }
        Target::Wrap(sym) => {
            let w = match ctx.wrapper_sym.get(sym) {
                Some(w) => w,
                None => {
                    if std::env::var("ZAIC_DEBUG").is_ok() {
                        eprintln!("[dbg-wrap] символ-обёртка не зарегистрирована: {:?}", ctx.semantic.scoping().symbol_name(*sym));
                    }
                    return None;
                }
            };
            let nums: Vec<f64> = args.iter().map(|v| v.to_num()).collect();
            let idx = w.index.eval(&nums);
            let mut next = vec![Val::Num(idx)];
            if let Some(x) = &w.xor {
                next.push(Val::Num(x.eval(&nums)));
            }
            dispatch_target(ctx, &w.target, &next, depth + 1)
        }
    }
}

fn js_parse_int(s: &str) -> f64 {
    let t = s.trim_start();
    let bytes = t.as_bytes();
    let mut i = 0;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return f64::NAN;
    }
    t[..i].parse::<f64>().unwrap_or(f64::NAN)
}

pub fn eval_expr(ctx: &Ctx, e: &Expression) -> Val {
    let nid = e.node_id();
    if let Some(v) = ctx.folded.get(&nid) {
        return v.clone();
    }
    eval_expr_inner(ctx, e)
}

fn eval_expr_inner(ctx: &Ctx, e: &Expression) -> Val {
    match e {
        Expression::NumericLiteral(l) => Val::Num(l.value),
        Expression::StringLiteral(s) => Val::Str(s.value.to_string()),
        Expression::BooleanLiteral(b) => Val::Bool(b.value),
        Expression::NullLiteral(_) => Val::Undefined,
        Expression::Identifier(idf) => eval_ident(ctx, idf),
        Expression::UnaryExpression(u) => eval_unary(ctx, u),
        Expression::BinaryExpression(b) => eval_binary(ctx, b),
        Expression::LogicalExpression(l) => {
            let left = eval_expr(ctx, &l.left);
            match l.operator {
                LogicalOperator::And => match left.truthy() {
                    Some(true) => eval_expr(ctx, &l.right),
                    Some(false) => left,
                    None => Val::Unknown,
                },
                LogicalOperator::Or => match left.truthy() {
                    Some(true) => left,
                    Some(false) => eval_expr(ctx, &l.right),
                    None => Val::Unknown,
                },
                _ => Val::Unknown,
            }
        }
        Expression::ConditionalExpression(c) => {
            match eval_expr(ctx, &c.test).truthy() {
                Some(true) => eval_expr(ctx, &c.consequent),
                Some(false) => eval_expr(ctx, &c.alternate),
                None => Val::Unknown,
            }
        }
        Expression::SequenceExpression(s) => s
            .expressions
            .last()
            .map(|e| eval_expr(ctx, e))
            .unwrap_or(Val::Undefined),
        Expression::AssignmentExpression(a) => eval_assign(ctx, a),
        Expression::CallExpression(c) => eval_call_node(ctx, c).unwrap_or(Val::Unknown),
        Expression::ComputedMemberExpression(c) => eval_computed_member(ctx, c),
        Expression::ParenthesizedExpression(p) => eval_expr(ctx, &p.expression),
        Expression::UpdateExpression(_) => Val::Unknown,
        _ => Val::Unknown,
    }
}

fn eval_ident(ctx: &Ctx, idf: &IdentifierReference) -> Val {
    if let Some(sym) = ref_symbol(ctx, idf.reference_id.get()) {
        if let Some(v) = ctx.seq_values.get(&sym) {
            return v.clone();
        }
        if let Some(v) = ctx.consts.get(&sym) {
            return v.clone();
        }
        if super::scan::symbol_target(ctx, sym).is_some() {
            return Val::Func;
        }
    }
    match idf.name.as_str() {
        "undefined" => Val::Undefined,
        "NaN" => Val::Num(f64::NAN),
        _ => Val::Unknown,
    }
}

fn eval_unary(ctx: &Ctx, u: &UnaryExpression) -> Val {
    let arg = eval_expr(ctx, &u.argument);
    match u.operator {
        UnaryOperator::LogicalNot => match arg.truthy() {
            Some(t) => Val::Bool(!t),
            None => Val::Unknown,
        },
        UnaryOperator::UnaryNegation => {
            if matches!(arg, Val::Unknown) {
                Val::Unknown
            } else {
                Val::Num(-arg.to_num())
            }
        }
        UnaryOperator::UnaryPlus => {
            if matches!(arg, Val::Unknown) {
                Val::Unknown
            } else {
                Val::Num(arg.to_num())
            }
        }
        UnaryOperator::BitwiseNot => {
            if matches!(arg, Val::Unknown) {
                Val::Unknown
            } else {
                Val::Num(!arg.to_int32() as f64)
            }
        }
        UnaryOperator::Void => Val::Undefined,
        UnaryOperator::Typeof => match arg {
            Val::Func | Val::BoundFn { .. } => Val::Str("function".into()),
            Val::Undefined => Val::Str("undefined".into()),
            Val::Num(_) => Val::Str("number".into()),
            Val::Str(_) => Val::Str("string".into()),
            Val::Bool(_) => Val::Str("boolean".into()),
            Val::Unknown => Val::Unknown,
        },
        _ => Val::Unknown,
    }
}

fn to_js_string(v: &Val) -> String {
    match v {
        Val::Str(s) => s.clone(),
        Val::Num(n) => {
            if n.is_nan() {
                "NaN".into()
            } else {
                super::fmt_num_pub(*n)
            }
        }
        Val::Bool(b) => b.to_string(),
        Val::Undefined => "undefined".into(),
        Val::Func | Val::BoundFn { .. } => "function".into(),
        _ => String::new(),
    }
}

fn eval_binary(ctx: &Ctx, b: &BinaryExpression) -> Val {
    let l = eval_expr(ctx, &b.left);
    let r = eval_expr(ctx, &b.right);
    if matches!(l, Val::Unknown) || matches!(r, Val::Unknown) {
        return Val::Unknown;
    }
    match b.operator {
        BinaryOperator::Addition => match (&l, &r) {
            (Val::Str(_), _) | (_, Val::Str(_)) => {
                Val::Str(format!("{}{}", to_js_string(&l), to_js_string(&r)))
            }
            _ => Val::Num(l.to_num() + r.to_num()),
        },
        BinaryOperator::Subtraction => Val::Num(l.to_num() - r.to_num()),
        BinaryOperator::Multiplication => Val::Num(l.to_num() * r.to_num()),
        BinaryOperator::Division => Val::Num(l.to_num() / r.to_num()),
        BinaryOperator::Remainder => Val::Num(l.to_num() % r.to_num()),
        BinaryOperator::Exponential => Val::Num(l.to_num().powf(r.to_num())),
        BinaryOperator::BitwiseAnd => Val::Num((l.to_int32() & r.to_int32()) as f64),
        BinaryOperator::BitwiseOR => Val::Num((l.to_int32() | r.to_int32()) as f64),
        BinaryOperator::BitwiseXOR => Val::Num((l.to_int32() ^ r.to_int32()) as f64),
        BinaryOperator::ShiftLeft => Val::Num(
            l.to_int32()
                .wrapping_shl(r.to_int32().rem_euclid(32) as u32) as f64,
        ),
        BinaryOperator::ShiftRight => Val::Num(
            l.to_int32()
                .wrapping_shr(r.to_int32().rem_euclid(32) as u32) as f64,
        ),
        BinaryOperator::ShiftRightZeroFill => Val::Num(
            (l.to_int32() as u32)
                .wrapping_shr(r.to_int32().rem_euclid(32) as u32) as f64,
        ),
        BinaryOperator::StrictEquality | BinaryOperator::Equality => Val::Bool(js_eq(&l, &r)),
        BinaryOperator::StrictInequality | BinaryOperator::Inequality => {
            Val::Bool(!js_eq(&l, &r))
        }
        BinaryOperator::LessThan => Val::Bool(l.to_num() < r.to_num()),
        BinaryOperator::LessEqualThan => Val::Bool(l.to_num() <= r.to_num()),
        BinaryOperator::GreaterThan => Val::Bool(l.to_num() > r.to_num()),
        BinaryOperator::GreaterEqualThan => Val::Bool(l.to_num() >= r.to_num()),
        _ => Val::Unknown,
    }
}

fn js_eq(l: &Val, r: &Val) -> bool {
    match (l, r) {
        (Val::Num(a), Val::Num(b)) => a == b,
        (Val::Str(a), Val::Str(b)) => a == b,
        (Val::Bool(a), Val::Bool(b)) => a == b,
        (Val::Undefined, Val::Undefined) => true,
        _ => l.to_num() == r.to_num() && !l.to_num().is_nan(),
    }
}

fn eval_assign(ctx: &Ctx, a: &AssignmentExpression) -> Val {
    match a.operator {
        AssignmentOperator::Assign => eval_expr(ctx, &a.right),
        AssignmentOperator::Addition => {
            let nid = a.node_id();
            if let Some(v) = ctx.assign_results.get(&nid) {
                return v.clone();
            }
            Val::Unknown
        }
        _ => Val::Unknown,
    }
}

fn eval_computed_member(ctx: &Ctx, c: &ComputedMemberExpression) -> Val {
    let idx = eval_expr(ctx, &c.expression);
    match &c.object {
        Expression::ArrayExpression(arr) => {
            if let Val::Num(i) = idx {
                if i >= 0.0 && i.fract() == 0.0 && (i as usize) < arr.elements.len() {
                    if let Some(e) = arr.elements[i as usize].as_expression() {
                        return eval_expr(ctx, e);
                    }
                }
            }
            Val::Unknown
        }
        Expression::ObjectExpression(obj) => {
            let key = match &idx {
                Val::Num(n) if n.fract() == 0.0 => format!("{}", *n as i64),
                Val::Str(s) => s.clone(),
                _ => return Val::Unknown,
            };
            for p in &obj.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = p {
                    let pk = match &p.key {
                        PropertyKey::StaticIdentifier(id) => id.name.as_str().to_string(),
                        PropertyKey::NumericLiteral(n) => format!("{}", n.value as i64),
                        PropertyKey::StringLiteral(s) => s.value.to_string(),
                        _ => continue,
                    };
                    if pk == key {
                        return eval_expr(ctx, &p.value);
                    }
                }
            }
            Val::Unknown
        }
        _ => Val::Unknown,
    }
}

pub fn scan_sequential(ctx: &mut Ctx) {
    use oxc::ast::AstKind;
    let kinds = all_kinds_pub(ctx);

    let mut assigns: Vec<(SymbolId, AssignmentOperator, NodeId, &Expression)> = Vec::new();
    for (id, kind) in kinds.iter().copied() {
        match kind {
            AstKind::AssignmentExpression(a) => {
                if let AssignmentTarget::AssignmentTargetIdentifier(idf) = &a.left {
                    if let Some(sym) = ref_symbol(ctx, idf.reference_id.get()) {
                        assigns.push((sym, a.operator, id, &a.right));
                    }
                }
            }
            AstKind::VariableDeclarator(d) => {
                let sym = match &d.id {
                    BindingPattern::BindingIdentifier(b) => {
                        ctx.span_sym.get(&b.span.start).copied()
                    }
                    _ => None,
                };
                if let (Some(init), Some(sym)) = (&d.init, sym) {
                    assigns.push((sym, AssignmentOperator::Assign, id, init));
                }
            }
            _ => {}
        }
    }

    for (sym, op, _nid, right) in assigns {
        let right_val = eval_expr(ctx, right);
        match op {
            AssignmentOperator::Assign => {
                if matches!(right_val, Val::Str(_) | Val::Num(_)) {
                    ctx.seq_values.insert(sym, right_val.clone());
                    ctx.assign_results.insert(_nid, right_val);
                }
            }
            AssignmentOperator::Addition => {
                let cur = ctx.seq_values.get(&sym).cloned();
                let newv = match (cur, right_val) {
                    (Some(Val::Str(a)), Val::Str(b)) => Some(Val::Str(format!("{}{}", a, b))),
                    (Some(Val::Str(a)), Val::Num(b)) if b.is_finite() => {
                        Some(Val::Str(format!("{}{}", a, super::fmt_num_pub(b))))
                    }
                    (Some(Val::Num(a)), Val::Str(b)) if a.is_finite() => {
                        Some(Val::Str(format!("{}{}", super::fmt_num_pub(a), b)))
                    }
                    (None, Val::Str(b)) => Some(Val::Str(b)),
                    _ => None,
                };
                if let Some(v) = newv {
                    ctx.seq_values.insert(sym, v.clone());
                    ctx.assign_results.insert(_nid, v);
                }
            }
            _ => {}
        }
    }
}

fn all_kinds_pub<'a>(ctx: &Ctx<'a>) -> Vec<(NodeId, AstKind<'a>)> {
    ctx.semantic
        .nodes()
        .iter()
        .map(|n| (n.id(), n.kind()))
        .collect()
}

fn builtin_callable(path: &str) -> Option<Callable> {
    match path {
        "parseInt" => Some(Callable::ParseInt),
        "Number" => Some(Callable::Number),
        "Math.round" => Some(Callable::Round),
        "Math.floor" => Some(Callable::Floor),
        "Math.ceil" => Some(Callable::Ceil),
        "Math.abs" => Some(Callable::Abs),
        "Math.pow" => Some(Callable::Pow),
        _ => None,
    }
}
