use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use oxc::ast::ast::*;
use oxc::ast::AstKind;
use oxc::span::GetSpan;
use oxc::syntax::node::NodeId;
use oxc::syntax::symbol::SymbolId;

use super::decoder::{lookup_from_alphabet, lookup_from_hex, Decoder};
use super::{ref_symbol, Ctx, ObjOp, RotationInfo, Sym, Target, Val, Wrapper};

fn all_kinds<'a>(ctx: &Ctx<'a>) -> Vec<(NodeId, AstKind<'a>)> {
    ctx.semantic
        .nodes()
        .iter()
        .map(|n| (n.id(), n.kind()))
        .collect()
}

fn strip_parens<'a, 'e>(e: &'e Expression<'a>) -> &'e Expression<'a> {
    match e {
        Expression::ParenthesizedExpression(p) => strip_parens(&p.expression),
        _ => e,
    }
}

fn reassign_inner<'a, 'e>(
    e: &'e Expression<'a>,
) -> Option<(&'e Function<'a>, &'e IdentifierReference<'a>)> {
    match strip_parens(e) {
        Expression::SequenceExpression(s) => {
            for el in &s.expressions {
                if let Some(r) = reassign_inner(el) {
                    return Some(r);
                }
            }
            None
        }
        Expression::CallExpression(c) => match strip_parens(&c.callee) {
            Expression::AssignmentExpression(a) if a.operator == AssignmentOperator::Assign => {
                match (&a.left, &a.right) {
                    (
                        AssignmentTarget::AssignmentTargetIdentifier(idf),
                        Expression::FunctionExpression(fe),
                    ) => Some((fe, idf)),
                    _ => None,
                }
            }
            _ => None,
        },
        Expression::AssignmentExpression(a) if a.operator == AssignmentOperator::Assign => {
            match (&a.left, &a.right) {
                (
                    AssignmentTarget::AssignmentTargetIdentifier(idf),
                    Expression::FunctionExpression(fe),
                ) => Some((fe, idf)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn param_names<'a>(f: &'a Function<'a>) -> Vec<&'a str> {
    f.params
        .items
        .iter()
        .filter_map(|p| {
            if let BindingPattern::BindingIdentifier(id) = &p.pattern {
                Some(id.name.as_str())
            } else {
                None
            }
        })
        .collect()
}

fn big_string_array(arr: &ArrayExpression) -> Option<Vec<String>> {
    let strs: Vec<String> = arr
        .elements
        .iter()
        .filter_map(|el| match el {
            ArrayExpressionElement::StringLiteral(s) => Some(s.value.to_string()),
            _ => None,
        })
        .collect();
    if strs.len() >= 8 && strs.len() == arr.elements.len() && strs.iter().filter(|x| is_entry_shaped(x)).count() * 3 >= strs.len() * 2 {
        Some(strs)
    } else {
        None
    }
}

pub fn passive_scan(ctx: &mut Ctx) {
    let mut writes: HashMap<SymbolId, u32> = HashMap::new();
    let mut consts: HashMap<SymbolId, Val> = HashMap::new();
    let mut aliases: HashMap<SymbolId, SymbolId> = HashMap::new();
    let mut getters: HashMap<SymbolId, Rc<RefCell<Vec<String>>>> = HashMap::new();
    let mut decl_tables: HashMap<SymbolId, Rc<RefCell<Vec<String>>>> = HashMap::new();
    let mut dead_spans: Vec<(oxc::span::Span, &'static str)> = Vec::new();
    let mut objfns: HashMap<(SymbolId, String), ObjOp> = HashMap::new();

    for (_id, kind) in all_kinds(ctx) {
        match kind {
            AstKind::VariableDeclarator(d) => {
                let Some(init) = &d.init else { continue };
                let Some(sym) = binding_symbol(ctx, &d.id) else { continue };
                if let Some(v) = literal_val(init) {
                    writes.entry(sym).and_modify(|w| *w += 1).or_insert(1);
                    consts.insert(sym, v);
                } else if let Expression::Identifier(idf) = init {
                    if let Some(target) = ref_symbol(ctx, idf.reference_id.get()) {
                        aliases.insert(sym, target);
                    }
                } else if let Some(builtin) = builtin_path(init) {
                    ctx.builtin_paths.insert(sym, builtin);
                } else if let Expression::CallExpression(call) = init {
                    if let Expression::FunctionExpression(fe) = &call.callee {
                        if let Some(strs) = iife_table(fe) {
                            decl_tables.insert(sym, Rc::new(RefCell::new(strs)));
                            dead_spans.push((init.span(), "[]"));
                        }
                    }
                }
            }
            AstKind::AssignmentExpression(a) => {
                if let AssignmentTarget::AssignmentTargetIdentifier(idf) = &a.left {
                    if let Some(sym) = ref_symbol(ctx, idf.reference_id.get()) {
                        writes.entry(sym).and_modify(|w| *w += 1).or_insert(1);
                    }
                }
                if let AssignmentTarget::StaticMemberExpression(m) = &a.left {
                    if let (Expression::Identifier(obj), Some(op)) =
                        (&m.object, objfn_op(&a.right))
                    {
                        if let Some(osym) = ref_symbol(ctx, obj.reference_id.get()) {
                            objfns
                                .entry((osym, m.property.name.as_str().to_string()))
                                .or_insert(op);
                        }
                    }
                }
            }
            AstKind::Function(f) => {
                if f.params.items.is_empty() {
                    if let Some((sym, table)) = match_getter(ctx, f) {
                        getters.insert(sym, table);
                    }
                }
            }
            _ => {}
        }
    }

    for (sym, w) in writes {
        if w > 1 {
            consts.remove(&sym);
        }
    }

    ctx.consts = consts;
    ctx.alias_sym = aliases;
    ctx.getters = getters;
    ctx.decl_tables = decl_tables;
    ctx.dead_spans = dead_spans;
    ctx.objfns = objfns;
}

fn literal_val(e: &Expression) -> Option<Val> {
    match e {
        Expression::NumericLiteral(l) => Some(Val::Num(l.value)),
        Expression::StringLiteral(s) => Some(Val::Str(s.value.to_string())),
        Expression::BooleanLiteral(b) => Some(Val::Bool(b.value)),
        Expression::NullLiteral(_) => Some(Val::Undefined),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            match &u.argument {
                Expression::NumericLiteral(l) => Some(Val::Num(-l.value)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn binding_symbol(ctx: &Ctx, pat: &BindingPattern) -> Option<SymbolId> {
    match pat {
        BindingPattern::BindingIdentifier(id) => ctx.span_sym.get(&id.span.start).copied(),
        _ => None,
    }
}

fn match_getter<'a>(ctx: &Ctx<'a>, f: &'a Function<'a>) -> Option<(SymbolId, Rc<RefCell<Vec<String>>>)> {    let body = f.body.as_ref()?;
    let mut big_array: Option<Vec<String>> = None;
    let mut self_reassign = false;
    for stmt in &body.statements {
        if let Statement::VariableDeclaration(v) = stmt {
            for d in &v.declarations {
                if let Some(Expression::ArrayExpression(arr)) = &d.init {
                    big_array = big_string_array(arr).or(big_array);
                }
            }
        }
        if let Statement::ReturnStatement(r) = stmt {
            if let Some(arg) = &r.argument {
                if reassign_inner(arg).is_some() {
                    self_reassign = true;
                }
            }
        }
    }
    if !self_reassign {
        return None;
    }
    let table = big_array?;
    let id = f.id.as_ref()?;
    let sym = ctx.span_sym.get(&id.span.start).copied()?;
    Some((sym, Rc::new(RefCell::new(table))))
}

fn dead_replacement(source: &str, start: u32) -> &'static str {
    let bytes = source.as_bytes();
    let mut i = start as usize;
    while i > 0 && (bytes[i - 1] as char).is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 {
        return "";
    }
    let c = bytes[i - 1];
    if matches!(
        c,
        b'=' | b'(' | b',' | b'[' | b':' | b'?' | b'&' | b'|' | b'+' | b'-' | b'*' | b'/' | b'%' | b'<'
            | b'>' | b'!' | b'~' | b'^'
    ) {
        return "0";
    }
    let head = &source[i.saturating_sub(8)..i];
    if ["return", "typeof", "new", "void", "delete", "throw"]
        .iter()
        .any(|k| head.ends_with(k))
    {
        return "0";
    }
    ""
}

pub fn scan_decoders(ctx: &mut Ctx) {
    let kinds = all_kinds(ctx);
    let mut found: Vec<Decoder> = Vec::new();
    let mut syms: Vec<SymbolId> = Vec::new();
    let mut dead_spans: Vec<(oxc::span::Span, &'static str)> = Vec::new();

    for (_id, kind) in kinds.iter().copied() {
        let AstKind::Function(f) = kind else { continue };
        let Some(dec) = match_decoder(ctx, f, &kinds) else { continue };
        if let Some(sym) = accessor_symbol(ctx, f) {
            syms.push(sym);
            found.push(dec);
            let repl = dead_replacement(ctx.source, f.span().start);
            dead_spans.push((f.span(), repl));
        }
    }

    for (sym, dec) in syms.into_iter().zip(found) {
        let idx = ctx.decoders.len();
        ctx.decoders.push(dec);
        ctx.decoder_sym.insert(sym, idx);
    }
    ctx.dead_spans.extend(dead_spans);
}

fn iife_table(fe: &Function) -> Option<Vec<String>> {
    if !fe.params.items.is_empty() {
        return None;
    }
    let body = fe.body.as_ref()?;
    let stmt = body.statements.first()?;
    let Statement::ReturnStatement(r) = stmt else {
        return None;
    };
    let Some(Expression::ArrayExpression(arr)) = &r.argument else {
        return None;
    };
    big_string_array(arr)
}

fn table_object_symbol<'a>(
    ctx: &Ctx<'a>,
    _inner: &'a Function<'a>,
    inner_span: oxc::span::Span,
    kinds: &[(NodeId, AstKind<'a>)],
) -> Option<SymbolId> {
    for (_nid, kind) in kinds.iter().copied() {
        let sp = kind.span();
        if sp.start < inner_span.start || sp.end > inner_span.end {
            continue;
        }
        if let AstKind::ComputedMemberExpression(cm) = kind {
            if let Expression::Identifier(idf) = &cm.object {
                if let Some(sym) = ref_symbol(ctx, idf.reference_id.get()) {
                    return Some(sym);
                }
            }
        }
    }
    None
}

fn accessor_symbol(ctx: &Ctx, f: &Function) -> Option<SymbolId> {
    let body = f.body.as_ref()?;
    for stmt in &body.statements {
        if let Statement::ReturnStatement(r) = stmt {
            if let Some(arg) = &r.argument {
                if let Some((_fe, idf)) = reassign_inner(arg) {
                    if let Some(sym) = ref_symbol(ctx, idf.reference_id.get()) {
                        return Some(sym);
                    }
                }
            }
        }
    }
    let id = f.id.as_ref()?;
    ctx.span_sym.get(&id.span.start).copied()
}

fn match_decoder<'a>(
    ctx: &Ctx<'a>,
    f: &'a Function<'a>,
    kinds: &[(NodeId, AstKind<'a>)],
) -> Option<Decoder> {    if f.params.items.len() < 1 {
        return None;
    }
    let body = f.body.as_ref()?;

    let mut inner: Option<&Function> = None;
    let mut reassign_sym: Option<SymbolId> = None;
    for stmt in &body.statements {
        if let Statement::ReturnStatement(r) = stmt {
            if let Some(arg) = &r.argument {
                if let Some((fe, idf)) = reassign_inner(arg) {
                    inner = Some(fe);
                    reassign_sym = ref_symbol(ctx, idf.reference_id.get());
                }
            }
        }
    }
    let inner = inner?;
    let ibody = inner.body.as_ref()?;
    let inner_span = ibody.span;

    let mut shift: Option<i64> = None;
    let mut has_iterative_decode = false;
    let mut alphabet_literal: Option<String> = None;
    let mut hex_alphabet: Option<String> = None;
    let mut lookup_xor: Option<u8> = None;
    let mut xor_out = false;

    let mut fc_spans: Vec<oxc::span::Span> = Vec::new();
    for (_nid, kind) in kinds.iter().copied() {
        let sp = kind.span();
        if sp.start < inner_span.start || sp.end > inner_span.end {
            continue;
        }
        if let AstKind::CallExpression(call) = kind {
            if let Some(m) = call.callee.as_member_expression() {
                if m.static_property_name() == Some("fromCharCode") {
                    fc_spans.push(call.span);
                }
            }
        }
    }

    for (_nid, kind) in kinds.iter().copied() {
        let sp = kind.span();
        if sp.start < inner_span.start || sp.end > inner_span.end {
            continue;
        }
        match kind {
            AstKind::AssignmentExpression(a) => {
                if a.operator == AssignmentOperator::Subtraction {
                    if let Expression::NumericLiteral(lit) = &a.right {
                        if shift.is_none() {
                            shift = Some(lit.value as i64);
                        }
                    }
                }
            }
            AstKind::CallExpression(call) => {
                if let Some(m) = call.callee.as_member_expression() {
                    let prop = m.static_property_name().unwrap_or("");
                    if prop == "indexOf" || is_lookup_call(call) {
                        if let Expression::StringLiteral(s) = &m.object() {
                            let v = s.value;
                            if is_b64_shaped(&v.to_string())
                            {
                                alphabet_literal = Some(v.to_string());
                            }
                        }
                        if let Some(Argument::BinaryExpression(b)) = call.arguments.first() {
                            if b.operator == BinaryOperator::BitwiseXOR {
                                if let Expression::NumericLiteral(k) = &b.left {
                                    lookup_xor = Some(k.value as u8);
                                }
                            }
                        }
                    }
                    if prop == "match" || is_table_split(call) {
                        if let Expression::StringLiteral(s) = &m.object() {
                            let v = s.value;
                            if is_hex_shaped(&v.to_string()) {
                                hex_alphabet = Some(v.to_string());
                            }
                        }
                    }

                }

            }
            AstKind::BinaryExpression(b) => {
                if b.operator == BinaryOperator::BitwiseXOR {
                    if let Expression::Identifier(_) = &b.right {
                        xor_out = true;
                    }
                    if has_shift_mask_form(&b.left) {
                        has_iterative_decode = true;
                    }
                }
            }
            AstKind::UpdateExpression(u) => {
                if is_counter(&u.argument) {
                    has_iterative_decode = true;
                }
            }
            _ => {}
        }
    }

    if !has_iterative_decode {
        return None;
    }
    let shift = shift?;

    let mut table: Option<Rc<RefCell<Vec<String>>>> = None;
    for stmt in &body.statements {
        if let Statement::VariableDeclaration(v) = stmt {
            for d in &v.declarations {
                if let Some(init) = &d.init {
                    match init {
                        Expression::ArrayExpression(arr) => {
                            if let Some(strs) = big_string_array(arr) {
                                table = Some(Rc::new(RefCell::new(strs)));
                            }
                        }
                        Expression::CallExpression(call) => {
                            if let Expression::Identifier(idf) = &call.callee {
                                if let Some(sym) = ref_symbol(ctx, idf.reference_id.get()) {
                                    if let Some(t) = ctx.getters.get(&sym) {
                                        table = Some(t.clone());
                                    }
                                }
                            } else if let Expression::FunctionExpression(fe) = &call.callee {
                                if let Some(strs) = iife_table(fe) {
                                    table = Some(Rc::new(RefCell::new(strs)));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    if table.is_none() {
        if let Some(sym) = table_object_symbol(ctx, inner, inner_span, kinds) {
            if let Some(t) = ctx.decl_tables.get(&sym) {
                table = Some(t.clone());
            }
        }
    }
    let table = table?;

    let lookup = if let Some(hex) = hex_alphabet {
        let k = lookup_xor.unwrap_or(0);
        lookup_from_hex(&hex, k)?
    } else if let Some(alpha) = alphabet_literal {
        lookup_from_alphabet(&alpha)
    } else {
        return None;
    };

    let name = reassign_sym
        .map(|s| ctx.semantic.scoping().symbol_name(s).to_string())
        .or_else(|| f.id.as_ref().map(|i| i.name.as_str().to_string()))
        .unwrap_or_else(|| "anon".into());

    Some(Decoder {
        name,
        table,
        shift,
        lookup,
        xor_out,
    })
}

pub fn run_rotations(ctx: &mut Ctx) -> Result<Vec<RotationInfo>, String> {
    let kinds = all_kinds(ctx);
    let mut infos = Vec::new();

    for (_id, kind) in kinds.iter().copied() {
        let AstKind::CallExpression(call) = kind else { continue };
        let Expression::FunctionExpression(fe) = &call.callee else { continue };
        let Some(Argument::Identifier(getter_id)) = call.arguments.first() else {
            continue;
        };
        let Some(getter_sym) = ref_symbol(ctx, getter_id.reference_id.get()) else { continue };
        if !ctx.getters.contains_key(&getter_sym) {
            continue;
        }
        let Some((target, cond)) = extract_rotation_condition(fe) else { continue };

        let table_len = ctx.getters[&getter_sym].borrow().len();
        let mut rotations = 0usize;
        let solved = (0..table_len.saturating_mul(2).max(1)).any(|_| {
            if let Val::Num(v) = super::eval::eval_test(ctx, cond) {
                if v == target {
                    return true;
                }
            }
            let t = ctx.getters[&getter_sym].borrow().len();
            if t > 1 {
                ctx.getters[&getter_sym].borrow_mut().rotate_left(1);
            }
            rotations += 1;
            false
        });
        if !solved {
            return Err(format!("rotation did not converge: target {}", target));
        }
        infos.push(RotationInfo {
            getter: ctx
                .semantic
                .scoping()
                .symbol_name(getter_sym)
                .to_string(),
            target,
            rotations,
            table_len,
        });
    }
    Ok(infos)
}

fn extract_rotation_condition<'a>(fe: &'a Function<'a>) -> Option<(f64, &'a Expression<'a>)> {
    let body = fe.body.as_ref()?;
    let mut cond: Option<&Expression> = None;
    for stmt in &body.statements {
        let mut st = stmt;
        loop {
            match st {
                Statement::ForStatement(f) => st = &f.body,
                Statement::WhileStatement(w) => st = &w.body,
                Statement::BlockStatement(b) => st = b.body.first()?,
                Statement::TryStatement(t) => {
                    for s in &t.block.body {
                        if let Statement::IfStatement(i) = s {
                            cond = Some(&i.test);
                            break;
                        }
                    }
                    break;
                }
                _ => break,
            }
        }
        if cond.is_some() {
            break;
        }
    }
    let c = cond?;
    if let Expression::BinaryExpression(b) = c {
        if b.operator == BinaryOperator::StrictEquality {
            if let (Expression::NumericLiteral(t), _) = (&b.left, &b.right) {
                return Some((t.value, &b.right));
            }
        }
    }
    None
}

pub fn scan_wrappers_fixpoint(ctx: &mut Ctx) -> usize {
    let mut total = 0usize;
    for _ in 0..8 {
        let before = ctx.wrapper_sym.len();
        scan_wrappers_once(ctx);
        total = ctx.wrapper_sym.len();
        if total == before {
            break;
        }
    }
    total
}

fn scan_wrappers_once(ctx: &mut Ctx) {
    let kinds = all_kinds(ctx);
    let mut candidates: Vec<(SymbolId, &Function)> = Vec::new();

    for (_id, kind) in kinds.iter().copied() {
        match kind {
            AstKind::Function(f) => {
                if f.params.items.len() == 2 {
                    if let Some(fid) = &f.id {
                        if let Some(sym) = ctx.span_sym.get(&fid.span.start) {
                            if !ctx.wrapper_sym.contains_key(sym)
                                && !ctx.decoder_sym.contains_key(sym)
                            {
                                candidates.push((*sym, f));
                            }
                        }
                    }
                }
            }
            AstKind::VariableDeclarator(d) => {
                if let Some(Expression::FunctionExpression(f)) = &d.init {
                    if f.params.items.len() == 2 {
                        if let Some(sym) = binding_symbol(ctx, &d.id) {
                            if !ctx.wrapper_sym.contains_key(&sym)
                                && !ctx.decoder_sym.contains_key(&sym)
                            {
                                candidates.push((sym, f));
                            }
                        }
                    }
                }
            }
            AstKind::AssignmentExpression(a) => {
                if a.operator == AssignmentOperator::Assign {
                    if let (
                        Expression::FunctionExpression(f),
                        AssignmentTarget::AssignmentTargetIdentifier(idf),
                    ) = (&a.right, &a.left)
                    {
                        if f.params.items.len() == 2 {
                            if let Some(sym) = ref_symbol(ctx, idf.reference_id.get()) {
                                if !ctx.wrapper_sym.contains_key(&sym)
                                    && !ctx.decoder_sym.contains_key(&sym)
                                {
                                    candidates.push((sym, f));
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    for (sym, f) in candidates {
        if ctx.wrapper_sym.contains_key(&sym) {
            continue;
        }
        if let Some(w) = match_wrapper(ctx, f).or_else(|| match_wrapper_flattened(ctx, f)) {
            ctx.wrapper_sym.insert(sym, w);
            let repl = dead_replacement(ctx.source, f.span().start);
            ctx.dead_spans.push((f.span(), repl));
        }
    }
}

pub fn scan_config_pairs(ctx: &Ctx) -> (Vec<(String, String)>, Vec<Vec<String>>) {
    let kinds = all_kinds(ctx);
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut fragments: Vec<Vec<String>> = Vec::new();
    for (_id, kind) in kinds.iter().copied() {
        match kind {
            AstKind::AssignmentExpression(a) => {
                if a.operator != AssignmentOperator::Assign {
                    continue;
                }
                let key = match &a.left {
                    AssignmentTarget::ComputedMemberExpression(cm) => {
                        match super::eval::eval_expr(ctx, &cm.expression) {
                            Val::Str(s) => s,
                            _ => continue,
                        }
                    }
                    AssignmentTarget::StaticMemberExpression(sm) => {
                        sm.property.name.as_str().to_string()
                    }
                    _ => continue,
                };
                if let Val::Str(v) = super::eval::eval_expr(ctx, &a.right) {
                    pairs.push((key, v));
                }
            }
            AstKind::ObjectProperty(p) => {
                let key = match &p.key {
                    PropertyKey::StaticIdentifier(id) => id.name.as_str().to_string(),
                    PropertyKey::StringLiteral(s) => s.value.to_string(),
                    _ => continue,
                };
                if let Val::Str(v) = super::eval::eval_expr(ctx, &p.value) {
                    pairs.push((key, v));
                }
            }
            AstKind::SequenceExpression(s) => {
                let mut parts = Vec::new();
                let mut all_str = true;
                for e in &s.expressions {
                    match super::eval::eval_expr(ctx, e) {
                        Val::Str(v) => parts.push(v),
                        _ => {
                            all_str = false;
                            break;
                        }
                    }
                }
                if all_str && parts.len() >= 3 {
                    fragments.push(parts);
                }
            }
            _ => {}
        }
    }
    (pairs, fragments)
}

fn match_wrapper_flattened<'a>(ctx: &Ctx<'a>, f: &'a Function<'a>) -> Option<Wrapper> {
    let dbg = std::env::var("ZAIC_DEBUG").is_ok();
    let fname = f.id.as_ref().map(|i| i.name.as_str()).unwrap_or("?").to_string();
    let _ = (&dbg, &fname);
    let body = f.body.as_ref()?;
    let params = param_names(f);
    if params.len() != 2 {
        return None;
    }
    let last = body.statements.last()?;
    let Statement::ReturnStatement(ret) = last else {
        return None;
    };
    let Expression::Identifier(ret_id) = strip_parens(ret.argument.as_ref()?) else {
        return None;
    };
    let ret_sym = ref_symbol(ctx, ret_id.reference_id.get())?;
    let fspan = f.span();
    let kinds = all_kinds(ctx);
    let mut assigns_to_ret: Vec<(u32, u32)> = Vec::new();
    for (_id, kind) in kinds.iter().copied() {
        if let AstKind::AssignmentExpression(a) = kind {
            if a.span().start >= fspan.start && a.span().end <= fspan.end {
                if let AssignmentTarget::AssignmentTargetIdentifier(idf) = &a.left {
                    if let Some(s) = ref_symbol(ctx, idf.reference_id.get()) {
                        if s == ret_sym {
                            assigns_to_ret.push((a.right.span().start, a.right.span().end));
                        }
                    }
                }
            }
        }
    }
    if assigns_to_ret.is_empty() {
        if dbg {
            eprintln!("[dbg-flatten] {}: нет присваиваний к ret-переменной", fname);
        }
        return None;
    }
    let mut found: Option<(Target, Sym, Option<Sym>)> = None;
    let dbg = std::env::var("ZAIC_DEBUG").is_ok();
    for (_id, kind) in kinds.iter().copied() {
        if let AstKind::CallExpression(call) = kind {
            let cs = call.span();
            if cs.start < fspan.start || cs.end > fspan.end {
                continue;
            }
            let Some((target, arg_exprs)) = resolve_callee_with_args(ctx, &call.callee, &call.arguments) else {
                if dbg {
                    eprintln!("[dbg-flatten] {} callee не разрешился @{}", f.id.as_ref().map(|i| i.name.as_str()).unwrap_or("?"), cs.start);
                }
                continue;
            };
            if !matches!(target, Target::Dec(_) | Target::Wrap(_)) {
                continue;
            }
            let inside_assign = assigns_to_ret.iter().any(|(s, e)| cs.start >= *s && cs.end <= *e);
            if !inside_assign {
                if dbg {
                    eprintln!("[dbg-flatten] {} вызов вне присваивания к ret @{}", f.id.as_ref().map(|i| i.name.as_str()).unwrap_or("?"), cs.start);
                }
                continue;
            }
            if arg_exprs.len() != 2 {
                continue;
            }
            let Some(index) = eval_sym_expr(ctx, arg_exprs[0], &params) else {
                if dbg {
                    eprintln!("[dbg-flatten] {} индекс не символьный @{}", f.id.as_ref().map(|i| i.name.as_str()).unwrap_or("?"), cs.start);
                }
                continue;
            };
            let xor = eval_sym_expr(ctx, arg_exprs[1], &params);
            match &found {
                None => found = Some((target, index, xor)),
                Some((pt, pi, px)) => {
                    if !same_target(pt, &target) || !super::sym_eq_canonical(pi, &index) {
                        return None;
                    }
                    match (px, &xor) {
                        (Some(p), Some(x)) => {
                            if !super::sym_eq_canonical(p, x) {
                                return None;
                            }
                        }
                        (None, None) => {}
                        _ => return None,
                    }
                }
            }
        }
    }
    let (target, index, xor) = found?;
    Some(Wrapper { target, index, xor })
}

fn same_target(a: &Target, b: &Target) -> bool {
    match (a, b) {
        (Target::Dec(x), Target::Dec(y)) => x == y,
        (Target::Wrap(x), Target::Wrap(y)) => x == y,
        _ => false,
    }
}

fn match_wrapper<'a>(_ctx: &Ctx<'a>, f: &'a Function<'a>) -> Option<Wrapper> {    let body = f.body.as_ref()?;
    if body.statements.len() != 1 {
        return None;
    }
    let Statement::ReturnStatement(r) = &body.statements[0] else {
        return None;
    };
    let Some(Expression::CallExpression(call)) = &r.argument else {
        return None;
    };

    let params = param_names(f);
    if params.len() != 2 {
        return None;
    }

    let (target, arg_exprs) = resolve_callee_with_args(_ctx, &call.callee, &call.arguments)?;
    if arg_exprs.len() != 2 {
        return None;
    }
    let index = eval_sym_expr(_ctx, arg_exprs[0], &params)?;
    let xor = eval_sym_expr(_ctx, arg_exprs[1], &params);
    Some(Wrapper { target, index, xor })
}

fn resolve_callee_with_args<'a, 'e>(
    ctx: &Ctx<'a>,
    callee: &'e Expression<'a>,
    args: &'e [Argument<'a>],
) -> Option<(Target, Vec<&'e Expression<'a>>)> {
    match callee {
        Expression::Identifier(idf) => {
            let sym = ref_symbol(ctx, idf.reference_id.get())?;
            let target = symbol_target(ctx, sym)?;
            let mut out = Vec::new();
            for a in args {
                if let Some(e) = a.as_expression() {
                    out.push(e);
                }
            }
            Some((target, out))
        }
        Expression::SequenceExpression(s) => {
            let last = s.expressions.last()?;
            resolve_callee_with_args(ctx, last, args)
        }
        Expression::ConditionalExpression(c) => {
            let t = super::eval::eval_expr(ctx, &c.test);
            let pick = if t.truthy()? { &c.consequent } else { &c.alternate };
            resolve_callee_with_args(ctx, pick, args)
        }
        Expression::LogicalExpression(l) => {
            let lt = super::eval::eval_expr(ctx, &l.left).truthy()?;
            let pick = if lt { &l.right } else { &l.left };
            resolve_callee_with_args(ctx, pick, args)
        }
        Expression::StaticMemberExpression(m) => match m.property.name.as_str() {
            "apply" => {
                let mut out: Vec<&Expression> = Vec::new();
                if let Some(Argument::ArrayExpression(arr)) = args.get(1) {
                    for el in &arr.elements {
                        if let Some(e) = el.as_expression() {
                            out.push(e);
                        }
                    }
                }
                resolve_callee_with_args_direct(ctx, &m.object, out)
            }
            "call" => {
                let mut out: Vec<&Expression> = Vec::new();
                for a in args.iter().skip(1) {
                    if let Some(e) = a.as_expression() {
                        out.push(e);
                    }
                }
                resolve_callee_with_args_direct(ctx, &m.object, out)
            }
            "bind" => {
                let mut out: Vec<&Expression> = Vec::new();
                for a in args.iter().skip(1) {
                    if let Some(e) = a.as_expression() {
                        out.push(e);
                    }
                }
                resolve_callee_with_args_direct(ctx, &m.object, out)
            }
            _ => None,
        },
        Expression::ParenthesizedExpression(p) => {
            resolve_callee_with_args(ctx, &p.expression, args)
        }
        Expression::ComputedMemberExpression(cm) => {
            let obj = strip_parens(&cm.object);
            let idx_ok = matches!(strip_parens(&cm.expression), Expression::NumericLiteral(_));
            if std::env::var("ZAIC_TRACE").is_ok() && ctx.source[cm.object.span().start as usize..].starts_with("[tW]") {
                eprintln!("[trace-cm] @{} obj_variant={:?} idx_ok={} obj_src={}", cm.object.span().start, std::mem::discriminant(obj), idx_ok, &ctx.source[cm.object.span().start as usize..(cm.object.span().start as usize + 12).min(ctx.source.len())]);
            }
            if !idx_ok {
                return None;
            }
            match obj {
                Expression::ObjectExpression(obj) => {
                    for p in &obj.properties {
                        if let ObjectPropertyKind::ObjectProperty(prop) = p {
                            let k0 = match &prop.key {
                                PropertyKey::NumericLiteral(n) => n.value as i64 == 0,
                                PropertyKey::StaticIdentifier(id) => id.name.as_str() == "0",
                                PropertyKey::StringLiteral(s) => s.value == "0",
                                _ => false,
                            };
                            if k0 {
                                return resolve_callee_with_args(ctx, &prop.value, args);
                            }
                        }
                    }
                    None
                }
                Expression::ArrayExpression(arr) => {
                    let mut first: Option<&Expression> = None;
                    for el in &arr.elements {
                        if let Some(e) = el.as_expression() {
                            first = Some(e);
                            break;
                        }
                    }
                    match first {
                        Some(e) => {
                            let out = resolve_callee_with_args(ctx, e, args);
                            if std::env::var("ZAIC_DEBUG").is_ok() {
                                let span = e.span();
                                let src_at = &ctx.source[span.start as usize..(span.start as usize + 8).min(ctx.source.len())];
                                eprintln!("[dbg-array-callee] elem={} → target={:?}", src_at, out.as_ref().map(|(t, _)| matches!(t, super::Target::Dec(_))));
                            }
                            out
                        }
                        None => None,
                    }
                }
                _ => None,
            }
        }
        Expression::CallExpression(inner) => {
            if let Expression::StaticMemberExpression(m) = &inner.callee {
                if m.property.name.as_str() == "bind" {
                    let mut out: Vec<&Expression> = Vec::new();
                    for a in inner.arguments.iter().skip(1) {
                        if let Some(e) = a.as_expression() {
                            out.push(e);
                        }
                    }
                    for a in args {
                        if let Some(e) = a.as_expression() {
                            out.push(e);
                        }
                    }
                    return resolve_callee_with_args_direct(ctx, &m.object, out);
                }
            }
            None
        }
        _ => None,
    }
}

fn resolve_callee_with_args_direct<'a, 'e>(
    ctx: &Ctx<'a>,
    callee: &'e Expression<'a>,
    args: Vec<&'e Expression<'a>>,
) -> Option<(Target, Vec<&'e Expression<'a>>)> {
    match callee {
        Expression::Identifier(idf) => {
            let sym = ref_symbol(ctx, idf.reference_id.get())?;
            let target = symbol_target(ctx, sym)?;
            Some((target, args))
        }
        Expression::SequenceExpression(s) => {
            let last = s.expressions.last()?;
            resolve_callee_with_args_direct(ctx, last, args)
        }
        Expression::ConditionalExpression(c) => {
            let t = super::eval::eval_expr(ctx, &c.test);
            let pick = if t.truthy()? { &c.consequent } else { &c.alternate };
            resolve_callee_with_args_direct(ctx, pick, args)
        }
        Expression::LogicalExpression(l) => {
            let lt = super::eval::eval_expr(ctx, &l.left).truthy()?;
            let pick = if lt { &l.right } else { &l.left };
            resolve_callee_with_args_direct(ctx, pick, args)
        }
        Expression::ParenthesizedExpression(p) => {
            resolve_callee_with_args_direct(ctx, &p.expression, args)
        }
        _ => None,
    }
}

pub fn symbol_target(ctx: &Ctx, sym: SymbolId) -> Option<Target> {
    if let Some(&idx) = ctx.decoder_sym.get(&sym) {
        return Some(Target::Dec(idx));
    }
    if ctx.wrapper_sym.contains_key(&sym) {
        return Some(Target::Wrap(sym));
    }
    if let Some(&alias) = ctx.alias_sym.get(&sym) {
        return symbol_target(ctx, alias);
    }
    None
}

fn eval_sym_expr(ctx: &Ctx, e: &Expression, params: &[&str]) -> Option<Sym> {
    let r = |s: Sym| Rc::new(s);
    match e {
        Expression::NumericLiteral(l) => Some(Sym::Lit(l.value)),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            Some(Sym::Neg(r(eval_sym_expr(ctx, &u.argument, params)?)))
        }
        Expression::BinaryExpression(b) => {
            let a = r(eval_sym_expr(ctx, &b.left, params)?);
            let c = r(eval_sym_expr(ctx, &b.right, params)?);
            Some(match b.operator {
                BinaryOperator::Addition => Sym::Add(a, c),
                BinaryOperator::Subtraction => Sym::Sub(a, c),
                BinaryOperator::Multiplication => Sym::Mul(a, c),
                BinaryOperator::Division => Sym::Div(a, c),
                _ => return None,
            })
        }
        Expression::Identifier(idf) => {
            let name = idf.name.as_str();
            if let Some(pos) = params.iter().position(|&p| p == name) {
                return Some(Sym::Arg(pos as u8));
            }
            if let Some(sym) = ref_symbol(ctx, idf.reference_id.get()) {
                if let Some(Val::Num(v)) = ctx.consts.get(&sym) {
                    return Some(Sym::Lit(*v));
                }
            }
            None
        }
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(m) = &call.callee {
                if let Expression::Identifier(obj) = &m.object {
                    if let Some(osym) = ref_symbol(ctx, obj.reference_id.get()) {
                        let key = (osym, m.property.name.as_str().to_string());
                        let op = *ctx.objfns.get(&key)?;
                        let a0 = arg_expr(call.arguments.first()?)?;
                        let a1 = arg_expr(call.arguments.get(1)?)?;
                        let x = r(eval_sym_expr(ctx, a0, params)?);
                        let y = r(eval_sym_expr(ctx, a1, params)?);
                        return Some(match op {
                            ObjOp::Add => Sym::Add(x, y),
                            ObjOp::Sub => Sym::Sub(x, y),
                            ObjOp::Mul => Sym::Mul(x, y),
                            ObjOp::Div => Sym::Div(x, y),
                            _ => return None,
                        });
                    }
                }
            }
            None
        }
        Expression::ParenthesizedExpression(p) => eval_sym_expr(ctx, &p.expression, params),
        _ => None,
    }
}

fn arg_expr<'a, 'e>(a: &'e Argument<'a>) -> Option<&'e Expression<'a>> {
    a.as_expression()
}

fn objfn_op(right: &Expression) -> Option<ObjOp> {
    let Expression::FunctionExpression(f) = right else { return None };
    if f.params.items.len() < 2 || f.params.items.len() > 3 {
        return None;
    }
    let body = f.body.as_ref()?;
    if body.statements.len() != 1 {
        return None;
    }
    let Statement::ReturnStatement(r) = &body.statements[0] else { return None };
    let Some(expr) = &r.argument else { return None };
    let params = param_names(f);
    match expr {
        Expression::BinaryExpression(b) => {
            let is_param = |e: &Expression| {
                matches!(e, Expression::Identifier(i) if params.contains(&i.name.as_str()))
            };
            if !(is_param(&b.left) && is_param(&b.right)) {
                return None;
            }
            Some(match b.operator {
                BinaryOperator::Addition => ObjOp::Add,
                BinaryOperator::Subtraction => ObjOp::Sub,
                BinaryOperator::Multiplication => ObjOp::Mul,
                BinaryOperator::Division => ObjOp::Div,
                BinaryOperator::BitwiseOR => ObjOp::Or,
                BinaryOperator::BitwiseAnd => ObjOp::And,
                BinaryOperator::BitwiseXOR => ObjOp::Xor,
                BinaryOperator::GreaterThan => ObjOp::Gt,
                BinaryOperator::LessThan => ObjOp::Lt,
                _ => return None,
            })
        }
        Expression::CallExpression(call) => {
            if let Expression::Identifier(i) = &call.callee {
                if i.name.as_str() == params[0] && call.arguments.len() == 2 {
                    return Some(if f.params.items.len() == 2 {
                        ObjOp::Call12
                    } else {
                        ObjOp::Call21
                    });
                }
            }
            None
        }
        _ => None,
    }
}

fn is_b64_shaped(v: &str) -> bool {
    let distinct = v
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=')
        .count();
    distinct == v.len() && v.len() >= 32 && distinct >= 24
}

fn is_hex_shaped(v: &str) -> bool {
    let n = v.bytes().filter(|b| b.is_ascii_hexdigit()).count();
    n == v.len() && v.len() % 2 == 0 && v.len() >= 16
}

fn is_entry_shaped(s: &str) -> bool {
    (8..=16).contains(&s.len())
        || (s.len() >= 4 && s.bytes().filter(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=').count() == s.len())
}

fn builtin_path(e: &Expression) -> Option<String> {
    fn walk(e: &Expression, out: &mut String) -> bool {
        match e {
            Expression::StaticMemberExpression(m) => {
                if !walk(&m.object, out) {
                    return false;
                }
                out.push('.');
                out.push_str(m.property.name.as_str());
                true
            }
            Expression::Identifier(idf) => {
                if idf.name.as_str() == "arguments" {
                    return false;
                }
                if is_global_ns_name(idf.name.as_str()) {
                    out.push_str(idf.name.as_str());
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }
    let mut out = String::new();
    if walk(e, &mut out) {
        Some(out)
    } else {
        None
    }
}

fn is_global_ns_name(n: &str) -> bool {
    matches!(
        n,
        "Math"
            | "JSON"
            | "String"
            | "Number"
            | "Object"
            | "Array"
            | "Date"
            | "Promise"
            | "Symbol"
            | "RegExp"
            | "Error"
            | "TypeError"
            | "Uint8Array"
            | "TextEncoder"
            | "TextDecoder"
            | "ArrayBuffer"
            | "decodeURIComponent"
            | "encodeURIComponent"
            | "isNaN"
            | "isFinite"
            | "parseInt"
            | "parseFloat"
    )
}

fn has_shift_mask_form(e: &Expression) -> bool {
    fn sm(e: &Expression) -> bool {
        match e {
            Expression::BinaryExpression(b) => match b.operator {
                BinaryOperator::ShiftRight
                | BinaryOperator::ShiftRightZeroFill
                | BinaryOperator::ShiftLeft
                | BinaryOperator::BitwiseAnd => sm(&b.left) || sm(&b.right) || is_num_or_ident(&b.left),
                _ => sm(&b.left) || sm(&b.right),
            },
            Expression::ParenthesizedExpression(p) => sm(&p.expression),
            Expression::UnaryExpression(u) => sm(&u.argument),
            _ => is_num_or_ident(e),
        }
    }
    fn is_num_or_ident(e: &Expression) -> bool {
        matches!(e, Expression::NumericLiteral(_) | Expression::Identifier(_))
    }
    sm(e)
}

fn is_counter(t: &SimpleAssignmentTarget) -> bool {
    matches!(t, SimpleAssignmentTarget::AssignmentTargetIdentifier(_))
}

fn is_lookup_call(call: &CallExpression) -> bool {
    call.arguments.first().is_some_and(|a| {
        matches!(a, Argument::BinaryExpression(b) if b.operator == BinaryOperator::BitwiseXOR)
    })
}

fn is_table_split(call: &CallExpression) -> bool {
    let Some(Argument::ObjectExpression(_)) = call.arguments.first() else {
        return false;
    };
    true
}
