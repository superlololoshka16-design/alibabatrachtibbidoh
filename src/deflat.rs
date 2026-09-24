use std::cell::RefCell;
use std::collections::HashMap;

use oxc::allocator::Allocator;
use oxc::ast::ast::*;
use oxc::ast::AstKind;
use oxc::parser::Parser;
use oxc::semantic::Semantic;
use oxc::span::GetSpan;
use oxc::span::SourceType;
use oxc::syntax::symbol::SymbolId;

use crate::egraph::Builder;

#[derive(Debug, Clone, PartialEq)]
pub enum S {
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
    Undefined,
    Env(String),
    Dyn(String),
    Var(String),
    Un(&'static str, Box<S>),
    Bin(String, Box<S>, Box<S>),
    Call(String, Vec<S>),
    Cond(Box<S>, Box<S>, Box<S>),
}

fn disp(k: &str) -> &str {
    match k.rfind('#') {
        Some(i) if i > 0 && k[i + 1..].chars().all(|c| c.is_ascii_digit()) => &k[..i],
        _ => k,
    }
}

impl S {
    pub fn render(&self) -> String {
        match self {
            S::Num(v) => crate::ast::fmt_num_pub(*v),
            S::Str(v) => format!("{:?}", v),
            S::Bool(v) => format!("{}", v),
            S::Null => "null".into(),
            S::Undefined => "undefined".into(),
            S::Env(v) => format!("@{}", v),
            S::Dyn(v) => format!("~{}", v),
            S::Var(v) => disp(v).to_string(),
            S::Un(op, a) => format!("{} {}", op, a.render()),
            S::Bin(op, a, b) => format!("({} {} {})", a.render(), op, b.render()),
            S::Call(f, args) => format!(
                "{}({})",
                f,
                args.iter()
                    .map(|a| a.render())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            S::Cond(c, a, b) => format!("{}?{}:{}", c.render(), a.render(), b.render()),
        }
    }

    fn keyed(&self) -> String {
        match self {
            S::Num(v) => crate::ast::fmt_num_pub(*v),
            S::Str(v) => format!("{:?}", v),
            S::Bool(v) => format!("{}", v),
            S::Null => "null".into(),
            S::Undefined => "undefined".into(),
            S::Env(v) => format!("@{}", v),
            S::Dyn(v) => format!("~{}", v),
            S::Var(v) => v.clone(),
            S::Un(op, a) => format!("{} {}", op, a.keyed()),
            S::Bin(op, a, b) => format!("({} {} {})", a.keyed(), op, b.keyed()),
            S::Call(f, args) => format!(
                "{}({})",
                f,
                args.iter()
                    .map(|a| a.keyed())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            S::Cond(c, a, b) => format!("{}?{}:{}", c.keyed(), a.keyed(), b.keyed()),
        }
    }

    fn vars(&self, out: &mut Vec<String>) {
        match self {
            S::Var(v) => {
                if !out.contains(v) {
                    out.push(v.clone());
                }
            }
            S::Un(_, a) => a.vars(out),
            S::Bin(_, a, b) => {
                a.vars(out);
                b.vars(out);
            }
            S::Call(_, args) => args.iter().for_each(|a| a.vars(out)),
            S::Cond(c, a, b) => {
                c.vars(out);
                a.vars(out);
                b.vars(out);
            }
            _ => {}
        }
    }

    fn subst(&self, name: &str, val: &S) -> S {
        match self {
            S::Var(v) if v == name => val.clone(),
            S::Var(v) => S::Var(v.clone()),
            S::Un(op, a) => S::Un(op, Box::new(a.subst(name, val))),
            S::Bin(op, a, b) => S::Bin(
                op.clone(),
                Box::new(a.subst(name, val)),
                Box::new(b.subst(name, val)),
            ),
            S::Call(f, args) => {
                S::Call(f.clone(), args.iter().map(|a| a.subst(name, val)).collect())
            }
            S::Cond(c, a, b) => S::Cond(
                Box::new(c.subst(name, val)),
                Box::new(a.subst(name, val)),
                Box::new(b.subst(name, val)),
            ),
            other => other.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Transition {
    pub cond: Option<S>,
    pub next: i64,
}

#[derive(Debug, Clone)]
pub enum Action {
    Assign(String, S),
    Call(String, Vec<S>),
    Return(Option<S>),
}

#[derive(Debug, Clone)]
pub struct Block {
    pub state: i64,
    pub actions: Vec<Action>,
    pub transitions: Vec<Transition>,
    pub span: (u32, u32),
}

pub struct FlatFn {
    pub name: String,
    pub init: i64,
    pub r_name: String,
    pub slices: Vec<(String, i64, i64)>,
    pub blocks: Vec<Block>,
}

impl FlatFn {
    pub fn block(&self, state: i64) -> Option<&Block> {
        self.blocks.iter().find(|b| b.state == state)
    }
}

#[derive(Debug, Clone)]
pub struct TraceStep {
    pub state: i64,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LamOp {
    Bin(&'static str),
    Un(&'static str),
}

fn sym_key(semantic: &Semantic, sid: SymbolId) -> String {
    format!("{}#{}", semantic.scoping().symbol_name(sid), sid.index())
}

fn strip<'a, 'e>(e: &'e Expression<'a>) -> &'e Expression<'a> {
    match e {
        Expression::ParenthesizedExpression(p) => strip(&p.expression),
        _ => e,
    }
}

fn lit_i64(e: &Expression<'_>) -> Option<i64> {
    match strip(e) {
        Expression::NumericLiteral(n) => Some(n.value as i64),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            match strip(&u.argument) {
                Expression::NumericLiteral(n) => Some(-(n.value as i64)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn literal_of(e: &Expression<'_>) -> Option<S> {
    match strip(e) {
        Expression::StringLiteral(s) => Some(S::Str(s.value.to_string())),
        Expression::NumericLiteral(n) => Some(S::Num(n.value)),
        Expression::BooleanLiteral(b) => Some(S::Bool(b.value)),
        Expression::NullLiteral(_) => Some(S::Null),
        _ => None,
    }
}

pub fn deflatten_all(source: &str) -> Result<Vec<FlatFn>, String> {
    std::thread::scope(|s| -> Result<Vec<FlatFn>, String> {
        let h = std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn_scoped(s, || deflatten_inner(source))
            .map_err(|e| e.to_string())?;
        h.join()
            .map_err(|_| "analysis thread panicked".to_string())?
    })
}

fn deflatten_inner(source: &str) -> Result<Vec<FlatFn>, String> {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, SourceType::cjs()).parse();
    if ret.diagnostics.len() > 3 {
        return Err(format!("parse errors: {}", ret.diagnostics.len()));
    }
    let program = ret.program;
    let sem_ret = oxc::semantic::SemanticBuilder::new()
        .with_check_syntax_error(false)
        .with_build_nodes(true)
        .build(&program);
    let semantic = sem_ret.semantic;

    let consts = const_map(&semantic);
    let lambdas = lambda_map(&semantic);
    let fns = fn_names(&semantic);

    let kinds: Vec<AstKind<'_>> = semantic.nodes().iter().map(|n| n.kind()).collect();

    let mut loops: Vec<LoopInfo<'_>> = Vec::new();
    for kind in &kinds {
        match kind {
            AstKind::ForStatement(f) => loops.push(LoopInfo {
                body: &f.body,
                test: f.test.as_ref(),
                init: f.init.as_ref(),
                update: f.update.as_ref(),
                post: false,
                span: (f.span.start, f.span.end),
            }),
            AstKind::WhileStatement(w) => loops.push(LoopInfo {
                body: &w.body,
                test: Some(&w.test),
                init: None,
                update: None,
                post: false,
                span: (w.span.start, w.span.end),
            }),
            AstKind::DoWhileStatement(w) => loops.push(LoopInfo {
                body: &w.body,
                test: Some(&w.test),
                init: None,
                update: None,
                post: true,
                span: (w.span.start, w.span.end),
            }),
            _ => {}
        }
    }
    loops.sort_by_key(|l| l.span.0);

    let mut dispatchers: Vec<Disp<'_>> = Vec::new();
    for lp in &loops {
        if let Some(d) = try_dispatcher(&semantic, lp, &kinds) {
            dispatchers.push(d);
        }
    }

    let mut out = Vec::new();
    for d in &dispatchers {
        if std::env::var("ZAIC_TIMING").is_ok() {
            eprintln!("[bfs] fn@{} r={} init={} start", d.span.0, d.r_key, d.init);
        }
        let sub_spans: Vec<u32> = dispatchers
            .iter()
            .filter(|o| o.span != d.span && o.span.0 >= d.span.0 && o.span.1 <= d.span.1)
            .map(|o| o.span.0)
            .collect();
        let interp = Interp {
            semantic: &semantic,
            consts: &consts,
            lambdas: &lambdas,
            r_key: d.r_key.clone(),
            sub_spans,
            memo: RefCell::new(HashMap::new()),
            tmem: RefCell::new(HashMap::new()),
        };
        let name = enclosing_fn_name(&fns, d.span.0);
        let slices = find_slices(&semantic, d, &consts);
        let blocks = interp.run_bfs(d);
        if std::env::var("ZAIC_TIMING").is_ok() {
            eprintln!("[bfs] fn@{} blocks={}", d.span.0, blocks.len());
        }
        out.push(FlatFn {
            name,
            init: d.init,
            r_name: disp(&d.r_key).to_string(),
            slices,
            blocks,
        });
    }
    Ok(out)
}

struct LoopInfo<'a> {
    body: &'a Statement<'a>,
    test: Option<&'a Expression<'a>>,
    init: Option<&'a ForStatementInit<'a>>,
    update: Option<&'a Expression<'a>>,
    post: bool,
    span: (u32, u32),
}

struct Disp<'a> {
    r_key: String,
    r_sym: Option<SymbolId>,
    init: i64,
    body: &'a Statement<'a>,
    test: Option<&'a Expression<'a>>,
    update: Option<&'a Expression<'a>>,
    post: bool,
    span: (u32, u32),
}

fn ref_sym(
    semantic: &Semantic,
    rid: Option<oxc::syntax::reference::ReferenceId>,
) -> Option<SymbolId> {
    let r = rid?;
    semantic.scoping().get_reference(r).symbol_id()
}

fn ident_ref_sym(semantic: &Semantic, id: &IdentifierReference) -> Option<SymbolId> {
    ref_sym(semantic, id.reference_id.get())
}

fn target_sym(semantic: &Semantic, t: &AssignmentTarget<'_>) -> Option<SymbolId> {
    match t {
        AssignmentTarget::AssignmentTargetIdentifier(idf) => {
            ref_sym(semantic, idf.reference_id.get())
        }
        _ => None,
    }
}

fn simple_target_sym(semantic: &Semantic, t: &SimpleAssignmentTarget<'_>) -> Option<SymbolId> {
    match t {
        SimpleAssignmentTarget::AssignmentTargetIdentifier(idf) => {
            ref_sym(semantic, idf.reference_id.get())
        }
        _ => None,
    }
}

fn test_var(semantic: &Semantic, test: &Expression<'_>) -> Option<SymbolId> {
    match strip(test) {
        Expression::Identifier(id) => ident_ref_sym(semantic, id),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => None,
        Expression::BinaryExpression(b)
            if matches!(
                b.operator,
                BinaryOperator::StrictInequality
                    | BinaryOperator::Inequality
                    | BinaryOperator::StrictEquality
                    | BinaryOperator::Equality
                    | BinaryOperator::GreaterThan
                    | BinaryOperator::LessThan
            ) =>
        {
            let l_id = match strip(&b.left) {
                Expression::Identifier(id) => Some(id),
                _ => None,
            };
            let r_id = match strip(&b.right) {
                Expression::Identifier(id) => Some(id),
                _ => None,
            };
            match (l_id, r_id, lit_i64(&b.right), lit_i64(&b.left)) {
                (Some(id), None, Some(_), _) => ident_ref_sym(semantic, id),
                (None, Some(id), _, Some(_)) => ident_ref_sym(semantic, id),
                _ => None,
            }
        }
        _ => None,
    }
}

fn try_dispatcher<'a>(
    semantic: &Semantic,
    lp: &LoopInfo<'a>,
    kinds: &[AstKind<'_>],
) -> Option<Disp<'a>> {
    let (mut r_sym, mut init) = (None, None);

    if let Some(fi) = lp.init {
        match fi {
            fi if fi.is_expression() => {
                let e = fi.as_expression().unwrap();
                let exprs: Vec<&Expression<'_>> = match strip(e) {
                    Expression::SequenceExpression(s) => s.expressions.iter().collect(),
                    other => vec![other],
                };
                for ex in exprs {
                    if let Expression::AssignmentExpression(a) = strip(ex) {
                        if a.operator == AssignmentOperator::Assign {
                            if let (Some(sid), Some(v)) =
                                (target_sym(semantic, &a.left), lit_i64(&a.right))
                            {
                                r_sym = Some(sid);
                                init = Some(v);
                            }
                        }
                    }
                }
            }
            ForStatementInit::VariableDeclaration(vd) => {
                if vd.declarations.len() == 1 {
                    let d = &vd.declarations[0];
                    if let (BindingPattern::BindingIdentifier(b), Some(i)) =
                        (&d.id, d.init.as_ref())
                    {
                        if let (Some(sid), Some(v)) = (b.symbol_id.get(), lit_i64(i)) {
                            r_sym = Some(sid);
                            init = Some(v);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if r_sym.is_none() {
        if let Some(t) = lp.test {
            r_sym = test_var(semantic, t);
        }
    }
    let rs = r_sym?;

    if init.is_none() {
        let mut best: Option<(u32, i64)> = None;
        for kind in kinds {
            let (sid, v, at) = match kind {
                AstKind::AssignmentExpression(a) => {
                    if a.operator != AssignmentOperator::Assign || a.span.start >= lp.span.0 {
                        continue;
                    }
                    match (target_sym(semantic, &a.left), lit_i64(&a.right)) {
                        (Some(s), Some(v)) => (s, v, a.span.start),
                        _ => continue,
                    }
                }
                AstKind::VariableDeclarator(d) => {
                    if d.span.start >= lp.span.0 {
                        continue;
                    }
                    let sid = match &d.id {
                        BindingPattern::BindingIdentifier(b) => b.symbol_id.get(),
                        _ => None,
                    };
                    match (sid, d.init.as_ref().and_then(lit_i64)) {
                        (Some(s), Some(v)) => (s, v, d.span.start),
                        _ => continue,
                    }
                }
                _ => continue,
            };
            if sid == rs {
                match best {
                    Some((b, _)) if b >= at => {}
                    _ => best = Some((at, v)),
                }
            }
        }
        init = best.map(|(_, v)| v);
    }
    let init_v = init?;

    let mut mutations = 0u32;
    let mut switches = 0u32;
    for kind in kinds {
        match kind {
            AstKind::AssignmentExpression(a) => {
                if a.span.start > lp.span.0
                    && a.span.end <= lp.span.1
                    && target_sym(semantic, &a.left) == Some(rs)
                {
                    mutations += 1;
                }
            }
            AstKind::UpdateExpression(u) => {
                if u.span.start > lp.span.0
                    && u.span.end <= lp.span.1
                    && simple_target_sym(semantic, &u.argument) == Some(rs)
                {
                    mutations += 1;
                }
            }
            AstKind::SwitchStatement(_) => {
                let sp = match kind {
                    AstKind::SwitchStatement(s) => s.span,
                    _ => unreachable!(),
                };
                if sp.start >= lp.span.0 && sp.end <= lp.span.1 {
                    switches += 1;
                }
            }
            _ => {}
        }
    }
    if mutations < 1 || switches < 1 {
        return None;
    }

    Some(Disp {
        r_key: sym_key(semantic, rs),
        r_sym: Some(rs),
        init: init_v,
        body: lp.body,
        test: lp.test,
        update: lp.update,
        post: lp.post,
        span: lp.span,
    })
}

fn fn_names(semantic: &Semantic) -> Vec<(u32, u32, String)> {
    let mut named: HashMap<u32, String> = HashMap::new();
    let mut out = Vec::new();
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::VariableDeclarator(d) => {
                if let BindingPattern::BindingIdentifier(b) = &d.id {
                    if let Some(init) = d.init.as_ref() {
                        if let Expression::FunctionExpression(f) = strip(init) {
                            named.insert(f.span.start, b.name.to_string());
                        } else if let Expression::ArrowFunctionExpression(a) = strip(init) {
                            named.insert(a.span.start, b.name.to_string());
                        }
                    }
                }
            }
            AstKind::AssignmentExpression(a) => {
                if a.operator == AssignmentOperator::Assign {
                    let target = match &a.left {
                        AssignmentTarget::AssignmentTargetIdentifier(idf) => idf.name.to_string(),
                        AssignmentTarget::StaticMemberExpression(m) => m.property.name.to_string(),
                        AssignmentTarget::ComputedMemberExpression(cm) => {
                            match computed_prop_str(&cm.expression) {
                                Some(p) => p.to_string(),
                                None => continue,
                            }
                        }
                        _ => continue,
                    };
                    match strip(&a.right) {
                        Expression::FunctionExpression(f) => {
                            named.insert(f.span.start, target);
                        }
                        Expression::ArrowFunctionExpression(ar) => {
                            named.insert(ar.span.start, target);
                        }
                        _ => {}
                    }
                }
            }
            AstKind::ObjectProperty(op) => {
                let key = match &op.key {
                    PropertyKey::StaticIdentifier(id) => id.name.to_string(),
                    PropertyKey::StringLiteral(s) => s.value.to_string(),
                    _ => continue,
                };
                match strip(&op.value) {
                    Expression::FunctionExpression(f) => {
                        named.insert(f.span.start, key);
                    }
                    Expression::ArrowFunctionExpression(ar) => {
                        named.insert(ar.span.start, key);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    for node in semantic.nodes().iter() {
        let (span, id_name) = match node.kind() {
            AstKind::Function(f) => (f.span, f.id.as_ref().map(|i| i.name.to_string())),
            AstKind::ArrowFunctionExpression(a) => (a.span, None),
            _ => continue,
        };
        let name = id_name
            .or_else(|| named.get(&span.start).cloned())
            .unwrap_or_else(|| format!("fn@{}", span.start));
        out.push((span.start, span.end, name));
    }
    out
}

fn enclosing_fn_name(fns: &[(u32, u32, String)], at: u32) -> String {
    let mut best: Option<(u32, u32, &String)> = None;
    for (s, e, n) in fns {
        if *s <= at && at <= *e {
            let wider = match best {
                Some((bs, be, _)) => (*e - *s) < (be - bs),
                None => true,
            };
            if wider {
                best = Some((*s, *e, n));
            }
        }
    }
    best.map(|(_, _, n)| n.clone())
        .unwrap_or_else(|| "top".into())
}

fn find_slices(
    semantic: &Semantic,
    d: &Disp<'_>,
    consts: &HashMap<String, S>,
) -> Vec<(String, i64, i64)> {
    let mut out: Vec<(String, i64, i64)> = Vec::new();
    let mut scan = |sw: &SwitchStatement<'_>| {
        if let Expression::SequenceExpression(seq) = &sw.discriminant {
            for e in &seq.expressions {
                if let Expression::AssignmentExpression(a) = strip(e) {
                    if a.operator != AssignmentOperator::Assign {
                        continue;
                    }
                    let tname = match &a.left {
                        AssignmentTarget::AssignmentTargetIdentifier(idf) => {
                            match ref_sym(semantic, idf.reference_id.get()) {
                                Some(sid) => sym_key(semantic, sid),
                                None => idf.name.to_string(),
                            }
                        }
                        _ => continue,
                    };
                    if let Some((sh, m)) = slice_of_r(semantic, &a.right, d.r_sym, d.span.1, consts)
                    {
                        out.push((tname, sh, m));
                    }
                }
            }
        }
    };
    walk_switches(d.body, &mut scan);
    out
}

fn walk_switches<'a>(st: &'a Statement<'a>, f: &mut impl FnMut(&SwitchStatement<'a>)) {
    match st {
        Statement::SwitchStatement(s) => f(s),
        Statement::BlockStatement(b) => b.body.iter().for_each(|s| walk_switches(s, f)),
        Statement::ForStatement(fs) => walk_switches(&fs.body, f),
        Statement::WhileStatement(w) => walk_switches(&w.body, f),
        Statement::IfStatement(i) => {
            walk_switches(&i.consequent, f);
            if let Some(a) = &i.alternate {
                walk_switches(a, f);
            }
        }
        _ => {}
    }
}

fn slice_of_r(
    semantic: &Semantic,
    e: &Expression<'_>,
    r_sym: Option<SymbolId>,
    _limit: u32,
    _consts: &HashMap<String, S>,
) -> Option<(i64, i64)> {
    let rs = r_sym?;
    let is_r = |x: &Expression<'_>| match strip(x) {
        Expression::Identifier(id) => ident_ref_sym(semantic, id) == Some(rs),
        _ => false,
    };
    match strip(e) {
        Expression::BinaryExpression(b) => match b.operator {
            BinaryOperator::ShiftRight | BinaryOperator::ShiftRightZeroFill if is_r(&b.left) => {
                Some((lit_i64(&b.right)?, -1))
            }
            BinaryOperator::BitwiseAnd => {
                if let Expression::BinaryExpression(inner) = strip(&b.left) {
                    if matches!(
                        inner.operator,
                        BinaryOperator::ShiftRight | BinaryOperator::ShiftRightZeroFill
                    ) && is_r(&inner.left)
                    {
                        return Some((lit_i64(&inner.right)?, lit_i64(&b.right)?));
                    }
                }
                if is_r(&b.right) {
                    Some((0, lit_i64(&b.left)?))
                } else if is_r(&b.left) {
                    Some((0, lit_i64(&b.right)?))
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    }
}

fn const_map(semantic: &Semantic) -> HashMap<String, S> {
    let mut total: HashMap<SymbolId, u32> = HashMap::new();
    let mut lit: HashMap<SymbolId, S> = HashMap::new();
    let mut bump = |sid: SymbolId,
                    v: Option<S>,
                    total: &mut HashMap<SymbolId, u32>,
                    lit: &mut HashMap<SymbolId, S>| {
        *total.entry(sid).or_insert(0) += 1;
        match v {
            Some(v) => {
                lit.insert(sid, v);
            }
            None => {
                lit.remove(&sid);
            }
        }
    };
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::VariableDeclarator(d) => {
                if let BindingPattern::BindingIdentifier(b) = &d.id {
                    if let Some(sid) = b.symbol_id.get() {
                        if let Some(init) = d.init.as_ref() {
                            bump(sid, literal_of(init), &mut total, &mut lit);
                        }
                    }
                }
            }
            AstKind::AssignmentExpression(a) => {
                if let Some(sid) = target_sym(semantic, &a.left) {
                    let v = if a.operator == AssignmentOperator::Assign {
                        literal_of(&a.right)
                    } else {
                        None
                    };
                    bump(sid, v, &mut total, &mut lit);
                }
            }
            AstKind::UpdateExpression(u) => {
                if let Some(sid) = simple_target_sym(semantic, &u.argument) {
                    bump(sid, None, &mut total, &mut lit);
                }
            }
            _ => {}
        }
    }
    let mut out = HashMap::new();
    for (sid, v) in lit {
        if total.get(&sid) == Some(&1) {
            out.insert(sym_key(semantic, sid), v);
        }
    }
    out
}

fn lambda_map(semantic: &Semantic) -> HashMap<(SymbolId, String), LamOp> {
    let mut m = HashMap::new();
    for node in semantic.nodes().iter() {
        if let AstKind::AssignmentExpression(a) = node.kind() {
            if a.operator != AssignmentOperator::Assign {
                continue;
            }
            let (tbl, prop) = match &a.left {
                AssignmentTarget::ComputedMemberExpression(cm) => {
                    let p = match computed_prop_str(&cm.expression) {
                        Some(p) => p.to_string(),
                        None => continue,
                    };
                    match strip(&cm.object) {
                        Expression::Identifier(base) => (base, p),
                        _ => continue,
                    }
                }
                AssignmentTarget::StaticMemberExpression(sm) => match strip(&sm.object) {
                    Expression::Identifier(base) => (base, sm.property.name.to_string()),
                    _ => continue,
                },
                _ => continue,
            };
            let sid = match ident_ref_sym(semantic, tbl) {
                Some(s) => s,
                None => continue,
            };
            let op = match strip(&a.right) {
                Expression::FunctionExpression(fe) => {
                    fe.body.as_ref().and_then(|b| body_op(&b.statements))
                }
                Expression::ArrowFunctionExpression(ar) => match &ar.body {
                    ArrowFunctionBody::FunctionBody(fb) => body_op(&fb.statements),
                    _ => None,
                },
                _ => None,
            };
            if let Some(op) = op {
                m.insert((sid, prop), op);
            }
        }
    }
    m
}

fn body_op(stmts: &[Statement<'_>]) -> Option<LamOp> {
    if stmts.len() != 1 {
        return None;
    }
    let ret = match &stmts[0] {
        Statement::ReturnStatement(r) => r,
        _ => return None,
    };
    let arg = strip(ret.argument.as_ref()?);
    Some(match arg {
        Expression::BinaryExpression(b) => LamOp::Bin(binop_str(b.operator)?),
        Expression::LogicalExpression(l) => LamOp::Bin(match l.operator {
            LogicalOperator::And => "&&",
            LogicalOperator::Or => "||",
            LogicalOperator::Coalesce => "??",
        }),
        Expression::UnaryExpression(u) => LamOp::Un(match u.operator {
            UnaryOperator::LogicalNot => "!",
            UnaryOperator::UnaryNegation => "-",
            UnaryOperator::BitwiseNot => "~",
            UnaryOperator::Typeof => "typeof",
            _ => return None,
        }),
        Expression::CallExpression(_) => LamOp::Un("@call"),
        Expression::StaticMemberExpression(m)
            if m.property.name.as_str() == "apply" || m.property.name.as_str() == "call" =>
        {
            LamOp::Un("@call")
        }
        _ => return None,
    })
}

fn binop_str(op: BinaryOperator) -> Option<&'static str> {
    Some(match op {
        BinaryOperator::Addition => "+",
        BinaryOperator::Subtraction => "-",
        BinaryOperator::Multiplication => "*",
        BinaryOperator::Division => "/",
        BinaryOperator::Remainder => "%",
        BinaryOperator::Exponential => "**",
        BinaryOperator::BitwiseAnd => "&",
        BinaryOperator::BitwiseOR => "|",
        BinaryOperator::BitwiseXOR => "^",
        BinaryOperator::ShiftLeft => "<<",
        BinaryOperator::ShiftRight => ">>",
        BinaryOperator::ShiftRightZeroFill => ">>>",
        BinaryOperator::Equality => "==",
        BinaryOperator::Inequality => "!=",
        BinaryOperator::StrictEquality => "===",
        BinaryOperator::StrictInequality => "!==",
        BinaryOperator::LessThan => "<",
        BinaryOperator::LessEqualThan => "<=",
        BinaryOperator::GreaterThan => ">",
        BinaryOperator::GreaterEqualThan => ">=",
        _ => return None,
    })
}

fn assign_op_str(op: AssignmentOperator) -> Option<&'static str> {
    Some(match op {
        AssignmentOperator::Addition => "+",
        AssignmentOperator::Subtraction => "-",
        AssignmentOperator::Multiplication => "*",
        AssignmentOperator::Division => "/",
        AssignmentOperator::Remainder => "%",
        AssignmentOperator::Exponential => "**",
        AssignmentOperator::BitwiseXOR => "^",
        AssignmentOperator::BitwiseAnd => "&",
        AssignmentOperator::BitwiseOR => "|",
        AssignmentOperator::ShiftLeft => "<<",
        AssignmentOperator::ShiftRight => ">>",
        AssignmentOperator::ShiftRightZeroFill => ">>>",
        _ => return None,
    })
}

fn computed_prop_str<'t>(e: &'t Expression<'_>) -> Option<&'t str> {
    match strip(e) {
        Expression::StringLiteral(s) => Some(s.value.as_str()),
        _ => None,
    }
}

fn stmts_of<'x, 'y>(s: &'x Statement<'y>) -> Vec<&'x Statement<'y>> {
    match s {
        Statement::BlockStatement(b) => b.body.iter().collect(),
        other => vec![other],
    }
}

fn un_not(s: &S) -> S {
    S::Un("!", Box::new(s.clone()))
}

fn merge_cond(a: Option<S>, b: S) -> Option<S> {
    match a {
        None => Some(b),
        Some(x) => Some(S::Bin("&&".into(), Box::new(x), Box::new(b))),
    }
}

fn contains_effect(e: &Expression<'_>) -> bool {
    match e {
        Expression::AssignmentExpression(_) | Expression::UpdateExpression(_) => true,
        Expression::ParenthesizedExpression(p) => contains_effect(&p.expression),
        Expression::SequenceExpression(s) => s.expressions.iter().any(contains_effect),
        Expression::ConditionalExpression(c) => {
            contains_effect(&c.test)
                || contains_effect(&c.consequent)
                || contains_effect(&c.alternate)
        }
        Expression::LogicalExpression(l) => contains_effect(&l.left) || contains_effect(&l.right),
        Expression::BinaryExpression(b) => contains_effect(&b.left) || contains_effect(&b.right),
        Expression::UnaryExpression(u) => contains_effect(&u.argument),
        Expression::CallExpression(c) => {
            c.arguments.iter().any(|a| match a {
                Argument::SpreadElement(s) => contains_effect(&s.argument),
                other => other.as_expression().map(contains_effect).unwrap_or(false),
            }) || contains_effect(&c.callee)
        }
        Expression::ArrayExpression(a) => a.elements.iter().any(|el| match el {
            ArrayExpressionElement::SpreadElement(s) => contains_effect(&s.argument),
            other => other.as_expression().map(contains_effect).unwrap_or(false),
        }),
        Expression::ObjectExpression(o) => o.properties.iter().any(|p| match p {
            ObjectPropertyKind::ObjectProperty(op) => contains_effect(&op.value),
            _ => false,
        }),
        Expression::TemplateLiteral(t) => t.expressions.iter().any(contains_effect),
        Expression::AwaitExpression(a) => contains_effect(&a.argument),
        Expression::ChainExpression(c) => match &c.expression {
            ChainElement::CallExpression(call) => call
                .arguments
                .iter()
                .any(|a| a.as_expression().map(contains_effect).unwrap_or(false)),
            ChainElement::StaticMemberExpression(m) => contains_effect(&m.object),
            ChainElement::ComputedMemberExpression(cm) => {
                contains_effect(&cm.object) || contains_effect(&cm.expression)
            }
            _ => false,
        },
        Expression::StaticMemberExpression(m) => contains_effect(&m.object),
        Expression::ComputedMemberExpression(cm) => {
            contains_effect(&cm.object) || contains_effect(&cm.expression)
        }
        Expression::NewExpression(n) => n
            .arguments
            .iter()
            .any(|a| a.as_expression().map(contains_effect).unwrap_or(false)),
        Expression::TaggedTemplateExpression(t) => contains_effect(&t.tag),
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq)]
enum J {
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
    Undefined,
}

fn truthy(j: &J) -> bool {
    match j {
        J::Num(n) => *n != 0.0 && !n.is_nan(),
        J::Str(s) => !s.is_empty(),
        J::Bool(b) => *b,
        J::Null | J::Undefined => false,
    }
}

fn js_str_to_num(s: &str) -> f64 {
    let t = s.trim_matches(|c: char| c.is_whitespace());
    if t.is_empty() {
        return 0.0;
    }
    if t == "Infinity" || t == "+Infinity" {
        return f64::INFINITY;
    }
    if t == "-Infinity" {
        return f64::NEG_INFINITY;
    }
    let neg = t.starts_with('-');
    let body = t.strip_prefix(['+', '-']).unwrap_or(t);
    let lower = body.to_ascii_lowercase();
    if lower == "inf" || lower == "infinity" || lower == "nan" {
        return f64::NAN;
    }
    let mag = if let Some(h) = lower.strip_prefix("0x") {
        match u64::from_str_radix(h, 16) {
            Ok(v) => v as f64,
            Err(_) => return f64::NAN,
        }
    } else if let Some(b) = lower.strip_prefix("0b") {
        match u64::from_str_radix(b, 2) {
            Ok(v) => v as f64,
            Err(_) => return f64::NAN,
        }
    } else if let Some(o) = lower.strip_prefix("0o") {
        match u64::from_str_radix(o, 8) {
            Ok(v) => v as f64,
            Err(_) => return f64::NAN,
        }
    } else {
        match body.parse::<f64>() {
            Ok(v) => v,
            Err(_) => return f64::NAN,
        }
    };
    if neg {
        -mag
    } else {
        mag
    }
}

fn to_num(j: &J) -> f64 {
    match j {
        J::Num(n) => *n,
        J::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        J::Str(s) => js_str_to_num(s),
        J::Undefined => f64::NAN,
        J::Null => 0.0,
    }
}

fn to_i32(j: &J) -> i32 {
    let n = to_num(j);
    if !n.is_finite() {
        return 0;
    }
    let t = n.trunc();
    let m = t.rem_euclid(4294967296.0);
    let u = if m >= 2147483648.0 {
        m - 4294967296.0
    } else {
        m
    };
    u as i32
}

fn to_u32(j: &J) -> u32 {
    to_i32(j) as u32
}

fn shift_count(j: &J) -> u32 {
    to_u32(j) & 31
}

fn to_str(j: &J) -> String {
    match j {
        J::Num(n) => {
            if n.is_nan() {
                "NaN".into()
            } else if *n == f64::INFINITY {
                "Infinity".into()
            } else if *n == f64::NEG_INFINITY {
                "-Infinity".into()
            } else {
                crate::ast::fmt_num_pub(*n)
            }
        }
        J::Str(s) => s.clone(),
        J::Bool(b) => format!("{}", b),
        J::Null => "null".into(),
        J::Undefined => "undefined".into(),
    }
}

fn js_loose_eq(a: &J, b: &J) -> bool {
    use J::*;
    match (a, b) {
        (Null, Undefined) | (Undefined, Null) | (Null, Null) | (Undefined, Undefined) => true,
        (Null, _) | (Undefined, _) | (_, Null) | (_, Undefined) => false,
        (Num(x), Num(y)) => x == y,
        (Str(x), Str(y)) => x == y,
        (Bool(_), _) => js_loose_eq(&Num(to_num(a)), b),
        (_, Bool(_)) => js_loose_eq(a, &Num(to_num(b))),
        (Num(_), Str(_)) | (Str(_), Num(_)) => {
            let x = to_num(a);
            let y = to_num(b);
            !x.is_nan() && !y.is_nan() && x == y
        }
        _ => false,
    }
}

fn js_strict_eq(a: &J, b: &J) -> bool {
    use J::*;
    match (a, b) {
        (Num(x), Num(y)) => x == y,
        (Str(x), Str(y)) => x == y,
        (Bool(x), Bool(y)) => x == y,
        (Null, Null) => true,
        (Undefined, Undefined) => true,
        _ => false,
    }
}

fn j_to_s(j: &J) -> S {
    match j {
        J::Num(v) => S::Num(*v),
        J::Str(v) => S::Str(v.clone()),
        J::Bool(v) => S::Bool(*v),
        J::Null => S::Null,
        J::Undefined => S::Undefined,
    }
}

fn js_parse_int(s: &str) -> f64 {
    let t = s.trim_start();
    let bytes = t.as_bytes();
    let mut i = 0;
    let neg = if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        let n = bytes[i] == b'-';
        i += 1;
        n
    } else {
        false
    };
    let rest = &t[i..];
    let lower = rest.to_ascii_lowercase();
    if let Some(h) = lower.strip_prefix("0x") {
        let digits: String = h.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        return match u64::from_str_radix(&digits, 16) {
            Ok(v) => {
                let r = v as f64;
                if neg {
                    -r
                } else {
                    r
                }
            }
            Err(_) => f64::NAN,
        };
    }
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return f64::NAN;
    }
    let r = digits.parse::<f64>().unwrap_or(f64::NAN);
    if neg {
        -r
    } else {
        r
    }
}

fn bin_js(op: &str, a: &J, b: &J) -> Option<J> {
    use J::*;
    Some(match op {
        "+" => match (a, b) {
            (Str(x), _) => Str(format!("{}{}", x, to_str(b))),
            (_, Str(y)) => Str(format!("{}{}", to_str(a), y)),
            _ => Num(to_num(a) + to_num(b)),
        },
        "-" => Num(to_num(a) - to_num(b)),
        "*" => Num(to_num(a) * to_num(b)),
        "/" => Num(to_num(a) / to_num(b)),
        "%" => Num(to_num(a) % to_num(b)),
        "**" => Num(js_pow(to_num(a), to_num(b))),
        "&" => Num((to_i32(a) & to_i32(b)) as f64),
        "|" => Num((to_i32(a) | to_i32(b)) as f64),
        "^" => Num((to_i32(a) ^ to_i32(b)) as f64),
        "<<" => Num((to_i32(a).wrapping_shl(shift_count(b))) as f64),
        ">>" => Num((to_i32(a).wrapping_shr(shift_count(b))) as f64),
        ">>>" => Num((to_u32(a).wrapping_shr(shift_count(b))) as f64),
        "==" => Bool(js_loose_eq(a, b)),
        "!=" => Bool(!js_loose_eq(a, b)),
        "===" => Bool(js_strict_eq(a, b)),
        "!==" => Bool(!js_strict_eq(a, b)),
        "<" | "<=" | ">" | ">=" => {
            let r = match (a, b) {
                (Str(x), Str(y)) => match op {
                    "<" => x < y,
                    "<=" => x <= y,
                    ">" => x > y,
                    _ => x >= y,
                },
                _ => {
                    let x = to_num(a);
                    let y = to_num(b);
                    if x.is_nan() || y.is_nan() {
                        false
                    } else {
                        match op {
                            "<" => x < y,
                            "<=" => x <= y,
                            ">" => x > y,
                            _ => x >= y,
                        }
                    }
                }
            };
            Bool(r)
        }
        "&&" => {
            if truthy(a) {
                b.clone()
            } else {
                a.clone()
            }
        }
        "||" => {
            if truthy(a) {
                a.clone()
            } else {
                b.clone()
            }
        }
        "??" => match a {
            Null | Undefined => b.clone(),
            _ => a.clone(),
        },
        "in" | "instanceof" => Bool(false),
        _ => return None,
    })
}

fn js_pow(x: f64, y: f64) -> f64 {
    if y == 0.0 {
        return 1.0;
    }
    x.powf(y)
}

fn call_js(f: &str, args: &[S]) -> Option<J> {
    let a: Vec<J> = args.iter().map(eval_js).collect::<Option<Vec<_>>>()?;
    let n0 = || to_num(a.first().unwrap_or(&J::Undefined));
    Some(match f {
        "Math.abs" => J::Num(n0().abs()),
        "Math.pow" => J::Num(js_pow(n0(), to_num(a.get(1)?))),
        "Math.round" => J::Num(n0().round()),
        "Math.floor" => J::Num(n0().floor()),
        "Math.ceil" => J::Num(n0().ceil()),
        "Math.sqrt" => J::Num(n0().sqrt()),
        "Math.trunc" => J::Num(n0().trunc()),
        "Math.max" => J::Num(a.iter().map(to_num).fold(f64::NEG_INFINITY, |m, v| {
            if m.is_nan() || v.is_nan() {
                f64::NAN
            } else {
                m.max(v)
            }
        })),
        "Math.min" => J::Num(a.iter().map(to_num).fold(f64::INFINITY, |m, v| {
            if m.is_nan() || v.is_nan() {
                f64::NAN
            } else {
                m.min(v)
            }
        })),
        "isNaN" => J::Bool(n0().is_nan()),
        "isFinite" => J::Bool(n0().is_finite()),
        "parseInt" => J::Num(js_parse_int(a.first()?.as_str_val()?)),
        "Number" => J::Num(n0()),
        "Boolean" => J::Bool(truthy(a.first()?)),
        "String" => J::Str(a.first().map(to_str).unwrap_or_default()),
        "String.fromCharCode" => {
            let mut s = String::new();
            for j in &a {
                let c = to_u32(j) as u16;
                s.push(char::from_u32(c as u32).unwrap_or('\u{fffd}'));
            }
            J::Str(s)
        }
        _ => return None,
    })
}

impl J {
    fn as_str_val(&self) -> Option<&str> {
        match self {
            J::Str(s) => Some(s),
            _ => None,
        }
    }
}

fn eval_js(s: &S) -> Option<J> {
    match s {
        S::Num(v) => Some(J::Num(*v)),
        S::Str(v) => Some(J::Str(v.clone())),
        S::Bool(v) => Some(J::Bool(*v)),
        S::Null => Some(J::Null),
        S::Undefined => Some(J::Undefined),
        S::Var(_) | S::Env(_) | S::Dyn(_) => None,
        S::Un(op, a) => {
            if *op == "typeof" {
                let name = match &**a {
                    S::Var(_) | S::Env(_) | S::Dyn(_) => return None,
                    other => match eval_js(other)? {
                        J::Num(_) => "number",
                        J::Str(_) => "string",
                        J::Bool(_) => "boolean",
                        J::Undefined => "undefined",
                        J::Null => "object",
                    },
                };
                return Some(J::Str(name.into()));
            }
            let av = eval_js(a)?;
            match *op {
                "!" => Some(J::Bool(!truthy(&av))),
                "-" => Some(J::Num(-to_num(&av))),
                "+" => Some(J::Num(to_num(&av))),
                "~" => Some(J::Num(!to_i32(&av) as f64)),
                "void" => Some(J::Undefined),
                _ => None,
            }
        }
        S::Bin(op, a, b) => {
            let av = eval_js(a)?;
            let bv = eval_js(b)?;
            bin_js(op, &av, &bv)
        }
        S::Call(f, args) => call_js(f, args),
        S::Cond(c, a, b) => {
            let cv = eval_js(c)?;
            if truthy(&cv) {
                eval_js(a)
            } else {
                eval_js(b)
            }
        }
    }
}

pub fn eval_js_bool(s: &S) -> Option<bool> {
    let v = eval_js(s)?;
    Some(truthy(&v))
}

fn resolve_atoms(s: &S, env: &HashMap<String, S>, consts: &HashMap<String, S>) -> S {
    let mut in_prog: Vec<String> = Vec::new();
    resolve_atoms_rec(s, env, consts, &mut in_prog)
}

fn resolve_atoms_rec(
    s: &S,
    env: &HashMap<String, S>,
    consts: &HashMap<String, S>,
    in_prog: &mut Vec<String>,
) -> S {
    match s {
        S::Var(k) => match env.get(k).or_else(|| consts.get(k)) {
            Some(v) if !matches!(v, S::Var(_)) && !in_prog.contains(k) => {
                in_prog.push(k.clone());
                let r = resolve_atoms_rec(v, env, consts, in_prog);
                in_prog.pop();
                r
            }
            _ => s.clone(),
        },
        S::Un(op, a) => S::Un(op, Box::new(resolve_atoms_rec(a, env, consts, in_prog))),
        S::Bin(op, a, b) => S::Bin(
            op.clone(),
            Box::new(resolve_atoms_rec(a, env, consts, in_prog)),
            Box::new(resolve_atoms_rec(b, env, consts, in_prog)),
        ),
        S::Call(f, args) => S::Call(
            f.clone(),
            args.iter()
                .map(|a| resolve_atoms_rec(a, env, consts, in_prog))
                .collect(),
        ),
        S::Cond(c, a, b) => S::Cond(
            Box::new(resolve_atoms_rec(c, env, consts, in_prog)),
            Box::new(resolve_atoms_rec(a, env, consts, in_prog)),
            Box::new(resolve_atoms_rec(b, env, consts, in_prog)),
        ),
        other => other.clone(),
    }
}

fn to_truth(s: &S, b: &mut crate::egraph::truth::TBuilder) -> Option<egg::Id> {
    match s {
        S::Bool(v) => Some(b.lit(if *v { 1 } else { 0 })),
        S::Num(v) if v.fract() == 0.0 && v.is_finite() => Some(b.lit(*v as i64)),
        S::Var(k) | S::Env(k) | S::Dyn(k) => Some(b.var(k)),
        S::Str(k) => Some(b.var(k)),
        S::Null | S::Undefined => Some(b.var("null")),
        S::Un("!", a) => to_truth(a, b).map(|x| b.not(x)),
        S::Bin(op, a, b2) => {
            let l = to_truth(a, b)?;
            let r = to_truth(b2, b)?;
            match op.as_str() {
                "||" => Some(b.b(l, r)),
                "&&" => {
                    let nl = b.not(l);
                    let nr = b.not(r);
                    let any_false = b.b(nl, nr);
                    Some(b.not(any_false))
                }
                "==" | "===" => Some(b.i(l, r)),
                "!=" | "!==" => {
                    let eq = b.i(l, r);
                    Some(b.not(eq))
                }
                "/" => Some(b.div(l, r)),
                ">=" | ">" => {
                    let z = b.lit(0);
                    let _ = z;
                    Some(b.ge(l, r))
                }
                _ => None,
            }
        }
        S::Call(f, args) if f == "Math.pow" => match args.get(1) {
            Some(S::Num(v)) if *v == 0.0 => Some(b.lit(1)),
            _ => None,
        },
        S::Call(f, args) if f == "isNaN" => {
            let x = to_truth(args.first()?, b)?;
            Some(b.isnan(x))
        }
        S::Call(f, args) if f == "Math.abs" => {
            let x = to_truth(args.first()?, b)?;
            Some(b.abs(x))
        }
        S::Cond(c, a, b2) => {
            let t = to_truth(c, b)?;
            let x = to_truth(a, b)?;
            let y = to_truth(b2, b)?;
            let nt = b.not(t);
            let fx = b.b(nt, x);
            let ty = b.b(t, y);
            Some(b.b(fx, ty))
        }
        _ => None,
    }
}

fn truth_fold(s: &S) -> Option<bool> {
    let mut b = crate::egraph::truth::TBuilder::new();
    let root = to_truth(s, &mut b)?;
    let expr = b.finish(root);
    crate::egraph::truth::fold_bool(&expr)
}

fn to_egg(s: &S, b: &mut Builder, depth: u32) -> Option<egg::Id> {
    if depth > 40 {
        return None;
    }
    let rec = |x: &S, b: &mut Builder| to_egg(x, b, depth + 1);
    Some(match s {
        S::Num(v) if v.fract() == 0.0 && v.abs() < 9e15 => b.lit(*v as i64),
        S::Bool(v) => b.lit(if *v { 1 } else { 0 }),
        S::Var(k) => b.var(k),
        S::Un("!", a) => {
            let x = rec(a, b)?;
            b.lnot(x)
        }
        S::Un("~", a) => {
            let x = rec(a, b)?;
            b.bnot(x)
        }
        S::Un("-", a) => {
            let z = b.lit(0);
            let x = rec(a, b)?;
            b.sub(z, x)
        }
        S::Bin(op, a, b2) => {
            let l = rec(a, b)?;
            let r = rec(b2, b)?;
            match op.as_str() {
                "+" => b.add(l, r),
                "-" => b.sub(l, r),
                "*" => b.mul(l, r),
                "/" => b.div(l, r),
                "%" => b.rem(l, r),
                "&" => b.band(l, r),
                "|" => b.bor(l, r),
                "^" => b.xor(l, r),
                "<<" => b.shl(l, r),
                ">>" => b.shr(l, r),
                ">>>" => b.ushr(l, r),
                "==" | "===" => b.eq(l, r),
                "<" => b.lt(l, r),
                _ => return None,
            }
        }
        S::Cond(c, a, b2) => {
            let ci = rec(c, b)?;
            let ai = rec(a, b)?;
            let bi = rec(b2, b)?;
            b.sel(ci, ai, bi)
        }
        _ => return None,
    })
}

fn egg_lit(s: &S, memo: &RefCell<HashMap<String, Option<i64>>>) -> Option<i64> {
    let key = s.keyed();
    if let Some(v) = memo.borrow().get(&key) {
        return *v;
    }
    let mut b = Builder::new();
    let r = match to_egg(s, &mut b, 0) {
        Some(r) => r,
        None => {
            memo.borrow_mut().insert(key, None);
            return None;
        }
    };
    let expr = b.finish(r);
    let can = crate::egraph::canonical(&expr);
    let v = crate::egraph::eval_literal(&can);
    memo.borrow_mut().insert(key, v);
    v
}

pub fn opaque_bool(s: &S) -> Option<bool> {
    let memo = RefCell::new(HashMap::new());
    let tmem = RefCell::new(HashMap::new());
    opaque_bool_in(s, &HashMap::new(), &HashMap::new(), &memo, &tmem)
}

fn opaque_bool_in(
    s: &S,
    env: &HashMap<String, S>,
    consts: &HashMap<String, S>,
    memo: &RefCell<HashMap<String, Option<i64>>>,
    tmem: &RefCell<HashMap<String, Option<bool>>>,
) -> Option<bool> {
    if let Some(j) = eval_js(s) {
        return Some(truthy(&j));
    }
    if let Some(v) = egg_lit(s, memo) {
        return Some(v != 0);
    }
    let resolved = resolve_atoms(s, env, consts);
    let key = resolved.keyed();
    if let Some(hit) = tmem.borrow().get(&key) {
        return *hit;
    }
    let out = truth_fold(&resolved);
    tmem.borrow_mut().insert(key, out);
    out
}

#[derive(Debug, Clone, PartialEq)]
enum Control {
    Run,
    Break(Option<String>),
    Continue(Option<String>),
    Return,
    Throw,
}

#[derive(Clone)]
struct Path {
    env: HashMap<String, S>,
    guard: Option<S>,
    actions: Vec<Action>,
    transitions: Vec<Transition>,
    ctl: Control,
}

const PATH_CAP: usize = 64;
const ACTION_CAP: usize = 4096;
const UNROLL_CAP: usize = 8;
const STATE_CAP: usize = 8192;

struct Interp<'a, 's> {
    semantic: &'a Semantic<'s>,
    consts: &'a HashMap<String, S>,
    lambdas: &'a HashMap<(SymbolId, String), LamOp>,
    r_key: String,
    sub_spans: Vec<u32>,
    memo: RefCell<HashMap<String, Option<i64>>>,
    tmem: RefCell<HashMap<String, Option<bool>>>,
}

impl<'a, 's> Interp<'a, 's> {
    fn ref_key(&self, id: &IdentifierReference) -> String {
        match ident_ref_sym(self.semantic, id) {
            Some(sid) => sym_key(self.semantic, sid),
            None => id.name.to_string(),
        }
    }

    fn bind_key(&self, b: &BindingIdentifier) -> String {
        match b.symbol_id.get() {
            Some(sid) => sym_key(self.semantic, sid),
            None => b.name.to_string(),
        }
    }

    fn simple_key(&self, t: &SimpleAssignmentTarget<'a>) -> Option<String> {
        match t {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(idf) => {
                Some(self.ref_key(idf.as_ref()))
            }
            _ => None,
        }
    }

    fn ident_val(&self, key: &str, env: &HashMap<String, S>) -> S {
        if let Some(v) = env.get(key) {
            return v.clone();
        }
        if let Some(v) = self.consts.get(key) {
            return v.clone();
        }
        match disp(key) {
            "undefined" => S::Undefined,
            "NaN" => S::Num(f64::NAN),
            "Infinity" => S::Num(f64::INFINITY),
            _ => S::Var(key.to_string()),
        }
    }

    fn fold_bool(&self, s: &S, env: &HashMap<String, S>) -> Option<bool> {
        opaque_bool_in(s, env, self.consts, &self.memo, &self.tmem)
    }

    fn push_action(&self, p: &mut Path, a: Action) {
        if p.actions.len() >= ACTION_CAP {
            return;
        }
        match (&p.guard, a) {
            (Some(g), Action::Assign(n, v)) => p.actions.push(Action::Call(
                format!("[{}]? {} = {}", g.render(), n, v.render()),
                vec![],
            )),
            (Some(g), Action::Call(d, args)) => p
                .actions
                .push(Action::Call(format!("[{}]? {}", g.render(), d), args)),
            (_, a) => p.actions.push(a),
        }
    }

    fn push_trans(&self, p: &mut Path, cond: Option<S>, next: i64) {
        let key = (cond.as_ref().map(|c| c.keyed()), next);
        if p.transitions
            .iter()
            .any(|t| (t.cond.as_ref().map(|c| c.keyed()), t.next) == key)
        {
            return;
        }
        p.transitions.push(Transition { cond, next });
    }

    fn run_bfs(&self, d: &Disp<'a>) -> Vec<Block> {
        let mut blocks: Vec<Block> = Vec::new();
        let mut seen: Vec<i64> = Vec::new();
        let mut queue: Vec<i64> = vec![d.init];
        while let Some(state) = queue.pop() {
            if state == 0 || seen.contains(&state) || blocks.len() >= STATE_CAP {
                continue;
            }
            seen.push(state);
            let blk = self.run_state(d, state);
            for t in &blk.transitions {
                if t.next != 0 && !seen.contains(&t.next) && !queue.contains(&t.next) {
                    queue.push(t.next);
                }
            }
            blocks.push(blk);
        }
        blocks.sort_by_key(|b| b.state);
        blocks
    }

    fn run_state(&self, d: &Disp<'a>, state: i64) -> Block {
        let mut env: HashMap<String, S> = self.consts.clone();
        env.insert(self.r_key.clone(), S::Num(state as f64));
        let p0 = Path {
            env,
            guard: None,
            actions: Vec::new(),
            transitions: Vec::new(),
            ctl: Control::Run,
        };
        let mut out: Vec<Path> = Vec::new();
        let refs = stmts_of(d.body);
        self.exec_from(&refs, 0, p0, &mut out);
        let mut actions = Vec::new();
        let mut transitions: Vec<Transition> = Vec::new();

        for mut q in out {
            if q.ctl == Control::Run
                && q.transitions.is_empty()
                && !q.actions.iter().any(|a| matches!(a, Action::Return(_)))
            {
                self.push_action(&mut q, Action::Call("#stuck".into(), vec![]));
            }
            actions.append(&mut q.actions);
            for t in q.transitions {
                let key = (t.cond.as_ref().map(|c| c.keyed()), t.next);
                if !transitions
                    .iter()
                    .any(|x| (x.cond.as_ref().map(|c| c.keyed()), x.next) == key)
                {
                    transitions.push(t);
                }
            }
        }
        Block {
            state,
            actions,
            transitions,
            span: d.span,
        }
    }

    fn exec_from(&self, stmts: &[&Statement<'a>], idx: usize, p: Path, out: &mut Vec<Path>) {
        if out.len() >= PATH_CAP {
            return;
        }
        if p.ctl != Control::Run || idx >= stmts.len() {
            out.push(p);
            return;
        }
        let forks = self.exec_stmt(stmts[idx], p);
        for f in forks {
            self.exec_from(stmts, idx + 1, f, out);
        }
    }

    fn exec_stmt(&self, st: &'a Statement<'a>, p: Path) -> Vec<Path> {
        if let Some(sp) = self.sub_span_hit(st) {
            let mut q = p;
            self.push_action(
                &mut q,
                Action::Call(format!("#sub-dispatch@{}", sp), vec![]),
            );
            return vec![q];
        }
        match st {
            Statement::ExpressionStatement(es) => self.exec_expr_stmt(&es.expression, p),
            Statement::VariableDeclaration(vd) => {
                let mut cur = vec![p];
                for d in &vd.declarations {
                    let mut next = Vec::new();
                    for q in cur {
                        match (&d.id, d.init.as_ref()) {
                            (BindingPattern::BindingIdentifier(b), Some(init)) => {
                                let key = self.bind_key(b);
                                for (mut q2, v) in self.ev(init, q) {
                                    if key == self.r_key {
                                        self.bind_r(&mut q2, &v);
                                    } else {
                                        q2.env.insert(key.clone(), v.clone());
                                        self.push_action(
                                            &mut q2,
                                            Action::Assign(disp(&key).to_string(), v),
                                        );
                                    }
                                    next.push(q2);
                                }
                            }
                            (_, Some(init)) => {
                                for (mut q2, _) in self.ev(init, q) {
                                    self.push_action(
                                        &mut q2,
                                        Action::Call("#destructure".into(), vec![]),
                                    );
                                    next.push(q2);
                                }
                            }
                            (BindingPattern::BindingIdentifier(b), None) => {
                                let mut q2 = q;
                                let key = self.bind_key(b);
                                q2.env.insert(key, S::Undefined);
                                next.push(q2);
                            }
                            _ => next.push(q),
                        }
                    }
                    cur = next;
                    if cur.len() > PATH_CAP {
                        cur.truncate(PATH_CAP);
                    }
                }
                cur
            }
            Statement::BlockStatement(b) => {
                let mut out = Vec::new();
                let refs: Vec<&Statement<'a>> = b.body.iter().collect();
                self.exec_from(&refs, 0, p, &mut out);
                out
            }
            Statement::IfStatement(i) => {
                let mut out = Vec::new();
                for (q, ts) in self.ev(&i.test, p.clone()) {
                    match self.fold_bool(&ts, &q.env) {
                        Some(true) => {
                            let refs = stmts_of(&i.consequent);
                            self.exec_from(&refs, 0, q, &mut out);
                        }
                        Some(false) => match &i.alternate {
                            Some(alt) => {
                                let refs = stmts_of(alt);
                                self.exec_from(&refs, 0, q, &mut out);
                            }
                            None => out.push(q),
                        },
                        None => {
                            let mut q1 = q.clone();
                            q1.guard = merge_cond(q1.guard, ts.clone());
                            let refs = stmts_of(&i.consequent);
                            self.exec_from(&refs, 0, q1, &mut out);
                            let mut q2 = q;
                            q2.guard = merge_cond(q2.guard, un_not(&ts));
                            match &i.alternate {
                                Some(alt) => {
                                    let refs2 = stmts_of(alt);
                                    self.exec_from(&refs2, 0, q2, &mut out);
                                }
                                None => out.push(q2),
                            }
                        }
                    }
                }
                out
            }
            Statement::SwitchStatement(sw) => {
                let mut out = Vec::new();
                for (q, d) in self.ev(&sw.discriminant, p.clone()) {
                    self.exec_switch(sw, q, d, 0, &mut out);
                }
                out
            }
            Statement::ReturnStatement(r) => {
                let mut out = Vec::new();
                match r.argument.as_ref() {
                    Some(arg) => {
                        for (mut q, v) in self.ev(arg, p.clone()) {
                            q.actions.push(Action::Return(Some(v)));
                            q.ctl = Control::Return;
                            out.push(q);
                        }
                    }
                    None => {
                        let mut q = p;
                        q.actions.push(Action::Return(None));
                        q.ctl = Control::Return;
                        out.push(q);
                    }
                }
                out
            }
            Statement::BreakStatement(b) => {
                let mut q = p;
                q.ctl = Control::Break(b.label.as_ref().map(|l| l.name.to_string()));
                vec![q]
            }
            Statement::ContinueStatement(c) => {
                let mut q = p;
                q.ctl = Control::Continue(c.label.as_ref().map(|l| l.name.to_string()));
                vec![q]
            }
            Statement::ThrowStatement(t) => {
                let mut out = Vec::new();
                for (mut q, v) in self.ev(&t.argument, p.clone()) {
                    self.push_action(
                        &mut q,
                        Action::Call(format!("#throw {}", v.render()), vec![]),
                    );
                    q.ctl = Control::Throw;
                    out.push(q);
                }
                out
            }
            Statement::TryStatement(t) => {
                let mut local = Vec::new();
                let refs: Vec<&Statement<'a>> = t.block.body.iter().collect();
                self.exec_from(&refs, 0, p, &mut local);
                let mut mid = Vec::new();
                for q in local {
                    if q.ctl == Control::Throw {
                        match &t.handler {
                            Some(h) => {
                                let mut c = q;
                                c.ctl = Control::Run;
                                if let Some(BindingPattern::BindingIdentifier(b)) =
                                    h.param.as_ref().map(|pp| &pp.pattern)
                                {
                                    let key = self.bind_key(b);
                                    c.env.insert(key, S::Dyn("exception".into()));
                                }
                                let refs2: Vec<&Statement<'a>> = h.body.body.iter().collect();
                                self.exec_from(&refs2, 0, c, &mut mid);
                            }
                            None => mid.push(q),
                        }
                    } else {
                        mid.push(q);
                    }
                }
                match &t.finalizer {
                    Some(fz) => {
                        let mut out = Vec::new();
                        let refs3: Vec<&Statement<'a>> = fz.body.iter().collect();
                        for q in mid {
                            self.exec_from(&refs3, 0, q, &mut out);
                        }
                        out
                    }
                    None => mid,
                }
            }
            Statement::WhileStatement(w) => {
                let mut out = Vec::new();
                self.exec_loop(Some(&w.test), None, &w.body, false, p, &mut out);
                out
            }
            Statement::DoWhileStatement(w) => {
                let mut out = Vec::new();
                self.exec_loop(Some(&w.test), None, &w.body, true, p, &mut out);
                out
            }
            Statement::ForStatement(f) => {
                let mut out = Vec::new();
                let mut cur = vec![p];
                if let Some(fi) = &f.init {
                    if let Some(e) = fi.as_expression() {
                        let mut nxt = Vec::new();
                        for q in cur {
                            for (q2, _) in self.ev(e, q) {
                                nxt.push(q2);
                            }
                        }
                        cur = nxt;
                    } else if let ForStatementInit::VariableDeclaration(vd) = fi {
                        let mut nxt = Vec::new();
                        for q in cur {
                            let mut qq = q;
                            for d in &vd.declarations {
                                if let (BindingPattern::BindingIdentifier(b), Some(init)) =
                                    (&d.id, d.init.as_ref())
                                {
                                    let key = self.bind_key(b);
                                    let mut vs = self.ev(init, qq.clone());
                                    if let Some((mut q2, v)) = vs.pop() {
                                        if key == self.r_key {
                                            self.bind_r(&mut q2, &v);
                                        } else {
                                            q2.env.insert(key, v);
                                        }
                                        qq = q2;
                                    }
                                }
                            }
                            nxt.push(qq);
                        }
                        cur = nxt;
                    }
                }
                let mut out2 = Vec::new();
                for q in cur {
                    self.exec_loop(
                        f.test.as_ref(),
                        f.update.as_ref(),
                        &f.body,
                        false,
                        q,
                        &mut out2,
                    );
                }
                out.extend(out2);
                out
            }
            Statement::LabeledStatement(ls) => {
                let label = ls.label.name.to_string();
                let mut local = Vec::new();
                let body_ref: &Statement<'a> = &ls.body;
                let one = [body_ref];
                self.exec_from(&one, 0, p, &mut local);
                for q in &mut local {
                    match &q.ctl {
                        Control::Break(Some(l)) if *l == label => q.ctl = Control::Run,
                        Control::Continue(Some(l)) if *l == label => q.ctl = Control::Run,
                        _ => {}
                    }
                }
                local
            }
            Statement::FunctionDeclaration(fd) => {
                let mut q = p;
                if let Some(id) = &fd.id {
                    let key = self.bind_key(id);
                    q.env.insert(key.clone(), S::Call("fn".into(), vec![]));
                    self.push_action(&mut q, Action::Call(format!("#fn {}", disp(&key)), vec![]));
                }
                vec![q]
            }
            Statement::EmptyStatement(_) => vec![p],
            Statement::ForInStatement(_) | Statement::ForOfStatement(_) => {
                let mut q = p;
                self.push_action(&mut q, Action::Call("#for-each".into(), vec![]));
                vec![q]
            }
            other => {
                let mut q = p;
                self.push_action(
                    &mut q,
                    Action::Call(format!("#stmt:{:?}", std::mem::discriminant(other)), vec![]),
                );
                vec![q]
            }
        }
    }

    fn sub_span_hit(&self, st: &Statement<'a>) -> Option<u32> {
        let s = st.span().start;
        if self.sub_spans.contains(&s) {
            Some(s)
        } else {
            None
        }
    }

    fn exec_loop(
        &self,
        test: Option<&Expression<'a>>,
        update: Option<&Expression<'a>>,
        body: &Statement<'a>,
        post: bool,
        p: Path,
        out: &mut Vec<Path>,
    ) {
        let mut cur = vec![p];
        let mut done: Vec<Path> = Vec::new();
        let mut it = 0usize;
        loop {
            if it >= UNROLL_CAP {
                for mut q in std::mem::take(&mut cur) {
                    self.push_action(&mut q, Action::Call("#loop-cap".into(), vec![]));
                    done.push(q);
                }
                break;
            }
            if !post || it > 0 {
                let mut keep = Vec::new();
                for q in cur {
                    match test {
                        Some(t) => {
                            for (q2, ts) in self.ev(t, q.clone()) {
                                match self.fold_bool(&ts, &q2.env) {
                                    Some(true) => keep.push(q2),
                                    Some(false) => done.push(q2),
                                    None => {
                                        let mut ka = q2.clone();
                                        ka.guard = merge_cond(ka.guard, ts.clone());
                                        keep.push(ka);
                                        let mut kb = q2;
                                        kb.guard = merge_cond(kb.guard, un_not(&ts));
                                        done.push(kb);
                                    }
                                }
                            }
                        }
                        None => keep.push(q),
                    }
                }
                cur = keep;
                if cur.is_empty() {
                    break;
                }
            }
            let mut after = Vec::new();
            let refs = stmts_of(body);
            for q in cur {
                self.exec_from(&refs, 0, q, &mut after);
            }
            let mut nxt = Vec::new();
            for mut q in after {
                match q.ctl.clone() {
                    Control::Break(None) => {
                        q.ctl = Control::Run;
                        done.push(q);
                    }
                    Control::Continue(None) => {
                        q.ctl = Control::Run;
                        nxt.push(q);
                    }
                    Control::Run => nxt.push(q),
                    _ => done.push(q),
                }
            }
            if let Some(u) = update {
                let mut n2 = Vec::new();
                for q in nxt {
                    for (q2, _) in self.ev(u, q) {
                        n2.push(q2);
                    }
                }
                nxt = n2;
            }
            cur = nxt;
            if cur.is_empty() {
                break;
            }
            it += 1;
            if done.len() + cur.len() > PATH_CAP {
                break;
            }
        }
        if post {
            let mut keep = Vec::new();
            for q in cur {
                match test {
                    Some(t) => {
                        for (q2, ts) in self.ev(t, q.clone()) {
                            match self.fold_bool(&ts, &q2.env) {
                                Some(false) => done.push(q2),
                                _ => keep.push(q2),
                            }
                        }
                    }
                    None => keep.push(q),
                }
            }
            for mut q in keep {
                self.push_action(&mut q, Action::Call("#loop-cap".into(), vec![]));
                done.push(q);
            }
        }
        out.extend(done);
    }

    fn exec_switch(
        &self,
        sw: &SwitchStatement<'a>,
        q: Path,
        d: S,
        depth: u32,
        out: &mut Vec<Path>,
    ) {
        if let S::Cond(c, a, b) = &d {
            if depth < 3 {
                let mut q1 = q.clone();
                q1.guard = merge_cond(q1.guard, (**c).clone());
                self.exec_switch(sw, q1, (**a).clone(), depth + 1, out);
                let mut q2 = q;
                q2.guard = merge_cond(q2.guard, un_not(c));
                self.exec_switch(sw, q2, (**b).clone(), depth + 1, out);
                return;
            }
        }
        let dj = match eval_js(&d) {
            Some(j) => j,
            None => {
                let mut q2 = q;
                self.push_action(
                    &mut q2,
                    Action::Call(format!("#dispatch-unknown {}", d.render()), vec![]),
                );
                out.push(q2);
                return;
            }
        };
        let mut start: Option<usize> = None;
        let mut def: Option<usize> = None;
        for (i, case) in sw.cases.iter().enumerate() {
            match &case.test {
                None => {
                    if def.is_none() {
                        def = Some(i);
                    }
                }
                Some(te) => {
                    let tv = self.sym(te, &q.env);
                    if let Some(tj) = eval_js(&tv) {
                        if js_strict_eq(&dj, &tj) {
                            start = Some(i);
                            break;
                        }
                    }
                }
            }
        }
        match start.or(def) {
            Some(i) => self.run_cases(sw, i, q, out),
            None => out.push(q),
        }
    }

    fn run_cases(&self, sw: &SwitchStatement<'a>, ci: usize, p: Path, out: &mut Vec<Path>) {
        if ci >= sw.cases.len() || out.len() >= PATH_CAP {
            out.push(p);
            return;
        }
        let refs: Vec<&Statement<'a>> = sw.cases[ci].consequent.iter().collect();
        let mut local = Vec::new();
        self.exec_from(&refs, 0, p, &mut local);
        for mut q in local {
            match q.ctl.clone() {
                Control::Break(None) => {
                    q.ctl = Control::Run;
                    out.push(q);
                }
                Control::Run => self.run_cases(sw, ci + 1, q, out),
                _ => out.push(q),
            }
        }
    }

    fn bind_r(&self, q: &mut Path, v: &S) {
        if let Some(n) = self.s_i64(v) {
            self.push_trans(q, q.guard.clone(), n);
            q.env.insert(self.r_key.clone(), S::Num(n as f64));
            return;
        }
        if let S::Cond(c, a, b) = v {
            let na = self.s_i64(a);
            let nb = self.s_i64(b);
            if na.is_some() || nb.is_some() {
                let g1 = merge_cond(q.guard.clone(), (**c).clone());
                let g2 = merge_cond(q.guard.clone(), un_not(c));
                if let Some(n) = na {
                    self.push_trans(q, g1, n);
                }
                if let Some(n) = nb {
                    self.push_trans(q, g2, n);
                }
                q.env.insert(self.r_key.clone(), v.clone());
                return;
            }
        }
        if let Some(j) = eval_js(v) {
            if let J::Num(n) = j {
                if n.fract() == 0.0 && n.is_finite() {
                    let ni = n as i64;
                    self.push_trans(q, q.guard.clone(), ni);
                    q.env.insert(self.r_key.clone(), S::Num(n));
                    return;
                }
            }
        }
        self.push_action(q, Action::Call(format!("#r = {}", v.render()), vec![]));
    }

    fn s_i64(&self, v: &S) -> Option<i64> {
        match v {
            S::Num(n) if n.fract() == 0.0 && n.is_finite() => Some(*n as i64),
            _ => eval_js(v).and_then(|j| match j {
                J::Num(n) if n.fract() == 0.0 && n.is_finite() => Some(n as i64),
                _ => None,
            }),
        }
    }

    fn exec_expr_stmt(&self, e: &Expression<'a>, p: Path) -> Vec<Path> {
        match strip(e) {
            Expression::CallExpression(c) => {
                let mut out = Vec::new();
                for (mut q, (desc, args)) in self.ev_call_parts(c, p.clone()) {
                    self.push_action(&mut q, Action::Call(desc, args));
                    out.push(q);
                }
                out
            }
            Expression::SequenceExpression(s) => {
                let mut cur = vec![p];
                for ex in &s.expressions {
                    let mut nxt = Vec::new();
                    for q in cur {
                        nxt.extend(self.exec_expr_stmt(ex, q));
                    }
                    cur = nxt;
                    if cur.len() > PATH_CAP {
                        cur.truncate(PATH_CAP);
                    }
                }
                cur
            }
            Expression::ConditionalExpression(c) => {
                let mut out = Vec::new();
                for (q, ts) in self.ev(&c.test, p.clone()) {
                    match self.fold_bool(&ts, &q.env) {
                        Some(true) => out.extend(self.exec_expr_stmt(&c.consequent, q)),
                        Some(false) => out.extend(self.exec_expr_stmt(&c.alternate, q)),
                        None => {
                            let mut q1 = q.clone();
                            q1.guard = merge_cond(q1.guard, ts.clone());
                            out.extend(self.exec_expr_stmt(&c.consequent, q1));
                            let mut q2 = q;
                            q2.guard = merge_cond(q2.guard, un_not(&ts));
                            out.extend(self.exec_expr_stmt(&c.alternate, q2));
                        }
                    }
                }
                out
            }
            other => {
                let mut out = Vec::new();
                for (q, _) in self.ev(other, p) {
                    out.push(q);
                }
                out
            }
        }
    }

    fn ev(&self, e: &Expression<'a>, p: Path) -> Vec<(Path, S)> {
        if !contains_effect(e) {
            let v = self.sym(e, &p.env);
            return vec![(p, v)];
        }
        match strip(e) {
            Expression::ParenthesizedExpression(pp) => self.ev(&pp.expression, p),
            Expression::SequenceExpression(s) => {
                let refs: Vec<&Expression<'a>> = s.expressions.iter().collect();
                let mut cur = vec![(p, S::Undefined)];
                for (i, ex) in refs.iter().enumerate() {
                    let mut nxt = Vec::new();
                    for (q, _) in cur {
                        for (q2, v) in self.ev(ex, q) {
                            if i + 1 == refs.len() {
                                nxt.push((q2, v));
                            } else {
                                nxt.push((q2, S::Undefined));
                            }
                        }
                    }
                    cur = nxt;
                    if cur.len() > PATH_CAP {
                        cur.truncate(PATH_CAP);
                    }
                }
                cur
            }
            Expression::AssignmentExpression(a) => self.ev_assign(a, p),
            Expression::UpdateExpression(u) => self.ev_update(u, p),
            Expression::ConditionalExpression(c) => {
                let mut out = Vec::new();
                for (q, ts) in self.ev(&c.test, p.clone()) {
                    match self.fold_bool(&ts, &q.env) {
                        Some(true) => out.extend(self.ev(&c.consequent, q)),
                        Some(false) => out.extend(self.ev(&c.alternate, q)),
                        None => {
                            let mut q1 = q.clone();
                            q1.guard = merge_cond(q1.guard, ts.clone());
                            out.extend(self.ev(&c.consequent, q1));
                            let mut q2 = q;
                            q2.guard = merge_cond(q2.guard, un_not(&ts));
                            out.extend(self.ev(&c.alternate, q2));
                        }
                    }
                }
                out
            }
            Expression::LogicalExpression(l) => {
                let mut out = Vec::new();
                for (q, lv) in self.ev(&l.left, p.clone()) {
                    let short_circuit = match l.operator {
                        LogicalOperator::And => self.fold_bool(&lv, &q.env) == Some(false),
                        LogicalOperator::Or => self.fold_bool(&lv, &q.env) == Some(true),
                        LogicalOperator::Coalesce => {
                            matches!(eval_js(&lv), Some(J::Null) | Some(J::Undefined)) == false
                                && eval_js(&lv).is_some()
                        }
                    };
                    if short_circuit {
                        out.push((q, lv));
                        continue;
                    }
                    match self.fold_bool(&lv, &q.env) {
                        Some(_) => out.extend(self.ev(&l.right, q)),
                        None => {
                            let mut q1 = q.clone();
                            q1.guard = merge_cond(q1.guard, lv.clone());
                            out.extend(self.ev(&l.right, q1));
                            let mut q2 = q;
                            q2.guard = merge_cond(q2.guard, un_not(&lv));
                            out.push((q2, lv.clone()));
                        }
                    }
                }
                out
            }
            Expression::CallExpression(c) => {
                let mut out = Vec::new();
                for (q, (desc, args)) in self.ev_call_parts(c, p.clone()) {
                    out.push((q, S::Call(desc, args)));
                }
                out
            }
            Expression::AwaitExpression(a) => self.ev(&a.argument, p),
            Expression::TemplateLiteral(t) => {
                let mut cur = vec![(p, Vec::new())];
                for ex in &t.expressions {
                    let mut nxt = Vec::new();
                    for (q, mut vals) in cur {
                        for (q2, v) in self.ev(ex, q) {
                            vals.push(v);
                            nxt.push((q2, vals.clone()));
                        }
                    }
                    cur = nxt;
                }
                cur.into_iter()
                    .map(|(q, vals)| {
                        let mut s = String::new();
                        let mut concrete = true;
                        for (i, qv) in t.quasis.iter().enumerate() {
                            s.push_str(qv.value.raw.as_str());
                            if let Some(v) = vals.get(i) {
                                match eval_js(v) {
                                    Some(j) => s.push_str(&to_str(&j)),
                                    None => concrete = false,
                                }
                            }
                        }
                        (
                            q,
                            if concrete {
                                S::Str(s)
                            } else {
                                S::Dyn("tpl".into())
                            },
                        )
                    })
                    .collect()
            }
            other => {
                let v = self.sym(other, &p.env);
                vec![(p, v)]
            }
        }
    }

    fn ev_assign(&self, a: &AssignmentExpression<'a>, p: Path) -> Vec<(Path, S)> {
        let mut out = Vec::new();
        for (mut q, rv) in self.ev(&a.right, p.clone()) {
            match &a.left {
                AssignmentTarget::AssignmentTargetIdentifier(idf) => {
                    let key = self.ref_key(idf.as_ref());
                    let val = if a.operator == AssignmentOperator::Assign {
                        rv.clone()
                    } else if matches!(
                        a.operator,
                        AssignmentOperator::LogicalAnd
                            | AssignmentOperator::LogicalOr
                            | AssignmentOperator::LogicalNullish
                    ) {
                        let old = self.ident_val(&key, &q.env);
                        let take_new = match a.operator {
                            AssignmentOperator::LogicalAnd => {
                                self.fold_bool(&old, &q.env) != Some(false)
                            }
                            AssignmentOperator::LogicalOr => {
                                self.fold_bool(&old, &q.env) == Some(false)
                            }
                            _ => matches!(eval_js(&old), Some(J::Null) | Some(J::Undefined)),
                        };
                        if take_new {
                            rv.clone()
                        } else {
                            old
                        }
                    } else {
                        let old = self.ident_val(&key, &q.env);
                        match assign_op_str(a.operator) {
                            Some(op) => match (eval_js(&old), eval_js(&rv)) {
                                (Some(jo), Some(jr)) => match bin_js(op, &jo, &jr) {
                                    Some(j) => j_to_s(&j),
                                    None => {
                                        S::Bin(op.to_string(), Box::new(old), Box::new(rv.clone()))
                                    }
                                },
                                _ => S::Bin(op.to_string(), Box::new(old), Box::new(rv.clone())),
                            },
                            None => rv.clone(),
                        }
                    };
                    if key == self.r_key {
                        self.bind_r(&mut q, &val);
                    } else {
                        q.env.insert(key.clone(), val.clone());
                        self.push_action(
                            &mut q,
                            Action::Assign(disp(&key).to_string(), val.clone()),
                        );
                    }
                    out.push((q, val));
                }
                other => {
                    let desc = self.target_desc(other, &q.env);
                    self.push_action(
                        &mut q,
                        Action::Call(format!("#set {} = {}", desc, rv.render()), vec![]),
                    );
                    out.push((q, rv));
                }
            }
        }
        out
    }

    fn ev_update(&self, u: &UpdateExpression<'a>, p: Path) -> Vec<(Path, S)> {
        let mut q = p;
        let op = match u.operator {
            UpdateOperator::Increment => "+",
            UpdateOperator::Decrement => "-",
        };
        match self.simple_key(&u.argument) {
            Some(key) => {
                let old = self.ident_val(&key, &q.env);
                let one = S::Num(1.0);
                let newv = match eval_js(&old) {
                    Some(jo) => match bin_js(op, &jo, &J::Num(1.0)) {
                        Some(j) => j_to_s(&j),
                        None => S::Bin(op.to_string(), Box::new(old.clone()), Box::new(one)),
                    },
                    None => S::Bin(op.to_string(), Box::new(old.clone()), Box::new(one)),
                };
                if key == self.r_key {
                    self.bind_r(&mut q, &newv);
                } else {
                    q.env.insert(key.clone(), newv.clone());
                    self.push_action(&mut q, Action::Assign(disp(&key).to_string(), newv.clone()));
                }
                let res = if u.prefix { newv } else { old };
                vec![(q, res)]
            }
            None => {
                let desc = self.update_target_desc(&u.argument, &q.env);
                self.push_action(
                    &mut q,
                    Action::Call(
                        format!("#{}{}", if u.prefix { op } else { "" }, desc),
                        vec![],
                    ),
                );
                vec![(q, S::Dyn("update".into()))]
            }
        }
    }

    fn update_target_desc(
        &self,
        t: &SimpleAssignmentTarget<'a>,
        env: &HashMap<String, S>,
    ) -> String {
        match t {
            SimpleAssignmentTarget::StaticMemberExpression(m) => {
                let base = self.sym(&m.object, env);
                format!("{}.{}", base.render(), m.property.name.as_str())
            }
            SimpleAssignmentTarget::ComputedMemberExpression(cm) => {
                let base = self.sym(&cm.object, env);
                let ix = self.sym(&cm.expression, env);
                format!("{}[{}]", base.render(), ix.render())
            }
            _ => "?update".into(),
        }
    }

    fn sym(&self, e: &Expression<'a>, env: &HashMap<String, S>) -> S {
        match strip(e) {
            Expression::NumericLiteral(n) => S::Num(n.value),
            Expression::StringLiteral(s) => S::Str(s.value.to_string()),
            Expression::BooleanLiteral(b) => S::Bool(b.value),
            Expression::NullLiteral(_) => S::Null,
            Expression::BigIntLiteral(b) => S::Num(b.value.parse::<f64>().unwrap_or(f64::NAN)),
            Expression::RegExpLiteral(_) => S::Dyn("regex".into()),
            Expression::Identifier(id) => {
                let key = self.ref_key(id);
                if key == self.r_key {
                    return env
                        .get(&self.r_key)
                        .cloned()
                        .unwrap_or(S::Var(self.r_key.clone()));
                }
                self.ident_val(&key, env)
            }
            Expression::UnaryExpression(u) => {
                let a = self.sym(&u.argument, env);
                match u.operator {
                    UnaryOperator::LogicalNot => S::Un("!", Box::new(a)),
                    UnaryOperator::UnaryNegation => match a {
                        S::Num(v) => S::Num(-v),
                        other => S::Un("-", Box::new(other)),
                    },
                    UnaryOperator::BitwiseNot => S::Un("~", Box::new(a)),
                    UnaryOperator::Typeof => S::Un("typeof", Box::new(a)),
                    UnaryOperator::UnaryPlus => match a {
                        S::Num(_) | S::Str(_) | S::Bool(_) => {
                            S::Bin("+".into(), Box::new(S::Num(0.0)), Box::new(a))
                        }
                        other => other,
                    },
                    UnaryOperator::Void => S::Undefined,
                    UnaryOperator::Delete => S::Bool(true),
                }
            }
            Expression::BinaryExpression(b) => {
                let l = self.sym(&b.left, env);
                let r = self.sym(&b.right, env);
                match binop_str(b.operator) {
                    Some(op) => match (eval_js(&l), eval_js(&r)) {
                        (Some(jl), Some(jr)) => match bin_js(op, &jl, &jr) {
                            Some(j) => j_to_s(&j),
                            None => S::Bin(op.to_string(), Box::new(l), Box::new(r)),
                        },
                        _ => S::Bin(op.to_string(), Box::new(l), Box::new(r)),
                    },
                    None => S::Dyn("binop".into()),
                }
            }
            Expression::LogicalExpression(l) => {
                let a = self.sym(&l.left, env);
                let b = self.sym(&l.right, env);
                let op = match l.operator {
                    LogicalOperator::And => "&&",
                    LogicalOperator::Or => "||",
                    LogicalOperator::Coalesce => "??",
                };
                match self.fold_bool(&a, env) {
                    Some(t) => {
                        let take_right = (op == "&&" && t) || (op == "||" && !t);
                        if take_right {
                            b
                        } else {
                            a
                        }
                    }
                    None => S::Bin(op.to_string(), Box::new(a), Box::new(b)),
                }
            }
            Expression::ConditionalExpression(c) => {
                let t = self.sym(&c.test, env);
                let a = self.sym(&c.consequent, env);
                let b = self.sym(&c.alternate, env);
                match self.fold_bool(&t, env) {
                    Some(true) => a,
                    Some(false) => b,
                    None => S::Cond(Box::new(t), Box::new(a), Box::new(b)),
                }
            }
            Expression::SequenceExpression(s) => s
                .expressions
                .last()
                .map(|e| self.sym(e, env))
                .unwrap_or(S::Undefined),
            Expression::AssignmentExpression(a) => self.sym(&a.right, env),
            Expression::CallExpression(call) => {
                let (desc, args) = self.call_desc(call, env);
                if let Some(j) = call_js(&desc, &args) {
                    j_to_s(&j)
                } else {
                    S::Call(desc, args)
                }
            }
            Expression::NewExpression(nw) => {
                let (desc, _, _) = self.callee_full(&nw.callee, env);
                S::Call(format!("new {}", desc), vec![])
            }
            Expression::StaticMemberExpression(m) => {
                self.member_sym(&m.object, m.property.name.as_str(), env)
            }
            Expression::ComputedMemberExpression(cm) => {
                if let Some(p) = computed_prop_str(&cm.expression) {
                    return self.member_sym(&cm.object, p, env);
                }
                let base = self.sym(&cm.object, env);
                let ix = self.sym(&cm.expression, env);
                S::Call("index".into(), vec![base, ix])
            }
            Expression::ArrayExpression(arr) => {
                let items: Vec<S> = arr
                    .elements
                    .iter()
                    .filter_map(|el| match el {
                        ArrayExpressionElement::SpreadElement(s) => {
                            Some(self.sym(&s.argument, env))
                        }
                        other => other.as_expression().map(|e| self.sym(e, env)),
                    })
                    .collect();
                S::Call("[]".into(), items)
            }
            Expression::ObjectExpression(obj) => {
                let items: Vec<S> = obj
                    .properties
                    .iter()
                    .map(|p| match p {
                        ObjectPropertyKind::ObjectProperty(op) => {
                            let key = match &op.key {
                                PropertyKey::StaticIdentifier(k) => S::Str(k.name.to_string()),
                                PropertyKey::StringLiteral(sl) => S::Str(sl.value.to_string()),
                                PropertyKey::NumericLiteral(nl) => S::Num(nl.value),
                                _ => S::Str("?".into()),
                            };
                            S::Call("kv".into(), vec![key, self.sym(&op.value, env)])
                        }
                        _ => S::Str("?".into()),
                    })
                    .collect();
                S::Call("{}".into(), items)
            }
            Expression::TemplateLiteral(t) => {
                let mut s = String::new();
                let mut concrete = true;
                for (i, qv) in t.quasis.iter().enumerate() {
                    s.push_str(qv.value.raw.as_str());
                    if let Some(ex) = t.expressions.get(i) {
                        match eval_js(&self.sym(ex, env)) {
                            Some(j) => s.push_str(&to_str(&j)),
                            None => concrete = false,
                        }
                    }
                }
                if concrete {
                    S::Str(s)
                } else {
                    S::Dyn("tpl".into())
                }
            }
            Expression::AwaitExpression(aw) => self.sym(&aw.argument, env),
            Expression::ChainExpression(ch) => match &ch.expression {
                ChainElement::CallExpression(call) => {
                    let (desc, args) = self.call_desc(call, env);
                    S::Call(desc, args)
                }
                ChainElement::StaticMemberExpression(m) => {
                    self.member_sym(&m.object, m.property.name.as_str(), env)
                }
                ChainElement::ComputedMemberExpression(cm) => {
                    let base = self.sym(&cm.object, env);
                    let ix = self.sym(&cm.expression, env);
                    S::Call("index".into(), vec![base, ix])
                }
                _ => S::Dyn("chain".into()),
            },
            Expression::ThisExpression(_) => S::Var("this".into()),
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) => {
                S::Call("fn".into(), vec![])
            }
            _ => S::Dyn("expr".into()),
        }
    }

    fn member_sym(&self, obj: &Expression<'a>, prop: &str, env: &HashMap<String, S>) -> S {
        if let Expression::Identifier(id) = strip(obj) {
            match id.name.as_str() {
                "navigator" | "screen" | "document" | "location" | "history" | "performance" => {
                    return S::Env(format!("{}.{}", id.name.as_str(), prop));
                }
                "window" | "globalThis" | "self" | "global" => {
                    return S::Env(format!("window.{}", prop));
                }
                "Math" => return S::Call(format!("Math.{}", prop), vec![]),
                "Date" => return S::Call(format!("Date.{}", prop), vec![]),
                "JSON" => return S::Call(format!("JSON.{}", prop), vec![]),
                "String" => return S::Call(format!("String.{}", prop), vec![]),
                "Number" => return S::Call(format!("Number.{}", prop), vec![]),
                "Object" => return S::Call(format!("Object.{}", prop), vec![]),
                "Array" => return S::Call(format!("Array.{}", prop), vec![]),
                _ => {}
            }
        }
        if let Expression::StaticMemberExpression(inner) = strip(obj) {
            let base = self.sym(&inner.object, env);
            if let S::Env(p) = base {
                return S::Env(format!("{}.{}", p, prop));
            }
        }
        let base = self.sym(obj, env);
        match base {
            S::Env(p) => S::Env(format!("{}.{}", p, prop)),
            other => S::Call(format!(".{}", prop), vec![other]),
        }
    }

    fn call_desc(&self, call: &CallExpression<'a>, env: &HashMap<String, S>) -> (String, Vec<S>) {
        if let Some(lam) = self.lambda_lookup(&call.callee) {
            let mut args: Vec<S> = Vec::new();
            for a in &call.arguments {
                if let Some(e) = a.as_expression() {
                    args.push(self.sym(e, env));
                }
            }
            let folded = match (lam, args.len()) {
                (LamOp::Bin(op), 2) => match (eval_js(&args[0]), eval_js(&args[1])) {
                    (Some(x), Some(y)) => match bin_js(op, &x, &y) {
                        Some(j) => j_to_s(&j),
                        None => S::Bin(
                            op.to_string(),
                            Box::new(args[0].clone()),
                            Box::new(args[1].clone()),
                        ),
                    },
                    _ => S::Bin(
                        op.to_string(),
                        Box::new(args[0].clone()),
                        Box::new(args[1].clone()),
                    ),
                },
                (LamOp::Un(op), 1) if *op != "@call" => match eval_js(&args[0]) {
                    Some(j) => {
                        let one = S::Un(op, Box::new(j_to_s(&j)));
                        match eval_js(&one) {
                            Some(j2) => j_to_s(&j2),
                            None => one,
                        }
                    }
                    None => S::Un(op, Box::new(args[0].clone())),
                },
                (LamOp::Un("@call"), n) if n >= 1 => {
                    let fname = match &args[0] {
                        S::Var(v) => disp(v).to_string(),
                        other => other.render(),
                    };
                    S::Call(fname, args[1..].to_vec())
                }
                _ => S::Call("lambda".into(), args),
            };
            return match folded {
                S::Call(f, a) => (f, a),
                other => (other.render(), vec![]),
            };
        }
        let (mut desc, mut args, base) = self.callee_full(&call.callee, env);
        for a in &call.arguments {
            if let Some(e) = a.as_expression() {
                args.push(self.sym(e, env));
            }
        }
        if let Some(b) = base {
            desc = format!("{} on {}", desc, b.render());
        }
        (desc, args)
    }

    fn ev_call_parts(&self, call: &CallExpression<'a>, p: Path) -> Vec<(Path, (String, Vec<S>))> {
        let mut arg_paths = vec![(p, Vec::new())];
        for a in &call.arguments {
            if let Some(e) = a.as_expression() {
                if !contains_effect(e) {
                    continue;
                }
                let mut nxt = Vec::new();
                for (q, mut acc) in arg_paths {
                    for (q2, v) in self.ev(e, q) {
                        acc.push(v);
                        nxt.push((q2, acc.clone()));
                    }
                }
                arg_paths = nxt;
                if arg_paths.len() > PATH_CAP {
                    arg_paths.truncate(PATH_CAP);
                }
            }
        }
        let mut out = Vec::new();
        for (mut q, extra) in arg_paths {
            let mut args: Vec<S> = Vec::new();
            let mut it = extra.into_iter();
            for a in &call.arguments {
                match a.as_expression() {
                    Some(e) if contains_effect(e) => {
                        if let Some(v) = it.next() {
                            args.push(v);
                        }
                    }
                    Some(e) => args.push(self.sym(e, &q.env)),
                    None => {}
                }
            }
            let _ = &mut q;
            let desc = self.call_desc_static(call, args, &q.env);
            out.push((q, desc));
        }
        out
    }

    fn call_desc_static(
        &self,
        call: &CallExpression<'a>,
        args: Vec<S>,
        env: &HashMap<String, S>,
    ) -> (String, Vec<S>) {
        if let Some(lam) = self.lambda_lookup(&call.callee) {
            let folded = match (lam, args.len()) {
                (LamOp::Bin(op), 2) => S::Bin(
                    op.to_string(),
                    Box::new(args[0].clone()),
                    Box::new(args[1].clone()),
                ),
                (LamOp::Un(op), 1) if *op != "@call" => S::Un(op, Box::new(args[0].clone())),
                (LamOp::Un("@call"), n) if n >= 1 => {
                    let fname = match &args[0] {
                        S::Var(v) => disp(v).to_string(),
                        other => other.render(),
                    };
                    S::Call(fname, args[1..].to_vec())
                }
                _ => S::Call("lambda".into(), args.clone()),
            };
            return match folded {
                S::Call(f, a) => (f, a),
                other => (other.render(), vec![]),
            };
        }
        let (mut desc, _, base) = self.callee_full(&call.callee, env);
        if let Some(b) = base {
            desc = format!("{} on {}", desc, b.render());
        }
        (desc, args)
    }

    fn lambda_lookup(&self, callee: &Expression<'a>) -> Option<&LamOp> {
        let (base, prop) = match strip(callee) {
            Expression::ComputedMemberExpression(cm) => {
                let p = computed_prop_str(&cm.expression)?.to_string();
                (&cm.object, p)
            }
            Expression::StaticMemberExpression(m) => {
                (&m.object, m.property.name.as_str().to_string())
            }
            _ => return None,
        };
        let id = match strip(base) {
            Expression::Identifier(id) => id,
            _ => return None,
        };
        let sid = ident_ref_sym(self.semantic, id)?;
        self.lambdas.get(&(sid, prop))
    }

    fn callee_full(
        &self,
        e: &Expression<'a>,
        env: &HashMap<String, S>,
    ) -> (String, Vec<S>, Option<S>) {
        match strip(e) {
            Expression::Identifier(id) => (id.name.to_string(), vec![], None),
            Expression::StaticMemberExpression(m) => {
                if let Expression::Identifier(obj) = strip(&m.object) {
                    if self.is_global_ns(obj) {
                        return (
                            format!("{}.{}", obj.name.as_str(), m.property.name.as_str()),
                            vec![],
                            None,
                        );
                    }
                }
                let base = self.sym(&m.object, env);
                let mname = m.property.name.as_str().to_string();
                match &base {
                    S::Env(p) => (format!("{}.{}", p, mname), vec![], None),
                    _ => (mname, vec![], Some(base)),
                }
            }
            Expression::ComputedMemberExpression(cm) => {
                if let Expression::Identifier(obj) = strip(&cm.object) {
                    if self.is_global_ns(obj) {
                        if let Some(p) = computed_prop_str(&cm.expression) {
                            return (format!("{}.{}", obj.name.as_str(), p), vec![], None);
                        }
                    }
                }
                let base = self.sym(&cm.object, env);
                let mname = computed_prop_str(&cm.expression).unwrap_or("?").to_string();
                match &base {
                    S::Env(p) => (format!("{}.{}", p, mname), vec![], None),
                    _ => (mname, vec![], Some(base)),
                }
            }
            Expression::CallExpression(inner) => {
                let (d, a, b) = self.callee_full(&inner.callee, env);
                (format!("{}()", d), a, b)
            }
            _ => ("?call".into(), vec![], None),
        }
    }

    fn target_desc(&self, t: &AssignmentTarget<'a>, env: &HashMap<String, S>) -> String {
        match t {
            AssignmentTarget::ComputedMemberExpression(cm) => {
                let base = self.sym(&cm.object, env);
                let prop = self.sym(&cm.expression, env);
                format!("{}[{}]", base.render(), prop.render())
            }
            AssignmentTarget::StaticMemberExpression(m) => {
                let base = self.sym(&m.object, env);
                format!("{}.{}", base.render(), m.property.name.as_str())
            }
            AssignmentTarget::AssignmentTargetIdentifier(idf) => {
                disp(&self.ref_key(idf)).to_string()
            }
            _ => "?target".into(),
        }
    }

    fn is_global_ns(&self, id: &IdentifierReference) -> bool {
        ident_ref_sym(self.semantic, id).is_none() && is_ns(id.name.as_str())
    }
}

fn is_ns(n: &str) -> bool {
    matches!(
        n,
        "Math" | "JSON" | "String" | "Number" | "Object" | "Array" | "Date"
    )
}

pub fn trace(f: &FlatFn, max_steps: usize) -> Vec<TraceStep> {
    let mut out = Vec::new();
    let mut state = f.init;
    let mut seen: Vec<i64> = Vec::new();
    for _ in 0..max_steps {
        if state == 0 {
            break;
        }
        if seen.contains(&state) {
            out.push(TraceStep {
                state,
                action: Action::Call(format!("#loop-back {}", state), vec![]),
            });
            break;
        }
        seen.push(state);
        let blk = match f.block(state) {
            Some(b) => b,
            None => {
                out.push(TraceStep {
                    state,
                    action: Action::Call("#unknown-state".into(), vec![]),
                });
                break;
            }
        };
        for a in &blk.actions {
            out.push(TraceStep {
                state,
                action: a.clone(),
            });
        }
        if blk.actions.iter().any(|a| matches!(a, Action::Return(_))) {
            break;
        }
        let mut advanced = false;
        for t in &blk.transitions {
            match &t.cond {
                None => {
                    state = t.next;
                    advanced = true;
                    break;
                }
                Some(c) => match opaque_bool(c) {
                    Some(true) => {
                        state = t.next;
                        advanced = true;
                        break;
                    }
                    Some(false) => {}
                    None => {}
                },
            }
        }
        if advanced {
            continue;
        }
        if blk.transitions.is_empty() {
            break;
        }
        for t in &blk.transitions {
            let c = t.cond.as_ref().map(|c| c.render()).unwrap_or_default();
            out.push(TraceStep {
                state,
                action: Action::Call(format!("#alt {} -> {}", c, t.next), vec![]),
            });
        }
        state = blk.transitions[0].next;
    }
    out
}

pub fn render_trace(f: &FlatFn, steps: &[TraceStep]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "== {} (init={}, slices={}) ==\n",
        f.name,
        f.init,
        f.slices
            .iter()
            .map(|(n, s, m)| format!("{}:>>{}&{}", n, s, m))
            .collect::<Vec<_>>()
            .join(" ")
    ));
    for st in steps {
        let a = match &st.action {
            Action::Assign(n, v) => format!("{} = {}", n, v.render()),
            Action::Call(d, args) => {
                if args.is_empty() {
                    d.clone()
                } else {
                    format!(
                        "{} [{}]",
                        d,
                        args.iter()
                            .map(|x| x.render())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            }
            Action::Return(v) => format!(
                "return {}",
                v.as_ref().map(|x| x.render()).unwrap_or_default()
            ),
        };
        out.push_str(&format!("  [{:>4}] {}\n", st.state, a));
    }
    out
}
