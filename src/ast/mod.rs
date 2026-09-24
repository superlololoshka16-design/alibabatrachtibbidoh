pub mod decoder;

mod eval;
mod extract;
mod scan;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use oxc::allocator::Allocator;
use oxc::ast::AstKind;
use oxc::parser::Parser;
use oxc::semantic::Semantic;
use oxc::span::SourceType;
use oxc::syntax::node::NodeId;
use oxc::syntax::reference::ReferenceId;
use oxc::syntax::symbol::SymbolId;

pub use decoder::Decoder;

pub struct Analysis {
    pub decoders: Vec<DecoderInfo>,
    pub wrappers: usize,
    pub rotations: Vec<RotationInfo>,
    pub inlined: usize,
    pub strings: Vec<String>,
    pub key_blobs: Vec<String>,
    pub config_pairs: Vec<(String, String)>,
    pub fragments: Vec<Vec<String>>,
    pub edits: Vec<(u32, u32, String)>,
}

#[derive(Clone)]
pub struct DecoderInfo {
    pub name: String,
    pub shift: i64,
    pub table_len: usize,
    pub xor_out: bool,
}

#[derive(Debug, Clone)]
pub struct RotationInfo {
    pub getter: String,
    pub target: f64,
    pub rotations: usize,
    pub table_len: usize,
}

#[derive(Debug, Clone)]
pub enum Sym {
    Arg(u8),
    Lit(f64),
    Add(Rc<Sym>, Rc<Sym>),
    Sub(Rc<Sym>, Rc<Sym>),
    Mul(Rc<Sym>, Rc<Sym>),
    Div(Rc<Sym>, Rc<Sym>),
    Neg(Rc<Sym>),
}

impl Sym {
    pub fn eval(&self, args: &[f64]) -> f64 {
        match self {
            Sym::Arg(i) => args.get(*i as usize).copied().unwrap_or(f64::NAN),
            Sym::Lit(v) => *v,
            Sym::Add(a, b) => a.eval(args) + b.eval(args),
            Sym::Sub(a, b) => a.eval(args) - b.eval(args),
            Sym::Mul(a, b) => a.eval(args) * b.eval(args),
            Sym::Div(a, b) => a.eval(args) / b.eval(args),
            Sym::Neg(a) => -a.eval(args),
        }
    }

    fn to_math(&self, b: &mut crate::egraph::Builder, depth: u32) -> Option<egg::Id> {
        if depth > 32 {
            return None;
        }
        fn two(
            x: &Sym,
            y: &Sym,
            b: &mut crate::egraph::Builder,
            d: u32,
        ) -> Option<(egg::Id, egg::Id)> {
            let a = x.to_math(b, d + 1)?;
            let c = y.to_math(b, d + 1)?;
            Some((a, c))
        }
        Some(match self {
            Sym::Lit(v) => b.lit(*v as i64),
            Sym::Arg(i) => b.var(&format!("a{}", i)),
            Sym::Add(x, y) => {
                let (l, r) = two(x, y, b, depth)?;
                b.add(l, r)
            }
            Sym::Sub(x, y) => {
                let (l, r) = two(x, y, b, depth)?;
                b.sub(l, r)
            }
            Sym::Mul(x, y) => {
                let (l, r) = two(x, y, b, depth)?;
                b.mul(l, r)
            }
            Sym::Div(x, y) => {
                let (l, r) = two(x, y, b, depth)?;
                b.div(l, r)
            }
            Sym::Neg(x) => {
                let z = b.lit(0);
                let v = x.to_math(b, depth + 1)?;
                b.sub(z, v)
            }
        })
    }

    pub fn canonical_key(&self) -> String {
        let mut b = crate::egraph::Builder::new();
        match self.to_math(&mut b, 0) {
            Some(root) => {
                let expr = b.finish(root);
                crate::egraph::sexpr(&crate::egraph::canonical(&expr))
            }
            None => format!("{:?}", self),
        }
    }
}

pub fn sym_eq_canonical(a: &Sym, b: &Sym) -> bool {
    a.canonical_key() == b.canonical_key()
}

#[derive(Debug, Clone)]
pub enum Val {
    Num(f64),
    Str(String),
    Bool(bool),
    Undefined,

    Func,

    BoundFn { target: Target, pre: Vec<Val> },
    Unknown,
}

impl Val {
    pub fn truthy(&self) -> Option<bool> {
        match self {
            Val::Num(v) => Some(*v != 0.0 && !v.is_nan()),
            Val::Str(s) => Some(!s.is_empty()),
            Val::Bool(b) => Some(*b),
            Val::Undefined => Some(false),
            Val::Func => Some(true),
            Val::BoundFn { .. } => Some(true),
            Val::Unknown => None,
        }
    }

    pub fn to_num(&self) -> f64 {
        match self {
            Val::Num(v) => *v,
            Val::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            Val::Str(s) => {
                let t = s.trim();
                if t.is_empty() {
                    f64::NAN
                } else {
                    t.parse::<f64>().unwrap_or(f64::NAN)
                }
            }
            _ => f64::NAN,
        }
    }

    pub fn to_int32(&self) -> i32 {
        let n = self.to_num();
        if !n.is_finite() {
            return 0;
        }
        let t = n.trunc();
        let m = t.rem_euclid(4294967296.0);
        let u = if m >= 2147483648.0 { m - 4294967296.0 } else { m };
        u as i32
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ObjOp {
    Add,
    Sub,
    Mul,
    Div,
    Or,
    And,
    Xor,
    Gt,
    Lt,
    Call12,
    Call21,
}

#[derive(Debug, Clone)]
pub enum Target {
    Dec(usize),
    Wrap(SymbolId),
}

pub struct Wrapper {
    pub target: Target,
    pub index: Sym,
    pub xor: Option<Sym>,
}

pub struct Ctx<'a> {
    pub semantic: Semantic<'a>,

    pub span_sym: HashMap<u32, SymbolId>,
    pub decoders: Vec<Decoder>,
    pub decoder_sym: HashMap<SymbolId, usize>,
    pub wrapper_sym: HashMap<SymbolId, Wrapper>,
    pub alias_sym: HashMap<SymbolId, SymbolId>,
    pub getters: HashMap<SymbolId, Rc<RefCell<Vec<String>>>>,

    pub decl_tables: HashMap<SymbolId, Rc<RefCell<Vec<String>>>>,
    pub objfns: HashMap<(SymbolId, String), ObjOp>,

    pub builtin_paths: HashMap<SymbolId, String>,

    pub consts: HashMap<SymbolId, Val>,

    pub seq_values: HashMap<SymbolId, Val>,

    pub assign_results: HashMap<NodeId, Val>,

    pub folded: HashMap<NodeId, Val>,

    pub inlined: usize,

    pub dead_spans: Vec<(oxc::span::Span, &'static str)>,
    pub source: &'a str,
}

pub fn analyze_src(source: &str) -> Result<Analysis, String> {
    let allocator = Allocator::default();
    let source_type = SourceType::cjs();
    let ret = Parser::new(&allocator, source, source_type).parse();
    if ret.diagnostics.len() > 3 {
        return Err(format!("parse errors: {}", ret.diagnostics.len()));
    }
    let program = ret.program;

    let sem_ret = oxc::semantic::SemanticBuilder::new()
        .with_check_syntax_error(false)
        .with_build_nodes(true)
        .build(&program);
    let semantic = sem_ret.semantic;
    if std::env::var("ZAIC_DEBUG").is_ok() {
        eprintln!("[dbg] nodes={} diagnostics={} symbols={}",
            semantic.nodes().len(), ret.diagnostics.len(), semantic.scoping().symbol_ids().count());
    }

    let mut ctx = Ctx {
        semantic,
        span_sym: HashMap::new(),
        decoders: Vec::new(),
        decoder_sym: HashMap::new(),
        wrapper_sym: HashMap::new(),
        alias_sym: HashMap::new(),
        getters: HashMap::new(),
        decl_tables: HashMap::new(),
        objfns: HashMap::new(),
        builtin_paths: HashMap::new(),
        consts: HashMap::new(),
        seq_values: HashMap::new(),
        assign_results: HashMap::new(),
        folded: HashMap::new(),
        inlined: 0,
        dead_spans: Vec::new(),
        source,
    };

    let scoping = ctx.semantic.scoping();
    let mut span_sym = HashMap::new();
    for sid in scoping.symbol_ids() {
        let sp = scoping.symbol_span(sid);
        span_sym.insert(sp.start, sid);
    }
    ctx.span_sym = span_sym;

    scan::passive_scan(&mut ctx);

    scan::scan_decoders(&mut ctx);

    let rotations = scan::run_rotations(&mut ctx)?;

    let wrapper_count = scan::scan_wrappers_fixpoint(&mut ctx);

    eval::scan_sequential(&mut ctx);

    fold_fixpoint(&mut ctx);

    let (strings, key_blobs) = extract::extract_keys(&ctx);

    let (config_pairs, fragments) = scan::scan_config_pairs(&ctx);

    let decoders = ctx
        .decoders
        .iter()
        .map(|d| DecoderInfo {
            name: d.name.clone(),
            shift: d.shift,
            table_len: d.table.borrow().len(),
            xor_out: d.xor_out,
        })
        .collect();

    Ok(Analysis {
        decoders,
        wrappers: wrapper_count,
        rotations,
        inlined: ctx.inlined,
        strings,
        key_blobs,
        config_pairs,
        fragments,
        edits: build_deobfuscation_edits(&ctx),
    })
}

fn build_deobfuscation_edits(ctx: &Ctx) -> Vec<(u32, u32, String)> {
    use oxc::span::GetSpan;
    let mut edits: Vec<(u32, u32, String)> = Vec::new();

    for node in ctx.semantic.nodes().iter() {
        if let Some(Val::Str(s)) = ctx.folded.get(&node.id()) {
            if !s.is_empty() {
                let sp = node.span();
                let esc = escape_js_string(s);
                edits.push((sp.start, sp.end, format!("'{}'", esc)));
            }
        }
    }

    for (sp, repl) in &ctx.dead_spans {
        edits.push((sp.start, sp.end, repl.to_string()));
    }
    edits.sort_by(|a, b| b.0.cmp(&a.0));
    edits.dedup_by(|a, b| a.0 == b.0);

    let all: Vec<(u32, u32)> = edits.iter().map(|(s, e, _)| (*s, *e)).collect();
    edits.retain(|(s, e, _)| {
        !all
            .iter()
            .any(|(s2, e2)| *s2 <= *s && *e <= *e2 && (s2, e2) != (s, e))
    });
    edits
}

fn escape_js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn analyze_file(path: &str) -> Result<Analysis, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
    analyze_src(&src)
}

fn fold_fixpoint(ctx: &mut Ctx) {
    for _ in 0..12 {
        let before = ctx.folded.len();
        let nodes: Vec<(NodeId, AstKind)> = ctx
            .semantic
            .nodes()
            .iter()
            .map(|n| (n.id(), n.kind()))
            .collect();
        let mut new_folds: Vec<(NodeId, Val)> = Vec::new();
        for (id, kind) in nodes {
            if ctx.folded.contains_key(&id) {
                continue;
            }
            let val = match kind {
                AstKind::CallExpression(call) => {
                    match eval::eval_call_node(ctx, call) {
                        Some(Val::Str(s)) => {
                            ctx.inlined += 1;
                            Some(Val::Str(s))
                        }
                        Some(v @ (Val::Num(_) | Val::Bool(_) | Val::Undefined)) => Some(v),
                        _ => None,
                    }
                }
                AstKind::BinaryExpression(bin)
                    if bin.operator == oxc::syntax::operator::BinaryOperator::Addition =>
                {
                    let l = eval::eval_expr(ctx, &bin.left);
                    let r = eval::eval_expr(ctx, &bin.right);
                    match (l, r) {
                        (Val::Str(a), Val::Str(b)) => Some(Val::Str(format!("{}{}", a, b))),
                        (Val::Str(a), Val::Num(b)) if b.is_finite() => {
                            Some(Val::Str(format!("{}{}", a, fmt_num_pub(b))))
                        }
                        (Val::Num(a), Val::Str(b)) if a.is_finite() => {
                            Some(Val::Str(format!("{}{}", fmt_num_pub(a), b)))
                        }
                        (Val::Num(a), Val::Num(b)) => Some(Val::Num(a + b)),
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some(v) = val {
                new_folds.push((id, v));
            }
        }
        for (id, v) in new_folds {
            ctx.folded.insert(id, v);
        }
        if ctx.folded.len() == before {
            break;
        }
    }
}

pub fn fmt_num_pub(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}

pub(crate) fn ref_symbol(ctx: &Ctx, reference_id: Option<ReferenceId>) -> Option<SymbolId> {
    let rid = reference_id?;
    ctx.semantic.scoping().get_reference(rid).symbol_id()
}
