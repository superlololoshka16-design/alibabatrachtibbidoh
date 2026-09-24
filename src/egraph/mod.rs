pub mod ops;
pub mod truth;

use egg::rewrite;
use egg::{
    define_language, Analysis, AstSize, DidMerge, EGraph, Id, RecExpr, Rewrite, Runner, Searcher,
    SimpleScheduler, Symbol,
};
use std::sync::OnceLock;

define_language! {
    pub enum Math {
        Lit(i64),
        Var(Symbol),
        "+" = Add([Id; 2]),
        "-" = Sub([Id; 2]),
        "*" = Mul([Id; 2]),
        "/" = Div([Id; 2]),
        "%" = Mod([Id; 2]),
        "&" = And([Id; 2]),
        "|" = Or([Id; 2]),
        "^" = Xor([Id; 2]),
        "~" = Not(Id),
        "<<" = Shl([Id; 2]),
        ">>" = Shr([Id; 2]),
        ">>>" = UShr([Id; 2]),
        "<<<" = Rol([Id; 2]),
        "u32" = Wrap32(Id),
        "sel" = Sel([Id; 3]),
        "==" = Eq([Id; 2]),
        "<" = Lt([Id; 2]),
        "!" = LNot(Id),
    }
}

#[derive(Default)]
pub struct MinLang;

impl Analysis<Math> for MinLang {
    type Data = ();
    fn merge(&mut self, _to: &mut (), _from: ()) -> DidMerge {
        DidMerge(false, false)
    }
    fn make(_egraph: &mut EGraph<Math, MinLang>, _enode: &Math, _id: Id) {}
    fn modify(_egraph: &mut EGraph<Math, MinLang>, _id: Id) {}
}

pub fn rules() -> &'static [Rewrite<Math, MinLang>] {
    static RULES: OnceLock<Vec<Rewrite<Math, MinLang>>> = OnceLock::new();
    RULES.get_or_init(|| {
        let identity: Vec<Rewrite<Math, MinLang>> = vec![
            rewrite!("add-0-l"; "(+ ?a 0)" => "?a"),
            rewrite!("add-0-r"; "(+ 0 ?a)" => "?a"),
            rewrite!("sub-0-r"; "(- ?a 0)" => "?a"),
            rewrite!("sub-self"; "(- ?a ?a)" => "0"),
            rewrite!("sub-cancel"; "(- (+ ?a ?b) ?b)" => "?a"),
            rewrite!("sub-cancel-r"; "(- (+ ?a ?b) ?a)" => "?b"),
            rewrite!("sub-neg"; "(- 0 ?a)" => "(* -1 ?a)"),
            rewrite!("neg-neg"; "(* -1 (* -1 ?a))" => "?a"),
            rewrite!("mul-1-l"; "(* 1 ?a)" => "?a"),
            rewrite!("mul-1-r"; "(* ?a 1)" => "?a"),
            rewrite!("mul-0-l"; "(* 0 ?a)" => "0"),
            rewrite!("mul-0-r"; "(* ?a 0)" => "0"),
            rewrite!("div-1"; "(/ ?a 1)" => "?a"),
            rewrite!("mod-1"; "(% ?a 1)" => "0"),
            rewrite!("xor-0-l"; "(^ ?a 0)" => "?a"),
            rewrite!("xor-0-r"; "(^ 0 ?a)" => "?a"),
            rewrite!("xor-self"; "(^ ?a ?a)" => "0"),
            rewrite!("xor-cancel"; "(^ (^ ?a ?b) ?b)" => "?a"),
            rewrite!("or-0-l"; "(| ?a 0)" => "?a"),
            rewrite!("or-0-r"; "(| 0 ?a)" => "?a"),
            rewrite!("or-self"; "(| ?a ?a)" => "?a"),
            rewrite!("and--1-l"; "(& ?a -1)" => "?a"),
            rewrite!("and--1-r"; "(& -1 ?a)" => "?a"),
            rewrite!("and-0-l"; "(& ?a 0)" => "0"),
            rewrite!("and-0-r"; "(& 0 ?a)" => "0"),
            rewrite!("and-self"; "(& ?a ?a)" => "?a"),
            rewrite!("not-not"; "(~ (~ ?a))" => "?a"),
            rewrite!("lnot-lnot"; "(! (! ?a))" => "?a"),
            rewrite!("shl-0"; "(<< ?a 0)" => "?a"),
            rewrite!("shr-0"; "(>> ?a 0)" => "?a"),
            rewrite!("ushr-0"; "(>>> ?a 0)" => "?a"),
            rewrite!("mul-neg-distr"; "(* -1 (- ?a ?b))" => "(- ?b ?a)"),
            rewrite!("add-neg"; "(+ ?a (* -1 ?b))" => "(- ?a ?b)"),
            rewrite!("sub-of-neg"; "(- ?a (* -1 ?b))" => "(+ ?a ?b)"),
            rewrite!("sel-true"; "(sel 1 ?a ?b)" => "?a"),
            rewrite!("sel-false"; "(sel 0 ?a ?b)" => "?b"),
            rewrite!("eq-lit"; "(== ?a ?a)" => "1"),
        ];
        let mba: Vec<Rewrite<Math, MinLang>> = vec![
            rewrite!("mba-add-xorcarry"; "(+ (^ ?a ?b) (<< (& ?a ?b) 1))" => "(+ ?a ?b)"),
            rewrite!("mba-carry-parts"; "(+ (<< (& ?a ?b) 1) (^ ?a ?b))" => "(+ ?a ?b)"),
            rewrite!("mba-or-parts"; "(+ (^ ?a ?b) (& ?a ?b))" => "(| ?a ?b)"),
            rewrite!("mba-xor-or-and"; "(^ (| ?a ?b) (& ?a ?b))" => "(^ ?a ?b)"),
            rewrite!("mba-not-sub"; "(~ ?a)" => "(- -1 ?a)"),
            rewrite!("mba-xor-and-mask"; "(^ ?a (& ?a ?b))" => "(& ?a (- -1 ?b))"),
        ];
        let structure: Vec<Rewrite<Math, MinLang>> = vec![
            rewrite!("add-comm"; "(+ ?a ?b)" => "(+ ?b ?a)"),
            rewrite!("add-assoc"; "(+ (+ ?a ?b) ?c)" => "(+ ?a (+ ?b ?c))"),
            rewrite!("mul-comm"; "(* ?a ?b)" => "(* ?b ?a)"),
            rewrite!("mul-assoc"; "(* (* ?a ?b) ?c)" => "(* ?a (* ?b ?c))"),
            rewrite!("shl-add"; "(<< (+ ?a ?b) ?n)" => "(+ (<< ?a ?n) (<< ?b ?n))"),
            rewrite!("shl-shl"; "(<< (<< ?a ?m) ?n)" => "(<< ?a (+ ?m ?n))"),
            rewrite!("shl-mul2"; "(<< ?a 1)" => "(* 2 ?a)"),
        ];
        let mut all = identity;
        all.extend(mba);
        all.extend(structure);
        all
    })
}

pub fn canonical(expr: &RecExpr<Math>) -> RecExpr<Math> {
    let runner: Runner<Math, MinLang, ()> = Runner::new(MinLang)
        .with_scheduler(SimpleScheduler)
        .with_iter_limit(30)
        .with_node_limit(120_000)
        .with_expr(expr)
        .run(rules());
    let root = runner.roots[0];
    egg::Extractor::new(&runner.egraph, AstSize)
        .find_best(root)
        .1
}

pub fn saturate_pair(expr: &RecExpr<Math>, pattern: &str) -> bool {
    let runner: Runner<Math, MinLang, ()> = Runner::new(MinLang)
        .with_scheduler(SimpleScheduler)
        .with_iter_limit(30)
        .with_node_limit(120_000)
        .with_expr(expr)
        .run(rules());
    let pat: egg::Pattern<Math> = pattern.parse().unwrap();
    !pat.search(&runner.egraph).is_empty()
}

pub fn eval_literal(expr: &RecExpr<Math>) -> Option<i64> {
    let mut vals: Vec<Option<i64>> = Vec::with_capacity(expr.len());
    for n in expr.iter() {
        let g = |i: &Id| vals.get(usize::from(*i)).copied().flatten();
        let v = match n {
            Math::Lit(v) => Some(*v),
            Math::Var(_) => None,
            Math::Add([a, b]) => Some(g(a)?.wrapping_add(g(b)?)),
            Math::Sub([a, b]) => Some(g(a)?.wrapping_sub(g(b)?)),
            Math::Mul([a, b]) => Some(g(a)?.wrapping_mul(g(b)?)),
            Math::Div([a, b]) => {
                let d = g(b)?;
                if d == 0 {
                    None
                } else {
                    Some(g(a)?.wrapping_div(d))
                }
            }
            Math::Mod([a, b]) => {
                let d = g(b)?;
                if d == 0 {
                    None
                } else {
                    Some(g(a)?.wrapping_rem(d))
                }
            }
            Math::And([a, b]) => Some(g(a)? & g(b)?),
            Math::Or([a, b]) => Some(g(a)? | g(b)?),
            Math::Xor([a, b]) => Some(g(a)? ^ g(b)?),
            Math::Not(a) => Some(!g(a)?),
            Math::Shl([a, b]) => Some(g(a)?.wrapping_shl(g(b)? as u32)),
            Math::Shr([a, b]) => Some(g(a)?.wrapping_shr(g(b)? as u32)),
            Math::UShr([a, b]) => Some(((g(a)? as u32).wrapping_shr(g(b)? as u32 & 31)) as i64),
            Math::Rol([a, b]) => Some((g(a)? as u32).rotate_left(g(b)? as u32 & 31) as i64),
            Math::Wrap32(a) => Some(g(a)? as i32 as i64),
            Math::Sel([c, a, b]) => {
                if g(c)? != 0 {
                    Some(g(a)?)
                } else {
                    Some(g(b)?)
                }
            }
            Math::Eq([a, b]) => Some((g(a)? == g(b)?) as i64),
            Math::Lt([a, b]) => Some((g(a)? < g(b)?) as i64),
            Math::LNot(a) => Some((g(a)? == 0) as i64),
        };
        vals.push(v);
    }
    vals.last().copied().flatten()
}

pub fn expr_vars(expr: &RecExpr<Math>) -> Vec<Symbol> {
    let mut out = Vec::new();
    for n in expr.iter() {
        if let Math::Var(s) = n {
            out.push(*s);
        }
    }
    out.sort();
    out.dedup();
    out
}

pub struct Builder {
    nodes: Vec<Math>,
}

macro_rules! push_bin {
    ($name:ident, $cons:ident) => {
        pub fn $name(&mut self, a: Id, b: Id) -> Id {
            let id: Id = self.nodes.len().into();
            self.nodes.push(Math::$cons([a, b]));
            id
        }
    };
}

macro_rules! push_un {
    ($name:ident, $cons:ident) => {
        pub fn $name(&mut self, a: Id) -> Id {
            let id: Id = self.nodes.len().into();
            self.nodes.push(Math::$cons(a));
            id
        }
    };
}

impl Builder {
    pub fn new() -> Builder {
        Builder { nodes: Vec::new() }
    }
    pub fn lit(&mut self, v: i64) -> Id {
        let id: Id = self.nodes.len().into();
        self.nodes.push(Math::Lit(v));
        id
    }
    pub fn var(&mut self, name: &str) -> Id {
        let id: Id = self.nodes.len().into();
        self.nodes.push(Math::Var(name.into()));
        id
    }
    push_bin!(add, Add);
    push_bin!(sub, Sub);
    push_bin!(mul, Mul);
    push_bin!(div, Div);
    push_bin!(rem, Mod);
    push_bin!(band, And);
    push_bin!(bor, Or);
    push_bin!(xor, Xor);
    push_bin!(shl, Shl);
    push_bin!(shr, Shr);
    push_bin!(ushr, UShr);
    push_bin!(rol, Rol);
    push_bin!(eq, Eq);
    push_bin!(lt, Lt);
    push_un!(bnot, Not);
    push_un!(wrap32, Wrap32);
    push_un!(lnot, LNot);
    pub fn sel(&mut self, c: Id, a: Id, b: Id) -> Id {
        let id: Id = self.nodes.len().into();
        self.nodes.push(Math::Sel([c, a, b]));
        id
    }
    pub fn finish(&self, _root: Id) -> RecExpr<Math> {
        RecExpr::from(self.nodes.clone())
    }
}

impl Default for Builder {
    fn default() -> Self {
        Builder::new()
    }
}

pub fn sexpr(expr: &RecExpr<Math>) -> String {
    format!("{}", expr)
}
