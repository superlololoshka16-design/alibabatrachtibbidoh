use egg::{
    define_language, rewrite, Applier, AstSize, EGraph, Extractor, Id, Pattern, RecExpr, Rewrite,
    Runner, SimpleScheduler, Subst, Symbol, Var,
};
use std::sync::LazyLock;

define_language! {
    pub enum T {
        Lit(i64),
        Var(Symbol),
        "or" = Or([Id; 2]),
        "eq" = Eq([Id; 2]),
        "!" = Not(Id),
        "div" = Div([Id; 2]),
        "isnan" = IsNaN(Id),
        "abs" = Abs(Id),
        "ge" = Ge([Id; 2]),
        "bmul" = BMul([Id; 2]),
    }
}

#[derive(Default)]
pub struct Truth;

impl egg::Analysis<T> for Truth {
    type Data = Option<bool>;
    fn make(eg: &mut EGraph<T, Truth>, enode: &T, _id: Id) -> Option<bool> {
        match enode {
            T::Not(a) => eg[*a].data.map(|b| !b),
            T::IsNaN(a) => eg[*a].data.map(|_| false),
            T::Or([x, y]) => match (eg[*x].data, eg[*y].data) {
                (Some(true), _) => Some(true),
                (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
            T::Eq([x, y]) => match (eg[*x].data, eg[*y].data) {
                (Some(a), Some(b)) => Some(a == b),
                _ => None,
            },
            _ => None,
        }
    }
    fn merge(&mut self, a: &mut Option<bool>, b: Option<bool>) -> egg::DidMerge {
        if *a == b {
            return egg::DidMerge(false, false);
        }
        if b.is_none() || a.is_some() {
            return egg::DidMerge(false, true);
        }
        *a = b;
        egg::DidMerge(true, true)
    }
    fn modify(eg: &mut EGraph<T, Truth>, id: Id) {
        if let Some(b) = eg[id].data {
            let lit = eg.add(T::Lit(if b { 1 } else { 0 }));
            let lit = eg.find(lit);
            let cur = eg.find(id);
            if lit != cur {
                eg.union(id, lit);
            }
        }
    }
}

fn class(eg: &EGraph<T, Truth>, id: Id) -> &egg::EClass<T, Option<bool>> {
    let eg = &*eg;
    &eg[eg.find(id)]
}

fn single_lit(eg: &EGraph<T, Truth>, id: Id) -> Option<i64> {
    let vs: Vec<i64> = class(eg, id)
        .nodes
        .iter()
        .filter_map(|n| if let T::Lit(v) = n { Some(*v) } else { None })
        .collect();
    if vs.len() == 1 {
        Some(vs[0])
    } else {
        None
    }
}

fn lit_not_eq(eg: &EGraph<T, Truth>, id: Id, eq: i64) -> bool {
    single_lit(eg, id).map(|v| v != eq).unwrap_or(false)
}

fn is_self_div(eg: &EGraph<T, Truth>, id: Id) -> bool {
    let c = class(eg, id);
    c.nodes
        .iter()
        .any(|n| matches!(n, T::Div([a, b]) if eg.find(*a) == eg.find(*b)))
}

struct FoldIfLit {
    var: Var,
    forbid: i64,
    out: i64,
}

impl Applier<T, Truth> for FoldIfLit {
    fn apply_one(
        &self,
        eg: &mut EGraph<T, Truth>,
        eclass: Id,
        subst: &Subst,
        _ast: Option<&egg::PatternAst<T>>,
        _rule: Symbol,
    ) -> Vec<Id> {
        match subst.get(self.var) {
            Some(id) => {
                if lit_not_eq(eg, *id, self.forbid) {
                    let lit = eg.add(T::Lit(self.out));
                    if eg.union(eclass, lit) {
                        vec![eclass]
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            }
            None => Vec::new(),
        }
    }
    fn vars(&self) -> Vec<Var> {
        vec![self.var]
    }
}

struct FoldSelfDiv {
    var: Var,
    out: i64,
}

impl Applier<T, Truth> for FoldSelfDiv {
    fn apply_one(
        &self,
        eg: &mut EGraph<T, Truth>,
        eclass: Id,
        subst: &Subst,
        _ast: Option<&egg::PatternAst<T>>,
        _rule: Symbol,
    ) -> Vec<Id> {
        match subst.get(self.var) {
            Some(id) => {
                if is_self_div(eg, *id) {
                    let lit = eg.add(T::Lit(self.out));
                    if eg.union(eclass, lit) {
                        vec![eclass]
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            }
            None => Vec::new(),
        }
    }
    fn vars(&self) -> Vec<Var> {
        vec![self.var]
    }
}

fn rules() -> &'static [Rewrite<T, Truth>] {
    static RULES: LazyLock<Vec<Rewrite<T, Truth>>> = LazyLock::new(|| {
        let mut v: Vec<Rewrite<T, Truth>> = vec![
            rewrite!("eq-comm"; "(eq ?a ?c)" => "(eq ?c ?a)"),
            rewrite!("not-not-not"; "(! (! (! ?a)))" => "(! ?a)"),
            rewrite!("not-lit-0"; "(! 0)" => "1"),
            rewrite!("not-lit-1"; "(! 1)" => "0"),
            rewrite!("eq-self-0"; "(eq ?a 0)" => "(! ?a)"),
            rewrite!("eq-lnot-1"; "(eq (! ?a) 1)" => "(! ?a)"),
            rewrite!("eq-lnot-0"; "(eq (! ?a) 0)" => "(! (! ?a))"),
            rewrite!("or-zero-l"; "(or 0 ?y)" => "?y"),
            rewrite!("or-zero-r"; "(or ?y 0)" => "?y"),
            rewrite!("or-absorb"; "(or ?a ?a)" => "?a"),
            rewrite!("or-one-l"; "(or 1 ?y)" => "1"),
            rewrite!("pow-zero"; "(or (isnan (div ?a ?a)) (eq (div ?a ?a) 1))" => "1"),
            rewrite!("pow-zero-r"; "(or (eq (div ?a ?a) 1) (isnan (div ?a ?a)))" => "1"),
            rewrite!("isnan-not"; "(isnan (! ?a))" => "0"),
            rewrite!("div-bool-zero"; "(div (! ?a) 0)" => "(div (! ?a) 0)"),
            rewrite!("abs-not-ge0"; "(ge (abs (! ?a)) 0)" => "1"),
            rewrite!("abs-not-ge-lit"; "(ge (abs (! ?a)) ?k)" => "1"),
            rewrite!("bmul-comm"; "(bmul ?a ?b)" => "(bmul ?b ?a)"),
            rewrite!("isnan-bmul"; "(isnan (bmul ?a ?b))" => "0"),
            rewrite!("ge-bmul-zero"; "(ge (bmul ?a ?b) 0)" => "1"),
            rewrite!("ge-abs-bmul"; "(ge (abs (bmul ?a ?b)) 0)" => "1"),
            rewrite!("pow-zero-bmul"; "(or (isnan (div (bmul ?a ?b) (bmul ?a ?b))) (eq (div (bmul ?a ?b) (bmul ?a ?b)) 1))" => "1"),
        ];
        v.push(
            Rewrite::new(
                "eq-divself",
                "(eq (div ?a ?a) ?k)".parse::<Pattern<T>>().unwrap(),
                FoldIfLit {
                    var: "?k".parse().unwrap(),
                    forbid: 1,
                    out: 0,
                },
            )
            .unwrap(),
        );
        v.push(
            Rewrite::new(
                "eq-divboolzero",
                "(eq (div (! ?a) 0) ?k)".parse::<Pattern<T>>().unwrap(),
                FoldIfLit {
                    var: "?k".parse().unwrap(),
                    forbid: i64::MIN,
                    out: 0,
                },
            )
            .unwrap(),
        );
        v.push(
            Rewrite::new(
                "eq-k-divboolzero",
                "(eq ?k (div (! ?a) 0))".parse::<Pattern<T>>().unwrap(),
                FoldIfLit {
                    var: "?k".parse().unwrap(),
                    forbid: i64::MIN,
                    out: 0,
                },
            )
            .unwrap(),
        );
        v.push(
            Rewrite::new(
                "eq-k-divself",
                "(eq ?k (div ?a ?a))".parse::<Pattern<T>>().unwrap(),
                FoldIfLit {
                    var: "?k".parse().unwrap(),
                    forbid: 1,
                    out: 0,
                },
            )
            .unwrap(),
        );
        v
    });
    &RULES
}

pub fn fold_bool(expr: &RecExpr<T>) -> Option<bool> {
    let runner: Runner<T, Truth, ()> = Runner::new(Truth)
        .with_scheduler(SimpleScheduler)
        .with_time_limit(std::time::Duration::from_millis(
            u64::try_from(expr.len()).unwrap_or(u64::MAX),
        ))
        .with_iter_limit(expr.len())
        .with_node_limit(
            expr.len()
                .saturating_mul(expr.len())
                .saturating_add(rules().len()),
        )
        .with_expr(&expr)
        .run(rules());
    let root = runner.roots[0];
    let eg = &runner.egraph;
    let best = Extractor::new(eg, AstSize).find_best(root).1;
    if best.as_ref().len() < 2 {
        if let Some(T::Lit(v)) = best.as_ref().iter().next() {
            return Some(*v != 0);
        }
    }
    eval(&best)
}

fn eval(expr: &RecExpr<T>) -> Option<bool> {
    let mut vals: Vec<Option<bool>> = Vec::with_capacity(expr.len());
    for n in expr.iter() {
        let g = |i: &Id| vals.get(usize::from(*i)).copied().flatten();
        let v = match n {
            T::Lit(v) => Some(*v != 0),
            T::Var(_) => None,
            T::Or([x, y]) => match (g(x), g(y)) {
                (Some(true), _) => Some(true),
                (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
            T::Eq([x, y]) => match (g(x), g(y)) {
                (Some(a), Some(b)) => Some(a == b),
                _ => None,
            },
            T::Not(x) => g(x).map(|a| !a),
            T::Div(_) => None,
            T::IsNaN(x) => g(x).map(|_| false),
            T::Abs(x) => g(x),
            T::Ge([_, _]) => None,
            T::BMul([x, y]) => match (g(x), g(y)) {
                (Some(false), _) => Some(false),
                (_, Some(false)) => Some(false),
                _ => None,
            },
        };
        vals.push(v);
    }
    vals.last().copied().flatten()
}

pub struct TBuilder {
    nodes: Vec<T>,
}

impl TBuilder {
    pub fn new() -> TBuilder {
        TBuilder { nodes: Vec::new() }
    }
    fn push(&mut self, n: T) -> Id {
        let id: Id = self.nodes.len().into();
        self.nodes.push(n);
        id
    }
    pub fn lit(&mut self, v: i64) -> Id {
        self.push(T::Lit(v))
    }
    pub fn var(&mut self, name: &str) -> Id {
        self.push(T::Var(name.into()))
    }
    pub fn b(&mut self, x: Id, y: Id) -> Id {
        self.push(T::Or([x, y]))
    }
    pub fn i(&mut self, x: Id, y: Id) -> Id {
        self.push(T::Eq([x, y]))
    }
    pub fn not(&mut self, x: Id) -> Id {
        self.push(T::Not(x))
    }
    pub fn div(&mut self, x: Id, y: Id) -> Id {
        self.push(T::Div([x, y]))
    }
    pub fn isnan(&mut self, x: Id) -> Id {
        self.push(T::IsNaN(x))
    }
    pub fn abs(&mut self, x: Id) -> Id {
        self.push(T::Abs(x))
    }
    pub fn ge(&mut self, x: Id, y: Id) -> Id {
        self.push(T::Ge([x, y]))
    }
    pub fn bmul(&mut self, x: Id, y: Id) -> Id {
        self.push(T::BMul([x, y]))
    }
    pub fn finish(&self, _root: Id) -> RecExpr<T> {
        RecExpr::from(self.nodes.clone())
    }
}

impl Default for TBuilder {
    fn default() -> Self {
        TBuilder::new()
    }
}
