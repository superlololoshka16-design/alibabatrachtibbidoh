use oxc::allocator::{Allocator, CloneIn};
use oxc::ast::builder::AstBuilder;

use oxc::ast::ast::*;
use oxc::ast_visit::VisitMut;
use oxc::parser::Parser;
use oxc::span::{GetSpan, SourceType};

fn num_lit(e: &Expression) -> Option<f64> {
    match e {
        Expression::NumericLiteral(n) => Some(n.value),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            match &u.argument {
                Expression::NumericLiteral(n) => Some(-n.value),
                _ => None,
            }
        }
        _ => None,
    }
}

fn eval_const(e: &Expression) -> Option<f64> {
    match e {
        Expression::NumericLiteral(n) => Some(n.value),
        Expression::BooleanLiteral(b) => Some(if b.value { 1.0 } else { 0.0 }),
        Expression::UnaryExpression(u) => match u.operator {
            UnaryOperator::LogicalNot => {
                eval_const(&u.argument).map(|v| if v != 0.0 && !v.is_nan() { 0.0 } else { 1.0 })
            }
            UnaryOperator::UnaryNegation => eval_const(&u.argument).map(|v| -v),
            UnaryOperator::BitwiseNot => eval_const(&u.argument).map(|v| !(v as i32) as f64),
            UnaryOperator::UnaryPlus => eval_const(&u.argument),
            _ => None,
        },
        Expression::BinaryExpression(b) => {
            let l = eval_const(&b.left)?;
            let r = eval_const(&b.right)?;
            use BinaryOperator::*;
            Some(match b.operator {
                Addition => l + r,
                Subtraction => l - r,
                Multiplication => l * r,
                Division => l / r,
                Remainder => l % r,
                BitwiseAnd => ((l as i32) & (r as i32)) as f64,
                BitwiseOR => ((l as i32) | (r as i32)) as f64,
                BitwiseXOR => ((l as i32) ^ (r as i32)) as f64,
                ShiftLeft => ((l as i32).wrapping_shl(r as u32 & 31)) as f64,
                ShiftRight => ((l as i32).wrapping_shr(r as u32 & 31)) as f64,
                ShiftRightZeroFill => ((l as u32).wrapping_shr(r as u32 & 31)) as f64,
                Equality | StrictEquality => ((l == r) || (l.is_nan() && r.is_nan())) as i32 as f64,
                Inequality | StrictInequality => !((l == r) || (l.is_nan() && r.is_nan())) as i32 as f64,
                LessThan => (l < r) as i32 as f64,
                LessEqualThan => (l <= r) as i32 as f64,
                GreaterThan => (l > r) as i32 as f64,
                GreaterEqualThan => (l >= r) as i32 as f64,
                Exponential => l.powf(r),
                _ => return None,
            })
        }
        _ => None,
    }
}

fn is_tautology(e: &Expression) -> Option<bool> {
    if let Expression::CallExpression(c) = e {
        if let Expression::StaticMemberExpression(m) = &c.callee {
            if let Expression::Identifier(idf) = &m.object {
                if idf.name.as_str() == "Math" && m.property.name.as_str() == "pow" {
                    if num_lit(c.arguments.get(1)?.as_expression()?) == Some(0.0) {
                        return Some(true);
                    }
                }
            }
        }
        if let Expression::Identifier(idf) = &c.callee {
            if idf.name.as_str() == "isNaN" {
                if let Some(a) = c.arguments.first().and_then(|x| x.as_expression()) {
                    if matches!(a, Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot) {
                        return Some(false);
                    }
                    if let Expression::BinaryExpression(b) = a {
                        if b.operator == BinaryOperator::Multiplication {
                            let l_not = matches!(&b.left, Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot);
                            let r_not = matches!(&b.right, Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot);
                            if l_not && r_not {
                                return Some(false);
                            }
                        }
                    }
                }
            }
        }
    }
    if let Expression::BinaryExpression(b) = e {
        if matches!(b.operator, BinaryOperator::GreaterEqualThan | BinaryOperator::GreaterThan) {
            let ge = matches!(b.operator, BinaryOperator::GreaterEqualThan);
            let left_zero = num_lit(&b.left) == Some(0.0);
            let right_zero = num_lit(&b.right) == Some(0.0);
            if left_zero || right_zero {
                let other = if left_zero { &b.right } else { &b.left };
                if let Expression::CallExpression(c) = other {
                    if let Expression::StaticMemberExpression(m) = &c.callee {
                        if let Expression::Identifier(idf) = &m.object {
                            if idf.name.as_str() == "Math" && m.property.name.as_str() == "abs" {
                                if let Some(a) = c.arguments.first().and_then(|x| x.as_expression()) {
                                    let mul = matches!(a, Expression::BinaryExpression(ib) if ib.operator == BinaryOperator::Multiplication);
                                    let not = matches!(a, Expression::UnaryExpression(iu) if iu.operator == UnaryOperator::LogicalNot);
                                    if mul || not {
                                        if left_zero {
                                            return Some(ge);
                                        }
                                        return Some(true);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if matches!(b.operator, BinaryOperator::Equality | BinaryOperator::StrictEquality) {
            if num_lit(&b.right).is_some() && num_lit(&b.right) != Some(0.0) {
                if let Expression::BinaryExpression(inner) = &b.left {
                    if inner.operator == BinaryOperator::Multiplication && num_lit(&inner.left) == Some(0.0) {
                        return Some(false);
                    }
                    if inner.operator == BinaryOperator::Division && num_lit(&inner.right) == Some(0.0) {
                        return Some(false);
                    }
                }
            }
        }
    }
    match eval_const(e) {
        Some(v) => Some(v != 0.0 && !v.is_nan()),
        None => None,
    }
}

/// opaque-фолд через VisitMut: заменяем узел целиком на выжившую ветвь (clone_in).
struct OpaqueFold<'a> {
    count: usize,
    alloc: &'a Allocator,
}

impl<'a> VisitMut<'a> for OpaqueFold<'a> {
    fn visit_expression(&mut self, it: &mut Expression<'a>) {
        // потомки обходятся walk_* по умолчанию ПОСЛЕ входа — переопределив, звать walk нельзя напрямую;
        // вызываем дефолтную диспетчеризацию через внутренний визитор-обход:VisitMut трейт даёт walk_* методы
        oxc::ast_visit::walk_mut::walk_expression(self, it);
        match it {
            Expression::ConditionalExpression(c) => {
                if let Some(t) = is_tautology(&c.test) {
                    let pick = if t { &c.consequent } else { &c.alternate };
                    let cloned = pick.clone_in(self.alloc);
                    *it = cloned;
                    self.count += 1;
                }
            }
            Expression::LogicalExpression(l) => {
                if let Some(lt) = is_tautology(&l.left) {
                    let take_right = match l.operator {
                        LogicalOperator::Or => !lt,
                        LogicalOperator::And => lt,
                        _ => return,
                    };
                    let pick = if take_right { &l.right } else { &l.left };
                    let cloned = pick.clone_in(self.alloc);
                    *it = cloned;
                    self.count += 1;
                }
            }
            _ => {}
        }
    }
}

pub fn opaque_fold_pass(source: &str) -> Result<(String, usize), String> {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, SourceType::cjs()).parse();
    if !ret.diagnostics.is_empty() {
        return Err(format!("parse errors: {}", ret.diagnostics.len()));
    }
    let mut program = ret.program;
    let mut fold = OpaqueFold { count: 0, alloc: &allocator };
    fold.visit_program(&mut program);
    if fold.count == 0 {
        return Ok((source.to_string(), 0));
    }
    let printed = oxc::codegen::Codegen::new()
        .with_options(oxc::codegen::CodegenOptions { minify: false, ..Default::default() })
        .build(&program);
    Ok((printed.code, fold.count))
}

/// CFF-эмиттер: for(r=N;r;)switch → блок тел кейсов. Иммутабельная замена узла.
struct CffEmit<'a> {
    count: usize,
    alloc: &'a Allocator,
}

impl<'a> VisitMut<'a> for CffEmit<'a> {
    fn visit_statement(&mut self, it: &mut Statement<'a>) {
        oxc::ast_visit::walk_mut::walk_statement(self, it);
        let Statement::ForStatement(f) = it else { return };
        let test_ok = matches!(f.test.as_ref(), Some(Expression::Identifier(_)));
        if !test_ok {
            return;
        }
        let stmts: Vec<&Statement> = match &f.body {
            Statement::BlockStatement(b) => b.body.iter().collect(),
            other => vec![other],
        };
        let Some(sw) = stmts.iter().find_map(|s| match s {
            Statement::SwitchStatement(sw) => Some(sw),
            _ => None,
        }) else { return };
        let mut bodies: Vec<Statement<'a>> = Vec::new();
        for (ci, case) in sw.cases.iter().enumerate() {
            if ci + 1 == sw.cases.len() && case.consequent.is_empty() {
                continue;
            }
            for st in &case.consequent {
                if !matches!(st, Statement::BreakStatement(_)) {
                    bodies.push(st.clone_in(self.alloc));
                }
            }
        }
        if bodies.is_empty() {
            return;
        }
        let builder = AstBuilder::new(self.alloc);
        let arena_bodies: oxc::allocator::Vec<Statement<'a>> = oxc::allocator::Vec::from_iter_in(bodies, &self.alloc);
        *it = Statement::new_block_statement(oxc::span::SPAN, arena_bodies, &builder);
        self.count += 1;
    }
}

pub fn cff_emit_pass(source: &str) -> Result<(String, usize), String> {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, SourceType::cjs()).parse();
    if !ret.diagnostics.is_empty() {
        return Err(format!("parse errors: {}", ret.diagnostics.len()));
    }
    let mut program = ret.program;
    let mut emit = CffEmit { count: 0, alloc: &allocator };
    emit.visit_program(&mut program);
    if emit.count == 0 {
        return Ok((source.to_string(), 0));
    }
    let printed = oxc::codegen::Codegen::new()
        .with_options(oxc::codegen::CodegenOptions { minify: false, ..Default::default() })
        .build(&program);
    Ok((printed.code, emit.count))
}
