use oxc::allocator::Allocator;
use oxc::ast::ast::*;
use oxc::ast::AstKind;
use oxc::parser::Parser;
use oxc::semantic::{Semantic, SemanticBuilder};
use oxc::span::GetSpan;
use std::collections::HashMap;

fn sp<'a, 'e>(e: &'e Expression<'a>) -> &'e Expression<'a> {
    match e {
        Expression::ParenthesizedExpression(p) => sp(&p.expression),
        _ => e,
    }
}

/// Лямбда-таблица: obj.X = function(a,b){return a OP b} → OP
/// + call-примитивы: obj.X = function(f,x){return f(x)}, obj.X = function(f,a,b){return f(a,b)}
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum LamKind {
    Bin(&'static str),
    Call1,
    Call2,
    Call6,
    Not,
}

fn body_lam(stmts: &[Statement]) -> Option<LamKind> {
    if stmts.len() != 1 {
        return None;
    }
    let ret = match &stmts[0] {
        Statement::ReturnStatement(r) => r,
        _ => return None,
    };
    let arg = ret.argument.as_ref()?;
    match sp(arg) {
        Expression::BinaryExpression(b) => {
            let op = match b.operator {
                BinaryOperator::Addition => "+",
                BinaryOperator::Subtraction => "-",
                BinaryOperator::Multiplication => "*",
                BinaryOperator::Division => "/",
                BinaryOperator::Remainder => "%",
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
            };
            Some(LamKind::Bin(op))
        }
        Expression::LogicalExpression(l) => match l.operator {
            LogicalOperator::And => Some(LamKind::Bin("&&")),
            LogicalOperator::Or => Some(LamKind::Bin("||")),
            _ => None,
        },
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => {
            Some(LamKind::Not)
        }
        Expression::CallExpression(c) => match sp(&c.callee) {
            Expression::Identifier(idf) if idf.name.as_str() == "arguments" || matches!(c.arguments.first().and_then(|a| a.as_expression()), Some(Expression::Identifier(_))) => {
                match c.arguments.len() {
                    1 => Some(LamKind::Call1),
                    2 => Some(LamKind::Call2),
                    6 => Some(LamKind::Call6),
                    _ => None,
                }
            }
            _ => None,
        },
        _ => None,
    }
}

/// Собрать таблицу лямбд: symbol_id(base) + prop → LamKind
fn sym_of(semantic: &Semantic, e: &Expression) -> Option<usize> {
    let idf = match sp(e) {
        Expression::Identifier(id) => id,
        _ => return None,
    };
    let rid = idf.reference_id.get()?;
    semantic.scoping().get_reference(rid).symbol_id().map(|s| s.index())
}

fn lambda_table(semantic: &Semantic) -> HashMap<(usize, String), LamKind> {
    let mut out = HashMap::new();
    let mut dbg_total = 0usize;
    let dbg_nodes = semantic.nodes().len();
    if std::env::var("ZAIC_SUBST_DEBUG").is_ok() { eprintln!("[lambda_table] nodes={}", dbg_nodes); }
    let mut dbg_table = 0usize;
    let mut dbg_body = 0usize;
    let mut dbg_right = 0usize;
    for node in semantic.nodes().iter() {
        let AstKind::AssignmentExpression(a) = node.kind() else { continue };
        if a.operator != AssignmentOperator::Assign {
            continue;
        }
        dbg_total += 1;
        let (base_span, prop) = match &a.left {
            AssignmentTarget::StaticMemberExpression(m) => {
                (sym_of(semantic, &m.object).unwrap_or(usize::MAX), m.property.name.as_str().to_string())
            }
            AssignmentTarget::ComputedMemberExpression(cm) => {
                let p = match sp(&cm.expression) {
                    Expression::StringLiteral(sl) => sl.value.to_string(),
                    _ => continue,
                };
                (sym_of(semantic, &cm.object).unwrap_or(usize::MAX), p)
            }
            _ => continue,
        };
        let kind = match sp(&a.right) {
            Expression::FunctionExpression(fe) => fe
                .body
                .as_ref()
                .and_then(|b| body_lam(&b.statements)),
            Expression::ArrowFunctionExpression(ar) => match &ar.body {
                ArrowFunctionBody::FunctionBody(fb) => body_lam(&fb.statements),
                _ => None,
            },
            _ => None,
        };
        dbg_right += 1;
        if let Some(k) = kind {
            dbg_table += 1;
            out.insert((base_span, prop), k);
        }
    }
    if std::env::var("ZAIC_SUBST_DEBUG").is_ok() {
        eprintln!("[lambda_table] assign={} right={} body={} table={}", dbg_total, dbg_right, dbg_body, dbg_table);
    }
    out
}

/// подстановка: ep.X(a, b) → (a OP b) / a(b) / a(b,c)
pub fn substitute_lambdas(source: &str) -> Result<(String, usize), String> {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, SourceType::cjs()).parse();
    if !ret.diagnostics.is_empty() {
        return Err(format!("parse errors: {}", ret.diagnostics.len()));
    }
    let program = ret.program;
    let sem_ret = SemanticBuilder::new()
        .with_check_syntax_error(false)
        .with_build_nodes(true)
        .build(&program);
    let semantic = sem_ret.semantic;

    let table = lambda_table(&semantic);
    let semantic_ref = &semantic;
    if std::env::var("ZAIC_SUBST_DEBUG").is_ok() {
        eprintln!("[subst] таблица: {} записей", table.len());
    }
    if table.is_empty() {
        return Ok((source.to_string(), 0));
    }

    let mut edits: Vec<(u32, u32, String)> = Vec::new();
    let mut count = 0usize;

    for node in semantic.nodes().iter() {
        let AstKind::CallExpression(c) = node.kind() else { continue };
        let (base_span, prop) = match sp(&c.callee) {
            Expression::StaticMemberExpression(m) => (sym_of(&semantic, &m.object).unwrap_or(usize::MAX), m.property.name.as_str().to_string()),
            Expression::ComputedMemberExpression(cm) => {
                let p = match sp(&cm.expression) {
                    Expression::StringLiteral(sl) => sl.value.to_string(),
                    _ => continue,
                };
                (sym_of(&semantic, &cm.object).unwrap_or(usize::MAX), p)
            }
            _ => continue,
        };
        let Some(kind) = table.get(&(base_span, prop)) else { continue };
        let cspan = c.span;
        let args: Vec<&Expression> = c
            .arguments
            .iter()
            .filter_map(|a| a.as_expression())
            .collect();
        let replacement: Option<String> = match kind {
            LamKind::Bin(op) => match args.len() {
                2 => {
                    let l = &args[0];
                    let r = &args[1];
                    let ltxt = source_text(source, l);
                    let rtxt = source_text(source, r);
                    // логические операторы требуют приоритета скобок — всегда оборачиваем
                    let needs = matches!(*op, "&&" | "||");
                    if needs {
                        Some(format!("(({} {} {}))", ltxt, op, rtxt))
                    } else {
                        Some(format!("({} {} {})", ltxt, op, rtxt))
                    }
                }
                _ => None,
            },
            LamKind::Not => match args.len() {
                1 => Some(format!("!({})", source_text(source, args[0]))),
                _ => None,
            },
            LamKind::Call1 => match args.len() {
                1 => Some(source_text(source, args[0])),
                _ => None,
            },
            LamKind::Call2 => match args.len() {
                2 => Some(format!(
                    "{}({})",
                    source_text(source, &args[0]),
                    source_text(source, &args[1])
                )),
                _ => None,
            },
            LamKind::Call6 => Some(
                args.iter()
                    .map(|a| source_text(source, a))
                    .collect::<Vec<_>>()
                    .join(",")
                    .split_once(',')
                    .map(|(f, rest)| format!("{}({})", f, rest))
                    .unwrap_or_default(),
            ),
        };
        if let Some(r) = replacement {
            edits.push((cspan.start, cspan.end, r));
            count += 1;
        }
    }

    if edits.is_empty() {
        return Ok((source.to_string(), 0));
    }

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
    Ok((out, count))
}

fn source_text(source: &str, e: &Expression) -> String {
    let s = e.span().start as usize;
    let en = e.span().end as usize;
    if en <= source.len() && s < en {
        source[s..en].to_string()
    } else {
        String::new()
    }
}

/// Фикспоинт подстановки лямбд (вложенные вызовы раскрываются итеративно)
pub fn substitute_lambdas_fixpoint(source: &str, rounds: usize) -> Result<(String, usize), String> {
    let mut cur = source.to_string();
    let mut total = 0usize;
    for _ in 0..rounds {
        let (next, n) = match substitute_lambdas(&cur) {
            Ok(x) => x,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        // валидация: подстановки не должны ломать парс
        let alloc = Allocator::default();
        let ok = Parser::new(&alloc, &next, SourceType::cjs()).parse();
        if ok.diagnostics.is_empty() {
            total += n;
            cur = next;
        } else {
            break;
        }
    }
    Ok((cur, total))
}
