use oxc::allocator::Allocator;
use oxc::ast::ast::*;
use oxc::ast::AstKind;
use oxc::parser::Parser;
use oxc::semantic::SemanticBuilder;
use oxc::span::GetSpan;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct AnchorMap {
    pub fields: BTreeMap<String, Vec<String>>,
    pub anchors: BTreeMap<String, usize>,
    pub total_anchors: usize,
}

const NS: [&str; 6] = ["navigator", "window", "screen", "document", "performance", "location"];

fn obj_name(e: &Expression) -> String {
    match e {
        Expression::Identifier(idf) => idf.name.to_string(),
        _ => "?".to_string(),
    }
}

fn member_path(e: &Expression) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = e;
    loop {
        match cur {
            Expression::StaticMemberExpression(m) => {
                parts.push(m.property.name.as_str().to_string());
                cur = &m.object;
            }
            Expression::ComputedMemberExpression(cm) => {
                if let Expression::StringLiteral(s) = &cm.expression {
                    parts.push(s.value.to_string());
                    cur = &cm.object;
                } else if matches!(cm.object, Expression::Identifier(_))
                    && NS.contains(&obj_name(&cm.object).as_str())
                {
                    return Some(format!("{}[?dyn]", obj_name(&cm.object)));
                } else {
                    return None;
                }
            }
            Expression::Identifier(idf) => {
                if NS.contains(&idf.name.as_str()) {
                    parts.push(idf.name.as_str().to_string());
                    parts.reverse();
                    return Some(parts.join("."));
                }
                return None;
            }
            Expression::ParenthesizedExpression(p) => cur = &p.expression,
            _ => return None,
        }
    }
}

fn collect_anchors_in(e: &Expression, out: &mut Vec<String>) {
    match e {
        Expression::StaticMemberExpression(_) | Expression::ComputedMemberExpression(_) => {
            if let Some(p) = member_path(e) {
                out.push(p);
            } else {
                if let Expression::StaticMemberExpression(m) = e {
                    collect_anchors_in(&m.object, out);
                    collect_anchors_in_expr_opt(&m.object, out);
                }
                if let Expression::ComputedMemberExpression(cm) = e {
                    collect_anchors_in(&cm.object, out);
                    collect_anchors_in_expr_opt(&cm.expression, out);
                }
            }
        }
        Expression::BinaryExpression(b) => {
            collect_anchors_in(&b.left, out);
            collect_anchors_in(&b.right, out);
        }
        Expression::UnaryExpression(u) => collect_anchors_in(&u.argument, out),
        Expression::CallExpression(c) => {
            collect_anchors_in(&c.callee, out);
            for a in &c.arguments {
                if let Some(e) = a.as_expression() {
                    collect_anchors_in(e, out);
                }
            }
        }
        Expression::ConditionalExpression(c) => {
            collect_anchors_in(&c.test, out);
            collect_anchors_in(&c.consequent, out);
            collect_anchors_in(&c.alternate, out);
        }
        Expression::LogicalExpression(l) => {
            collect_anchors_in(&l.left, out);
            collect_anchors_in(&l.right, out);
        }
        Expression::AssignmentExpression(a) => {
            collect_anchors_in(&a.right, out);
        }
        Expression::SequenceExpression(s) => {
            for e in &s.expressions {
                collect_anchors_in(e, out);
            }
        }
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(e) = el.as_expression() {
                    collect_anchors_in(e, out);
                }
            }
        }
        Expression::ObjectExpression(o) => {
            for p in &o.properties {
                if let ObjectPropertyKind::ObjectProperty(op) = p {
                    collect_anchors_in(&op.value, out);
                }
            }
        }
        Expression::ParenthesizedExpression(p) => collect_anchors_in(&p.expression, out),
        _ => {}
    }
}

fn collect_anchors_in_expr_opt(e: &Expression, out: &mut Vec<String>) {
    collect_anchors_in(e, out);
}

fn target_key(t: &AssignmentTarget) -> Option<String> {
    match t {
        AssignmentTarget::AssignmentTargetIdentifier(idf) => Some(idf.name.to_string()),
        AssignmentTarget::StaticMemberExpression(m) => {
            Some(format!("{}.{}", obj_str(&m.object), m.property.name.as_str()))
        }
        AssignmentTarget::ComputedMemberExpression(cm) => {
            let prop = match &cm.expression {
                Expression::StringLiteral(s) => s.value.to_string(),
                Expression::NumericLiteral(n) => format!("{}", n.value),
                _ => return None,
            };
            Some(format!("{}[{}]", obj_str(&cm.object), prop))
        }
        _ => None,
    }
}

fn obj_str(e: &Expression) -> String {
    match e {
        Expression::Identifier(idf) => idf.name.to_string(),
        Expression::StaticMemberExpression(m) => format!("{}.{}", obj_str(&m.object), m.property.name.as_str()),
        Expression::ComputedMemberExpression(cm) => match &cm.expression {
            Expression::StringLiteral(s) => format!("{}[{}]", obj_str(&cm.object), s.value),
            _ => format!("{}[?]", obj_str(&cm.object)),
        },
        _ => "?".to_string(),
    }
}

pub fn build_anchor_map(source: &str) -> Result<AnchorMap, String> {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, oxc::span::SourceType::cjs()).parse();
    if ret.diagnostics.len() > 3 {
        return Err(format!("parse errors: {}", ret.diagnostics.len()));
    }
    let program = ret.program;
    let sem_ret = SemanticBuilder::new()
        .with_check_syntax_error(false)
        .with_build_nodes(true)
        .build(&program);
    let semantic = sem_ret.semantic;

    let mut map = AnchorMap::default();

    for node in semantic.nodes().iter() {
        let (target, value): (Option<String>, Option<&Expression>) = match node.kind() {
            AstKind::AssignmentExpression(a) => (target_key(&a.left), Some(&a.right)),
            AstKind::VariableDeclarator(d) => {
                let key = match &d.id {
                    BindingPattern::BindingIdentifier(b) => Some(b.name.to_string()),
                    _ => None,
                };
                (key, d.init.as_ref())
            }
            _ => continue,
        };
        let Some(value) = value else { continue };
        let mut anchors: Vec<String> = Vec::new();
        collect_anchors_in(value, &mut anchors);
        if !anchors.is_empty() {
            map.total_anchors += anchors.len();
            for a in &anchors {
                *map.anchors.entry(a.clone()).or_insert(0) += 1;
            }
            if let Some(t) = target {
                let entry = map.fields.entry(t).or_default();
                for a in &anchors {
                    if !entry.contains(a) {
                        entry.push(a.clone());
                    }
                }
            }
        }
    }

    Ok(map)
}
