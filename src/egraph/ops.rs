use super::Math;
use egg::{Id, RecExpr};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Op {
    Lit(i64),
    Load(u8),
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    UShr,
    Rol,
    Wrap32,
    Sel,
    Eq,
    Lt,
    LNot,
}

pub struct Program {
    pub ops: Vec<Op>,
    pub n_vars: usize,
}

impl Program {
    pub fn exec(&self, vars: &[i64]) -> Option<i64> {
        let mut st: Vec<i64> = Vec::with_capacity(self.ops.len());
        for op in &self.ops {
            match op {
                Op::Lit(v) => st.push(*v),
                Op::Load(i) => st.push(*vars.get(*i as usize)?),
                Op::Add => bin(&mut st, |a, b| Some(a.wrapping_add(b)))?,
                Op::Sub => bin(&mut st, |a, b| Some(a.wrapping_sub(b)))?,
                Op::Mul => bin(&mut st, |a, b| Some(a.wrapping_mul(b)))?,
                Op::Div => bin(&mut st, |a, b| {
                    if b == 0 {
                        None
                    } else {
                        Some(a.wrapping_div(b))
                    }
                })?,
                Op::Mod => bin(&mut st, |a, b| {
                    if b == 0 {
                        None
                    } else {
                        Some(a.wrapping_rem(b))
                    }
                })?,
                Op::And => bin(&mut st, |a, b| Some(a & b))?,
                Op::Or => bin(&mut st, |a, b| Some(a | b))?,
                Op::Xor => bin(&mut st, |a, b| Some(a ^ b))?,
                Op::Not => un(&mut st, |a| Some(!a))?,
                Op::Shl => bin(&mut st, |a, b| Some(a.wrapping_shl(b as u32)))?,
                Op::Shr => bin(&mut st, |a, b| Some(a.wrapping_shr(b as u32)))?,
                Op::UShr => bin(&mut st, |a, b| {
                    Some(((a as u32).wrapping_shr(b as u32 & 31)) as i64)
                })?,
                Op::Rol => bin(&mut st, |a, b| {
                    Some(((a as u32).rotate_left(b as u32 & 31)) as i64)
                })?,
                Op::Wrap32 => un(&mut st, |a| Some(a as i32 as i64))?,
                Op::Sel => {
                    let b = st.pop()?;
                    let a = st.pop()?;
                    let c = st.pop()?;
                    st.push(if c != 0 { a } else { b });
                }
                Op::Eq => bin(&mut st, |a, b| Some((a == b) as i64))?,
                Op::Lt => bin(&mut st, |a, b| Some((a < b) as i64))?,
                Op::LNot => un(&mut st, |a| Some((a == 0) as i64))?,
            }
        }
        st.last().copied()
    }
}

fn bin(st: &mut Vec<i64>, f: impl Fn(i64, i64) -> Option<i64>) -> Option<()> {
    let b = st.pop()?;
    let a = st.pop()?;
    st.push(f(a, b)?);
    Some(())
}

fn un(st: &mut Vec<i64>, f: impl Fn(i64) -> Option<i64>) -> Option<()> {
    let a = st.pop()?;
    st.push(f(a)?);
    Some(())
}

pub fn flatten(expr: &RecExpr<Math>) -> Program {
    let mut var_ids: HashMap<egg::Symbol, u8> = HashMap::new();
    let mut prog: Vec<Op> = Vec::with_capacity(expr.len());
    for n in expr.iter() {
        let op = match n {
            Math::Lit(v) => Op::Lit(*v),
            Math::Var(s) => {
                let next = var_ids.len() as u8;
                let slot = *var_ids.entry(*s).or_insert(next);
                Op::Load(slot)
            }
            Math::Add(..) => Op::Add,
            Math::Sub(..) => Op::Sub,
            Math::Mul(..) => Op::Mul,
            Math::Div(..) => Op::Div,
            Math::Mod(..) => Op::Mod,
            Math::And(..) => Op::And,
            Math::Or(..) => Op::Or,
            Math::Xor(..) => Op::Xor,
            Math::Not(_) => Op::Not,
            Math::Shl(..) => Op::Shl,
            Math::Shr(..) => Op::Shr,
            Math::UShr(..) => Op::UShr,
            Math::Rol(..) => Op::Rol,
            Math::Wrap32(_) => Op::Wrap32,
            Math::Sel(..) => Op::Sel,
            Math::Eq(..) => Op::Eq,
            Math::Lt(..) => Op::Lt,
            Math::LNot(_) => Op::LNot,
        };
        prog.push(op);
    }
    Program {
        ops: prog,
        n_vars: var_ids.len(),
    }
}

pub fn unused_guard(_: Id) {}
