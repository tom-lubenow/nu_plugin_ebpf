//! Hindley-Milner type inference for HIR with let-generalization.
//!
//! This pass is intentionally lightweight: it focuses on variable bindings
//! (StoreVariable/LoadVariable) and basic ops to enable rank-1 polymorphism
//! for let-bound values. It is designed to be permissive and avoid false
//! negatives for unsupported operations.

use std::collections::HashMap;

use nu_protocol::ast::{Boolean, Operator};
use nu_protocol::{DeclId, RegId, Value, VarId};

use super::hindley_milner::{
    HMType, Substitution, TypeScheme, TypeVar, TypeVarGenerator, UnifyError, unify,
};
use super::hir::{HirBlock, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator};
use super::mir::AddressSpace;
use super::type_infer::TypeError;

#[derive(Debug, Clone, Default)]
struct VarEnv {
    bindings: HashMap<VarId, TypeScheme>,
}

impl VarEnv {
    fn get(&self, var_id: VarId) -> Option<&TypeScheme> {
        self.bindings.get(&var_id)
    }

    fn insert(&mut self, var_id: VarId, scheme: TypeScheme) {
        self.bindings.insert(var_id, scheme);
    }

    fn remove(&mut self, var_id: VarId) {
        self.bindings.remove(&var_id);
    }

    fn free_vars(&self) -> std::collections::HashSet<TypeVar> {
        let mut vars = std::collections::HashSet::new();
        for scheme in self.bindings.values() {
            vars.extend(scheme.free_vars());
        }
        vars
    }

    fn apply(&self, subst: &Substitution) -> Self {
        Self {
            bindings: self
                .bindings
                .iter()
                .map(|(k, scheme)| {
                    (
                        *k,
                        TypeScheme {
                            quantified: scheme.quantified.clone(),
                            ty: subst.apply(&scheme.ty),
                        },
                    )
                })
                .collect(),
        }
    }

    fn generalize(&self, ty: &HMType) -> TypeScheme {
        let env_vars = self.free_vars();
        let ty_vars = ty.free_vars();
        let quantified: Vec<TypeVar> = ty_vars.difference(&env_vars).copied().collect();
        TypeScheme {
            quantified,
            ty: ty.clone(),
        }
    }
}

pub fn infer_hir(
    program: &HirProgram,
    decl_names: &HashMap<DeclId, String>,
) -> Result<(), Vec<TypeError>> {
    let mut errors = Vec::new();

    infer_function(&program.main, decl_names, &mut errors);
    for func in program.closures.values() {
        infer_function(func, decl_names, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

struct HirTypeInference<'a> {
    tvar_gen: TypeVarGenerator,
    reg_vars: HashMap<u32, TypeVar>,
    substitution: Substitution,
    env: VarEnv,
    decl_names: &'a HashMap<DeclId, String>,
}

impl<'a> HirTypeInference<'a> {
    fn new(decl_names: &'a HashMap<DeclId, String>) -> Self {
        Self {
            tvar_gen: TypeVarGenerator::new(),
            reg_vars: HashMap::new(),
            substitution: Substitution::new(),
            env: VarEnv::default(),
            decl_names,
        }
    }

    fn infer_function(&mut self, func: &HirFunction) -> Result<(), Vec<TypeError>> {
        let mut errors = Vec::new();

        for block in &func.blocks {
            if let Err(errs) = self.infer_block(block) {
                errors.extend(errs);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn infer_block(&mut self, block: &HirBlock) -> Result<(), Vec<TypeError>> {
        let mut errors = Vec::new();

        for stmt in &block.stmts {
            if let Err(err) = self.infer_stmt(stmt) {
                errors.push(err);
            }
        }

        if let Err(err) = self.infer_terminator(&block.terminator) {
            errors.push(err);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn infer_stmt(&mut self, stmt: &HirStmt) -> Result<(), TypeError> {
        match stmt {
            HirStmt::LoadLiteral { dst, lit } => {
                let dst_ty = self.reg_type(*dst);
                let lit_ty = hm_type_for_literal(lit);
                self.constrain(dst_ty, lit_ty, "literal")?;
            }
            HirStmt::LoadValue { dst, val } => {
                let dst_ty = self.reg_type(*dst);
                let lit_ty = hm_type_for_value(val);
                self.constrain(dst_ty, lit_ty, "value")?;
            }
            HirStmt::Move { dst, src }
            | HirStmt::Clone { dst, src }
            | HirStmt::CloneCellPath { dst, src, .. } => {
                let dst_ty = self.reg_type(*dst);
                let src_ty = self.reg_type(*src);
                self.constrain(dst_ty, src_ty, "move")?;
            }
            HirStmt::Collect { src_dst }
            | HirStmt::Span { src_dst }
            | HirStmt::Drain { src: src_dst }
            | HirStmt::DrainIfEnd { src: src_dst }
            | HirStmt::Drop { src: src_dst }
            | HirStmt::CheckErrRedirected { src: src_dst }
            | HirStmt::Not { src_dst } => {
                if matches!(stmt, HirStmt::Not { .. }) {
                    let dst_ty = self.reg_type(*src_dst);
                    self.constrain(dst_ty, HMType::Bool, "not")?;
                }
            }
            HirStmt::LoadVariable { dst, var_id } => {
                let dst_ty = self.reg_type(*dst);
                let scheme = self
                    .env
                    .get(*var_id)
                    .cloned()
                    .unwrap_or_else(|| TypeScheme::mono(HMType::Unknown));
                let inst = scheme.instantiate(&mut self.tvar_gen);
                self.constrain(dst_ty, inst, "load_var")?;
            }
            HirStmt::StoreVariable { var_id, src } => {
                let src_ty = self.reg_type(*src);
                let src_ty = self.substitution.apply(&src_ty);
                let env = self.env.apply(&self.substitution);
                let scheme = env.generalize(&src_ty);
                self.env.insert(*var_id, scheme);
            }
            HirStmt::DropVariable { var_id } => {
                self.env.remove(*var_id);
            }
            HirStmt::BinaryOp { lhs_dst, op, rhs } => {
                let lhs_ty = self.reg_type(*lhs_dst);
                let rhs_ty = self.reg_type(*rhs);
                match op {
                    Operator::Comparison(_) => {
                        self.constrain(lhs_ty, HMType::I64, "cmp_lhs")?;
                        self.constrain(rhs_ty, HMType::I64, "cmp_rhs")?;
                    }
                    Operator::Boolean(Boolean::And)
                    | Operator::Boolean(Boolean::Or)
                    | Operator::Boolean(Boolean::Xor) => {
                        self.constrain(lhs_ty, HMType::Bool, "bool_lhs")?;
                        self.constrain(rhs_ty, HMType::Bool, "bool_rhs")?;
                    }
                    Operator::Math(_) => {
                        self.constrain(lhs_ty, HMType::I64, "math_lhs")?;
                        self.constrain(rhs_ty, HMType::I64, "math_rhs")?;
                    }
                    _ => {}
                }
            }
            HirStmt::Call { decl_id, src_dst, .. } => {
                let dst_ty = self.reg_type(*src_dst);
                let name = self
                    .decl_names
                    .get(decl_id)
                    .map(|s| s.as_str())
                    .unwrap_or("");
                let ret_ty = match name {
                    "stop-timer" => HMType::U64,
                    _ => HMType::Unknown,
                };
                self.constrain(dst_ty, ret_ty, "call")?;
            }
            _ => {}
        }

        Ok(())
    }

    fn infer_terminator(&mut self, term: &HirTerminator) -> Result<(), TypeError> {
        match term {
            HirTerminator::Jump { .. }
            | HirTerminator::Goto { .. }
            | HirTerminator::Unreachable
            | HirTerminator::Iterate { .. }
            | HirTerminator::BranchIf { .. }
            | HirTerminator::BranchIfEmpty { .. }
            | HirTerminator::Match { .. }
            | HirTerminator::ReturnEarly { .. }
            | HirTerminator::Return { .. } => {}
        }
        Ok(())
    }

    fn reg_type(&mut self, reg: RegId) -> HMType {
        let id = reg.get();
        let entry = self.reg_vars.entry(id).or_insert_with(|| self.tvar_gen.fresh());
        HMType::Var(*entry)
    }

    fn constrain(&mut self, expected: HMType, actual: HMType, context: &str) -> Result<(), TypeError> {
        let expected = self.substitution.apply(&expected);
        let actual = self.substitution.apply(&actual);
        match unify(&expected, &actual) {
            Ok(s) => {
                self.substitution = s.compose(&self.substitution);
                Ok(())
            }
            Err(err) => Err(TypeError::from(UnifyError {
                expected: err.expected,
                actual: err.actual,
                message: format!("{context}: {}", err.message),
            })),
        }
    }
}

fn infer_function(
    func: &HirFunction,
    decl_names: &HashMap<DeclId, String>,
    errors: &mut Vec<TypeError>,
) {
    let mut infer = HirTypeInference::new(decl_names);
    if let Err(mut errs) = infer.infer_function(func) {
        errors.append(&mut errs);
    }
}

fn hm_type_for_literal(lit: &HirLiteral) -> HMType {
    match lit {
        HirLiteral::Bool(_) => HMType::Bool,
        HirLiteral::Int(_)
        | HirLiteral::Float(_)
        | HirLiteral::Filesize(_)
        | HirLiteral::Duration(_)
        | HirLiteral::Date(_) => HMType::I64,
        HirLiteral::Binary(_)
        | HirLiteral::String(_)
        | HirLiteral::RawString(_)
        | HirLiteral::Filepath { .. }
        | HirLiteral::Directory { .. }
        | HirLiteral::GlobPattern { .. } => HMType::Ptr {
            pointee: Box::new(HMType::U8),
            address_space: AddressSpace::Stack,
        },
        HirLiteral::List { .. } => HMType::Ptr {
            pointee: Box::new(HMType::I64),
            address_space: AddressSpace::Stack,
        },
        HirLiteral::Record { .. } => HMType::Ptr {
            pointee: Box::new(HMType::I64),
            address_space: AddressSpace::Stack,
        },
        _ => HMType::Unknown,
    }
}

fn hm_type_for_value(val: &Value) -> HMType {
    match val {
        Value::Bool { .. } => HMType::Bool,
        Value::Int { .. }
        | Value::Float { .. }
        | Value::Filesize { .. }
        | Value::Duration { .. }
        | Value::Date { .. } => HMType::I64,
        _ => HMType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::hir::{HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator};
    use nu_protocol::RegId;

    #[test]
    fn test_let_generalization_allows_distinct_instantiations() {
        let mut func = HirFunction {
            blocks: Vec::new(),
            entry: HirBlockId(0),
            spans: Vec::new(),
            ast: Vec::new(),
            comments: Vec::new(),
            register_count: 4,
            file_count: 0,
        };

        let mut block = HirBlock {
            id: HirBlockId(0),
            stmts: Vec::new(),
            terminator: HirTerminator::Return { src: RegId::new(0) },
        };

        // Store unconstrained register into a variable => generalized.
        block.stmts.push(HirStmt::StoreVariable {
            var_id: VarId::new(0),
            src: RegId::new(0),
        });

        // First instantiation: constrain to bool via Not.
        block.stmts.push(HirStmt::LoadVariable {
            dst: RegId::new(1),
            var_id: VarId::new(0),
        });
        block.stmts.push(HirStmt::Not { src_dst: RegId::new(1) });

        // Second instantiation: constrain to a pointer via move from a string literal.
        block.stmts.push(HirStmt::LoadVariable {
            dst: RegId::new(2),
            var_id: VarId::new(0),
        });
        block.stmts.push(HirStmt::LoadLiteral {
            dst: RegId::new(3),
            lit: HirLiteral::String("hi".into()),
        });
        block.stmts.push(HirStmt::Move {
            dst: RegId::new(2),
            src: RegId::new(3),
        });

        func.blocks.push(block);

        let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
        let decl_names = HashMap::new();
        infer_hir(&program, &decl_names).expect("expected polymorphic let to type-check");
    }

    #[test]
    fn test_conflicting_constraints_without_let() {
        let mut func = HirFunction {
            blocks: Vec::new(),
            entry: HirBlockId(0),
            spans: Vec::new(),
            ast: Vec::new(),
            comments: Vec::new(),
            register_count: 2,
            file_count: 0,
        };

        let mut block = HirBlock {
            id: HirBlockId(0),
            stmts: Vec::new(),
            terminator: HirTerminator::Return { src: RegId::new(0) },
        };

        // Constrain RegId(0) to a pointer and then to bool without let-generalization.
        block.stmts.push(HirStmt::LoadLiteral {
            dst: RegId::new(0),
            lit: HirLiteral::String("oops".into()),
        });
        block.stmts.push(HirStmt::Not { src_dst: RegId::new(0) });

        func.blocks.push(block);

        let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
        let decl_names = HashMap::new();
        assert!(infer_hir(&program, &decl_names).is_err());
    }
}
