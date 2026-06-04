use super::*;
use crate::compiler::ctx_field_for_bpf_sock_projection_member;
use crate::compiler::mir::AddressSpace;
use crate::compiler::mir::UnaryOpKind;
use crate::kernel_btf::{
    TrampolineBitfieldInfo, TrampolineFieldProjection, TrampolineFieldSelector,
    TrampolineValueKind, TrampolineValueSpec, TypeInfo,
};
use nu_protocol::ast::{Expr, MatchPattern, Range};

mod context_helpers;
mod packet;
mod trampoline;

use trampoline::TypedProjectionStep;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalarMatchKind {
    Bool,
    Int,
    Filesize,
    Duration,
    Nothing,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownSourceMatchKind {
    Scalar(ScalarMatchKind),
    NumericScalar,
    NonScalar,
}

#[derive(Debug, Clone)]
enum StringConcatSource {
    Literal(Vec<u8>),
    Slot { slot: StackSlotId, max_len: usize },
}

#[derive(Debug, Clone)]
struct StringEqualitySource {
    slot: StackSlotId,
    len_vreg: VReg,
    exact_len: Option<usize>,
    max_len: usize,
}

impl<'a> HirToMirLowering<'a> {
    pub(super) fn lower_binary_op(
        &mut self,
        lhs_dst: RegId,
        op: nu_protocol::ast::Operator,
        rhs: RegId,
    ) -> Result<(), CompileError> {
        use nu_protocol::ast::{Comparison, Math, Operator};

        let constant_value = self
            .get_metadata(lhs_dst)
            .and_then(|meta| meta.constant_value.as_ref())
            .zip(
                self.get_metadata(rhs)
                    .and_then(|meta| meta.constant_value.as_ref()),
            )
            .and_then(|(lhs, rhs)| Self::constant_apply_binary_operator(lhs, op, rhs));

        let lhs_vreg = self.get_vreg(lhs_dst);
        let rhs_vreg = self.get_vreg(rhs);

        if matches!(
            op,
            Operator::Comparison(Comparison::Equal | Comparison::NotEqual)
        ) {
            if let Some(value @ Value::Bool { .. }) = constant_value.as_ref()
                && self
                    .get_metadata(lhs_dst)
                    .is_some_and(|meta| meta.constant_value.is_some())
                && self
                    .get_metadata(rhs)
                    .is_some_and(|meta| meta.constant_value.is_some())
            {
                self.lower_constant_value(lhs_dst, value)?;
                return Ok(());
            }

            match (
                self.source_match_kind(lhs_dst, lhs_vreg),
                self.source_match_kind(rhs, rhs_vreg),
            ) {
                (
                    Some(KnownSourceMatchKind::Scalar(lhs_kind)),
                    Some(KnownSourceMatchKind::Scalar(rhs_kind)),
                ) if lhs_kind != rhs_kind => {
                    let result = matches!(op, Operator::Comparison(Comparison::NotEqual));
                    self.lower_constant_value(lhs_dst, &Value::bool(result, Span::unknown()))?;
                    return Ok(());
                }
                (
                    Some(KnownSourceMatchKind::Scalar(lhs_kind)),
                    Some(KnownSourceMatchKind::NumericScalar),
                )
                | (
                    Some(KnownSourceMatchKind::NumericScalar),
                    Some(KnownSourceMatchKind::Scalar(lhs_kind)),
                ) if !Self::scalar_match_kind_is_numeric(lhs_kind) => {
                    let result = matches!(op, Operator::Comparison(Comparison::NotEqual));
                    self.lower_constant_value(lhs_dst, &Value::bool(result, Span::unknown()))?;
                    return Ok(());
                }
                (
                    Some(KnownSourceMatchKind::Scalar(ScalarMatchKind::String)),
                    Some(KnownSourceMatchKind::Scalar(ScalarMatchKind::String)),
                )
                | (Some(KnownSourceMatchKind::Scalar(ScalarMatchKind::String)), _)
                | (_, Some(KnownSourceMatchKind::Scalar(ScalarMatchKind::String))) => {
                    if self.lower_runtime_string_equality(
                        lhs_dst,
                        rhs,
                        matches!(op, Operator::Comparison(Comparison::NotEqual)),
                    )? {
                        return Ok(());
                    }
                    return Err(CompileError::UnsupportedInstruction(
                        "string equality requires compile-time constant operands in eBPF".into(),
                    ));
                }
                _ => {}
            }
        }

        if let Some(Value::String { val, .. } | Value::Glob { val, .. }) = constant_value.as_ref() {
            self.lower_string_like_literal(lhs_dst, lhs_vreg, val.as_bytes())?;
            self.clear_source_var(lhs_dst);
            self.set_reg_constant_value(lhs_dst, constant_value);
            return Ok(());
        }

        if matches!(
            op,
            Operator::Math(Math::Add) | Operator::Math(Math::Concatenate)
        ) {
            if self.lower_runtime_string_concat(lhs_dst, lhs_vreg, rhs)? {
                return Ok(());
            }
        }

        if matches!(op, Operator::Math(Math::Pow)) {
            self.lower_integer_pow(lhs_dst, lhs_vreg, rhs, constant_value)?;
            return Ok(());
        }

        if let Some(value) = constant_value.as_ref()
            && Self::runtime_binop_kind(op).is_none()
        {
            self.lower_constant_value(lhs_dst, value)?;
            return Ok(());
        }

        let Some(mir_op) = Self::runtime_binop_kind(op) else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "Operator {op} is not supported in eBPF runtime lowering. \
                 It may still be used when the expression is compile-time constant."
            )));
        };

        self.emit(MirInst::BinOp {
            dst: lhs_vreg,
            op: mir_op,
            lhs: MirValue::VReg(lhs_vreg),
            rhs: MirValue::VReg(rhs_vreg),
        });
        self.clear_source_var(lhs_dst);
        self.set_reg_constant_value(lhs_dst, constant_value);

        Ok(())
    }

    fn lower_runtime_string_equality(
        &mut self,
        lhs_dst: RegId,
        rhs: RegId,
        invert: bool,
    ) -> Result<bool, CompileError> {
        let lhs_meta = self.get_metadata(lhs_dst).cloned();
        let rhs_meta = self.get_metadata(rhs).cloned();
        let lhs_source = lhs_meta
            .as_ref()
            .and_then(|meta| self.string_equality_source(meta));
        let rhs_source = rhs_meta
            .as_ref()
            .and_then(|meta| self.string_equality_source(meta));

        let (lhs_source, rhs_source) = match (lhs_source, rhs_source) {
            (None, None) => return Ok(false),
            (Some(lhs_source), Some(rhs_source)) => (lhs_source, rhs_source),
            _ => {
                return Err(CompileError::UnsupportedInstruction(
                    "string equality requires string operands in eBPF".into(),
                ));
            }
        };

        let (known_source, other_source) = if lhs_source.exact_len.is_some() {
            (&lhs_source, &rhs_source)
        } else if rhs_source.exact_len.is_some() {
            (&rhs_source, &lhs_source)
        } else {
            return Err(CompileError::UnsupportedInstruction(
                "string equality requires at least one compile-time known string operand in eBPF"
                    .into(),
            ));
        };
        let compare_len = known_source
            .exact_len
            .expect("known source should have exact length");
        let result_vreg = self.assign_fresh_vreg(lhs_dst);

        if compare_len > other_source.max_len {
            self.lower_runtime_string_equality_const(lhs_dst, result_vreg, invert, false);
            return Ok(true);
        }

        let len_matches = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: len_matches,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(other_source.len_vreg),
            rhs: MirValue::Const(compare_len as i64),
        });
        self.vreg_type_hints.insert(len_matches, MirType::Bool);

        let equal_vreg = if compare_len == 0 {
            len_matches
        } else {
            let bytes_match = self.func.alloc_vreg();
            self.emit(MirInst::StrCmp {
                dst: bytes_match,
                lhs: other_source.slot,
                lhs_offset: 0,
                rhs: known_source.slot,
                rhs_offset: 0,
                len: compare_len,
            });
            self.vreg_type_hints.insert(bytes_match, MirType::Bool);

            let equal_vreg = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: equal_vreg,
                op: BinOpKind::And,
                lhs: MirValue::VReg(len_matches),
                rhs: MirValue::VReg(bytes_match),
            });
            self.vreg_type_hints.insert(equal_vreg, MirType::Bool);
            equal_vreg
        };

        if invert {
            self.emit(MirInst::BinOp {
                dst: result_vreg,
                op: BinOpKind::Eq,
                lhs: MirValue::VReg(equal_vreg),
                rhs: MirValue::Const(0),
            });
        } else {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::VReg(equal_vreg),
            });
        }
        self.finish_runtime_bool_result(lhs_dst, result_vreg);
        Ok(true)
    }

    fn lower_runtime_string_equality_const(
        &mut self,
        dst: RegId,
        dst_vreg: VReg,
        invert: bool,
        equal: bool,
    ) {
        let result = if invert { !equal } else { equal };
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(if result { 1 } else { 0 }),
        });
        self.finish_runtime_bool_result(dst, dst_vreg);
    }

    fn finish_runtime_bool_result(&mut self, dst: RegId, dst_vreg: VReg) {
        self.reset_call_result_metadata(dst);
        let meta = self.get_or_create_metadata(dst);
        meta.field_type = Some(MirType::Bool);
        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
    }

    fn string_equality_source(&self, meta: &RegMetadata) -> Option<StringEqualitySource> {
        let slot = meta.string_slot?;
        let len_vreg = meta.string_len_vreg?;
        let slot_max_len = self
            .stack_slot_size(slot)
            .map(|size| size.saturating_sub(1))
            .unwrap_or_else(|| meta.string_len_bound.unwrap_or(0));
        let max_len = meta
            .string_len_bound
            .unwrap_or(slot_max_len)
            .min(slot_max_len);
        Some(StringEqualitySource {
            slot,
            len_vreg,
            exact_len: Self::exact_string_metadata_len(meta),
            max_len,
        })
    }

    fn exact_string_metadata_len(meta: &RegMetadata) -> Option<usize> {
        if let Some(value) = meta.literal_string.as_ref() {
            return Some(value.len());
        }

        match meta.constant_value.as_ref()? {
            Value::String { val, .. } | Value::Glob { val, .. } => Some(val.len()),
            _ => None,
        }
    }

    fn lower_runtime_string_concat(
        &mut self,
        lhs_dst: RegId,
        lhs_vreg: VReg,
        rhs: RegId,
    ) -> Result<bool, CompileError> {
        let lhs_meta = self.get_metadata(lhs_dst).cloned();
        let rhs_meta = self.get_metadata(rhs).cloned();
        let lhs_source = lhs_meta
            .as_ref()
            .and_then(|meta| self.string_concat_source(meta));
        let rhs_source = rhs_meta
            .as_ref()
            .and_then(|meta| self.string_concat_source(meta));

        match (lhs_source, rhs_source) {
            (None, None) => Ok(false),
            (Some(lhs_source), Some(rhs_source)) => {
                self.lower_string_like_literal(lhs_dst, lhs_vreg, b"")?;
                self.append_string_concat_source(lhs_dst, lhs_source)?;
                self.append_string_concat_source(lhs_dst, rhs_source)?;
                self.clear_source_var(lhs_dst);
                self.set_reg_constant_value(lhs_dst, None);
                Ok(true)
            }
            _ => Err(CompileError::UnsupportedInstruction(
                "string concatenation with + requires string operands in eBPF".into(),
            )),
        }
    }

    fn string_concat_source(&self, meta: &RegMetadata) -> Option<StringConcatSource> {
        if let Some(slot) = meta.string_slot {
            let max_len = meta
                .string_len_bound
                .or_else(|| {
                    self.stack_slot_size(slot)
                        .map(|size| size.saturating_sub(1))
                })
                .unwrap_or(0);
            return Some(StringConcatSource::Slot { slot, max_len });
        }

        if let Some(value) = meta.literal_string.as_ref() {
            return Some(StringConcatSource::Literal(value.as_bytes().to_vec()));
        }

        match meta.constant_value.as_ref()? {
            Value::String { val, .. } | Value::Glob { val, .. } => {
                Some(StringConcatSource::Literal(val.as_bytes().to_vec()))
            }
            _ => None,
        }
    }

    fn append_string_concat_source(
        &mut self,
        dst: RegId,
        source: StringConcatSource,
    ) -> Result<(), CompileError> {
        let dst_slot = self
            .get_metadata(dst)
            .and_then(|meta| meta.string_slot)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "string concatenation result buffer is unavailable in eBPF".into(),
                )
            })?;
        let dst_len = self
            .get_metadata(dst)
            .and_then(|meta| meta.string_len_vreg)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "string concatenation result length is unavailable in eBPF".into(),
                )
            })?;
        let current_bound = self
            .get_metadata(dst)
            .and_then(|meta| meta.string_len_bound)
            .unwrap_or(0);

        let (val_type, append_max) = match source {
            StringConcatSource::Literal(bytes) => {
                let append_max = bytes
                    .iter()
                    .rposition(|byte| *byte != 0)
                    .map(|idx| idx + 1)
                    .unwrap_or(0);
                (StringAppendType::Literal { bytes }, append_max)
            }
            StringConcatSource::Slot { slot, max_len } => {
                if max_len > STRING_APPEND_COPY_CAP {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "string concatenation with + supports tracked string operands up to {STRING_APPEND_COPY_CAP} bytes in eBPF"
                    )));
                }
                (StringAppendType::StringSlot { slot, max_len }, max_len)
            }
        };

        let new_bound = current_bound.saturating_add(append_max);
        let new_size = self.ensure_string_slot_capacity(dst_slot, new_bound)?;
        {
            let meta = self.get_or_create_metadata(dst);
            meta.string_len_bound = Some(new_bound);
            meta.field_type = Some(MirType::Array {
                elem: Box::new(MirType::U8),
                len: new_size,
            });
        }

        self.emit(MirInst::StringAppend {
            dst_buffer: dst_slot,
            dst_len,
            val: MirValue::Const(0),
            val_type,
        });
        Ok(())
    }

    fn runtime_binop_kind(op: nu_protocol::ast::Operator) -> Option<BinOpKind> {
        use nu_protocol::ast::{Bits, Boolean, Comparison, Math, Operator};

        Some(match op {
            Operator::Math(Math::Add) => BinOpKind::Add,
            Operator::Math(Math::Subtract) => BinOpKind::Sub,
            Operator::Math(Math::Multiply) => BinOpKind::Mul,
            Operator::Math(Math::Divide) => BinOpKind::Div,
            Operator::Math(Math::Modulo) => BinOpKind::Mod,
            Operator::Comparison(Comparison::Equal) => BinOpKind::Eq,
            Operator::Comparison(Comparison::NotEqual) => BinOpKind::Ne,
            Operator::Comparison(Comparison::LessThan) => BinOpKind::Lt,
            Operator::Comparison(Comparison::LessThanOrEqual) => BinOpKind::Le,
            Operator::Comparison(Comparison::GreaterThan) => BinOpKind::Gt,
            Operator::Comparison(Comparison::GreaterThanOrEqual) => BinOpKind::Ge,
            Operator::Bits(Bits::BitAnd) => BinOpKind::And,
            Operator::Bits(Bits::BitOr) => BinOpKind::Or,
            Operator::Bits(Bits::BitXor) => BinOpKind::Xor,
            Operator::Bits(Bits::ShiftLeft) => BinOpKind::Shl,
            Operator::Bits(Bits::ShiftRight) => BinOpKind::Shr,
            // Logical and/or - use bitwise ops since comparisons return 0 or 1
            Operator::Boolean(Boolean::And) => BinOpKind::And,
            Operator::Boolean(Boolean::Or) => BinOpKind::Or,
            Operator::Boolean(Boolean::Xor) => BinOpKind::Xor,
            _ => return None,
        })
    }

    fn lower_integer_pow(
        &mut self,
        lhs_dst: RegId,
        lhs_vreg: VReg,
        rhs: RegId,
        constant_value: Option<Value>,
    ) -> Result<(), CompileError> {
        let exponent = self
            .compile_time_integer_value(rhs)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "Operator ** requires a compile-time known integer exponent in eBPF runtime lowering"
                        .into(),
                )
            })?;
        if exponent < 0 {
            return Err(CompileError::UnsupportedInstruction(
                "Operator ** requires a non-negative integer exponent in eBPF runtime lowering"
                    .into(),
            ));
        }

        if exponent == 0 {
            self.emit(MirInst::Copy {
                dst: lhs_vreg,
                src: MirValue::Const(1),
            });
            self.clear_source_var(lhs_dst);
            self.set_reg_constant_value(lhs_dst, Some(Value::int(1, nu_protocol::Span::unknown())));
            self.vreg_type_hints.insert(lhs_vreg, MirType::I64);
            return Ok(());
        }

        let power_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: power_vreg,
            src: MirValue::VReg(lhs_vreg),
        });
        self.emit(MirInst::Copy {
            dst: lhs_vreg,
            src: MirValue::Const(1),
        });

        let mut remaining = exponent as u64;
        while remaining > 0 {
            if remaining & 1 == 1 {
                self.emit(MirInst::BinOp {
                    dst: lhs_vreg,
                    op: BinOpKind::Mul,
                    lhs: MirValue::VReg(lhs_vreg),
                    rhs: MirValue::VReg(power_vreg),
                });
            }
            remaining >>= 1;
            if remaining > 0 {
                self.emit(MirInst::BinOp {
                    dst: power_vreg,
                    op: BinOpKind::Mul,
                    lhs: MirValue::VReg(power_vreg),
                    rhs: MirValue::VReg(power_vreg),
                });
            }
        }

        self.clear_source_var(lhs_dst);
        self.set_reg_constant_value(lhs_dst, constant_value);
        self.vreg_type_hints.insert(lhs_vreg, MirType::I64);
        self.vreg_type_hints.insert(power_vreg, MirType::I64);
        Ok(())
    }

    fn compile_time_integer_value(&self, reg: RegId) -> Option<i64> {
        self.get_metadata(reg).and_then(|meta| {
            meta.literal_int
                .or_else(|| match meta.constant_value.as_ref() {
                    Some(Value::Int { val, .. }) => Some(*val),
                    _ => None,
                })
        })
    }

    /// Lower Match instruction (used for pattern matching and short-circuit boolean evaluation)
    pub(super) fn lower_match(
        &mut self,
        pattern: &Pattern,
        src: RegId,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        let src_vreg = self.get_vreg(src);

        match pattern {
            Pattern::Value(value) => {
                self.lower_match_value(value, src, src_vreg, if_true, if_false)?
            }
            Pattern::Expression(expr) => {
                self.lower_match_expression(expr, src, src_vreg, if_true, if_false)?
            }
            Pattern::Or(patterns) => {
                self.lower_match_or(patterns, src, src_vreg, if_true, if_false)?
            }
            Pattern::Variable(var_id) => {
                self.bind_variable_to_src_value(*var_id, src, src_vreg)?;
                self.terminate(MirInst::Jump { target: if_true });
            }
            Pattern::IgnoreValue => {
                self.terminate(MirInst::Jump { target: if_true });
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Pattern matching not supported in eBPF: {pattern:?}"
                )));
            }
        }
        Ok(())
    }

    fn lower_match_or(
        &mut self,
        patterns: &[MatchPattern],
        src: RegId,
        src_vreg: VReg,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        if patterns.is_empty() {
            self.terminate(MirInst::Jump { target: if_false });
            return Ok(());
        }

        for (idx, alternative) in patterns.iter().enumerate() {
            if alternative.guard.is_some() {
                return Err(CompileError::UnsupportedInstruction(
                    "Match or-pattern guards are not supported in eBPF".into(),
                ));
            }

            let next_false = if idx + 1 == patterns.len() {
                if_false
            } else {
                self.func.alloc_block()
            };

            match &alternative.pattern {
                Pattern::Value(value) => {
                    self.lower_match_value(value, src, src_vreg, if_true, next_false)?
                }
                Pattern::Expression(expr) => {
                    self.lower_match_expression(expr, src, src_vreg, if_true, next_false)?
                }
                Pattern::IgnoreValue => {
                    self.terminate(MirInst::Jump { target: if_true });
                    return Ok(());
                }
                Pattern::Or(patterns) => {
                    self.lower_match_or(patterns, src, src_vreg, if_true, next_false)?
                }
                pattern => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Match or-pattern alternative {pattern:?} is not supported in eBPF"
                    )));
                }
            }

            if idx + 1 < patterns.len() {
                self.current_block = next_false;
            }
        }

        Ok(())
    }

    fn terminate_bool_match(
        &mut self,
        src_vreg: VReg,
        expected: bool,
        if_true: BlockId,
        if_false: BlockId,
    ) {
        if expected {
            self.terminate(MirInst::Branch {
                cond: src_vreg,
                if_true,
                if_false,
            });
        } else {
            self.terminate(MirInst::Branch {
                cond: src_vreg,
                if_true: if_false,
                if_false: if_true,
            });
        }
    }

    fn terminate_i64_match(
        &mut self,
        src_vreg: VReg,
        expected: i64,
        if_true: BlockId,
        if_false: BlockId,
    ) {
        let cmp_result = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: cmp_result,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(src_vreg),
            rhs: MirValue::Const(expected),
        });
        self.terminate(MirInst::Branch {
            cond: cmp_result,
            if_true,
            if_false,
        });
    }

    fn terminate_known_match_mismatch(&mut self, if_false: BlockId) {
        self.terminate(MirInst::Jump { target: if_false });
    }

    fn terminate_known_match_result(&mut self, matched: bool, if_true: BlockId, if_false: BlockId) {
        self.terminate(MirInst::Jump {
            target: if matched { if_true } else { if_false },
        });
    }

    fn source_literal_string(&self, src: RegId) -> Option<String> {
        let meta = self.get_metadata(src)?;
        if let Some(Value::String { val, .. } | Value::Glob { val, .. }) =
            meta.constant_value.as_ref()
        {
            return Some(val.clone());
        }
        if meta.string_slot.is_some() {
            return meta.literal_string.clone();
        }
        None
    }

    fn lower_match_string(
        &mut self,
        expected: &str,
        src: RegId,
        src_vreg: VReg,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        if self.source_scalar_match_is_known_mismatch(src, src_vreg, ScalarMatchKind::String) {
            self.terminate_known_match_mismatch(if_false);
            return Ok(());
        }

        if let Some(actual) = self.source_literal_string(src) {
            self.terminate_known_match_result(actual == expected, if_true, if_false);
            return Ok(());
        }

        let source = self
            .get_metadata(src)
            .and_then(|meta| self.string_equality_source(meta))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "Match against string patterns requires a compile-time known or tracked source string in eBPF"
                        .into(),
                )
            })?;
        self.terminate_string_literal_match(expected, source, if_true, if_false)
    }

    fn terminate_string_literal_match(
        &mut self,
        expected: &str,
        source: StringEqualitySource,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        let expected_len = expected.len();
        if expected_len > source.max_len {
            self.terminate_known_match_mismatch(if_false);
            return Ok(());
        }

        let len_matches = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: len_matches,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(source.len_vreg),
            rhs: MirValue::Const(expected_len as i64),
        });
        self.vreg_type_hints.insert(len_matches, MirType::Bool);

        if expected_len == 0 {
            self.terminate(MirInst::Branch {
                cond: len_matches,
                if_true,
                if_false,
            });
            return Ok(());
        }

        let expected_slot = self.alloc_string_literal_compare_slot(expected.as_bytes())?;
        let bytes_match = self.func.alloc_vreg();
        self.emit(MirInst::StrCmp {
            dst: bytes_match,
            lhs: source.slot,
            lhs_offset: 0,
            rhs: expected_slot,
            rhs_offset: 0,
            len: expected_len,
        });
        self.vreg_type_hints.insert(bytes_match, MirType::Bool);

        let matches = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: matches,
            op: BinOpKind::And,
            lhs: MirValue::VReg(len_matches),
            rhs: MirValue::VReg(bytes_match),
        });
        self.vreg_type_hints.insert(matches, MirType::Bool);
        self.terminate(MirInst::Branch {
            cond: matches,
            if_true,
            if_false,
        });
        Ok(())
    }

    fn alloc_string_literal_compare_slot(
        &mut self,
        bytes: &[u8],
    ) -> Result<StackSlotId, CompileError> {
        let max_content_len = MAX_STRING_SIZE.saturating_sub(1);
        if bytes.len() > max_content_len {
            return Err(CompileError::UnsupportedInstruction(format!(
                "string pattern is {} bytes; eBPF lowering supports at most {} bytes",
                bytes.len(),
                max_content_len
            )));
        }

        let aligned_len = align_to_eight(bytes.len() + 1).min(MAX_STRING_SIZE).max(16);
        let slot = self
            .func
            .alloc_stack_slot(aligned_len, 8, StackSlotKind::StringBuffer);
        self.record_stack_slot_type(
            slot,
            MirType::Array {
                elem: Box::new(MirType::U8),
                len: aligned_len,
            },
        );

        let mut literal_bytes = vec![0u8; aligned_len];
        literal_bytes[..bytes.len()].copy_from_slice(bytes);
        let len_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: len_vreg,
            src: MirValue::Const(0),
        });
        self.emit(MirInst::StringAppend {
            dst_buffer: slot,
            dst_len: len_vreg,
            val: MirValue::Const(0),
            val_type: StringAppendType::Literal {
                bytes: literal_bytes,
            },
        });
        Ok(slot)
    }

    fn scalar_match_kind_for_value(value: &Value) -> Option<ScalarMatchKind> {
        match value {
            Value::Bool { .. } => Some(ScalarMatchKind::Bool),
            Value::Nothing { .. } => Some(ScalarMatchKind::Nothing),
            Value::Int { .. } => Some(ScalarMatchKind::Int),
            Value::Filesize { .. } => Some(ScalarMatchKind::Filesize),
            Value::Duration { .. } => Some(ScalarMatchKind::Duration),
            Value::String { .. } | Value::Glob { .. } => Some(ScalarMatchKind::String),
            _ => None,
        }
    }

    fn known_match_kind_for_mir_type(ty: &MirType) -> Option<KnownSourceMatchKind> {
        match ty {
            MirType::Bool => Some(KnownSourceMatchKind::Scalar(ScalarMatchKind::Bool)),
            MirType::I8
            | MirType::I16
            | MirType::I32
            | MirType::I64
            | MirType::U8
            | MirType::U16
            | MirType::U32
            | MirType::U64 => Some(KnownSourceMatchKind::NumericScalar),
            MirType::Unknown => None,
            _ => Some(KnownSourceMatchKind::NonScalar),
        }
    }

    fn scalar_match_kind_is_numeric(kind: ScalarMatchKind) -> bool {
        matches!(
            kind,
            ScalarMatchKind::Int | ScalarMatchKind::Filesize | ScalarMatchKind::Duration
        )
    }

    fn source_match_kind(&self, src: RegId, src_vreg: VReg) -> Option<KnownSourceMatchKind> {
        if let Some(kind) = self
            .get_metadata(src)
            .and_then(|meta| meta.constant_value.as_ref())
            .and_then(Self::scalar_match_kind_for_value)
        {
            return Some(KnownSourceMatchKind::Scalar(kind));
        }

        if self
            .get_metadata(src)
            .is_some_and(|meta| meta.string_slot.is_some())
        {
            return Some(KnownSourceMatchKind::Scalar(ScalarMatchKind::String));
        }

        self.vreg_type_hints
            .get(&src_vreg)
            .and_then(Self::known_match_kind_for_mir_type)
    }

    fn source_scalar_match_is_known_mismatch(
        &self,
        src: RegId,
        src_vreg: VReg,
        expected: ScalarMatchKind,
    ) -> bool {
        match self.source_match_kind(src, src_vreg) {
            Some(KnownSourceMatchKind::Scalar(actual)) => actual != expected,
            Some(KnownSourceMatchKind::NumericScalar) => {
                !Self::scalar_match_kind_is_numeric(expected)
            }
            Some(KnownSourceMatchKind::NonScalar) => true,
            None => false,
        }
    }

    fn terminate_i64_range_match(
        &mut self,
        src_vreg: VReg,
        range: &Range,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        let start = match &range.from {
            Some(expr) => Self::match_expression_i64_literal(expr).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "Match range patterns require a literal integer start in eBPF".into(),
                )
            })?,
            None => 0,
        };
        let end = match &range.to {
            Some(expr) => Some(Self::match_expression_i64_literal(expr).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "Match range patterns require a literal integer end in eBPF".into(),
                )
            })?),
            None => None,
        };
        let next = match &range.next {
            Some(expr) => Some(Self::match_expression_i64_literal(expr).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "Match range patterns require a literal integer next value in eBPF".into(),
                )
            })?),
            None => None,
        };

        let Some(end) = end else {
            if let Some(next) = next {
                return self.terminate_i64_stepped_range_match(
                    src_vreg,
                    start,
                    next,
                    None,
                    range.operator.inclusion,
                    if_true,
                    if_false,
                );
            }
            let lower_cmp = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: lower_cmp,
                op: BinOpKind::Ge,
                lhs: MirValue::VReg(src_vreg),
                rhs: MirValue::Const(start),
            });
            self.terminate(MirInst::Branch {
                cond: lower_cmp,
                if_true,
                if_false,
            });
            return Ok(());
        };

        if let Some(next) = next {
            return self.terminate_i64_stepped_range_match(
                src_vreg,
                start,
                next,
                Some(end),
                range.operator.inclusion,
                if_true,
                if_false,
            );
        }

        let (lower_op, lower_bound, upper_op, upper_bound) = if start <= end {
            let upper_op = match range.operator.inclusion {
                RangeInclusion::Inclusive => BinOpKind::Le,
                RangeInclusion::RightExclusive => BinOpKind::Lt,
            };
            (BinOpKind::Ge, start, upper_op, end)
        } else {
            let upper_op = match range.operator.inclusion {
                RangeInclusion::Inclusive => BinOpKind::Le,
                RangeInclusion::RightExclusive => BinOpKind::Lt,
            };
            (BinOpKind::Ge, end, upper_op, start)
        };

        let lower_cmp = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: lower_cmp,
            op: lower_op,
            lhs: MirValue::VReg(src_vreg),
            rhs: MirValue::Const(lower_bound),
        });
        let upper_cmp = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: upper_cmp,
            op: upper_op,
            lhs: MirValue::VReg(src_vreg),
            rhs: MirValue::Const(upper_bound),
        });
        let in_range = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: in_range,
            op: BinOpKind::And,
            lhs: MirValue::VReg(lower_cmp),
            rhs: MirValue::VReg(upper_cmp),
        });
        self.terminate(MirInst::Branch {
            cond: in_range,
            if_true,
            if_false,
        });
        Ok(())
    }

    fn terminate_i64_stepped_range_match(
        &mut self,
        src_vreg: VReg,
        start: i64,
        next: i64,
        end: Option<i64>,
        inclusion: RangeInclusion,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        let raw_step = next.checked_sub(start).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "Match range pattern step overflows i64 in eBPF".into(),
            )
        })?;
        if raw_step == 0 {
            return Err(CompileError::UnsupportedInstruction(
                "Match range patterns require a non-zero explicit step in eBPF".into(),
            ));
        }
        let step = raw_step.checked_abs().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "Match range pattern step is too large for eBPF".into(),
            )
        })?;

        if end.is_some_and(|end| start > end) {
            self.terminate_known_match_mismatch(if_false);
            return Ok(());
        }

        let lower_cmp = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: lower_cmp,
            op: BinOpKind::Ge,
            lhs: MirValue::VReg(src_vreg),
            rhs: MirValue::Const(start),
        });
        let mut in_range = lower_cmp;

        if let Some(end) = end {
            let upper_cmp = self.func.alloc_vreg();
            let upper_op = match inclusion {
                RangeInclusion::Inclusive => BinOpKind::Le,
                RangeInclusion::RightExclusive => BinOpKind::Lt,
            };
            self.emit(MirInst::BinOp {
                dst: upper_cmp,
                op: upper_op,
                lhs: MirValue::VReg(src_vreg),
                rhs: MirValue::Const(end),
            });
            let combined = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: combined,
                op: BinOpKind::And,
                lhs: MirValue::VReg(in_range),
                rhs: MirValue::VReg(upper_cmp),
            });
            in_range = combined;
        }

        if step != 1 {
            let offset = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: offset,
                op: BinOpKind::Sub,
                lhs: MirValue::VReg(src_vreg),
                rhs: MirValue::Const(start),
            });
            let remainder = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: remainder,
                op: BinOpKind::Mod,
                lhs: MirValue::VReg(offset),
                rhs: MirValue::Const(step),
            });
            let aligned = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: aligned,
                op: BinOpKind::Eq,
                lhs: MirValue::VReg(remainder),
                rhs: MirValue::Const(0),
            });
            let combined = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: combined,
                op: BinOpKind::And,
                lhs: MirValue::VReg(in_range),
                rhs: MirValue::VReg(aligned),
            });
            in_range = combined;
        }

        self.terminate(MirInst::Branch {
            cond: in_range,
            if_true,
            if_false,
        });
        Ok(())
    }

    fn match_expression_i64_literal(expr: &nu_protocol::ast::Expression) -> Option<i64> {
        match &expr.expr {
            Expr::Int(value) => Some(*value),
            _ => None,
        }
    }

    fn match_expression_unit_value(expr: &nu_protocol::ast::Expression) -> Option<Value> {
        let Expr::ValueWithUnit(value_with_unit) = &expr.expr else {
            return None;
        };
        let size = Self::match_expression_i64_literal(&value_with_unit.expr)?;
        value_with_unit.unit.item.build_value(size, expr.span).ok()
    }

    fn lower_match_value(
        &mut self,
        value: &Value,
        src: RegId,
        src_vreg: VReg,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        match value {
            Value::Bool { val, .. } => {
                if self.source_scalar_match_is_known_mismatch(src, src_vreg, ScalarMatchKind::Bool)
                {
                    self.terminate_known_match_mismatch(if_false);
                } else {
                    self.terminate_bool_match(src_vreg, *val, if_true, if_false);
                }
            }
            Value::Nothing { .. } => {
                if self.source_scalar_match_is_known_mismatch(
                    src,
                    src_vreg,
                    ScalarMatchKind::Nothing,
                ) {
                    self.terminate_known_match_mismatch(if_false);
                } else {
                    self.terminate_i64_match(src_vreg, 0, if_true, if_false);
                }
            }
            Value::Int { val, .. } => {
                if self.source_scalar_match_is_known_mismatch(src, src_vreg, ScalarMatchKind::Int) {
                    self.terminate_known_match_mismatch(if_false);
                } else {
                    self.terminate_i64_match(src_vreg, *val, if_true, if_false);
                }
            }
            Value::Filesize { val, .. } => {
                if self.source_scalar_match_is_known_mismatch(
                    src,
                    src_vreg,
                    ScalarMatchKind::Filesize,
                ) {
                    self.terminate_known_match_mismatch(if_false);
                } else {
                    self.terminate_i64_match(src_vreg, val.get(), if_true, if_false);
                }
            }
            Value::Duration { val, .. } => {
                if self.source_scalar_match_is_known_mismatch(
                    src,
                    src_vreg,
                    ScalarMatchKind::Duration,
                ) {
                    self.terminate_known_match_mismatch(if_false);
                } else {
                    self.terminate_i64_match(src_vreg, *val, if_true, if_false);
                }
            }
            Value::String { val, .. } | Value::Glob { val, .. } => {
                self.lower_match_string(val, src, src_vreg, if_true, if_false)?;
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Match against value type {:?} not supported in eBPF",
                    value.get_type()
                )));
            }
        }
        Ok(())
    }

    fn lower_match_expression(
        &mut self,
        expr: &nu_protocol::ast::Expression,
        src: RegId,
        src_vreg: VReg,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        match &expr.expr {
            Expr::Bool(val) => {
                if self.source_scalar_match_is_known_mismatch(src, src_vreg, ScalarMatchKind::Bool)
                {
                    self.terminate_known_match_mismatch(if_false);
                } else {
                    self.terminate_bool_match(src_vreg, *val, if_true, if_false);
                }
            }
            Expr::Int(val) => {
                if self.source_scalar_match_is_known_mismatch(src, src_vreg, ScalarMatchKind::Int) {
                    self.terminate_known_match_mismatch(if_false);
                } else {
                    self.terminate_i64_match(src_vreg, *val, if_true, if_false);
                }
            }
            Expr::Range(range) => {
                if self.source_scalar_match_is_known_mismatch(src, src_vreg, ScalarMatchKind::Int) {
                    self.terminate_known_match_mismatch(if_false);
                    return Ok(());
                }
                return self.terminate_i64_range_match(src_vreg, range, if_true, if_false);
            }
            Expr::Nothing => {
                if self.source_scalar_match_is_known_mismatch(
                    src,
                    src_vreg,
                    ScalarMatchKind::Nothing,
                ) {
                    self.terminate_known_match_mismatch(if_false);
                } else {
                    self.terminate_i64_match(src_vreg, 0, if_true, if_false);
                }
            }
            Expr::String(val)
            | Expr::RawString(val)
            | Expr::Filepath(val, _)
            | Expr::Directory(val, _)
            | Expr::GlobPattern(val, _) => {
                self.lower_match_string(val, src, src_vreg, if_true, if_false)?;
            }
            Expr::ValueWithUnit(_) => {
                let value = Self::match_expression_unit_value(expr).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "Match unit patterns require a literal integer value in eBPF".into(),
                    )
                })?;
                self.lower_match_value(&value, src, src_vreg, if_true, if_false)?;
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Match against expression pattern {:?} not supported in eBPF",
                    expr.expr
                )));
            }
        }
        Ok(())
    }

    pub(super) fn typed_value_path_desc(path: &[PathMember]) -> String {
        let mut out = String::new();
        for (idx, member) in path.iter().enumerate() {
            if idx > 0 {
                out.push('.');
            }
            match member {
                PathMember::String { val, .. } => out.push_str(val),
                PathMember::Int { val, .. } => out.push_str(&val.to_string()),
            }
        }
        out
    }

    pub(super) fn typed_value_runtime_type(&self, reg: RegId, vreg: VReg) -> Option<MirType> {
        self.vreg_type_hints
            .get(&vreg)
            .cloned()
            .or_else(|| self.current_type_hints.get(&reg.get()).cloned())
            .or_else(|| {
                self.get_metadata(reg).and_then(|m| {
                    m.field_type
                        .clone()
                        .or_else(|| Self::metadata_record_layout(m))
                })
            })
    }

    fn mir_type_is_signed(ty: &MirType) -> bool {
        matches!(ty, MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64)
    }

    fn mir_type_is_unsigned(ty: &MirType) -> bool {
        matches!(ty, MirType::U8 | MirType::U16 | MirType::U32 | MirType::U64)
    }

    pub(super) fn coerce_scalar_assignment_value(
        &mut self,
        src_vreg: VReg,
        src_ty: &MirType,
        dst_ty: &MirType,
    ) -> Option<VReg> {
        if src_ty == dst_ty {
            return Some(src_vreg);
        }

        let src_size = src_ty.size();
        let dst_size = dst_ty.size();
        if src_size == 0 || dst_size == 0 || src_size > dst_size {
            return None;
        }

        if Self::mir_type_is_unsigned(src_ty) && Self::mir_type_is_unsigned(dst_ty) {
            let widened = self.func.alloc_vreg();
            self.vreg_type_hints.insert(widened, dst_ty.clone());
            self.emit(MirInst::Copy {
                dst: widened,
                src: MirValue::VReg(src_vreg),
            });
            return Some(widened);
        }

        if Self::mir_type_is_signed(src_ty) && Self::mir_type_is_signed(dst_ty) {
            let sign_bit_shift = u32::try_from(src_size.checked_mul(8)?.checked_sub(1)?).ok()?;
            let sign_bit = 1i64.checked_shl(sign_bit_shift)?;
            let sign_bit_value = self.large_const_operand(dst_ty, sign_bit);
            let xor_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(xor_vreg, dst_ty.clone());
            self.emit(MirInst::BinOp {
                dst: xor_vreg,
                op: BinOpKind::Xor,
                lhs: MirValue::VReg(src_vreg),
                rhs: sign_bit_value,
            });

            let sign_bit_value = self.large_const_operand(dst_ty, sign_bit);
            let widened = self.func.alloc_vreg();
            self.vreg_type_hints.insert(widened, dst_ty.clone());
            self.emit(MirInst::BinOp {
                dst: widened,
                op: BinOpKind::Sub,
                lhs: MirValue::VReg(xor_vreg),
                rhs: sign_bit_value,
            });
            return Some(widened);
        }

        None
    }

    pub(super) fn large_const_operand(&mut self, ty: &MirType, value: i64) -> MirValue {
        if i32::try_from(value).is_ok() {
            return MirValue::Const(value);
        }

        let const_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(const_vreg, ty.clone());
        self.emit(MirInst::Copy {
            dst: const_vreg,
            src: MirValue::Const(value),
        });
        MirValue::VReg(const_vreg)
    }

    pub(super) fn packet_guard_end_field(root_ctx_field: Option<&CtxField>) -> CtxField {
        root_ctx_field
            .and_then(CtxField::bounded_end_field)
            .unwrap_or(CtxField::DataEnd)
    }

    pub(super) fn emit_packet_guarded_load(
        &mut self,
        dst_vreg: VReg,
        packet_ptr_vreg: VReg,
        load_ty: &MirType,
        end_field: CtxField,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        if matches!(
            load_ty,
            MirType::Array { .. }
                | MirType::Struct { .. }
                | MirType::Ptr { .. }
                | MirType::MapRef { .. }
                | MirType::Unknown
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "packet load for '{}' requires a scalar element type, got {:?}",
                path_desc, load_ty
            )));
        }

        let access_size = i64::try_from(load_ty.size()).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "packet load for '{}' has unsupported size {}",
                path_desc,
                load_ty.size()
            ))
        })?;
        if access_size <= 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "packet load for '{}' requires positive size",
                path_desc
            )));
        }

        self.vreg_type_hints.insert(dst_vreg, load_ty.clone());
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(0),
        });

        let packet_ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        };
        let data_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(data_end_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::LoadCtxField {
            dst: data_end_vreg,
            field: end_field,
            slot: None,
        });

        let access_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(access_end_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::BinOp {
            dst: access_end_vreg,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(packet_ptr_vreg),
            rhs: MirValue::Const(access_size),
        });

        let cond_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: cond_vreg,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(access_end_vreg),
            rhs: MirValue::VReg(data_end_vreg),
        });

        let load_block = self.func.alloc_block();
        let join_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: cond_vreg,
            if_true: load_block,
            if_false: join_block,
        });

        self.current_block = load_block;
        self.emit(MirInst::Load {
            dst: dst_vreg,
            ptr: packet_ptr_vreg,
            offset: 0,
            ty: load_ty.clone(),
        });
        self.terminate(MirInst::Jump { target: join_block });

        self.current_block = join_block;
        Ok(())
    }

    pub(super) fn emit_xdp_packet_guarded_load(
        &mut self,
        dst_vreg: VReg,
        packet_ptr_vreg: VReg,
        load_ty: &MirType,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        self.emit_packet_guarded_load(
            dst_vreg,
            packet_ptr_vreg,
            load_ty,
            CtxField::DataEnd,
            path_desc,
        )
    }

    pub(super) fn emit_packet_guarded_store(
        &mut self,
        packet_ptr_vreg: VReg,
        val_vreg: VReg,
        store_ty: &MirType,
        end_field: CtxField,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        if matches!(
            store_ty,
            MirType::Array { .. }
                | MirType::Struct { .. }
                | MirType::Ptr { .. }
                | MirType::MapRef { .. }
                | MirType::Unknown
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "packet store for '{}' requires a scalar element type, got {:?}",
                path_desc, store_ty
            )));
        }

        let access_size = i64::try_from(store_ty.size()).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "packet store for '{}' has unsupported size {}",
                path_desc,
                store_ty.size()
            ))
        })?;
        if access_size <= 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "packet store for '{}' requires positive size",
                path_desc
            )));
        }

        let packet_ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        };
        let data_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(data_end_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::LoadCtxField {
            dst: data_end_vreg,
            field: end_field,
            slot: None,
        });

        let access_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(access_end_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::BinOp {
            dst: access_end_vreg,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(packet_ptr_vreg),
            rhs: MirValue::Const(access_size),
        });

        let cond_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: cond_vreg,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(access_end_vreg),
            rhs: MirValue::VReg(data_end_vreg),
        });

        let store_block = self.func.alloc_block();
        let join_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: cond_vreg,
            if_true: store_block,
            if_false: join_block,
        });

        self.current_block = store_block;
        self.emit(MirInst::Store {
            ptr: packet_ptr_vreg,
            offset: 0,
            val: MirValue::VReg(val_vreg),
            ty: store_ty.clone(),
        });
        self.terminate(MirInst::Jump { target: join_block });

        self.current_block = join_block;
        Ok(())
    }

    pub(super) fn emit_context_buffer_guarded_load(
        &mut self,
        dst_vreg: VReg,
        base_ptr_vreg: VReg,
        read_offset_bytes: usize,
        load_ty: &MirType,
        end_field: CtxField,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        if matches!(
            load_ty,
            MirType::Array { .. }
                | MirType::Struct { .. }
                | MirType::Ptr { .. }
                | MirType::MapRef { .. }
                | MirType::Unknown
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "bounded context-buffer load for '{}' requires a scalar element type, got {:?}",
                path_desc, load_ty
            )));
        }

        let access_size = i64::try_from(load_ty.size()).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "bounded context-buffer load for '{}' has unsupported size {}",
                path_desc,
                load_ty.size()
            ))
        })?;
        if access_size <= 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "bounded context-buffer load for '{}' requires positive size",
                path_desc
            )));
        }

        let ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        };
        self.vreg_type_hints.insert(dst_vreg, load_ty.clone());
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(0),
        });

        let non_null_cond_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: non_null_cond_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(base_ptr_vreg),
            rhs: MirValue::Const(0),
        });

        let guard_block = self.func.alloc_block();
        let load_block = self.func.alloc_block();
        let join_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: non_null_cond_vreg,
            if_true: guard_block,
            if_false: join_block,
        });

        self.current_block = guard_block;
        let read_ptr_vreg = if read_offset_bytes == 0 {
            base_ptr_vreg
        } else {
            let read_ptr_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(read_ptr_vreg, ptr_ty.clone());
            self.emit(MirInst::BinOp {
                dst: read_ptr_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(base_ptr_vreg),
                rhs: MirValue::Const(i64::from(Self::trampoline_projection_offset_i32(
                    read_offset_bytes,
                    path_desc,
                )?)),
            });
            read_ptr_vreg
        };

        let end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(end_vreg, ptr_ty.clone());
        self.emit(MirInst::LoadCtxField {
            dst: end_vreg,
            field: end_field,
            slot: None,
        });

        let access_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(access_end_vreg, ptr_ty);
        self.emit(MirInst::BinOp {
            dst: access_end_vreg,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(read_ptr_vreg),
            rhs: MirValue::Const(access_size),
        });

        let within_bounds_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: within_bounds_vreg,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(access_end_vreg),
            rhs: MirValue::VReg(end_vreg),
        });
        self.terminate(MirInst::Branch {
            cond: within_bounds_vreg,
            if_true: load_block,
            if_false: join_block,
        });

        self.current_block = load_block;
        self.emit(MirInst::Load {
            dst: dst_vreg,
            ptr: read_ptr_vreg,
            offset: 0,
            ty: load_ty.clone(),
        });
        self.terminate(MirInst::Jump { target: join_block });

        self.current_block = join_block;
        Ok(())
    }

    pub(super) fn emit_packet_big_endian_scalar_normalize(
        &mut self,
        dst_vreg: VReg,
        ty: &MirType,
    ) -> Result<(), CompileError> {
        let hint = ty.clone();
        match ty {
            MirType::U16 => {
                let mask_ff = self.large_const_operand(ty, 0xff);
                let shift_8 = self.large_const_operand(ty, 8);
                let low = self.func.alloc_vreg();
                self.vreg_type_hints.insert(low, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: low,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: mask_ff.clone(),
                });

                let low_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(low_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: low_shifted,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(low),
                    rhs: shift_8.clone(),
                });

                let high = self.func.alloc_vreg();
                self.vreg_type_hints.insert(high, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: high,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: shift_8,
                });

                let high_masked = self.func.alloc_vreg();
                self.vreg_type_hints.insert(high_masked, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: high_masked,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(high),
                    rhs: mask_ff,
                });

                self.vreg_type_hints.insert(dst_vreg, hint);
                self.emit(MirInst::BinOp {
                    dst: dst_vreg,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(low_shifted),
                    rhs: MirValue::VReg(high_masked),
                });
                Ok(())
            }
            MirType::U32 => {
                let mask_ff = self.large_const_operand(ty, 0x0000_00ff);
                let mask_ff00 = self.large_const_operand(ty, 0x0000_ff00);
                let shift_8 = self.large_const_operand(ty, 8);
                let shift_24 = self.large_const_operand(ty, 24);
                let b0 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b0, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b0,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: mask_ff.clone(),
                });
                let b0_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b0_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b0_shifted,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(b0),
                    rhs: shift_24.clone(),
                });

                let b1 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b1, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b1,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: mask_ff00.clone(),
                });
                let b1_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b1_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b1_shifted,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(b1),
                    rhs: shift_8.clone(),
                });

                let b2_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b2_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b2_shifted,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: shift_8.clone(),
                });
                let b2 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b2, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b2,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(b2_shifted),
                    rhs: mask_ff00,
                });

                let b3_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b3_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b3_shifted,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: shift_24,
                });
                let b3 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b3, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b3,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(b3_shifted),
                    rhs: mask_ff,
                });

                let hi = self.func.alloc_vreg();
                self.vreg_type_hints.insert(hi, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: hi,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(b0_shifted),
                    rhs: MirValue::VReg(b1_shifted),
                });
                let lo = self.func.alloc_vreg();
                self.vreg_type_hints.insert(lo, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: lo,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(b2),
                    rhs: MirValue::VReg(b3),
                });

                self.vreg_type_hints.insert(dst_vreg, hint);
                self.emit(MirInst::BinOp {
                    dst: dst_vreg,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(hi),
                    rhs: MirValue::VReg(lo),
                });
                Ok(())
            }
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "big-endian packet scalar normalization is not supported for {:?}",
                ty
            ))),
        }
    }

    pub(super) fn normalize_host_order_u32_array_slot(
        &mut self,
        base_ptr_vreg: VReg,
    ) -> Result<(), CompileError> {
        let element_ty = MirType::U32;
        for index in 0..4 {
            let word_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(word_vreg, element_ty.clone());
            self.emit(MirInst::Load {
                dst: word_vreg,
                ptr: base_ptr_vreg,
                offset: (index * 4) as i32,
                ty: element_ty.clone(),
            });
            self.emit_packet_big_endian_scalar_normalize(word_vreg, &element_ty)?;
            self.emit(MirInst::Store {
                ptr: base_ptr_vreg,
                offset: (index * 4) as i32,
                val: MirValue::VReg(word_vreg),
                ty: element_ty.clone(),
            });
        }
        Ok(())
    }

    pub(super) fn lower_typed_value_projection(
        &mut self,
        dst_reg: RegId,
        dst_vreg: VReg,
        base_vreg: VReg,
        base_runtime_ty: &MirType,
        path_members: &[PathMember],
        path_desc: &str,
        root_ctx_field: Option<&CtxField>,
        trusted_btf: bool,
        projected_semantics: Option<&AnnotatedValueSemantics>,
    ) -> Result<MirType, CompileError> {
        self.record_context_projection_compat_fields(root_ctx_field, path_members);

        let projected_by_ref =
            |ty: &MirType| matches!(ty, MirType::Array { .. } | MirType::Struct { .. });

        enum ValueCursor {
            Pointer {
                base_vreg: VReg,
                address_space: AddressSpace,
                base_offset: usize,
                target_ty: MirType,
                direct: bool,
                trusted_btf: bool,
            },
            PacketScalar {
                base_vreg: VReg,
                base_offset: usize,
                element_ty: MirType,
                element_size: usize,
                big_endian: bool,
            },
        }

        let mut cursor = match base_runtime_ty {
            MirType::Ptr {
                pointee,
                address_space,
            } => ValueCursor::Pointer {
                base_vreg,
                address_space: *address_space,
                base_offset: 0,
                target_ty: pointee.as_ref().clone(),
                direct: true,
                trusted_btf: *address_space == AddressSpace::Kernel && trusted_btf,
            },
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' requires a typed pointer value, got {:?}",
                    path_desc, base_runtime_ty
                )));
            }
        };

        if let Some(projected_ty) = self.try_lower_helper_backed_typed_projection(
            dst_reg,
            dst_vreg,
            base_vreg,
            base_runtime_ty,
            path_members,
            path_desc,
            root_ctx_field,
            projected_semantics,
        )? {
            return Ok(projected_ty);
        }

        for (segment_idx, member) in path_members.iter().enumerate() {
            let is_last = segment_idx + 1 == path_members.len();
            if let ValueCursor::PacketScalar {
                base_vreg,
                base_offset,
                element_ty,
                element_size,
                big_endian,
            } = &cursor
            {
                let packet_offset = match member {
                    PathMember::Int { val, .. } => {
                        let index = usize::try_from(*val).map_err(|_| {
                            CompileError::UnsupportedInstruction(format!(
                                "typed field path '{}' requires a non-negative packet scalar index",
                                path_desc
                            ))
                        })?;
                        base_offset
                            .checked_add(index.checked_mul(*element_size).ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "typed field path '{}' packet scalar index overflowed",
                                    path_desc
                                ))
                            })?)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "typed field path '{}' offset overflowed",
                                    path_desc
                                ))
                            })?
                    }
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "typed field path '{}' expects a numeric index after packet scalar view",
                            path_desc
                        )));
                    }
                };

                if !is_last {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' does not support nested projection after a packet scalar index",
                        path_desc
                    )));
                }

                let packet_ptr_vreg = if packet_offset == 0 {
                    *base_vreg
                } else {
                    let ptr_vreg = self.func.alloc_vreg();
                    self.vreg_type_hints.insert(
                        ptr_vreg,
                        MirType::Ptr {
                            pointee: Box::new(element_ty.clone()),
                            address_space: AddressSpace::Packet,
                        },
                    );
                    self.emit(MirInst::BinOp {
                        dst: ptr_vreg,
                        op: BinOpKind::Add,
                        lhs: MirValue::VReg(*base_vreg),
                        rhs: MirValue::Const(i64::from(Self::trampoline_projection_offset_i32(
                            packet_offset,
                            path_desc,
                        )?)),
                    });
                    ptr_vreg
                };
                let packet_ptr_vreg = self.packet_load_ptr_vreg(
                    packet_ptr_vreg,
                    MirType::Ptr {
                        pointee: Box::new(MirType::U8),
                        address_space: AddressSpace::Packet,
                    },
                    dst_vreg,
                );

                self.emit_packet_guarded_load(
                    dst_vreg,
                    packet_ptr_vreg,
                    element_ty,
                    Self::packet_guard_end_field(root_ctx_field),
                    path_desc,
                )?;
                if *big_endian {
                    self.emit_packet_big_endian_scalar_normalize(dst_vreg, element_ty)?;
                }
                return Ok(element_ty.clone());
            }

            loop {
                let ValueCursor::Pointer {
                    base_vreg,
                    address_space,
                    base_offset,
                    target_ty,
                    direct,
                    trusted_btf,
                } = &cursor
                else {
                    break;
                };
                let MirType::Ptr {
                    pointee,
                    address_space: next_space,
                } = target_ty
                else {
                    break;
                };
                if *direct && matches!(member, PathMember::Int { .. }) {
                    break;
                }

                let current_base_vreg = *base_vreg;
                let current_address_space = *address_space;
                let current_base_offset = *base_offset;
                let current_trusted_btf = *trusted_btf;
                let next_space = *next_space;
                let ptr_ty = MirType::Ptr {
                    pointee: pointee.clone(),
                    address_space: next_space,
                };
                let ptr_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(ptr_vreg, ptr_ty.clone());
                match current_address_space {
                    AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context => {
                        self.emit(MirInst::Load {
                            dst: ptr_vreg,
                            ptr: current_base_vreg,
                            offset: Self::trampoline_projection_offset_i32(
                                current_base_offset,
                                path_desc,
                            )?,
                            ty: ptr_ty,
                        });
                    }
                    AddressSpace::Kernel | AddressSpace::User => {
                        if current_trusted_btf && current_address_space == AddressSpace::Kernel {
                            self.emit(MirInst::Load {
                                dst: ptr_vreg,
                                ptr: current_base_vreg,
                                offset: Self::trampoline_projection_offset_i32(
                                    current_base_offset,
                                    path_desc,
                                )?,
                                ty: ptr_ty,
                            });
                        } else {
                            let pointer_slot = self.func.alloc_stack_slot(
                                align_to_eight(8),
                                8,
                                StackSlotKind::Local,
                            );
                            self.record_stack_slot_type(pointer_slot, ptr_ty.clone());
                            self.emit_trampoline_probe_read_to_slot(
                                current_base_vreg,
                                current_address_space,
                                current_base_offset,
                                pointer_slot,
                                &ptr_ty,
                                path_desc,
                            )?;
                            self.emit(MirInst::LoadSlot {
                                dst: ptr_vreg,
                                slot: pointer_slot,
                                offset: 0,
                                ty: ptr_ty,
                            });
                        }
                    }
                    AddressSpace::Packet => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "xdp packet path '{}' does not support nested pointer dereferences",
                            path_desc
                        )));
                    }
                }
                cursor = ValueCursor::Pointer {
                    base_vreg: ptr_vreg,
                    address_space: next_space,
                    base_offset: 0,
                    target_ty: pointee.as_ref().clone(),
                    direct: true,
                    trusted_btf: current_trusted_btf && next_space == AddressSpace::Kernel,
                };
            }

            let ValueCursor::Pointer {
                base_vreg,
                address_space,
                base_offset,
                target_ty,
                direct,
                trusted_btf,
            } = &cursor
            else {
                continue;
            };

            if *address_space == AddressSpace::Packet {
                if let Some(kind) = Self::packet_payload_step_kind(target_ty, member) {
                    let payload_ptr_vreg = self.emit_packet_payload_ptr_step(
                        *base_vreg,
                        *base_offset,
                        kind,
                        path_desc,
                    )?;
                    if is_last {
                        self.vreg_type_hints.insert(
                            dst_vreg,
                            MirType::Ptr {
                                pointee: Box::new(MirType::U8),
                                address_space: AddressSpace::Packet,
                            },
                        );
                        self.emit(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::VReg(payload_ptr_vreg),
                        });
                        return Ok(MirType::U8);
                    }

                    cursor = ValueCursor::Pointer {
                        base_vreg: payload_ptr_vreg,
                        address_space: *address_space,
                        base_offset: 0,
                        target_ty: MirType::U8,
                        direct: true,
                        trusted_btf: false,
                    };
                    continue;
                }

                if let Some((payload_kind, view_ty)) =
                    Self::packet_protocol_header_view_spec(target_ty, member)
                {
                    let view_ptr_vreg = self.emit_packet_payload_ptr_step(
                        *base_vreg,
                        *base_offset,
                        payload_kind,
                        path_desc,
                    )?;
                    if is_last {
                        self.vreg_type_hints.insert(
                            dst_vreg,
                            MirType::Ptr {
                                pointee: Box::new(view_ty.clone()),
                                address_space: AddressSpace::Packet,
                            },
                        );
                        self.emit(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::VReg(view_ptr_vreg),
                        });
                        return Ok(view_ty);
                    }

                    cursor = ValueCursor::Pointer {
                        base_vreg: view_ptr_vreg,
                        address_space: *address_space,
                        base_offset: 0,
                        target_ty: view_ty,
                        direct: false,
                        trusted_btf: false,
                    };
                    continue;
                }

                if let Some(TypedProjectionStep {
                    offset: view_offset,
                    ty: view_ty,
                    ..
                }) = Self::packet_header_view_spec(target_ty, member)
                {
                    let field_offset = base_offset.checked_add(view_offset).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "typed field path '{}' offset overflowed",
                            path_desc
                        ))
                    })?;

                    if is_last {
                        self.vreg_type_hints.insert(
                            dst_vreg,
                            MirType::Ptr {
                                pointee: Box::new(view_ty.clone()),
                                address_space: AddressSpace::Packet,
                            },
                        );
                        if field_offset == 0 {
                            self.emit(MirInst::Copy {
                                dst: dst_vreg,
                                src: MirValue::VReg(*base_vreg),
                            });
                        } else {
                            self.emit(MirInst::BinOp {
                                dst: dst_vreg,
                                op: BinOpKind::Add,
                                lhs: MirValue::VReg(*base_vreg),
                                rhs: MirValue::Const(i64::from(
                                    Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                )),
                            });
                        }
                        return Ok(view_ty);
                    }

                    cursor = ValueCursor::Pointer {
                        base_vreg: *base_vreg,
                        address_space: *address_space,
                        base_offset: field_offset,
                        target_ty: view_ty,
                        direct: false,
                        trusted_btf: false,
                    };
                    continue;
                }

                if matches!(target_ty, MirType::U8)
                    && let Some((element_ty, element_size, big_endian)) =
                        Self::packet_scalar_view_spec(member)
                {
                    if is_last {
                        let packet_ptr_vreg = self.packet_load_ptr_vreg(
                            *base_vreg,
                            MirType::Ptr {
                                pointee: Box::new(target_ty.clone()),
                                address_space: AddressSpace::Packet,
                            },
                            dst_vreg,
                        );
                        self.emit_packet_guarded_load(
                            dst_vreg,
                            packet_ptr_vreg,
                            &element_ty,
                            Self::packet_guard_end_field(root_ctx_field),
                            path_desc,
                        )?;
                        if big_endian {
                            self.emit_packet_big_endian_scalar_normalize(dst_vreg, &element_ty)?;
                        }
                        return Ok(element_ty);
                    }

                    cursor = ValueCursor::PacketScalar {
                        base_vreg: *base_vreg,
                        base_offset: *base_offset,
                        element_ty,
                        element_size,
                        big_endian,
                    };
                    continue;
                }
            }

            let TypedProjectionStep {
                offset: segment_offset,
                ty: next_ty,
                bitfield,
                packet_big_endian,
            } = match (direct, member) {
                (true, PathMember::Int { val, .. })
                    if !matches!(target_ty, MirType::Array { .. }) =>
                {
                    Self::resolve_pointer_sequence_index_step(target_ty, *val, path_desc)?
                }
                _ => Self::resolve_typed_value_projection_step(target_ty, member, path_desc)?,
            };
            let field_offset = base_offset.checked_add(segment_offset).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' offset overflowed",
                    path_desc
                ))
            })?;

            if is_last {
                if projected_by_ref(&next_ty) {
                    match address_space {
                        AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context => {
                            if let Some(AnnotatedValueSemantics::NumericList { max_len, .. }) =
                                projected_semantics
                            {
                                let buffer_size =
                                    (max_len.saturating_add(1)) * std::mem::size_of::<i64>();
                                let slot = self.func.alloc_stack_slot(
                                    buffer_size,
                                    8,
                                    StackSlotKind::ListBuffer,
                                );
                                self.record_list_buffer_slot_type(slot, *max_len);
                                self.emit(MirInst::ListNew {
                                    dst: dst_vreg,
                                    buffer: slot,
                                    max_len: *max_len,
                                });
                                self.vreg_type_hints.insert(
                                    dst_vreg,
                                    MirType::Ptr {
                                        pointee: Box::new(next_ty.clone()),
                                        address_space: AddressSpace::Stack,
                                    },
                                );
                                self.emit_ptr_to_slot_copy(
                                    slot,
                                    0,
                                    *base_vreg,
                                    field_offset,
                                    next_ty.size(),
                                )?;
                                let meta = self.get_or_create_metadata(dst_reg);
                                meta.list_buffer = Some((slot, *max_len));
                                meta.annotated_semantics = projected_semantics.cloned();
                                return Ok(next_ty);
                            }
                            if let Some(AnnotatedValueSemantics::String {
                                slot_len,
                                content_cap,
                            }) = projected_semantics
                            {
                                let slot = self.func.alloc_stack_slot(
                                    *slot_len,
                                    8,
                                    StackSlotKind::StringBuffer,
                                );
                                self.record_stack_slot_type(
                                    slot,
                                    MirType::Array {
                                        elem: Box::new(MirType::U8),
                                        len: *slot_len,
                                    },
                                );
                                self.emit(MirInst::Copy {
                                    dst: dst_vreg,
                                    src: MirValue::StackSlot(slot),
                                });
                                self.vreg_type_hints.insert(
                                    dst_vreg,
                                    MirType::Ptr {
                                        pointee: Box::new(MirType::Array {
                                            elem: Box::new(MirType::U8),
                                            len: *slot_len,
                                        }),
                                        address_space: AddressSpace::Stack,
                                    },
                                );
                                let len_vreg = self.func.alloc_vreg();
                                self.emit(MirInst::Load {
                                    dst: len_vreg,
                                    ptr: *base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: MirType::U64,
                                });
                                self.vreg_type_hints.insert(len_vreg, MirType::U64);
                                self.emit_ptr_to_slot_copy(
                                    slot,
                                    0,
                                    *base_vreg,
                                    field_offset.saturating_add(8),
                                    *slot_len,
                                )?;
                                let meta = self.get_or_create_metadata(dst_reg);
                                meta.string_slot = Some(slot);
                                meta.string_len_vreg = Some(len_vreg);
                                meta.string_len_bound = Some(*content_cap);
                                meta.annotated_semantics = projected_semantics.cloned();
                                return Ok(next_ty);
                            }
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: *address_space,
                                },
                            );
                            if field_offset == 0 {
                                self.emit(MirInst::Copy {
                                    dst: dst_vreg,
                                    src: MirValue::VReg(*base_vreg),
                                });
                            } else {
                                self.emit(MirInst::BinOp {
                                    dst: dst_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(*base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                            }
                        }
                        AddressSpace::Kernel | AddressSpace::User => {
                            let projected_slot = self.func.alloc_stack_slot(
                                align_to_eight(next_ty.size()),
                                8,
                                StackSlotKind::Local,
                            );
                            self.record_stack_slot_type(projected_slot, next_ty.clone());
                            self.emit_trampoline_probe_read_to_slot(
                                *base_vreg,
                                *address_space,
                                field_offset,
                                projected_slot,
                                &next_ty,
                                path_desc,
                            )?;
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: AddressSpace::Stack,
                                },
                            );
                            self.emit(MirInst::Copy {
                                dst: dst_vreg,
                                src: MirValue::StackSlot(projected_slot),
                            });
                        }
                        AddressSpace::Packet => {
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: *address_space,
                                },
                            );
                            if field_offset == 0 {
                                self.emit(MirInst::Copy {
                                    dst: dst_vreg,
                                    src: MirValue::VReg(*base_vreg),
                                });
                            } else {
                                self.emit(MirInst::BinOp {
                                    dst: dst_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(*base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                            }
                        }
                    }
                } else {
                    match address_space {
                        AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context => {
                            let loaded_vreg = if bitfield.is_some() {
                                let storage_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints.insert(storage_vreg, next_ty.clone());
                                self.emit(MirInst::Load {
                                    dst: storage_vreg,
                                    ptr: *base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: next_ty.clone(),
                                });
                                storage_vreg
                            } else {
                                dst_vreg
                            };
                            if let Some(bitfield) = bitfield {
                                self.emit_bitfield_extract(
                                    dst_vreg,
                                    loaded_vreg,
                                    &next_ty,
                                    bitfield,
                                )?;
                            } else {
                                self.vreg_type_hints.insert(dst_vreg, next_ty.clone());
                                self.emit(MirInst::Load {
                                    dst: dst_vreg,
                                    ptr: *base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: next_ty.clone(),
                                });
                            }
                        }
                        AddressSpace::Kernel | AddressSpace::User => {
                            if *trusted_btf
                                && *address_space == AddressSpace::Kernel
                                && matches!(
                                    next_ty,
                                    MirType::Ptr {
                                        address_space: AddressSpace::Kernel,
                                        ..
                                    }
                                )
                            {
                                self.vreg_type_hints.insert(dst_vreg, next_ty.clone());
                                self.emit(MirInst::Load {
                                    dst: dst_vreg,
                                    ptr: *base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: next_ty.clone(),
                                });
                            } else if *trusted_btf && *address_space == AddressSpace::Kernel {
                                let loaded_vreg = if bitfield.is_some() {
                                    let storage_vreg = self.func.alloc_vreg();
                                    self.vreg_type_hints.insert(storage_vreg, next_ty.clone());
                                    self.emit(MirInst::Load {
                                        dst: storage_vreg,
                                        ptr: *base_vreg,
                                        offset: Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                        ty: next_ty.clone(),
                                    });
                                    storage_vreg
                                } else {
                                    dst_vreg
                                };
                                if let Some(bitfield) = bitfield {
                                    self.emit_bitfield_extract(
                                        dst_vreg,
                                        loaded_vreg,
                                        &next_ty,
                                        bitfield,
                                    )?;
                                } else {
                                    self.vreg_type_hints.insert(dst_vreg, next_ty.clone());
                                    self.emit(MirInst::Load {
                                        dst: dst_vreg,
                                        ptr: *base_vreg,
                                        offset: Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                        ty: next_ty.clone(),
                                    });
                                }
                            } else if *address_space == AddressSpace::Kernel
                                && root_ctx_field == Some(&CtxField::SockoptOptval)
                            {
                                if bitfield.is_some() {
                                    return Err(CompileError::UnsupportedInstruction(format!(
                                        "bounded context-buffer path '{}' does not support bitfield extraction",
                                        path_desc
                                    )));
                                }
                                self.emit_context_buffer_guarded_load(
                                    dst_vreg,
                                    *base_vreg,
                                    field_offset,
                                    &next_ty,
                                    CtxField::SockoptOptvalEnd,
                                    path_desc,
                                )?;
                            } else {
                                let projected_slot = self.func.alloc_stack_slot(
                                    align_to_eight(next_ty.size()),
                                    8,
                                    StackSlotKind::Local,
                                );
                                self.record_stack_slot_type(projected_slot, next_ty.clone());
                                self.emit_trampoline_probe_read_to_slot(
                                    *base_vreg,
                                    *address_space,
                                    field_offset,
                                    projected_slot,
                                    &next_ty,
                                    path_desc,
                                )?;
                                let loaded_vreg = if bitfield.is_some() {
                                    let storage_vreg = self.func.alloc_vreg();
                                    self.vreg_type_hints.insert(storage_vreg, next_ty.clone());
                                    self.emit(MirInst::LoadSlot {
                                        dst: storage_vreg,
                                        slot: projected_slot,
                                        offset: 0,
                                        ty: next_ty.clone(),
                                    });
                                    storage_vreg
                                } else {
                                    dst_vreg
                                };
                                if let Some(bitfield) = bitfield {
                                    self.emit_bitfield_extract(
                                        dst_vreg,
                                        loaded_vreg,
                                        &next_ty,
                                        bitfield,
                                    )?;
                                } else {
                                    self.vreg_type_hints.insert(dst_vreg, next_ty.clone());
                                    self.emit(MirInst::LoadSlot {
                                        dst: dst_vreg,
                                        slot: projected_slot,
                                        offset: 0,
                                        ty: next_ty.clone(),
                                    });
                                }
                            }
                        }
                        AddressSpace::Packet => {
                            let packet_ptr_vreg = if field_offset == 0 {
                                *base_vreg
                            } else {
                                let ptr_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints.insert(
                                    ptr_vreg,
                                    MirType::Ptr {
                                        pointee: Box::new(next_ty.clone()),
                                        address_space: AddressSpace::Packet,
                                    },
                                );
                                self.emit(MirInst::BinOp {
                                    dst: ptr_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(*base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                                ptr_vreg
                            };
                            let packet_ptr_vreg = self.packet_load_ptr_vreg(
                                packet_ptr_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: AddressSpace::Packet,
                                },
                                dst_vreg,
                            );
                            let loaded_vreg = if bitfield.is_some() {
                                let storage_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints.insert(storage_vreg, next_ty.clone());
                                storage_vreg
                            } else {
                                dst_vreg
                            };
                            self.emit_packet_guarded_load(
                                loaded_vreg,
                                packet_ptr_vreg,
                                &next_ty,
                                Self::packet_guard_end_field(root_ctx_field),
                                path_desc,
                            )?;
                            if packet_big_endian {
                                self.emit_packet_big_endian_scalar_normalize(
                                    loaded_vreg,
                                    &next_ty,
                                )?;
                            }
                            if let Some(bitfield) = bitfield {
                                self.emit_bitfield_extract(
                                    dst_vreg,
                                    loaded_vreg,
                                    &next_ty,
                                    bitfield,
                                )?;
                            }
                        }
                    }
                }
                return Ok(next_ty);
            }

            cursor = ValueCursor::Pointer {
                base_vreg: *base_vreg,
                address_space: *address_space,
                base_offset: field_offset,
                target_ty: next_ty,
                direct: false,
                trusted_btf: *trusted_btf,
            };
        }

        Err(CompileError::UnsupportedInstruction(format!(
            "empty typed field path '{}'",
            path_desc
        )))
    }

    fn record_context_projection_compat_fields(
        &mut self,
        root_ctx_field: Option<&CtxField>,
        path_members: &[PathMember],
    ) {
        if !matches!(
            root_ctx_field,
            Some(CtxField::Socket | CtxField::MigratingSocket)
        ) {
            return;
        }

        let Some(PathMember::String { val, .. }) = path_members.first() else {
            return;
        };
        if let Some(field) = ctx_field_for_bpf_sock_projection_member(val) {
            self.implied_ctx_fields.insert(field);
        }
    }
}
