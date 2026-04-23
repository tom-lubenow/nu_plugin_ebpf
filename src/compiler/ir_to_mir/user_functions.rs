use super::*;
use crate::compiler::subfn_summaries::{
    SubfunctionReturnSummary, infer_subfunction_return_summaries,
};
use nu_protocol::Record;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy)]
pub(super) struct UserFunctionCallArg {
    pub(super) vreg: VReg,
    pub(super) source_reg: Option<RegId>,
}

#[derive(Debug, Clone)]
enum AggregateReturnCallSetup {
    Record {
        slot: StackSlotId,
        ty: MirType,
    },
    List {
        slot: StackSlotId,
        max_len: usize,
    },
    String {
        call_slot: StackSlotId,
        slot_len: usize,
        len_vreg: VReg,
    },
}

impl<'a> HirToMirLowering<'a> {
    fn inferred_literal_type(lit: &HirLiteral) -> Option<MirType> {
        match lit {
            HirLiteral::Bool(_) => Some(MirType::Bool),
            HirLiteral::Int(_) | HirLiteral::Duration(_) | HirLiteral::Filesize(_) => {
                Some(MirType::I64)
            }
            HirLiteral::Float(_) => Some(MirType::I64),
            HirLiteral::String(bytes)
            | HirLiteral::RawString(bytes)
            | HirLiteral::Binary(bytes) => Some(MirType::Array {
                elem: Box::new(MirType::U8),
                len: align_to_eight(bytes.len().saturating_add(1))
                    .min(MAX_STRING_SIZE)
                    .max(16),
            }),
            HirLiteral::Filepath { val, .. }
            | HirLiteral::Directory { val, .. }
            | HirLiteral::GlobPattern { val, .. } => Some(MirType::Array {
                elem: Box::new(MirType::U8),
                len: align_to_eight(val.len().saturating_add(1))
                    .min(MAX_STRING_SIZE)
                    .max(16),
            }),
            HirLiteral::List { capacity } => Some(MirType::Array {
                elem: Box::new(MirType::I64),
                len: capacity.saturating_add(1),
            }),
            _ => None,
        }
    }

    fn infer_block_aggregate_return_abi(
        &self,
        decl_id: DeclId,
        block: &crate::compiler::hir::HirBlock,
        return_src: RegId,
    ) -> Option<SubfunctionAggregateReturnAbi> {
        fn clear_tracked_reg(
            literal_strings: &mut HashMap<RegId, String>,
            string_slots: &mut HashSet<RegId>,
            string_bounds: &mut HashMap<RegId, usize>,
            reg_types: &mut HashMap<RegId, MirType>,
            list_caps: &mut HashMap<RegId, usize>,
            record_fields: &mut HashMap<RegId, Vec<(String, MirType)>>,
            reg: RegId,
        ) {
            literal_strings.remove(&reg);
            string_slots.remove(&reg);
            string_bounds.remove(&reg);
            reg_types.remove(&reg);
            list_caps.remove(&reg);
            record_fields.remove(&reg);
        }

        let hint_map = self.decl_type_hints.get(&decl_id);
        let mut literal_strings: HashMap<RegId, String> = HashMap::new();
        let mut reg_types: HashMap<RegId, MirType> = HashMap::new();
        let mut list_caps: HashMap<RegId, usize> = HashMap::new();
        let mut record_fields: HashMap<RegId, Vec<(String, MirType)>> = HashMap::new();
        let mut string_slots: HashSet<RegId> = HashSet::new();
        let mut string_bounds: HashMap<RegId, usize> = HashMap::new();

        for stmt in &block.stmts {
            match stmt {
                HirStmt::LoadLiteral { dst, lit } => {
                    clear_tracked_reg(
                        &mut literal_strings,
                        &mut string_slots,
                        &mut string_bounds,
                        &mut reg_types,
                        &mut list_caps,
                        &mut record_fields,
                        *dst,
                    );
                    if let Some(ty) = hint_map
                        .and_then(|hints| hints.get(&dst.get()).cloned())
                        .or_else(|| Self::inferred_literal_type(&lit))
                    {
                        reg_types.insert(*dst, ty);
                    }
                    match lit {
                        HirLiteral::String(bytes) | HirLiteral::RawString(bytes) => {
                            if let Ok(string) = std::str::from_utf8(&bytes) {
                                literal_strings.insert(*dst, string.to_string());
                            }
                            string_slots.insert(*dst);
                            string_bounds
                                .insert(*dst, bytes.len().min(MAX_STRING_SIZE.saturating_sub(1)));
                        }
                        HirLiteral::Filepath { val, .. }
                        | HirLiteral::Directory { val, .. }
                        | HirLiteral::GlobPattern { val, .. } => {
                            if let Ok(string) = std::str::from_utf8(&val) {
                                literal_strings.insert(*dst, string.to_string());
                            }
                            string_slots.insert(*dst);
                            string_bounds
                                .insert(*dst, val.len().min(MAX_STRING_SIZE.saturating_sub(1)));
                        }
                        HirLiteral::Record { .. } => {
                            record_fields.insert(*dst, Vec::new());
                        }
                        HirLiteral::List { capacity } => {
                            list_caps.insert(*dst, *capacity);
                        }
                        _ => {}
                    }
                }
                HirStmt::LoadValue { dst, val } => match &**val {
                    Value::String { val, .. } | Value::Glob { val, .. } => {
                        clear_tracked_reg(
                            &mut literal_strings,
                            &mut string_slots,
                            &mut string_bounds,
                            &mut reg_types,
                            &mut list_caps,
                            &mut record_fields,
                            *dst,
                        );
                        literal_strings.insert(*dst, val.clone());
                        string_slots.insert(*dst);
                        string_bounds
                            .insert(*dst, val.len().min(MAX_STRING_SIZE.saturating_sub(1)));
                        reg_types.insert(
                            *dst,
                            MirType::Array {
                                elem: Box::new(MirType::U8),
                                len: align_to_eight(val.len().saturating_add(1))
                                    .min(MAX_STRING_SIZE)
                                    .max(16),
                            },
                        );
                    }
                    Value::Int { .. } => {
                        clear_tracked_reg(
                            &mut literal_strings,
                            &mut string_slots,
                            &mut string_bounds,
                            &mut reg_types,
                            &mut list_caps,
                            &mut record_fields,
                            *dst,
                        );
                        reg_types.insert(*dst, MirType::I64);
                    }
                    Value::Bool { .. } => {
                        clear_tracked_reg(
                            &mut literal_strings,
                            &mut string_slots,
                            &mut string_bounds,
                            &mut reg_types,
                            &mut list_caps,
                            &mut record_fields,
                            *dst,
                        );
                        reg_types.insert(*dst, MirType::Bool);
                    }
                    _ => {
                        clear_tracked_reg(
                            &mut literal_strings,
                            &mut string_slots,
                            &mut string_bounds,
                            &mut reg_types,
                            &mut list_caps,
                            &mut record_fields,
                            *dst,
                        );
                    }
                },
                HirStmt::Move { dst, src } | HirStmt::Clone { dst, src } => {
                    clear_tracked_reg(
                        &mut literal_strings,
                        &mut string_slots,
                        &mut string_bounds,
                        &mut reg_types,
                        &mut list_caps,
                        &mut record_fields,
                        *dst,
                    );
                    if let Some(string) = literal_strings.get(&src).cloned() {
                        literal_strings.insert(*dst, string);
                    }
                    if string_slots.contains(&src) {
                        string_slots.insert(*dst);
                    }
                    if let Some(bound) = string_bounds.get(&src).copied() {
                        string_bounds.insert(*dst, bound);
                    }
                    if let Some(ty) = hint_map
                        .and_then(|hints| hints.get(&dst.get()).cloned())
                        .or_else(|| reg_types.get(&src).cloned())
                    {
                        reg_types.insert(*dst, ty);
                    }
                    if let Some(capacity) = list_caps.get(&src).copied() {
                        list_caps.insert(*dst, capacity);
                    }
                    if let Some(fields) = record_fields.get(&src).cloned() {
                        record_fields.insert(*dst, fields);
                    }
                }
                HirStmt::LoadVariable { dst, .. } => {
                    clear_tracked_reg(
                        &mut literal_strings,
                        &mut string_slots,
                        &mut string_bounds,
                        &mut reg_types,
                        &mut list_caps,
                        &mut record_fields,
                        *dst,
                    );
                    if let Some(ty) = hint_map
                        .and_then(|hints| hints.get(&dst.get()).cloned())
                        .map(|ty| self.stored_generic_map_value_type(&ty))
                    {
                        reg_types.insert(*dst, ty);
                    }
                }
                HirStmt::RecordInsert { src_dst, key, val } => {
                    let key_name = literal_strings.get(&key)?.clone();
                    let value_ty = hint_map
                        .and_then(|hints| hints.get(&val.get()).cloned())
                        .or_else(|| reg_types.get(&val).cloned())
                        .or_else(|| {
                            record_fields
                                .get(&val)
                                .map(|fields| Self::record_type_from_fields(fields))
                        })
                        .or_else(|| {
                            list_caps.get(&val).map(|capacity| MirType::Array {
                                elem: Box::new(MirType::I64),
                                len: capacity.saturating_add(1),
                            })
                        })
                        .map(|ty| self.stored_generic_map_value_type(&ty))
                        .map(|ty| {
                            if string_slots.contains(&val) {
                                Self::stored_record_field_type(&ty)
                            } else {
                                ty
                            }
                        })?;
                    let fields = record_fields.entry(*src_dst).or_default();
                    if let Some(existing) = fields.iter_mut().find(|(name, _)| *name == key_name) {
                        existing.1 = value_ty;
                    } else {
                        fields.push((key_name, value_ty));
                    }
                }
                HirStmt::RecordSpread { src_dst, items } => {
                    let spread_fields = record_fields.get(items)?.clone();
                    let fields = record_fields.entry(*src_dst).or_default();
                    for (name, ty) in spread_fields {
                        if let Some(existing) = fields.iter_mut().find(|(field, _)| *field == name)
                        {
                            existing.1 = ty;
                        } else {
                            fields.push((name, ty));
                        }
                    }
                }
                HirStmt::ListPush { src_dst, .. } => {
                    if let Some(capacity) = list_caps.get(&src_dst).copied() {
                        reg_types.insert(
                            *src_dst,
                            MirType::Array {
                                elem: Box::new(MirType::I64),
                                len: capacity.saturating_add(1),
                            },
                        );
                    }
                }
                HirStmt::StringAppend { src_dst, val } => {
                    let Some(current_bound) = string_bounds.get(&src_dst).copied() else {
                        continue;
                    };
                    let append_bound = string_bounds
                        .get(&val)
                        .copied()
                        .or_else(|| {
                            literal_strings
                                .get(&val)
                                .map(|string| string.len().min(MAX_STRING_SIZE.saturating_sub(1)))
                        })
                        .unwrap_or(MAX_INT_STRING_LEN);
                    let new_bound = current_bound.saturating_add(append_bound);
                    if new_bound.saturating_add(1) > MAX_STRING_SIZE {
                        string_bounds.remove(&src_dst);
                        string_slots.remove(&src_dst);
                        reg_types.remove(&src_dst);
                        continue;
                    }
                    let new_slot_len = align_to_eight(new_bound.saturating_add(1))
                        .min(MAX_STRING_SIZE)
                        .max(16);
                    string_bounds.insert(*src_dst, new_bound);
                    string_slots.insert(*src_dst);
                    reg_types.insert(
                        *src_dst,
                        MirType::Array {
                            elem: Box::new(MirType::U8),
                            len: new_slot_len,
                        },
                    );
                }
                _ => {}
            }
        }

        record_fields
            .get(&return_src)
            .map(|fields| SubfunctionAggregateReturnAbi::Record {
                ty: Self::record_type_from_fields(fields),
            })
            .or_else(|| {
                list_caps
                    .get(&return_src)
                    .copied()
                    .map(|max_len| SubfunctionAggregateReturnAbi::List { max_len })
            })
            .or_else(|| {
                string_bounds.get(&return_src).copied().map(|bound| {
                    SubfunctionAggregateReturnAbi::String {
                        slot_len: align_to_eight(bound.saturating_add(1))
                            .min(MAX_STRING_SIZE)
                            .max(16),
                    }
                })
            })
    }

    fn stored_record_field_type(ty: &MirType) -> MirType {
        match ty {
            MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::U8) => {
                MirType::Array {
                    elem: elem.clone(),
                    len: len.saturating_add(std::mem::size_of::<u64>()),
                }
            }
            _ => ty.clone(),
        }
    }

    pub(super) fn constant_record_key_value(
        reg_constants: &HashMap<RegId, Value>,
        key: RegId,
    ) -> Option<String> {
        reg_constants.get(&key).and_then(|value| match value {
            Value::String { val, .. } | Value::Glob { val, .. } => Some(val.clone()),
            Value::Binary { val, .. } => String::from_utf8(val.clone()).ok(),
            _ => None,
        })
    }

    pub(super) fn constant_follow_cell_path(value: &Value, path: &CellPath) -> Option<Value> {
        let mut current = value.clone();
        for member in &path.members {
            match member {
                PathMember::String { val, .. } => {
                    let Value::Record { val: record, .. } = &current else {
                        return None;
                    };
                    current = record.get(val)?.clone();
                }
                PathMember::Int { val, .. } => {
                    let Value::List { vals, .. } = &current else {
                        return None;
                    };
                    current = vals.get(*val as usize)?.clone();
                }
            }
        }
        Some(current)
    }

    pub(super) fn constant_upsert_cell_path(
        value: &Value,
        path: &CellPath,
        new_value: Value,
    ) -> Option<Value> {
        fn upsert(current: &Value, members: &[PathMember], new_value: &Value) -> Option<Value> {
            let Some((member, rest)) = members.split_first() else {
                return Some(new_value.clone());
            };

            match member {
                PathMember::String { val, .. } => {
                    let Value::Record { val: record, .. } = current else {
                        return None;
                    };
                    let mut record = record.clone().into_owned();
                    let updated = if rest.is_empty() {
                        new_value.clone()
                    } else {
                        let current_child = record.get(val)?;
                        upsert(current_child, rest, new_value)?
                    };
                    record.insert(val.clone(), updated);
                    Some(Value::record(record, Span::unknown()))
                }
                PathMember::Int { val, .. } => {
                    let Value::List { vals, .. } = current else {
                        return None;
                    };
                    let idx = *val as usize;
                    let current_child = vals.get(idx)?;
                    let mut vals = vals.clone();
                    vals[idx] = if rest.is_empty() {
                        new_value.clone()
                    } else {
                        upsert(current_child, rest, new_value)?
                    };
                    Some(Value::list(vals, Span::unknown()))
                }
            }
        }

        upsert(value, &path.members, &new_value)
    }

    pub(super) fn constant_apply_binary_operator(
        lhs: &Value,
        op: nu_protocol::ast::Operator,
        rhs: &Value,
    ) -> Option<Value> {
        use nu_protocol::ast::{Bits, Boolean, Comparison, Math, Operator};

        let op_span = Span::unknown();
        let span = Span::unknown();

        match op {
            Operator::Math(math) => match math {
                Math::Add => lhs.add(op_span, rhs, span).ok(),
                Math::Subtract => lhs.sub(op_span, rhs, span).ok(),
                Math::Multiply => lhs.mul(op_span, rhs, span).ok(),
                Math::Divide => lhs.div(op_span, rhs, span).ok(),
                Math::FloorDivide => lhs.floor_div(op_span, rhs, span).ok(),
                Math::Modulo => lhs.modulo(op_span, rhs, span).ok(),
                Math::Pow => lhs.pow(op_span, rhs, span).ok(),
                Math::Concatenate => lhs.concat(op_span, rhs, span).ok(),
            },
            Operator::Comparison(comparison) => match comparison {
                Comparison::LessThan => lhs.lt(op_span, rhs, span).ok(),
                Comparison::LessThanOrEqual => lhs.lte(op_span, rhs, span).ok(),
                Comparison::GreaterThan => lhs.gt(op_span, rhs, span).ok(),
                Comparison::GreaterThanOrEqual => lhs.gte(op_span, rhs, span).ok(),
                Comparison::Equal => lhs.eq(op_span, rhs, span).ok(),
                Comparison::NotEqual => lhs.ne(op_span, rhs, span).ok(),
                Comparison::In => lhs.r#in(op_span, rhs, span).ok(),
                Comparison::NotIn => lhs.not_in(op_span, rhs, span).ok(),
                Comparison::Has => lhs.has(op_span, rhs, span).ok(),
                Comparison::NotHas => lhs.not_has(op_span, rhs, span).ok(),
                Comparison::StartsWith => lhs.starts_with(op_span, rhs, span).ok(),
                Comparison::NotStartsWith => lhs.not_starts_with(op_span, rhs, span).ok(),
                Comparison::EndsWith => lhs.ends_with(op_span, rhs, span).ok(),
                Comparison::NotEndsWith => lhs.not_ends_with(op_span, rhs, span).ok(),
                Comparison::RegexMatch | Comparison::NotRegexMatch => None,
            },
            Operator::Bits(bits) => match bits {
                Bits::BitAnd => lhs.bit_and(op_span, rhs, span).ok(),
                Bits::BitOr => lhs.bit_or(op_span, rhs, span).ok(),
                Bits::BitXor => lhs.bit_xor(op_span, rhs, span).ok(),
                Bits::ShiftLeft => lhs.bit_shl(op_span, rhs, span).ok(),
                Bits::ShiftRight => lhs.bit_shr(op_span, rhs, span).ok(),
            },
            Operator::Boolean(boolean) => match boolean {
                Boolean::And => lhs.and(op_span, rhs, span).ok(),
                Boolean::Or => lhs.or(op_span, rhs, span).ok(),
                Boolean::Xor => lhs.xor(op_span, rhs, span).ok(),
            },
            Operator::Assignment(_) => None,
        }
    }

    pub(super) fn apply_constant_hir_stmt(
        stmt: &HirStmt,
        reg_constants: &mut HashMap<RegId, Value>,
        var_constants: &mut HashMap<VarId, Value>,
    ) -> Option<()> {
        match stmt {
            HirStmt::LoadLiteral { dst, lit } => {
                if let Some(value) = lit.to_constant_value() {
                    reg_constants.insert(*dst, value);
                } else {
                    match lit {
                        HirLiteral::CellPath(path) => {
                            reg_constants
                                .insert(*dst, Value::cell_path((**path).clone(), Span::unknown()));
                        }
                        HirLiteral::List { .. } => {
                            reg_constants.insert(*dst, Value::list(Vec::new(), Span::unknown()));
                        }
                        HirLiteral::Record { .. } => {
                            reg_constants
                                .insert(*dst, Value::record(Record::new(), Span::unknown()));
                        }
                        _ => return None,
                    }
                }
            }
            HirStmt::LoadValue { dst, val } => {
                reg_constants.insert(*dst, (**val).clone());
            }
            HirStmt::Move { dst, src } | HirStmt::Clone { dst, src } => {
                let value = reg_constants.get(src)?.clone();
                reg_constants.insert(*dst, value);
            }
            HirStmt::Not { src_dst } => {
                let Value::Bool { val, .. } = reg_constants.get(src_dst)? else {
                    return None;
                };
                reg_constants.insert(*src_dst, Value::bool(!val, Span::unknown()));
            }
            HirStmt::BinaryOp { lhs_dst, op, rhs } => {
                let lhs = reg_constants.get(lhs_dst)?;
                let rhs = reg_constants.get(rhs)?;
                let value = Self::constant_apply_binary_operator(lhs, *op, rhs)?;
                reg_constants.insert(*lhs_dst, value);
            }
            HirStmt::LoadVariable { dst, var_id } => {
                let value = var_constants.get(var_id)?.clone();
                reg_constants.insert(*dst, value);
            }
            HirStmt::StoreVariable { var_id, src } => {
                let value = reg_constants.get(src)?.clone();
                var_constants.insert(*var_id, value);
            }
            HirStmt::DropVariable { var_id } => {
                var_constants.remove(var_id);
            }
            HirStmt::StringAppend { src_dst, val } => {
                let Value::String { val: mut dst, .. } = reg_constants.get(src_dst)?.clone() else {
                    return None;
                };
                let appended = reg_constants.get(val)?.clone().coerce_into_string().ok()?;
                dst.push_str(&appended);
                reg_constants.insert(*src_dst, Value::string(dst, Span::unknown()));
            }
            HirStmt::GlobFrom { src_dst, no_expand } => {
                let source = reg_constants
                    .get(src_dst)?
                    .clone()
                    .coerce_into_string()
                    .ok()?;
                reg_constants.insert(*src_dst, Value::glob(source, *no_expand, Span::unknown()));
            }
            HirStmt::ListPush { src_dst, item } => {
                let Value::List { mut vals, .. } = reg_constants.get(src_dst)?.clone() else {
                    return None;
                };
                vals.push(reg_constants.get(item)?.clone());
                reg_constants.insert(*src_dst, Value::list(vals, Span::unknown()));
            }
            HirStmt::ListSpread { src_dst, items } => {
                let Value::List { mut vals, .. } = reg_constants.get(src_dst)?.clone() else {
                    return None;
                };
                let Value::List {
                    vals: spread_vals, ..
                } = reg_constants.get(items)?.clone()
                else {
                    return None;
                };
                vals.extend(spread_vals);
                reg_constants.insert(*src_dst, Value::list(vals, Span::unknown()));
            }
            HirStmt::RecordInsert { src_dst, key, val } => {
                let Value::Record { val: record, .. } = reg_constants.get(src_dst)?.clone() else {
                    return None;
                };
                let mut record = record.into_owned();
                let key = Self::constant_record_key_value(reg_constants, *key)?;
                let value = reg_constants.get(val)?.clone();
                record.insert(key, value);
                reg_constants.insert(*src_dst, Value::record(record, Span::unknown()));
            }
            HirStmt::RecordSpread { src_dst, items } => {
                let Value::Record { val: record, .. } = reg_constants.get(src_dst)?.clone() else {
                    return None;
                };
                let Value::Record {
                    val: spread_record, ..
                } = reg_constants.get(items)?.clone()
                else {
                    return None;
                };
                let mut record = record.into_owned();
                for (key, value) in spread_record.iter() {
                    record.insert(key, value.clone());
                }
                reg_constants.insert(*src_dst, Value::record(record, Span::unknown()));
            }
            HirStmt::CloneCellPath { dst, src, path } => {
                let value = reg_constants.get(src)?.clone();
                let path_value = reg_constants.get(path)?;
                let Value::CellPath { val: cell_path, .. } = path_value else {
                    return None;
                };
                let projected = Self::constant_follow_cell_path(&value, cell_path)?;
                reg_constants.insert(*dst, projected);
            }
            HirStmt::FollowCellPath { src_dst, path } => {
                let value = reg_constants.get(src_dst)?.clone();
                let path_value = reg_constants.get(path)?;
                let Value::CellPath { val: cell_path, .. } = path_value else {
                    return None;
                };
                let projected = Self::constant_follow_cell_path(&value, cell_path)?;
                reg_constants.insert(*src_dst, projected);
            }
            HirStmt::UpsertCellPath {
                src_dst,
                path,
                new_value,
            } => {
                let value = reg_constants.get(src_dst)?.clone();
                let path_value = reg_constants.get(path)?;
                let Value::CellPath { val: cell_path, .. } = path_value else {
                    return None;
                };
                let updated = Self::constant_upsert_cell_path(
                    &value,
                    cell_path,
                    reg_constants.get(new_value)?.clone(),
                )?;
                reg_constants.insert(*src_dst, updated);
            }
            HirStmt::Collect { .. }
            | HirStmt::Span { .. }
            | HirStmt::Drain { .. }
            | HirStmt::DrainIfEnd { .. }
            | HirStmt::Drop { .. }
            | HirStmt::RedirectOut { .. }
            | HirStmt::RedirectErr { .. }
            | HirStmt::CheckErrRedirected { .. }
            | HirStmt::OnError { .. }
            | HirStmt::OnErrorInto { .. }
            | HirStmt::PopErrorHandler => {}
            _ => return None,
        }

        Some(())
    }

    fn eval_constant_user_function_return(hir: &HirFunction) -> Option<Value> {
        if hir.blocks.len() != 1 {
            return None;
        }
        let block = hir.blocks.first()?;
        let HirTerminator::Return { src } = block.terminator else {
            return None;
        };

        let mut reg_constants = HashMap::<RegId, Value>::new();
        let mut var_constants = HashMap::<VarId, Value>::new();

        for stmt in &block.stmts {
            Self::apply_constant_hir_stmt(stmt, &mut reg_constants, &mut var_constants)?;
        }

        reg_constants.get(&src).cloned()
    }

    pub(super) fn infer_param_vars(hir: &HirFunction) -> Vec<VarId> {
        let mut stored = HashSet::new();
        let mut params = HashSet::new();

        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::StoreVariable { var_id, .. } = stmt {
                    stored.insert(*var_id);
                }
            }
        }

        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::LoadVariable { var_id, .. } = stmt {
                    if *var_id != IN_VARIABLE_ID && !stored.contains(var_id) {
                        params.insert(*var_id);
                    }
                }
            }
        }

        let mut vars: Vec<VarId> = params.into_iter().collect();
        vars.sort_by_key(|var_id| var_id.get());
        vars
    }

    pub(super) fn infer_param_base_var_id(hir: &HirFunction) -> Option<VarId> {
        let mut stored = HashSet::new();
        let mut min_var: Option<usize> = None;

        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::StoreVariable { var_id, .. } = stmt {
                    stored.insert(*var_id);
                }
            }
        }

        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::LoadVariable { var_id, .. } = stmt {
                    if *var_id != IN_VARIABLE_ID && !stored.contains(var_id) {
                        let id = var_id.get();
                        min_var = Some(min_var.map_or(id, |cur| cur.min(id)));
                    }
                }
            }
        }

        min_var.map(VarId::new)
    }

    pub(super) fn infer_referenced_var_base_var_id(hir: &HirFunction) -> Option<VarId> {
        let mut min_var: Option<usize> = None;

        for block in &hir.blocks {
            for stmt in &block.stmts {
                let var_id = match stmt {
                    HirStmt::LoadVariable { var_id, .. }
                    | HirStmt::StoreVariable { var_id, .. }
                    | HirStmt::DropVariable { var_id } => Some(*var_id),
                    _ => None,
                };
                if let Some(var_id) = var_id
                    && var_id != IN_VARIABLE_ID
                {
                    let id = var_id.get();
                    min_var = Some(min_var.map_or(id, |cur| cur.min(id)));
                }
            }
        }

        min_var.map(VarId::new)
    }

    pub(super) fn uses_in_variable(hir: &HirFunction) -> bool {
        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::LoadVariable { var_id, .. } = stmt {
                    if *var_id == IN_VARIABLE_ID {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub(super) fn infer_pipeline_input_reg(hir: &HirFunction) -> Option<RegId> {
        fn stmt_defined_reg(stmt: &HirStmt) -> Option<RegId> {
            match stmt {
                HirStmt::LoadLiteral { dst, .. }
                | HirStmt::LoadValue { dst, .. }
                | HirStmt::Move { dst, .. }
                | HirStmt::Clone { dst, .. }
                | HirStmt::CloneCellPath { dst, .. }
                | HirStmt::LoadVariable { dst, .. }
                | HirStmt::LoadEnv { dst, .. }
                | HirStmt::LoadEnvOpt { dst, .. }
                | HirStmt::OnErrorInto { dst, .. } => Some(*dst),
                HirStmt::BinaryOp { lhs_dst, .. }
                | HirStmt::Not { src_dst: lhs_dst }
                | HirStmt::FollowCellPath {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::UpsertCellPath {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::RecordInsert {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::RecordSpread {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::StringAppend {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::GlobFrom {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::ListPush {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::ListSpread {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::Call {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::Collect { src_dst: lhs_dst }
                | HirStmt::Span { src_dst: lhs_dst } => Some(*lhs_dst),
                _ => None,
            }
        }

        let mut defined = HashSet::new();
        for block in &hir.blocks {
            for stmt in &block.stmts {
                match stmt {
                    HirStmt::Collect { src_dst }
                    | HirStmt::Drain { src: src_dst }
                    | HirStmt::DrainIfEnd { src: src_dst } => {
                        if !defined.contains(src_dst) {
                            return Some(*src_dst);
                        }
                    }
                    _ => {}
                }
                if let Some(dst) = stmt_defined_reg(stmt) {
                    defined.insert(dst);
                }
            }
        }
        None
    }

    pub(super) fn sig_param_count(sig: &UserFunctionSig) -> usize {
        sig.params
            .iter()
            .filter(|param| param.kind != UserParamKind::Input)
            .count()
    }

    fn build_args_from_signature(
        &mut self,
        sig: &UserFunctionSig,
        src_dst: RegId,
        needs_input: bool,
    ) -> Result<Vec<UserFunctionCallArg>, CompileError> {
        let mut args = Vec::new();
        let mut positional_idx = 0usize;
        let mut used_named = HashSet::new();
        let mut used_flags = HashSet::new();

        for param in &sig.params {
            match param.kind {
                UserParamKind::Input => {
                    if needs_input {
                        args.push(UserFunctionCallArg {
                            vreg: self.input_vreg_for_call(src_dst),
                            source_reg: self.input_source_reg_for_call(src_dst),
                        });
                    }
                }
                UserParamKind::Positional => {
                    if let Some((vreg, _)) = self.positional_args.get(positional_idx) {
                        args.push(UserFunctionCallArg {
                            vreg: *vreg,
                            source_reg: self
                                .positional_args
                                .get(positional_idx)
                                .map(|(_, reg)| *reg),
                        });
                        positional_idx += 1;
                    } else if param.optional {
                        args.push(UserFunctionCallArg {
                            vreg: self.const_vreg(0),
                            source_reg: None,
                        });
                    } else {
                        return Err(CompileError::UnsupportedInstruction(
                            "User-defined function missing positional arguments".into(),
                        ));
                    }
                }
                UserParamKind::Named => {
                    let name = param
                        .name
                        .as_ref()
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "User-defined function named parameter missing name".into(),
                            )
                        })?
                        .to_string();
                    if let Some((vreg, _)) = self.named_args.get(&name) {
                        used_named.insert(name.clone());
                        args.push(UserFunctionCallArg {
                            vreg: *vreg,
                            source_reg: self.named_args.get(&name).map(|(_, reg)| *reg),
                        });
                    } else if param.optional {
                        args.push(UserFunctionCallArg {
                            vreg: self.const_vreg(0),
                            source_reg: None,
                        });
                    } else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "User-defined function missing named argument '{}'",
                            name
                        )));
                    }
                }
                UserParamKind::Switch => {
                    let name = param
                        .name
                        .as_ref()
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "User-defined function switch parameter missing name".into(),
                            )
                        })?
                        .to_string();
                    if self.named_flags.contains(&name) {
                        used_flags.insert(name.clone());
                        args.push(UserFunctionCallArg {
                            vreg: self.const_vreg(1),
                            source_reg: None,
                        });
                    } else {
                        args.push(UserFunctionCallArg {
                            vreg: self.const_vreg(0),
                            source_reg: None,
                        });
                    }
                }
                UserParamKind::Rest => {
                    return Err(CompileError::UnsupportedInstruction(
                        "User-defined functions with rest parameters are not supported".into(),
                    ));
                }
            }
        }

        if positional_idx != self.positional_args.len() {
            return Err(CompileError::UnsupportedInstruction(
                "User-defined function argument count mismatch (too many positional args)".into(),
            ));
        }

        for name in self.named_args.keys() {
            if !used_named.contains(name) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "User-defined function does not accept named argument '{}'",
                    name
                )));
            }
        }

        for flag in &self.named_flags {
            if !used_flags.contains(flag) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "User-defined function does not accept flag '{}'",
                    flag
                )));
            }
        }

        Ok(args)
    }

    fn input_source_reg_for_call(&self, src_dst: RegId) -> Option<RegId> {
        if self.pipeline_input.is_some() {
            self.pipeline_input_reg
        } else if self.reg_map.contains_key(&src_dst.get()) {
            Some(src_dst)
        } else {
            None
        }
    }

    fn has_aggregate_builder(hir: &HirFunction) -> bool {
        hir.blocks.iter().any(|block| {
            block.stmts.iter().any(|stmt| {
                matches!(
                    stmt,
                    HirStmt::RecordInsert { .. }
                        | HirStmt::UpsertCellPath { .. }
                        | HirStmt::StringAppend { .. }
                        | HirStmt::ListPush { .. }
                        | HirStmt::LoadLiteral {
                            lit: HirLiteral::Record { .. } | HirLiteral::List { .. },
                            ..
                        }
                )
            })
        })
    }

    pub(super) fn subfunction_aggregate_return_abi(
        &self,
        decl_id: DeclId,
        hir: &HirFunction,
    ) -> Option<SubfunctionAggregateReturnAbi> {
        let return_srcs: Vec<RegId> = hir
            .blocks
            .iter()
            .filter_map(|block| match &block.terminator {
                HirTerminator::Return { src } => Some(*src),
                _ => None,
            })
            .collect();
        let simple_list_builder = hir.blocks.iter().all(|block| {
            block.stmts.iter().all(|stmt| {
                matches!(
                    stmt,
                    HirStmt::LoadLiteral { .. }
                        | HirStmt::LoadValue { .. }
                        | HirStmt::LoadVariable { .. }
                        | HirStmt::Move { .. }
                        | HirStmt::Clone { .. }
                        | HirStmt::ListPush { .. }
                        | HirStmt::Drain { .. }
                        | HirStmt::Drop { .. }
                        | HirStmt::DrainIfEnd { .. }
                )
            })
        });
        let simple_string_builder = hir.blocks.iter().all(|block| {
            block.stmts.iter().all(|stmt| {
                matches!(
                    stmt,
                    HirStmt::LoadLiteral { .. }
                        | HirStmt::LoadValue { .. }
                        | HirStmt::LoadVariable { .. }
                        | HirStmt::Move { .. }
                        | HirStmt::Clone { .. }
                        | HirStmt::StringAppend { .. }
                        | HirStmt::Drain { .. }
                        | HirStmt::Drop { .. }
                        | HirStmt::DrainIfEnd { .. }
                )
            })
        });
        let simple_record_builder = hir.blocks.iter().all(|block| {
            block.stmts.iter().all(|stmt| {
                matches!(
                    stmt,
                    HirStmt::LoadLiteral { .. }
                        | HirStmt::LoadValue { .. }
                        | HirStmt::LoadVariable { .. }
                        | HirStmt::Move { .. }
                        | HirStmt::Clone { .. }
                        | HirStmt::RecordInsert { .. }
                        | HirStmt::Drain { .. }
                        | HirStmt::Drop { .. }
                        | HirStmt::DrainIfEnd { .. }
                )
            })
        });

        if simple_list_builder && let Some(hints) = self.decl_type_hints.get(&decl_id) {
            let return_tys: Vec<MirType> = return_srcs
                .iter()
                .filter_map(|src| hints.get(&src.get()).cloned())
                .collect();
            if return_tys.len() == return_srcs.len()
                && let Some(first_return_ty) = return_tys.first().cloned()
            {
                if return_tys.iter().all(|ty| ty == &first_return_ty) {
                    let has_list_builder = hir.blocks.iter().any(|block| {
                        block.stmts.iter().any(|stmt| {
                            matches!(
                                stmt,
                                HirStmt::ListPush { .. }
                                    | HirStmt::LoadLiteral {
                                        lit: HirLiteral::List { .. },
                                        ..
                                    }
                            )
                        })
                    });
                    if has_list_builder
                        && let MirType::Array { elem, len } = first_return_ty
                        && len > 0
                        && matches!(elem.as_ref(), MirType::I64)
                    {
                        return Some(SubfunctionAggregateReturnAbi::List { max_len: len - 1 });
                    }
                }
            }
        }

        let inferred_abis: Vec<Option<SubfunctionAggregateReturnAbi>> = hir
            .blocks
            .iter()
            .filter_map(|block| match &block.terminator {
                HirTerminator::Return { src } => {
                    Some(self.infer_block_aggregate_return_abi(decl_id, block, *src))
                }
                _ => None,
            })
            .collect();
        let first_abi = inferred_abis.first()?.clone()?;
        inferred_abis
            .iter()
            .all(|abi| abi.as_ref() == Some(&first_abi))
            .then_some(first_abi)
            .and_then(|abi| match abi {
                SubfunctionAggregateReturnAbi::List { .. } if simple_list_builder => Some(abi),
                SubfunctionAggregateReturnAbi::List { .. } => None,
                SubfunctionAggregateReturnAbi::String { .. } if simple_string_builder => Some(abi),
                SubfunctionAggregateReturnAbi::String { .. } => None,
                SubfunctionAggregateReturnAbi::Record { .. } if simple_record_builder => Some(abi),
                SubfunctionAggregateReturnAbi::Record { .. } => None,
            })
    }

    fn prepare_aggregate_return_call_setup(
        &mut self,
        arg_seeds: &mut Vec<SubfunctionArgSeed>,
        args: &mut Vec<VReg>,
        abi: &SubfunctionAggregateReturnAbi,
    ) -> AggregateReturnCallSetup {
        match abi {
            SubfunctionAggregateReturnAbi::Record { ty } => {
                let slot =
                    self.func
                        .alloc_stack_slot(align_to_eight(ty.size()), 8, StackSlotKind::Local);
                self.record_stack_slot_type(slot, ty.clone());
                let ptr_vreg = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: ptr_vreg,
                    src: MirValue::StackSlot(slot),
                });
                let ptr_ty = MirType::Ptr {
                    pointee: Box::new(ty.clone()),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                };
                self.vreg_type_hints.insert(ptr_vreg, ptr_ty.clone());
                arg_seeds.push(SubfunctionArgSeed {
                    type_hint: Some(ptr_ty),
                    metadata: None,
                });
                args.push(ptr_vreg);
                AggregateReturnCallSetup::Record {
                    slot,
                    ty: ty.clone(),
                }
            }
            SubfunctionAggregateReturnAbi::List { max_len } => {
                let slot =
                    self.func
                        .alloc_stack_slot(8 + (max_len * 8), 8, StackSlotKind::ListBuffer);
                self.record_list_buffer_slot_type(slot, *max_len);
                let ptr_vreg = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: ptr_vreg,
                    src: MirValue::StackSlot(slot),
                });
                let ptr_ty = MirType::Ptr {
                    pointee: Box::new(MirType::Array {
                        elem: Box::new(MirType::I64),
                        len: max_len.saturating_add(1),
                    }),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                };
                self.vreg_type_hints.insert(ptr_vreg, ptr_ty.clone());
                arg_seeds.push(SubfunctionArgSeed {
                    type_hint: Some(ptr_ty),
                    metadata: None,
                });
                args.push(ptr_vreg);
                AggregateReturnCallSetup::List {
                    slot,
                    max_len: *max_len,
                }
            }
            SubfunctionAggregateReturnAbi::String { slot_len } => {
                let slot = self
                    .func
                    .alloc_stack_slot(*slot_len, 8, StackSlotKind::StringBuffer);
                self.record_stack_slot_type(
                    slot,
                    MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: *slot_len,
                    },
                );
                let ptr_vreg = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: ptr_vreg,
                    src: MirValue::StackSlot(slot),
                });
                let ptr_ty = MirType::Ptr {
                    pointee: Box::new(MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: *slot_len,
                    }),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                };
                self.vreg_type_hints.insert(ptr_vreg, ptr_ty.clone());
                arg_seeds.push(SubfunctionArgSeed {
                    type_hint: Some(ptr_ty),
                    metadata: None,
                });
                args.push(ptr_vreg);
                AggregateReturnCallSetup::String {
                    call_slot: slot,
                    slot_len: *slot_len,
                    len_vreg: self.func.alloc_vreg(),
                }
            }
        }
    }

    pub(super) fn subfunction_params(&mut self, decl_id: DeclId, func: &HirFunction) -> Vec<VarId> {
        if let Some(params) = self.subfunction_params.get(&decl_id) {
            return params.clone();
        }
        let params = Self::infer_param_vars(func);
        self.subfunction_params.insert(decl_id, params.clone());
        params
    }

    pub(super) fn lower_user_function_call(
        &mut self,
        decl_id: DeclId,
        src_dst: RegId,
        dst_vreg: VReg,
    ) -> Result<(), CompileError> {
        let hir = self.user_functions.get(&decl_id).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "User-defined function {} not found",
                decl_id.get()
            ))
        })?;
        let input_reg = Self::infer_pipeline_input_reg(hir);
        let uses_in = Self::uses_in_variable(hir);
        let needs_input = input_reg.is_some() || uses_in;
        let call_args = if let Some(sig) = self.decl_signatures.get(&decl_id) {
            self.build_args_from_signature(sig, src_dst, needs_input)?
        } else {
            if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                return Err(CompileError::UnsupportedInstruction(
                    "User-defined functions do not support named arguments or flags yet".into(),
                ));
            }
            let param_vars = self.subfunction_params(decl_id, hir);

            let input_vreg = self.input_vreg_for_call(src_dst);
            let mut args = Vec::new();
            if needs_input {
                args.push(UserFunctionCallArg {
                    vreg: input_vreg,
                    source_reg: self.input_source_reg_for_call(src_dst),
                });
            }

            let mut positional_idx = 0usize;
            for _ in &param_vars {
                let (arg_vreg, _) = self.positional_args.get(positional_idx).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "User-defined function missing positional arguments".into(),
                    )
                })?;
                args.push(UserFunctionCallArg {
                    vreg: *arg_vreg,
                    source_reg: self
                        .positional_args
                        .get(positional_idx)
                        .map(|(_, reg)| *reg),
                });
                positional_idx += 1;
            }

            if positional_idx != self.positional_args.len() {
                return Err(CompileError::UnsupportedInstruction(
                    "User-defined function argument count mismatch (too many positional args)"
                        .into(),
                ));
            }
            args
        };
        let call_args: Vec<UserFunctionCallArg> = call_args
            .into_iter()
            .map(|arg| {
                let vreg = if let Some(source_reg) = arg.source_reg {
                    self.materialized_metadata_aggregate_vreg(source_reg, arg.vreg)?
                } else {
                    arg.vreg
                };
                Ok(UserFunctionCallArg {
                    vreg,
                    source_reg: arg.source_reg,
                })
            })
            .collect::<Result<_, CompileError>>()?;

        if let Some(value) = Self::eval_constant_user_function_return(hir) {
            self.lower_constant_value(src_dst, &value)?;
            return Ok(());
        }

        let has_trusted_btf_arg = call_args
            .iter()
            .filter_map(|arg| arg.source_reg)
            .any(|reg| self.get_metadata(reg).is_some_and(|meta| meta.trusted_btf));
        let aggregate_return_abi = self.subfunction_aggregate_return_abi(decl_id, hir);
        if has_trusted_btf_arg
            || (Self::has_aggregate_builder(hir)
                && (aggregate_return_abi.is_none() || call_args.len().saturating_add(1) > 5))
        {
            self.inline_user_function(decl_id, src_dst, dst_vreg, &call_args)?;
            return Ok(());
        }

        if call_args.len() > 5 {
            return Err(CompileError::UnsupportedInstruction(
                "BPF subfunctions support at most 5 arguments".into(),
            ));
        }

        let mut arg_seeds: Vec<SubfunctionArgSeed> = call_args
            .iter()
            .map(|arg| {
                let metadata = arg
                    .source_reg
                    .and_then(|reg| self.get_metadata(reg).cloned());
                let type_hint = self.vreg_type_hints.get(&arg.vreg).cloned().or_else(|| {
                    metadata.as_ref().and_then(|meta| {
                        meta.field_type
                            .clone()
                            .or_else(|| Self::metadata_record_layout(meta))
                    })
                });
                SubfunctionArgSeed {
                    type_hint,
                    metadata,
                }
            })
            .collect();
        let mut args: Vec<VReg> = call_args.iter().map(|arg| arg.vreg).collect();
        let aggregate_return_setup = aggregate_return_abi
            .as_ref()
            .map(|abi| self.prepare_aggregate_return_call_setup(&mut arg_seeds, &mut args, abi));

        let subfn = self.get_or_create_subfunction(decl_id, &arg_seeds)?;
        let return_seed = self
            .subfunction_return_seeds
            .get(subfn.0 as usize)
            .cloned()
            .flatten();
        let returned_arg_seed = if aggregate_return_setup.is_none() {
            if let Some(SubfunctionReturnSummary::ReturnsArg(idx)) =
                infer_subfunction_return_summaries(&self.subfunctions)
                    .get(&subfn)
                    .copied()
            {
                arg_seeds.get(idx).cloned().inspect(|seed| {
                    if let Some(arg_ty) = seed.type_hint.clone() {
                        self.vreg_type_hints.insert(dst_vreg, arg_ty);
                    }
                })
            } else {
                None
            }
        } else {
            None
        };
        let call_dst = match &aggregate_return_setup {
            Some(AggregateReturnCallSetup::String { len_vreg, .. }) => *len_vreg,
            Some(_) => self.func.alloc_vreg(),
            None => dst_vreg,
        };
        self.emit(MirInst::CallSubfn {
            dst: call_dst,
            subfn,
            args,
        });

        self.reg_metadata.remove(&src_dst.get());
        if let Some(setup) = aggregate_return_setup {
            match setup {
                AggregateReturnCallSetup::Record { slot, ty } => {
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::StackSlot(slot),
                    });
                    self.vreg_type_hints.insert(
                        dst_vreg,
                        MirType::Ptr {
                            pointee: Box::new(ty.clone()),
                            address_space: crate::compiler::mir::AddressSpace::Stack,
                        },
                    );
                    let meta = self.get_or_create_metadata(src_dst);
                    meta.field_type = return_seed
                        .as_ref()
                        .and_then(|seed| seed.field_type.clone())
                        .or(Some(ty));
                    meta.annotated_semantics =
                        return_seed.and_then(|seed| seed.annotated_semantics);
                    meta.source_var = None;
                }
                AggregateReturnCallSetup::List { slot, max_len } => {
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::StackSlot(slot),
                    });
                    self.vreg_type_hints.insert(
                        dst_vreg,
                        MirType::Ptr {
                            pointee: Box::new(MirType::Array {
                                elem: Box::new(MirType::I64),
                                len: max_len.saturating_add(1),
                            }),
                            address_space: crate::compiler::mir::AddressSpace::Stack,
                        },
                    );
                    let meta = self.get_or_create_metadata(src_dst);
                    meta.list_buffer = Some((slot, max_len));
                    meta.field_type = return_seed
                        .as_ref()
                        .and_then(|seed| seed.field_type.clone())
                        .or(Some(MirType::Array {
                            elem: Box::new(MirType::I64),
                            len: max_len.saturating_add(1),
                        }));
                    meta.annotated_semantics =
                        return_seed.and_then(|seed| seed.annotated_semantics);
                    meta.source_var = None;
                }
                AggregateReturnCallSetup::String {
                    call_slot,
                    slot_len,
                    len_vreg,
                } => {
                    self.vreg_type_hints.insert(len_vreg, MirType::U64);
                    let result_slot =
                        self.func
                            .alloc_stack_slot(slot_len, 8, StackSlotKind::StringBuffer);
                    self.record_stack_slot_type(
                        result_slot,
                        MirType::Array {
                            elem: Box::new(MirType::U8),
                            len: slot_len,
                        },
                    );
                    let call_ptr = self.func.alloc_vreg();
                    self.emit(MirInst::Copy {
                        dst: call_ptr,
                        src: MirValue::StackSlot(call_slot),
                    });
                    self.vreg_type_hints.insert(
                        call_ptr,
                        MirType::Ptr {
                            pointee: Box::new(MirType::Array {
                                elem: Box::new(MirType::U8),
                                len: slot_len,
                            }),
                            address_space: crate::compiler::mir::AddressSpace::Stack,
                        },
                    );
                    self.emit_ptr_to_slot_copy(result_slot, 0, call_ptr, 0, slot_len)?;
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::StackSlot(result_slot),
                    });
                    self.vreg_type_hints.insert(
                        dst_vreg,
                        MirType::Ptr {
                            pointee: Box::new(MirType::Array {
                                elem: Box::new(MirType::U8),
                                len: slot_len,
                            }),
                            address_space: crate::compiler::mir::AddressSpace::Stack,
                        },
                    );
                    let meta = self.get_or_create_metadata(src_dst);
                    meta.string_slot = Some(result_slot);
                    meta.string_len_vreg = Some(len_vreg);
                    meta.string_len_bound = Some(slot_len.saturating_sub(1));
                    meta.field_type = return_seed
                        .as_ref()
                        .and_then(|seed| seed.field_type.clone())
                        .or(Some(MirType::Array {
                            elem: Box::new(MirType::U8),
                            len: slot_len,
                        }));
                    meta.annotated_semantics =
                        return_seed.and_then(|seed| seed.annotated_semantics);
                    meta.source_var = None;
                }
            }
        } else if let Some(seed) = returned_arg_seed {
            if let Some(meta) = seed.metadata {
                self.reg_metadata.insert(src_dst.get(), meta);
            } else if let Some(arg_ty) = seed.type_hint {
                self.get_or_create_metadata(src_dst).field_type = Some(arg_ty);
            }
        } else if let Some(seed) = return_seed {
            if let Some(type_hint) = seed.type_hint.clone() {
                self.vreg_type_hints.insert(dst_vreg, type_hint);
            }
            let meta = self.get_or_create_metadata(src_dst);
            meta.field_type = seed.field_type;
            meta.annotated_semantics = seed.annotated_semantics;
            meta.source_var = None;
        }
        Ok(())
    }
}
