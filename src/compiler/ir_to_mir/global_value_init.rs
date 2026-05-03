use super::*;
impl<'a> HirToMirLowering<'a> {
    pub(super) fn mutable_numeric_list_global_repr(
        values: &[Value],
    ) -> Result<Option<(MirType, Vec<u8>, usize)>, CompileError> {
        if values
            .iter()
            .any(|value| Self::scalar_constant_rodata_repr(value).is_none())
        {
            return Ok(None);
        }

        let max_len = values.len();
        let mut data = Vec::with_capacity((max_len.saturating_add(1)) * std::mem::size_of::<i64>());
        data.extend_from_slice(&(max_len as u64).to_le_bytes());
        for value in values {
            let Some((_item_ty, item_data)) = Self::scalar_constant_rodata_repr(value) else {
                return Ok(None);
            };
            data.extend_from_slice(&item_data);
        }

        Ok(Some((
            MirType::Array {
                elem: Box::new(MirType::I64),
                len: max_len.saturating_add(1),
            },
            data,
            max_len,
        )))
    }

    pub(super) fn mutable_string_global_repr(value: &Value) -> Option<(MirType, Vec<u8>, usize)> {
        let bytes = match value {
            Value::String { val, .. } => Some(val.as_bytes()),
            Value::Glob { val, .. } => Some(val.as_bytes()),
            _ => None,
        }?;

        let content_len = bytes.len().min(MAX_STRING_SIZE.saturating_sub(1));
        let aligned_len = align_to_eight(content_len + 1).min(MAX_STRING_SIZE).max(16);
        let mut data = vec![0u8; 8 + aligned_len];
        data[..8].copy_from_slice(&(content_len as u64).to_le_bytes());
        data[8..8 + content_len].copy_from_slice(&bytes[..content_len]);
        Some((
            MirType::Array {
                elem: Box::new(MirType::U8),
                len: 8 + aligned_len,
            },
            data,
            aligned_len,
        ))
    }

    pub(super) fn binary_constant_rodata_repr(
        bytes: &[u8],
    ) -> Result<(MirType, Vec<u8>), CompileError> {
        if bytes.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "empty binary constants are not yet supported in eBPF lowering".into(),
            ));
        }

        Ok((
            MirType::Array {
                elem: Box::new(MirType::U8),
                len: bytes.len(),
            },
            bytes.to_vec(),
        ))
    }

    pub(super) fn mutable_capture_global_repr(
        value: &Value,
    ) -> Result<Option<(MirType, Vec<u8>, Option<usize>, Option<usize>)>, CompileError> {
        let repr = match value {
            Value::Bool { val, .. } => Some((MirType::Bool, vec![u8::from(*val)], None, None)),
            Value::Int { val, .. } => Some((MirType::I64, val.to_le_bytes().to_vec(), None, None)),
            Value::Filesize { val, .. } => {
                Some((MirType::I64, val.get().to_le_bytes().to_vec(), None, None))
            }
            Value::Duration { val, .. } => {
                Some((MirType::I64, val.to_le_bytes().to_vec(), None, None))
            }
            Value::Nothing { .. } => Some((MirType::I64, 0i64.to_le_bytes().to_vec(), None, None)),
            Value::Binary { val, .. } => {
                let (ty, data) = Self::binary_constant_rodata_repr(val)?;
                Some((ty, data, None, None))
            }
            Value::Record { val, .. } => {
                let (ty, data) = Self::constant_record_rodata_repr(val.as_ref())?;
                Some((ty, data, None, None))
            }
            value if Self::mutable_string_global_repr(value).is_some() => {
                let (ty, data, slot_len) = Self::mutable_string_global_repr(value).unwrap();
                Some((ty, data, None, Some(slot_len)))
            }
            Value::List { vals, .. }
                if crate::compiler::hir::supports_numeric_constant_list(value) =>
            {
                Self::mutable_numeric_list_global_repr(vals)?
                    .map(|(ty, data, max_len)| (ty, data, Some(max_len), None))
            }
            Value::List { vals, .. }
                if crate::compiler::hir::supports_fixed_array_constant_list(value) =>
            {
                let (ty, data) = Self::constant_fixed_array_rodata_repr(vals)?;
                Some((ty, data, None, None))
            }
            _ => None,
        };
        Ok(repr)
    }

    pub(super) fn init_mutable_capture_globals(
        &mut self,
        mutable_capture_vars: &HashSet<VarId>,
    ) -> Result<(), CompileError> {
        for (var_id, value) in self.captures {
            if !mutable_capture_vars.contains(var_id) {
                continue;
            }

            let Some((ty, data, list_max_len, string_slot_len)) =
                Self::mutable_capture_global_repr(value)?
            else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "mutating captured variable {} of type {} is not yet supported; mutable captured globals currently only support numeric scalar values, strings, fixed binary values, numeric constant lists, homogeneous fixed arrays of scalar/string/binary/record constants with fixed-layout fields, and representable constant records",
                    var_id.get(),
                    value.get_type()
                )));
            };

            let symbol = format!("__nu_capture_global_{}", var_id.get());
            if data.iter().all(|byte| *byte == 0) {
                self.bss_globals.push(BssGlobal {
                    name: symbol.clone(),
                    size: data.len(),
                });
            } else {
                self.data_globals.push(DataGlobal {
                    name: symbol.clone(),
                    data,
                });
            }
            self.mutable_capture_globals.insert(
                *var_id,
                MutableCaptureGlobal {
                    symbol,
                    ty,
                    list_max_len,
                    string_slot_len,
                    string_content_cap: string_slot_len.map(|slot_len| slot_len.saturating_sub(1)),
                },
            );
            if let Some(semantics) = Self::mutable_global_value_semantics(value)? {
                self.mutable_capture_global_semantics
                    .insert(*var_id, semantics);
            }
        }

        Ok(())
    }

    fn typed_mutable_global_zero_repr(
        declared_type: &nu_protocol::Type,
    ) -> Result<Option<(MirType, Vec<u8>, Option<usize>, Option<usize>)>, CompileError> {
        match declared_type {
            nu_protocol::Type::Bool => Ok(Some((MirType::Bool, vec![0], None, None))),
            nu_protocol::Type::Duration
            | nu_protocol::Type::Filesize
            | nu_protocol::Type::Int
            | nu_protocol::Type::Nothing => Ok(Some((
                MirType::I64,
                0i64.to_le_bytes().to_vec(),
                None,
                None,
            ))),
            nu_protocol::Type::Record(fields) => {
                let mut field_reprs = Vec::with_capacity(fields.len());

                for (field_name, field_type) in fields.iter() {
                    let Some((field_ty, field_data, field_list_max_len, field_string_slot_len)) =
                        Self::typed_mutable_global_zero_repr(field_type)?
                    else {
                        return Ok(None);
                    };
                    let _ = (field_list_max_len, field_string_slot_len);
                    field_reprs.push((field_name.clone(), field_ty, field_data));
                }

                let (ty, data) = Self::record_type_and_data_from_field_reprs(&field_reprs)?;
                Ok(Some((ty, data, None, None)))
            }
            _ => Ok(None),
        }
    }

    pub(super) fn typed_mutable_global_repr(
        declared_type: &nu_protocol::Type,
        value: &Value,
    ) -> Result<Option<(MirType, Vec<u8>, Option<usize>, Option<usize>)>, CompileError> {
        if matches!(value, Value::Nothing { .. }) {
            return Self::typed_mutable_global_zero_repr(declared_type);
        }

        let allow_partial_record_initializer = matches!(
            (declared_type, value),
            (nu_protocol::Type::Record(_), Value::Record { .. })
        );

        if !allow_partial_record_initializer && !value.is_subtype_of(declared_type) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "annotated mutable global initializer of type {} does not match declared type {}",
                value.get_type(),
                declared_type
            )));
        }

        match declared_type {
            nu_protocol::Type::Bool => match value {
                Value::Bool { val, .. } => {
                    return Ok(Some((MirType::Bool, vec![u8::from(*val)], None, None)));
                }
                _ => return Ok(None),
            },
            nu_protocol::Type::Duration => match value {
                Value::Duration { val, .. } => {
                    return Ok(Some((MirType::I64, val.to_le_bytes().to_vec(), None, None)));
                }
                _ => return Ok(None),
            },
            nu_protocol::Type::Filesize => match value {
                Value::Filesize { val, .. } => {
                    return Ok(Some((
                        MirType::I64,
                        val.get().to_le_bytes().to_vec(),
                        None,
                        None,
                    )));
                }
                _ => return Ok(None),
            },
            nu_protocol::Type::Int => match value {
                Value::Int { val, .. } => {
                    return Ok(Some((MirType::I64, val.to_le_bytes().to_vec(), None, None)));
                }
                Value::Filesize { val, .. } => {
                    return Ok(Some((
                        MirType::I64,
                        val.get().to_le_bytes().to_vec(),
                        None,
                        None,
                    )));
                }
                Value::Duration { val, .. } => {
                    return Ok(Some((MirType::I64, val.to_le_bytes().to_vec(), None, None)));
                }
                Value::Nothing { .. } => {
                    return Ok(Some((
                        MirType::I64,
                        0i64.to_le_bytes().to_vec(),
                        None,
                        None,
                    )));
                }
                _ => return Ok(None),
            },
            nu_protocol::Type::String | nu_protocol::Type::Glob => {
                let Some((ty, data, slot_len)) = Self::mutable_string_global_repr(value) else {
                    return Ok(None);
                };
                return Ok(Some((ty, data, None, Some(slot_len))));
            }
            nu_protocol::Type::Binary => {
                let Value::Binary { val, .. } = value else {
                    return Ok(None);
                };
                let (ty, data) = Self::binary_constant_rodata_repr(val)?;
                return Ok(Some((ty, data, None, None)));
            }
            _ => {}
        }

        match declared_type {
            nu_protocol::Type::List(inner)
                if matches!(
                    inner.as_ref(),
                    nu_protocol::Type::Int | nu_protocol::Type::Nothing
                ) =>
            {
                let Value::List { vals, .. } = value else {
                    return Ok(None);
                };
                Ok(Self::mutable_numeric_list_global_repr(vals)?
                    .map(|(ty, data, max_len)| (ty, data, Some(max_len), None)))
            }
            nu_protocol::Type::List(_)
                if crate::compiler::hir::supports_fixed_array_constant_list(value) =>
            {
                let Value::List { vals, .. } = value else {
                    return Ok(None);
                };
                let (ty, data) = Self::constant_fixed_array_rodata_repr(vals)?;
                Ok(Some((ty, data, None, None)))
            }
            nu_protocol::Type::Record(fields) => {
                let Value::Record { val, .. } = value else {
                    return Ok(None);
                };

                if let Some((extra_name, _)) = val
                    .iter()
                    .find(|(name, _)| !fields.iter().any(|(field_name, _)| field_name == *name))
                {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "annotated mutable global initializer contains unexpected record field '{}'",
                        extra_name
                    )));
                }

                let mut field_reprs = Vec::with_capacity(fields.len());

                for (field_name, field_type) in fields.iter() {
                    let field_repr = if let Some(field_value) = val.get(field_name) {
                        Self::typed_mutable_global_repr(field_type, field_value)?
                    } else {
                        Self::typed_mutable_global_zero_repr(field_type)?
                    };
                    let Some((field_ty, field_data, field_list_max_len, field_string_slot_len)) =
                        field_repr
                    else {
                        if val.get(field_name).is_some() {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "record field '{}' of declared type {} is not yet supported in annotated mutable globals",
                                field_name, field_type
                            )));
                        }

                        return Err(CompileError::UnsupportedInstruction(format!(
                            "annotated mutable global initializer omitted record field '{}' of declared type {}; plain Nushell type annotations do not carry enough information to zero-initialize that field, so provide a concrete value for '{}', or switch to `global-define --type 'record{{...}}'` if you need an explicit fixed-capacity zero-initialized global",
                            field_name, field_type, field_name
                        )));
                    };
                    let _ = (field_list_max_len, field_string_slot_len);
                    field_reprs.push((field_name.clone(), field_ty, field_data));
                }

                let (ty, data) = Self::record_type_and_data_from_field_reprs(&field_reprs)?;
                Ok(Some((ty, data, None, None)))
            }
            _ => Ok(None),
        }
    }

    pub(super) fn annotated_mutable_global_semantics(
        declared_type: &nu_protocol::Type,
        value: &Value,
    ) -> Result<Option<AnnotatedValueSemantics>, CompileError> {
        if matches!(value, Value::Nothing { .. }) {
            return Ok(None);
        }

        let allow_partial_record_initializer = matches!(
            (declared_type, value),
            (nu_protocol::Type::Record(_), Value::Record { .. })
        );

        if !allow_partial_record_initializer && !value.is_subtype_of(declared_type) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "annotated mutable global initializer of type {} does not match declared type {}",
                value.get_type(),
                declared_type
            )));
        }

        match declared_type {
            nu_protocol::Type::String | nu_protocol::Type::Glob => {
                let Some((_ty, _data, slot_len)) = Self::mutable_string_global_repr(value) else {
                    return Ok(None);
                };
                return Ok(Some(AnnotatedValueSemantics::String {
                    slot_len,
                    content_cap: slot_len.saturating_sub(1),
                }));
            }
            nu_protocol::Type::List(inner)
                if matches!(
                    inner.as_ref(),
                    nu_protocol::Type::Int | nu_protocol::Type::Nothing
                ) =>
            {
                let Value::List { vals, .. } = value else {
                    return Ok(None);
                };
                return Ok(Some(AnnotatedValueSemantics::NumericList {
                    max_len: vals.len(),
                }));
            }
            nu_protocol::Type::List(_)
                if crate::compiler::hir::supports_fixed_array_constant_list(value) =>
            {
                let Value::List { vals, .. } = value else {
                    return Ok(None);
                };
                return Self::fixed_array_value_semantics(vals);
            }
            nu_protocol::Type::Record(fields) => {
                let Value::Record { val, .. } = value else {
                    return Ok(None);
                };

                if let Some((extra_name, _)) = val
                    .iter()
                    .find(|(name, _)| !fields.iter().any(|(field_name, _)| field_name == *name))
                {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "annotated mutable global initializer contains unexpected record field '{}'",
                        extra_name
                    )));
                }

                let mut field_semantics = Vec::new();
                for (field_name, field_type) in fields.iter() {
                    let Some(field_value) = val.get(field_name) else {
                        if Self::typed_mutable_global_zero_repr(field_type)?.is_none() {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "annotated mutable global initializer omitted record field '{}' of declared type {}; plain Nushell type annotations do not carry enough information to zero-initialize that field, so provide a concrete value for '{}', or switch to `global-define --type 'record{{...}}'` if you need an explicit fixed-capacity zero-initialized global",
                                field_name, field_type, field_name
                            )));
                        }
                        continue;
                    };
                    if let Some(field_semantics_value) =
                        Self::annotated_mutable_global_semantics(field_type, field_value)?
                    {
                        field_semantics.push((field_name.clone(), field_semantics_value));
                    }
                }

                if field_semantics.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(AnnotatedValueSemantics::Record(field_semantics)))
                }
            }
            _ => Ok(None),
        }
    }
}
