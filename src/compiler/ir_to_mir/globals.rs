use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn named_program_global_symbol(name: &str) -> String {
        format!("__nu_global_{}", name)
    }

    pub(super) fn named_program_global(&self, name: &str) -> Option<&MutableCaptureGlobal> {
        self.named_program_globals.get(name)
    }

    pub(super) fn named_program_global_semantics(
        &self,
        name: &str,
    ) -> Option<&AnnotatedValueSemantics> {
        self.named_program_global_semantics.get(name)
    }

    pub(super) fn tracked_value_semantics(
        &self,
        src: RegId,
        constant_value: Option<&Value>,
    ) -> Result<Option<AnnotatedValueSemantics>, CompileError> {
        if let Some(value) = constant_value {
            return Self::mutable_global_value_semantics(value);
        }

        let Some(meta) = self.get_metadata(src) else {
            return Ok(None);
        };

        if let Some(semantics) = meta.annotated_semantics.clone() {
            return Ok(Some(semantics));
        }

        if let Some((_, max_len)) = meta.list_buffer {
            return Ok(Some(AnnotatedValueSemantics::NumericList { max_len }));
        }

        if let Some(slot) = meta.string_slot {
            let slot_len = self.stack_slot_size(slot).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "string slot not found during global value semantics inference".into(),
                )
            })?;
            return Ok(Some(AnnotatedValueSemantics::String {
                slot_len,
                content_cap: meta.string_len_bound.unwrap_or(slot_len.saturating_sub(1)),
            }));
        }

        Ok(None)
    }

    fn typed_named_program_global_layout(
        symbol: String,
        spec: &str,
    ) -> Result<(MutableCaptureGlobal, Option<AnnotatedValueSemantics>), CompileError> {
        const MAX_NUMERIC_LIST_CAPACITY: usize = 60;

        #[derive(Debug)]
        struct ParsedGlobalType {
            ty: MirType,
            list_max_len: Option<usize>,
            string_slot_len: Option<usize>,
            string_content_cap: Option<usize>,
            semantics: Option<AnnotatedValueSemantics>,
        }

        fn split_top_level_fields<'a>(
            body: &'a str,
            spec: &str,
        ) -> Result<Vec<&'a str>, CompileError> {
            let mut fields = Vec::new();
            let mut depth = 0usize;
            let mut start = 0usize;

            for (idx, ch) in body.char_indices() {
                match ch {
                    '{' => depth = depth.saturating_add(1),
                    '}' => {
                        if depth == 0 {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "global type spec '{}' has an unmatched '}}'",
                                spec
                            )));
                        }
                        depth -= 1;
                    }
                    ',' if depth == 0 => {
                        fields.push(body[start..idx].trim());
                        start = idx + 1;
                    }
                    _ => {}
                }
            }

            if depth != 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global type spec '{}' has unmatched '{{' braces",
                    spec
                )));
            }

            fields.push(body[start..].trim());
            Ok(fields)
        }

        fn split_top_level_field<'a>(field: &'a str) -> Result<(&'a str, &'a str), CompileError> {
            let mut depth = 0usize;

            for (idx, ch) in field.char_indices() {
                match ch {
                    '{' => depth = depth.saturating_add(1),
                    '}' => {
                        if depth == 0 {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "record field '{}' has an unmatched '}}'",
                                field
                            )));
                        }
                        depth -= 1;
                    }
                    ':' if depth == 0 => {
                        let (name, rest) = field.split_at(idx);
                        return Ok((name.trim(), rest[1..].trim()));
                    }
                    _ => {}
                }
            }

            Err(CompileError::UnsupportedInstruction(format!(
                "record field '{}' must use name:type syntax",
                field
            )))
        }

        fn parse_named_global_type(spec: &str) -> Result<ParsedGlobalType, CompileError> {
            let scalar_ty = match spec {
                "i8" => Some(MirType::I8),
                "i16" => Some(MirType::I16),
                "i32" => Some(MirType::I32),
                "i64" => Some(MirType::I64),
                "duration" => Some(MirType::I64),
                "filesize" => Some(MirType::I64),
                "u8" => Some(MirType::U8),
                "u16" => Some(MirType::U16),
                "u32" => Some(MirType::U32),
                "u64" => Some(MirType::U64),
                "bool" => Some(MirType::Bool),
                _ => None,
            };

            if let Some(ty) = scalar_ty {
                return Ok(ParsedGlobalType {
                    ty,
                    list_max_len: None,
                    string_slot_len: None,
                    string_content_cap: None,
                    semantics: None,
                });
            }

            if let Some(body) = spec
                .strip_prefix("record{")
                .and_then(|rest| rest.strip_suffix('}'))
            {
                if body.trim().is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "record global declarations require at least one field".into(),
                    ));
                }

                let mut fields = Vec::new();
                let mut field_semantics = Vec::new();
                let mut offset = 0usize;

                for field in split_top_level_fields(body, spec)? {
                    if field.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "global record type spec '{}' contains an empty field",
                            spec
                        )));
                    }

                    let (name, field_spec) = split_top_level_field(field)?;
                    if name.is_empty() || field_spec.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "record field '{}' must use name:type syntax",
                            field
                        )));
                    }

                    if fields
                        .iter()
                        .any(|existing: &StructField| existing.name == name)
                    {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "record global declarations do not support duplicate field name '{}'",
                            name
                        )));
                    }

                    let parsed_field = parse_named_global_type(field_spec)?;
                    let ty = parsed_field.ty;
                    if let Some(semantics) = parsed_field.semantics {
                        field_semantics.push((name.to_string(), semantics));
                    }
                    fields.push(StructField {
                        name: name.to_string(),
                        ty: ty.clone(),
                        offset,
                        synthetic: false,
                        bitfield: None,
                    });
                    offset = offset.saturating_add(ty.size());
                }

                return Ok(ParsedGlobalType {
                    ty: MirType::Struct {
                        name: None,
                        kernel_btf_type_id: None,
                        fields,
                    },
                    list_max_len: None,
                    string_slot_len: None,
                    string_content_cap: None,
                    semantics: (!field_semantics.is_empty())
                        .then_some(AnnotatedValueSemantics::Record(field_semantics)),
                });
            }

            let byte_len = spec
                .strip_prefix("bytes:")
                .or_else(|| spec.strip_prefix("binary:"))
                .map(|len| {
                    len.parse::<usize>().map_err(|_| {
                        CompileError::UnsupportedInstruction(format!(
                            "global type spec '{}' has an invalid byte length",
                            spec
                        ))
                    })
                })
                .transpose()?;

            if let Some(len) = byte_len {
                if len == 0 {
                    return Err(CompileError::UnsupportedInstruction(
                        "global byte-array declarations require a positive length".into(),
                    ));
                }

                return Ok(ParsedGlobalType {
                    ty: MirType::Array {
                        elem: Box::new(MirType::U8),
                        len,
                    },
                    list_max_len: None,
                    string_slot_len: None,
                    string_content_cap: None,
                    semantics: None,
                });
            }

            if let Some(cap) = spec
                .strip_prefix("string:")
                .map(|len| {
                    len.parse::<usize>().map_err(|_| {
                        CompileError::UnsupportedInstruction(format!(
                            "global type spec '{}' has an invalid string capacity",
                            spec
                        ))
                    })
                })
                .transpose()?
            {
                if cap == 0 || cap >= MAX_STRING_SIZE {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global string declarations require a capacity between 1 and {}",
                        MAX_STRING_SIZE - 1
                    )));
                }

                let slot_len = align_to_eight(cap.saturating_add(1))
                    .min(MAX_STRING_SIZE)
                    .max(16);
                return Ok(ParsedGlobalType {
                    ty: MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: 8 + slot_len,
                    },
                    list_max_len: None,
                    string_slot_len: Some(slot_len),
                    string_content_cap: Some(cap),
                    semantics: Some(AnnotatedValueSemantics::String {
                        slot_len,
                        content_cap: cap,
                    }),
                });
            }

            if let Some(cap) = spec
                .strip_prefix("list:i64:")
                .map(|len| {
                    len.parse::<usize>().map_err(|_| {
                        CompileError::UnsupportedInstruction(format!(
                            "global type spec '{}' has an invalid list capacity",
                            spec
                        ))
                    })
                })
                .transpose()?
            {
                if cap > MAX_NUMERIC_LIST_CAPACITY {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global numeric list declarations require a capacity of at most {}",
                        MAX_NUMERIC_LIST_CAPACITY
                    )));
                }

                return Ok(ParsedGlobalType {
                    ty: MirType::Array {
                        elem: Box::new(MirType::I64),
                        len: cap.saturating_add(1),
                    },
                    list_max_len: Some(cap),
                    string_slot_len: None,
                    string_content_cap: None,
                    semantics: Some(AnnotatedValueSemantics::NumericList { max_len: cap }),
                });
            }

            Err(CompileError::UnsupportedInstruction(format!(
                "unsupported global type spec '{}'; expected one of i8, i16, i32, i64, duration, filesize, u8, u16, u32, u64, bool, bytes:N, binary:N, string:N, list:i64:N, or nested record{{field:type,...}}",
                spec
            )))
        }

        let parsed = parse_named_global_type(spec)?;
        Ok((
            MutableCaptureGlobal {
                symbol,
                ty: parsed.ty,
                list_max_len: parsed.list_max_len,
                string_slot_len: parsed.string_slot_len,
                string_content_cap: parsed.string_content_cap,
            },
            parsed.semantics,
        ))
    }

    fn infer_mutable_global_layout(
        &self,
        symbol: String,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        if let Some(meta) = self.get_metadata(src) {
            if let Some((_, max_len)) = meta.list_buffer {
                return Ok(MutableCaptureGlobal {
                    symbol,
                    ty: MirType::Array {
                        elem: Box::new(MirType::I64),
                        len: max_len.saturating_add(1),
                    },
                    list_max_len: Some(max_len),
                    string_slot_len: None,
                    string_content_cap: None,
                });
            }

            if let Some(slot) = meta.string_slot {
                let slot_len = self.stack_slot_size(slot).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "string slot not found during mutable global layout inference".into(),
                    )
                })?;
                return Ok(MutableCaptureGlobal {
                    symbol,
                    ty: MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: 8 + slot_len,
                    },
                    list_max_len: None,
                    string_slot_len: Some(slot_len),
                    string_content_cap: Some(
                        meta.string_len_bound.unwrap_or(slot_len.saturating_sub(1)),
                    ),
                });
            }

            if let Some(field_ty) = meta.field_type.clone() {
                let stored_ty = self.stored_generic_map_value_type(&field_ty);
                if matches!(
                    stored_ty,
                    MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Bool
                        | MirType::Array { .. }
                        | MirType::Struct { .. }
                ) {
                    return Ok(MutableCaptureGlobal {
                        symbol,
                        ty: stored_ty,
                        list_max_len: None,
                        string_slot_len: None,
                        string_content_cap: None,
                    });
                }
            }
        }

        let fallback_ty = self
            .vreg_type_hints
            .get(&src_vreg)
            .cloned()
            .map(|ty| self.stored_generic_map_value_type(&ty))
            .or_else(|| {
                self.get_metadata(src)
                    .and_then(|m| m.literal_int.map(|_| MirType::I64))
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "global-set requires a value with a known fixed layout".into(),
                )
            })?;

        match fallback_ty {
            MirType::I8
            | MirType::I16
            | MirType::I32
            | MirType::I64
            | MirType::U8
            | MirType::U16
            | MirType::U32
            | MirType::U64
            | MirType::Bool
            | MirType::Array { .. }
            | MirType::Struct { .. } => Ok(MutableCaptureGlobal {
                symbol,
                ty: fallback_ty,
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
            }),
            _ => Err(CompileError::UnsupportedInstruction(
                "global-set requires a scalar, string, fixed binary, numeric list, or representable aggregate value".into(),
            )),
        }
    }

    fn ensure_named_program_global_with_mode(
        &mut self,
        name: &str,
        src: RegId,
        src_vreg: VReg,
        initialize_from_constant: bool,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        let symbol = Self::named_program_global_symbol(name);
        let source_constant_value = self
            .get_metadata(src)
            .and_then(|meta| meta.constant_value.clone());
        let value_semantics = self.tracked_value_semantics(src, source_constant_value.as_ref())?;
        let constant_value = if initialize_from_constant {
            source_constant_value.clone()
        } else {
            None
        };
        let initialized_repr = if let Some(value) = constant_value.as_ref() {
            Self::mutable_capture_global_repr(value)?
        } else {
            None
        };
        let inferred =
            if let Some((ty, _data, list_max_len, string_slot_len)) = initialized_repr.as_ref() {
                MutableCaptureGlobal {
                    symbol: symbol.clone(),
                    ty: ty.clone(),
                    list_max_len: *list_max_len,
                    string_slot_len: *string_slot_len,
                    string_content_cap: string_slot_len.map(|slot_len| slot_len.saturating_sub(1)),
                }
            } else {
                self.infer_mutable_global_layout(symbol.clone(), src, src_vreg)?
            };

        if let Some(existing) = self.named_program_globals.get(name) {
            if existing != &inferred {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global '{}' is used with incompatible layouts",
                    name
                )));
            }
            if let Some(semantics) = value_semantics {
                match self.named_program_global_semantics.get(name) {
                    Some(existing_semantics) if existing_semantics != &semantics => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "global '{}' is used with incompatible value semantics",
                            name
                        )));
                    }
                    Some(_) => {}
                    None => {
                        self.named_program_global_semantics
                            .insert(name.to_string(), semantics);
                    }
                }
            }
            return Ok(existing.clone());
        }

        let size = inferred.ty.size();
        if size == 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' inferred an empty layout, which is not yet supported",
                name
            )));
        }

        if let Some((_ty, data, _list_max_len, _string_slot_len)) = initialized_repr {
            if data.iter().all(|byte| *byte == 0) {
                self.bss_globals.push(BssGlobal { name: symbol, size });
            } else {
                self.data_globals.push(DataGlobal { name: symbol, data });
            }
        } else {
            self.bss_globals.push(BssGlobal { name: symbol, size });
        }
        self.named_program_globals
            .insert(name.to_string(), inferred.clone());
        if let Some(semantics) = value_semantics {
            self.named_program_global_semantics
                .insert(name.to_string(), semantics);
        }
        Ok(inferred)
    }

    pub(super) fn ensure_named_program_global(
        &mut self,
        name: &str,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        self.ensure_named_program_global_with_mode(name, src, src_vreg, true)
    }

    pub(super) fn ensure_zeroed_named_program_global(
        &mut self,
        name: &str,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        self.ensure_named_program_global_with_mode(name, src, src_vreg, false)
    }

    pub(super) fn predeclare_named_program_global_from_value(
        &mut self,
        name: &str,
        value: &Value,
        initialize: bool,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        let symbol = Self::named_program_global_symbol(name);
        let Some((ty, data, list_max_len, string_slot_len)) =
            Self::mutable_capture_global_repr(value)?
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' requires a compile-time constant with a fixed layout",
                name
            )));
        };

        let inferred = MutableCaptureGlobal {
            symbol: symbol.clone(),
            ty,
            list_max_len,
            string_slot_len,
            string_content_cap: string_slot_len.map(|slot_len| slot_len.saturating_sub(1)),
        };

        if let Some(existing) = self.named_program_globals.get(name) {
            if existing != &inferred {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global '{}' is used with incompatible layouts",
                    name
                )));
            }
            if let Some(semantics) = Self::mutable_global_value_semantics(value)? {
                match self.named_program_global_semantics.get(name) {
                    Some(existing_semantics) if existing_semantics != &semantics => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "global '{}' is used with incompatible value semantics",
                            name
                        )));
                    }
                    Some(_) => {}
                    None => {
                        self.named_program_global_semantics
                            .insert(name.to_string(), semantics);
                    }
                }
            }
            return Ok(existing.clone());
        }

        let size = inferred.ty.size();
        if size == 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' inferred an empty layout, which is not yet supported",
                name
            )));
        }

        if initialize && data.iter().any(|byte| *byte != 0) {
            self.data_globals.push(DataGlobal { name: symbol, data });
        } else {
            // Forward global-get support from later global-set is layout-only.
            // The later set still performs the real initialization at runtime,
            // so the compile-time global must remain zero-initialized.
            self.bss_globals.push(BssGlobal { name: symbol, size });
        }
        self.named_program_globals
            .insert(name.to_string(), inferred.clone());
        if let Some(semantics) = Self::mutable_global_value_semantics(value)? {
            self.named_program_global_semantics
                .insert(name.to_string(), semantics);
        }
        Ok(inferred)
    }

    pub(super) fn define_named_program_global_from_type_spec(
        &mut self,
        name: &str,
        spec: &str,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        let symbol = Self::named_program_global_symbol(name);
        let (inferred, semantics) = Self::typed_named_program_global_layout(symbol.clone(), spec)?;

        if let Some(existing) = self.named_program_globals.get(name) {
            if existing != &inferred {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global '{}' is used with incompatible layouts",
                    name
                )));
            }
            if let Some(semantics) = semantics {
                match self.named_program_global_semantics.get(name) {
                    Some(existing_semantics) if existing_semantics != &semantics => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "global '{}' is used with incompatible value semantics",
                            name
                        )));
                    }
                    Some(_) => {}
                    None => {
                        self.named_program_global_semantics
                            .insert(name.to_string(), semantics);
                    }
                }
            }
            return Ok(existing.clone());
        }

        let size = inferred.ty.size();
        if size == 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' inferred an empty layout, which is not yet supported",
                name
            )));
        }

        self.bss_globals.push(BssGlobal { name: symbol, size });
        self.named_program_globals
            .insert(name.to_string(), inferred.clone());
        if let Some(semantics) = semantics {
            self.named_program_global_semantics
                .insert(name.to_string(), semantics);
        }
        Ok(inferred)
    }

    pub(super) fn load_mutable_global_value(
        &mut self,
        dst: RegId,
        dst_vreg: VReg,
        global: &MutableCaptureGlobal,
    ) -> Result<(), CompileError> {
        let global_ptr = self.func.alloc_vreg();
        self.emit(MirInst::LoadGlobal {
            dst: global_ptr,
            symbol: global.symbol.clone(),
            ty: global.ty.clone(),
        });
        let global_ptr_ty = MirType::Ptr {
            pointee: Box::new(global.ty.clone()),
            address_space: crate::compiler::mir::AddressSpace::Map,
        };
        self.vreg_type_hints
            .insert(global_ptr, global_ptr_ty.clone());

        self.reg_metadata.insert(dst.get(), RegMetadata::default());

        if let Some(max_len) = global.list_max_len {
            let buffer_size = (max_len.saturating_add(1)) * std::mem::size_of::<i64>();
            let slot = self
                .func
                .alloc_stack_slot(buffer_size, 8, StackSlotKind::ListBuffer);
            self.record_list_buffer_slot_type(slot, max_len);
            self.emit(MirInst::ListNew {
                dst: dst_vreg,
                buffer: slot,
                max_len,
            });
            let stack_list_ptr_ty = MirType::Ptr {
                pointee: Box::new(global.ty.clone()),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            };
            self.vreg_type_hints.insert(dst_vreg, stack_list_ptr_ty);
            self.emit_ptr_copy(dst_vreg, global_ptr, global.ty.size())?;
            let meta = self.get_or_create_metadata(dst);
            meta.field_type = Some(global.ty.clone());
            meta.list_buffer = Some((slot, max_len));
        } else if let Some(slot_len) = global.string_slot_len {
            let slot = self
                .func
                .alloc_stack_slot(slot_len, 8, StackSlotKind::StringBuffer);
            self.record_stack_slot_type(
                slot,
                MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: slot_len,
                },
            );
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::StackSlot(slot),
            });
            let stack_string_ptr_ty = MirType::Ptr {
                pointee: Box::new(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: slot_len,
                }),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            };
            self.vreg_type_hints.insert(dst_vreg, stack_string_ptr_ty);
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::Load {
                dst: len_vreg,
                ptr: global_ptr,
                offset: 0,
                ty: MirType::U64,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);
            self.emit_ptr_copy_with_offsets(dst_vreg, 0, global_ptr, 8, slot_len)?;
            let meta = self.get_or_create_metadata(dst);
            meta.string_slot = Some(slot);
            meta.string_len_vreg = Some(len_vreg);
            meta.string_len_bound = Some(
                global
                    .string_content_cap
                    .unwrap_or(slot_len.saturating_sub(1)),
            );
            meta.field_type = Some(MirType::Array {
                elem: Box::new(MirType::U8),
                len: slot_len,
            });
        } else if matches!(global.ty, MirType::Array { .. } | MirType::Struct { .. }) {
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::VReg(global_ptr),
            });
            self.vreg_type_hints.insert(dst_vreg, global_ptr_ty);
            let meta = self.get_or_create_metadata(dst);
            meta.field_type = Some(global.ty.clone());
        } else {
            self.emit(MirInst::Load {
                dst: dst_vreg,
                ptr: global_ptr,
                offset: 0,
                ty: global.ty.clone(),
            });
            self.vreg_type_hints.insert(dst_vreg, global.ty.clone());
            let meta = self.get_or_create_metadata(dst);
            meta.field_type = Some(global.ty.clone());
        }

        Ok(())
    }

    pub(super) fn store_into_mutable_global(
        &mut self,
        context: &str,
        global: &MutableCaptureGlobal,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<(), CompileError> {
        let global_ptr = self.func.alloc_vreg();
        self.emit(MirInst::LoadGlobal {
            dst: global_ptr,
            symbol: global.symbol.clone(),
            ty: global.ty.clone(),
        });
        self.vreg_type_hints.insert(
            global_ptr,
            MirType::Ptr {
                pointee: Box::new(global.ty.clone()),
                address_space: crate::compiler::mir::AddressSpace::Map,
            },
        );

        if let Some(max_len) = global.list_max_len {
            let Some((slot, src_max_len)) = self.get_metadata(src).and_then(|m| m.list_buffer)
            else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a materialized numeric list value",
                    context
                )));
            };

            if src_max_len != max_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing numeric list of capacity {} into {} with capacity {} is not supported",
                    src_max_len, context, max_len
                )));
            }

            let src_ptr = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: src_ptr,
                src: MirValue::StackSlot(slot),
            });
            self.vreg_type_hints.insert(
                src_ptr,
                MirType::Ptr {
                    pointee: Box::new(global.ty.clone()),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                },
            );
            self.emit_ptr_copy(global_ptr, src_ptr, global.ty.size())?;
        } else if let Some(slot_len) = global.string_slot_len {
            let src_meta = self.get_metadata(src).cloned();
            let Some(meta) = src_meta else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a materialized string value with tracked length",
                    context
                )));
            };
            let Some(slot) = meta.string_slot else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a materialized string value with tracked length",
                    context
                )));
            };
            let Some(len_vreg) = meta.string_len_vreg else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a tracked string length",
                    context
                )));
            };
            let src_slot_size = self.stack_slot_size(slot).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "string slot not found during mutable global store".into(),
                )
            })?;
            if src_slot_size > slot_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing string buffer of size {} into {} with capacity {} is not supported",
                    src_slot_size, context, slot_len
                )));
            }
            let src_max_len = meta
                .string_len_bound
                .unwrap_or(src_slot_size.saturating_sub(1));
            let dst_max_len = global
                .string_content_cap
                .unwrap_or(slot_len.saturating_sub(1));
            if src_max_len > dst_max_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing string value with capacity {} into {} with content capacity {} is not supported",
                    src_max_len, context, dst_max_len
                )));
            }

            self.emit(MirInst::Store {
                ptr: global_ptr,
                offset: 0,
                val: MirValue::VReg(len_vreg),
                ty: MirType::U64,
            });

            let src_ptr = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: src_ptr,
                src: MirValue::StackSlot(slot),
            });
            self.vreg_type_hints.insert(
                src_ptr,
                MirType::Ptr {
                    pointee: Box::new(MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: src_slot_size,
                    }),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                },
            );
            self.emit_ptr_copy_with_offsets(global_ptr, 8, src_ptr, 0, src_slot_size)?;
            if src_slot_size < slot_len {
                self.emit_ptr_zero(global_ptr, 8 + src_slot_size, slot_len - src_slot_size)?;
            }
        } else {
            match &global.ty {
                MirType::Array { .. } | MirType::Struct { .. } => {
                    let Some(src_runtime_ty) = self.vreg_type_hints.get(&src_vreg).cloned() else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "storing into {} requires a materialized aggregate pointer value",
                            context
                        )));
                    };

                    let Some(MirType::Ptr {
                        pointee,
                        address_space:
                            crate::compiler::mir::AddressSpace::Stack
                            | crate::compiler::mir::AddressSpace::Map,
                    }) = Some(src_runtime_ty)
                    else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "storing into {} requires a stack/map aggregate pointer value",
                            context
                        )));
                    };

                    if pointee.as_ref() != &global.ty {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "storing type {:?} into {} of type {:?} is not supported",
                            pointee, context, global.ty
                        )));
                    }

                    self.emit_ptr_copy(global_ptr, src_vreg, global.ty.size())?;
                }
                _ => {
                    self.emit(MirInst::Store {
                        ptr: global_ptr,
                        offset: 0,
                        val: MirValue::VReg(src_vreg),
                        ty: global.ty.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}
