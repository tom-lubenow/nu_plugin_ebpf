use super::*;

impl KernelBtf {
    pub(super) fn function_trampoline_layout(
        &self,
        function_name: &str,
    ) -> Result<TrampolineFunctionLayout, BtfError> {
        {
            let cache = self.trampoline_layout_cache.read().unwrap();
            if let Some(layout) = cache.get(function_name) {
                return layout.clone();
            }
        }

        let layout = self.compute_function_trampoline_layout(function_name);

        let mut cache = self.trampoline_layout_cache.write().unwrap();
        cache.insert(function_name.to_string(), layout.clone());
        layout
    }

    fn compute_function_trampoline_layout(
        &self,
        function_name: &str,
    ) -> Result<TrampolineFunctionLayout, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let function_ret_type_ids = self.load_kfunc_return_type_id_map().unwrap_or_default();
        let ty = Self::resolve_named_trampoline_callable(&btf, function_name)?;
        let Type::FunctionProto(proto) = &ty.base_type else {
            return Err(BtfError::KernelBtfError(format!(
                "function '{}' is missing a function prototype in kernel BTF",
                function_name
            )));
        };

        let mut next_slot = 0usize;
        let mut args = Vec::with_capacity(proto.params.len());
        for param in &proto.params {
            // BTF varargs are represented by a terminal unnamed param with type_id=0.
            if param.type_id == 0 {
                break;
            }
            let raw_size_bytes = self
                .load_raw_type_size_map()
                .ok()
                .and_then(|sizes| sizes.get(&param.type_id).copied())
                .map(|size| size as usize);
            let layout =
                Self::trampoline_field_layout(&btf, param.type_id, next_slot, raw_size_bytes)?;
            next_slot = next_slot.checked_add(layout.slot_count).ok_or_else(|| {
                BtfError::KernelBtfError(format!(
                    "trampoline layout for '{}' overflowed slot accounting",
                    function_name
                ))
            })?;
            args.push(layout);
        }

        let retval = match function_ret_type_ids.get(&ty.type_id).copied() {
            Some(0) | None => None,
            Some(ret_type_id) => {
                let raw_size_bytes = self
                    .load_raw_type_size_map()
                    .ok()
                    .and_then(|sizes| sizes.get(&ret_type_id).copied())
                    .map(|size| size as usize);
                Some(Self::trampoline_field_layout(
                    &btf,
                    ret_type_id,
                    next_slot,
                    raw_size_bytes,
                )?)
            }
        };

        Ok(TrampolineFunctionLayout { args, retval })
    }

    pub(super) fn struct_ops_callback_layout(
        &self,
        value_type_name: &str,
        callback_name: &str,
    ) -> Result<TrampolineFunctionLayout, BtfError> {
        let key = (value_type_name.to_string(), callback_name.to_string());
        {
            let cache = self.struct_ops_layout_cache.read().unwrap();
            if let Some(layout) = cache.get(&key) {
                return layout.clone();
            }
        }

        let layout = self.compute_struct_ops_callback_layout(value_type_name, callback_name);

        let mut cache = self.struct_ops_layout_cache.write().unwrap();
        cache.insert(key, layout.clone());
        layout
    }

    fn compute_struct_ops_callback_layout(
        &self,
        value_type_name: &str,
        callback_name: &str,
    ) -> Result<TrampolineFunctionLayout, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let callback_ty =
            Self::resolve_struct_ops_callback_member_type(&btf, value_type_name, callback_name)?;
        let Type::FunctionProto(proto) = &callback_ty.base_type else {
            return Err(BtfError::KernelBtfError(format!(
                "struct_ops callback '{}.{}' is missing a function prototype in kernel BTF",
                value_type_name, callback_name
            )));
        };

        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let mut next_slot = 0usize;
        let mut args = Vec::with_capacity(proto.params.len());
        for param in &proto.params {
            if param.type_id == 0 {
                break;
            }
            let raw_size_bytes = raw_type_sizes
                .get(&param.type_id)
                .copied()
                .map(|size| size as usize);
            let layout =
                Self::trampoline_field_layout(&btf, param.type_id, next_slot, raw_size_bytes)?;
            next_slot = next_slot.checked_add(layout.slot_count).ok_or_else(|| {
                BtfError::KernelBtfError(format!(
                    "trampoline layout for struct_ops callback '{}.{}' overflowed slot accounting",
                    value_type_name, callback_name
                ))
            })?;
            args.push(layout);
        }

        Ok(TrampolineFunctionLayout { args, retval: None })
    }

    pub(super) fn resolve_struct_ops_callback_member_type(
        btf: &Btf,
        value_type_name: &str,
        callback_name: &str,
    ) -> Result<FlattenedType, BtfError> {
        let ty = btf
            .get_type_by_name(value_type_name)
            .map_err(|_| BtfError::TypeNotFound(value_type_name.to_string()))?;

        let member = match &ty.base_type {
            Type::Struct(struct_ty) | Type::Union(struct_ty) => struct_ty
                .members
                .iter()
                .find(|member| member.name.as_deref() == Some(callback_name))
                .ok_or_else(|| {
                    BtfError::KernelBtfError(format!(
                        "kernel BTF type '{}' has no callback member '{}'",
                        value_type_name, callback_name
                    ))
                })?,
            other => {
                return Err(BtfError::KernelBtfError(format!(
                    "kernel BTF type '{}' is not a struct/union (got {:?})",
                    value_type_name, other
                )));
            }
        };

        let member_ty = btf.get_type_by_id(member.type_id).map_err(|e| {
            BtfError::KernelBtfError(format!(
                "failed to resolve kernel BTF type {}: {}",
                member.type_id, e
            ))
        })?;
        if member_ty.num_refs == 0 {
            return Err(BtfError::KernelBtfError(format!(
                "struct_ops callback '{}.{}' is not a function pointer",
                value_type_name, callback_name
            )));
        }
        if !matches!(member_ty.base_type, Type::FunctionProto(_)) {
            return Err(BtfError::KernelBtfError(format!(
                "struct_ops callback '{}.{}' does not resolve to a function prototype",
                value_type_name, callback_name
            )));
        }

        Ok(member_ty.clone())
    }

    pub(super) fn flattened_base_type_bits(btf: &Btf, base_type: &Type) -> Option<u32> {
        match base_type {
            Type::Integer(int_ty) => Some(int_ty.bits),
            Type::Float(float_ty) => Some(float_ty.bits),
            Type::Enum32(_) => Some(32),
            Type::Enum64(_) => Some(64),
            Type::Array(array_ty) => btf
                .get_type_by_id(array_ty.elem_type_id)
                .ok()
                .and_then(|elem_ty| elem_ty.bits.checked_mul(array_ty.num_elements)),
            Type::Struct(struct_ty) | Type::Union(struct_ty) => {
                let mut max_bits: u32 = 0;
                for member in &struct_ty.members {
                    let member_bits = if let Some(bitfield_bits) = member.bits {
                        bitfield_bits
                    } else {
                        btf.get_type_by_id(member.type_id).ok()?.bits
                    };
                    let end = member.offset.checked_add(member_bits)?;
                    max_bits = max_bits.max(end);
                }
                Some(max_bits)
            }
            Type::Void | Type::Fwd(_) | Type::FunctionProto(_) | Type::DataSection(_) => None,
            Type::Pointer(_)
            | Type::Typedef(_)
            | Type::Volatile(_)
            | Type::Const(_)
            | Type::Restrict(_)
            | Type::Function(_)
            | Type::Variable(_)
            | Type::DeclTag(_)
            | Type::TypeTag(_) => None,
        }
    }

    fn trampoline_field_layout(
        btf: &Btf,
        type_id: u32,
        slot_index: usize,
        raw_size_bytes: Option<usize>,
    ) -> Result<TrampolineFieldLayout, BtfError> {
        let ty = btf.get_type_by_id(type_id).map_err(|e| {
            BtfError::KernelBtfError(format!("failed to resolve kernel BTF type {type_id}: {e}"))
        })?;
        let slot_count = Self::trampoline_slot_count(btf, &ty, raw_size_bytes)?;
        let value = Self::trampoline_value_kind(btf, &ty, raw_size_bytes)
            .map(|kind| TrampolineValueSpec { slot_index, kind });
        let unsupported_reason = value
            .is_none()
            .then(|| Self::trampoline_unsupported_reason(&ty));
        Ok(TrampolineFieldLayout {
            slot_index,
            slot_count,
            value,
            unsupported_reason,
        })
    }

    pub(super) fn trampoline_size_bytes(
        btf: &Btf,
        ty: &FlattenedType,
        raw_size_bytes: Option<usize>,
    ) -> Result<usize, BtfError> {
        if ty.num_refs > 0 {
            return Ok(8);
        }
        if matches!(ty.base_type, Type::Struct(_) | Type::Union(_))
            && let Some(size) = raw_size_bytes
        {
            return Ok(size);
        }
        let bits = Self::flattened_base_type_bits(btf, &ty.base_type)
            .or_else(|| (ty.bits > 0).then_some(ty.bits))
            .ok_or_else(|| {
                BtfError::KernelBtfError(format!(
                    "missing size information for trampoline type '{}'",
                    ty.name.as_deref().unwrap_or("<anonymous>")
                ))
            })?;
        usize::try_from(bits.div_ceil(8)).map_err(|_| {
            BtfError::KernelBtfError(format!(
                "size overflow for trampoline type '{}'",
                ty.name.as_deref().unwrap_or("<anonymous>")
            ))
        })
    }

    fn trampoline_slot_count(
        btf: &Btf,
        ty: &FlattenedType,
        raw_size_bytes: Option<usize>,
    ) -> Result<usize, BtfError> {
        let size_bytes = Self::trampoline_size_bytes(btf, ty, raw_size_bytes)?;
        match size_bytes {
            1 | 2 | 4 | 8 => Ok(1),
            16 => Ok(2),
            _ => Err(BtfError::KernelBtfError(format!(
                "trampoline type '{}' uses unsupported {}-byte by-value layout",
                ty.name.as_deref().unwrap_or("<anonymous>"),
                size_bytes
            ))),
        }
    }

    fn trampoline_value_kind(
        btf: &Btf,
        ty: &FlattenedType,
        raw_size_bytes: Option<usize>,
    ) -> Option<TrampolineValueKind> {
        if ty.num_refs > 0 {
            return Some(TrampolineValueKind::Pointer {
                user_space: Self::has_user_type_tag(&ty.type_tags),
            });
        }

        match &ty.base_type {
            Type::Integer(_) | Type::Float(_) | Type::Enum32(_) | Type::Enum64(_) => {
                Some(TrampolineValueKind::Scalar)
            }
            Type::Array(_) | Type::Struct(_) | Type::Union(_) => {
                let size_bytes = Self::trampoline_size_bytes(btf, ty, raw_size_bytes).ok()?;
                Some(TrampolineValueKind::Aggregate { size_bytes })
            }
            Type::Void
            | Type::Fwd(_)
            | Type::Function(_)
            | Type::FunctionProto(_)
            | Type::Variable(_)
            | Type::DataSection(_) => None,
            Type::Pointer(_)
            | Type::Typedef(_)
            | Type::Volatile(_)
            | Type::Const(_)
            | Type::Restrict(_)
            | Type::DeclTag(_)
            | Type::TypeTag(_) => Some(TrampolineValueKind::Scalar),
        }
    }

    fn trampoline_unsupported_reason(ty: &FlattenedType) -> String {
        let type_name = ty.name.as_deref().unwrap_or("<anonymous>");
        match &ty.base_type {
            Type::Array(_) => format!("by-value array type '{type_name}'"),
            Type::Struct(_) | Type::Union(_) => format!("by-value aggregate type '{type_name}'"),
            Type::Void => "void type".to_string(),
            _ => format!("type '{type_name}'"),
        }
    }

    pub(super) fn resolve_trampoline_field_projection(
        &self,
        btf: &Btf,
        root_type_id: u32,
        field_path: &[TrampolineFieldSelector],
        raw_type_sizes: &HashMap<u32, u32>,
        raw_pointer_targets: &HashMap<u32, u32>,
    ) -> Result<TrampolineFieldProjection, BtfError> {
        if field_path.is_empty() {
            return Err(BtfError::KernelBtfError(
                "empty trampoline field path".to_string(),
            ));
        }

        let mut current_ty = btf
            .get_type_by_id(root_type_id)
            .map_err(|e| {
                BtfError::KernelBtfError(format!(
                    "failed to resolve kernel BTF type {}: {}",
                    root_type_id, e
                ))
            })?
            .clone();
        let mut path = Vec::with_capacity(field_path.len());

        let path_desc = Self::format_trampoline_field_path(field_path);
        for segment in field_path {
            while current_ty.num_refs > 1 && !matches!(segment, TrampolineFieldSelector::Index(_)) {
                let mut deref_ty = current_ty.clone();
                deref_ty.num_refs -= 1;
                path.push(TrampolineFieldPathSegment {
                    offset_bytes: 0,
                    type_info: Self::type_info_from_btf_type(
                        btf,
                        &deref_ty,
                        raw_type_sizes,
                        raw_pointer_targets,
                    )?,
                    bitfield: None,
                });
                current_ty = deref_ty;
            }
            let ty_name = current_ty.name.as_deref().unwrap_or("<anonymous>");
            let (next_ty, offset_bytes, bitfield, next_type_info) = match (
                segment,
                &current_ty.base_type,
            ) {
                (TrampolineFieldSelector::Field(segment), Type::Struct(struct_ty))
                | (TrampolineFieldSelector::Field(segment), Type::Union(struct_ty)) => {
                    let member = struct_ty
                        .members
                        .iter()
                        .find(|member| member.name.as_deref() == Some(segment.as_str()))
                        .ok_or_else(|| {
                            BtfError::KernelBtfError(format!(
                                "trampoline aggregate type '{}' has no field '{}'",
                                ty_name, segment
                            ))
                        })?;

                    let member_ty = btf
                        .get_type_by_id(member.type_id)
                        .map_err(|e| {
                            BtfError::KernelBtfError(format!(
                                "failed to resolve kernel BTF type {}: {}",
                                member.type_id, e
                            ))
                        })?
                        .clone();
                    let member_type_info = Self::type_info_from_btf_type(
                        btf,
                        &member_ty,
                        raw_type_sizes,
                        raw_pointer_targets,
                    )?;

                    let (offset_bytes, bitfield) = if let Some(bit_size) =
                        member.bits.filter(|bits| *bits != 0)
                    {
                        if !matches!(member_type_info, TypeInfo::Int { .. }) {
                            return Err(BtfError::KernelBtfError(format!(
                                "trampoline bitfield '{}.{}' uses unsupported storage type {:?}",
                                ty_name, segment, member_type_info
                            )));
                        }

                        let raw_size_bytes = raw_type_sizes
                            .get(&member.type_id)
                            .copied()
                            .map(|size| size as usize);
                        let storage_size_bytes =
                            Self::trampoline_size_bytes(btf, &member_ty, raw_size_bytes)?;
                        let storage_bits =
                            u32::try_from(storage_size_bytes.checked_mul(8).ok_or_else(|| {
                                BtfError::KernelBtfError(format!(
                                    "size overflow while resolving trampoline bitfield '{}.{}'",
                                    ty_name, segment
                                ))
                            })?)
                            .map_err(|_| {
                                BtfError::KernelBtfError(format!(
                                    "size overflow while resolving trampoline bitfield '{}.{}'",
                                    ty_name, segment
                                ))
                            })?;
                        if storage_bits == 0 {
                            return Err(BtfError::KernelBtfError(format!(
                                "trampoline bitfield '{}.{}' has zero-sized storage",
                                ty_name, segment
                            )));
                        }
                        let storage_base_bits = (member.offset / storage_bits)
                            .checked_mul(storage_bits)
                            .ok_or_else(|| {
                                BtfError::KernelBtfError(format!(
                                    "offset overflow while resolving trampoline bitfield '{}.{}'",
                                    ty_name, segment
                                ))
                            })?;
                        let bit_offset = member.offset.checked_sub(storage_base_bits).ok_or_else(
                            || {
                                BtfError::KernelBtfError(format!(
                                    "offset underflow while resolving trampoline bitfield '{}.{}'",
                                    ty_name, segment
                                ))
                            },
                        )?;
                        let end_bits = bit_offset.checked_add(bit_size).ok_or_else(|| {
                            BtfError::KernelBtfError(format!(
                                "size overflow while resolving trampoline bitfield '{}.{}'",
                                ty_name, segment
                            ))
                        })?;
                        if end_bits > storage_bits {
                            return Err(BtfError::KernelBtfError(format!(
                                "trampoline bitfield '{}.{}' spans multiple storage units",
                                ty_name, segment
                            )));
                        }
                        (
                            usize::try_from(storage_base_bits / 8).map_err(|_| {
                                BtfError::KernelBtfError(format!(
                                    "offset overflow while resolving trampoline bitfield '{}.{}'",
                                    ty_name, segment
                                ))
                            })?,
                            Some(TrampolineBitfieldInfo {
                                bit_offset,
                                bit_size,
                            }),
                        )
                    } else {
                        if member.offset % 8 != 0 {
                            return Err(BtfError::KernelBtfError(format!(
                                "trampoline field '{}.{}' is not byte-aligned",
                                ty_name, segment
                            )));
                        }
                        (
                            usize::try_from(member.offset / 8).map_err(|_| {
                                BtfError::KernelBtfError(format!(
                                    "offset overflow while resolving trampoline field '{}.{}'",
                                    ty_name, segment
                                ))
                            })?,
                            None,
                        )
                    };

                    (member_ty, offset_bytes, bitfield, Some(member_type_info))
                }
                (TrampolineFieldSelector::Field(segment), Type::Array(_)) => {
                    return Err(BtfError::KernelBtfError(format!(
                        "trampoline array type '{}' does not have a field '{}'; use a numeric index",
                        ty_name, segment
                    )));
                }
                (TrampolineFieldSelector::Field(_), _) => {
                    return Err(BtfError::KernelBtfError(format!(
                        "trampoline field path '{}' requires a struct/union or array, got '{}'",
                        path_desc, ty_name
                    )));
                }
                (TrampolineFieldSelector::Index(index), _) if current_ty.num_refs > 0 => {
                    let mut elem_ty = current_ty.clone();
                    elem_ty.num_refs -= 1;
                    let raw_size_bytes = raw_type_sizes
                        .get(&elem_ty.type_id)
                        .copied()
                        .map(|size| size as usize);
                    let elem_size_bytes =
                        Self::trampoline_size_bytes(btf, &elem_ty, raw_size_bytes)?;
                    let offset_bytes = index.checked_mul(elem_size_bytes).ok_or_else(|| {
                        BtfError::KernelBtfError(format!(
                            "offset overflow while resolving trampoline field '{}'",
                            path_desc
                        ))
                    })?;
                    (elem_ty, offset_bytes, None, None)
                }
                (TrampolineFieldSelector::Index(index), Type::Array(array_ty)) => {
                    let num_elements = array_ty.num_elements as usize;
                    if *index >= num_elements {
                        return Err(BtfError::KernelBtfError(format!(
                            "trampoline array type '{}' index {} is out of bounds (len {})",
                            ty_name, index, num_elements
                        )));
                    }
                    let elem_ty = btf
                        .get_type_by_id(array_ty.elem_type_id)
                        .map_err(|e| {
                            BtfError::KernelBtfError(format!(
                                "failed to resolve kernel BTF type {}: {}",
                                array_ty.elem_type_id, e
                            ))
                        })?
                        .clone();
                    let raw_size_bytes = raw_type_sizes
                        .get(&array_ty.elem_type_id)
                        .copied()
                        .map(|size| size as usize);
                    let elem_size_bytes =
                        Self::trampoline_size_bytes(btf, &elem_ty, raw_size_bytes)?;
                    let offset_bytes = index.checked_mul(elem_size_bytes).ok_or_else(|| {
                        BtfError::KernelBtfError(format!(
                            "offset overflow while resolving trampoline field '{}'",
                            path_desc
                        ))
                    })?;
                    (elem_ty, offset_bytes, None, None)
                }
                (TrampolineFieldSelector::Index(index), _) => {
                    return Err(BtfError::KernelBtfError(format!(
                        "trampoline field path '{}' cannot index {} on non-array type '{}'",
                        path_desc, index, ty_name
                    )));
                }
            };

            path.push(TrampolineFieldPathSegment {
                offset_bytes,
                type_info: match next_type_info {
                    Some(type_info) => type_info,
                    None => Self::type_info_from_btf_type(
                        btf,
                        &next_ty,
                        raw_type_sizes,
                        raw_pointer_targets,
                    )?,
                },
                bitfield,
            });
            current_ty = next_ty;
        }

        let type_info = path
            .last()
            .map(|segment| segment.type_info.clone())
            .ok_or_else(|| {
                BtfError::KernelBtfError("empty trampoline field projection".to_string())
            })?;

        Ok(TrampolineFieldProjection { path, type_info })
    }

    fn format_trampoline_field_path(field_path: &[TrampolineFieldSelector]) -> String {
        let mut out = String::new();
        for (idx, segment) in field_path.iter().enumerate() {
            if idx > 0 {
                out.push('.');
            }
            match segment {
                TrampolineFieldSelector::Field(name) => out.push_str(name),
                TrampolineFieldSelector::Index(index) => out.push_str(&index.to_string()),
            }
        }
        out
    }

    pub(super) fn type_info_from_btf_type(
        btf: &Btf,
        ty: &FlattenedType,
        raw_type_sizes: &HashMap<u32, u32>,
        raw_pointer_targets: &HashMap<u32, u32>,
    ) -> Result<TypeInfo, BtfError> {
        let mut active_type_ids = HashSet::new();
        Self::type_info_from_btf_type_inner(
            btf,
            ty,
            raw_type_sizes,
            raw_pointer_targets,
            &mut active_type_ids,
            Self::TRAMPOLINE_POINTER_TYPE_DEPTH,
        )
    }

    fn recursive_type_info_fallback(
        btf: &Btf,
        ty: &FlattenedType,
        raw_type_sizes: &HashMap<u32, u32>,
    ) -> Result<TypeInfo, BtfError> {
        let raw_size_bytes = raw_type_sizes
            .get(&ty.type_id)
            .copied()
            .map(|size| size as usize);
        match &ty.base_type {
            Type::Struct(_) | Type::Union(_) => Ok(TypeInfo::Struct {
                name: ty.name.clone().unwrap_or_else(|| "<anonymous>".to_string()),
                btf_type_id: Some(ty.type_id),
                size: Self::trampoline_size_bytes(btf, ty, raw_size_bytes)?,
                fields: Vec::new(),
            }),
            _ => Ok(TypeInfo::Unknown),
        }
    }

    fn type_info_from_btf_type_inner(
        btf: &Btf,
        ty: &FlattenedType,
        raw_type_sizes: &HashMap<u32, u32>,
        raw_pointer_targets: &HashMap<u32, u32>,
        active_type_ids: &mut HashSet<u32>,
        pointer_type_depth: usize,
    ) -> Result<TypeInfo, BtfError> {
        let raw_size_bytes = raw_type_sizes
            .get(&ty.type_id)
            .copied()
            .map(|size| size as usize);
        if ty.num_refs > 0 {
            let pointee_ty = raw_pointer_targets
                .get(&ty.type_id)
                .and_then(|target_id| btf.get_type_by_id(*target_id).ok())
                .cloned()
                .unwrap_or_else(|| {
                    let mut pointee_ty = ty.clone();
                    pointee_ty.num_refs -= 1;
                    pointee_ty
                });
            let target = if pointer_type_depth == 0
                || (pointee_ty.num_refs == 0 && active_type_ids.contains(&pointee_ty.type_id))
            {
                Self::recursive_type_info_fallback(btf, &pointee_ty, raw_type_sizes)?
            } else {
                Self::type_info_from_btf_type_inner(
                    btf,
                    &pointee_ty,
                    raw_type_sizes,
                    raw_pointer_targets,
                    active_type_ids,
                    pointer_type_depth - 1,
                )?
            };
            return Ok(TypeInfo::Ptr {
                target: Box::new(target),
                is_user: Self::has_user_type_tag(&ty.type_tags),
            });
        }

        if !active_type_ids.insert(ty.type_id) {
            return Self::recursive_type_info_fallback(btf, ty, raw_type_sizes);
        }

        let result = match &ty.base_type {
            Type::Integer(int_ty) => Ok(TypeInfo::Int {
                size: usize::try_from(int_ty.bits.div_ceil(8)).map_err(|_| {
                    BtfError::KernelBtfError(format!(
                        "size overflow for integer trampoline field '{}'",
                        ty.name.as_deref().unwrap_or("<anonymous>")
                    ))
                })?,
                signed: int_ty.is_signed,
            }),
            Type::Enum32(_) => Ok(TypeInfo::Int {
                size: 4,
                signed: false,
            }),
            Type::Enum64(_) => Ok(TypeInfo::Int {
                size: 8,
                signed: false,
            }),
            Type::Array(array_ty) => {
                let elem_ty = btf.get_type_by_id(array_ty.elem_type_id).map_err(|e| {
                    BtfError::KernelBtfError(format!(
                        "failed to resolve array element type {}: {}",
                        array_ty.elem_type_id, e
                    ))
                })?;
                Ok(TypeInfo::Array {
                    element: Box::new(Self::type_info_from_btf_type_inner(
                        btf,
                        &elem_ty,
                        raw_type_sizes,
                        raw_pointer_targets,
                        active_type_ids,
                        pointer_type_depth,
                    )?),
                    len: array_ty.num_elements as usize,
                })
            }
            Type::Struct(struct_ty) => {
                let size = Self::trampoline_size_bytes(btf, ty, raw_size_bytes)?;
                Ok(TypeInfo::Struct {
                    name: ty.name.clone().unwrap_or_else(|| "<anonymous>".to_string()),
                    btf_type_id: Some(ty.type_id),
                    size,
                    fields: Self::struct_field_infos_from_btf_type(
                        btf,
                        struct_ty,
                        size,
                        raw_type_sizes,
                        raw_pointer_targets,
                        active_type_ids,
                        pointer_type_depth,
                    )?,
                })
            }
            Type::Union(_) => Ok(TypeInfo::Struct {
                name: ty.name.clone().unwrap_or_else(|| "<anonymous>".to_string()),
                btf_type_id: Some(ty.type_id),
                size: Self::trampoline_size_bytes(btf, ty, raw_size_bytes)?,
                fields: Vec::new(),
            }),
            Type::Void => Ok(TypeInfo::Void),
            Type::Float(_)
            | Type::Fwd(_)
            | Type::FunctionProto(_)
            | Type::DataSection(_)
            | Type::Pointer(_)
            | Type::Typedef(_)
            | Type::Volatile(_)
            | Type::Const(_)
            | Type::Restrict(_)
            | Type::Function(_)
            | Type::Variable(_)
            | Type::DeclTag(_)
            | Type::TypeTag(_) => Ok(TypeInfo::Unknown),
        };

        active_type_ids.remove(&ty.type_id);
        result
    }

    fn struct_field_infos_from_btf_type(
        btf: &Btf,
        struct_ty: &btf::btf::Struct,
        struct_size: usize,
        raw_type_sizes: &HashMap<u32, u32>,
        raw_pointer_targets: &HashMap<u32, u32>,
        active_type_ids: &mut HashSet<u32>,
        pointer_type_depth: usize,
    ) -> Result<Vec<FieldInfo>, BtfError> {
        let mut fields = Vec::with_capacity(struct_ty.members.len());
        for member in &struct_ty.members {
            let Some(name) = member.name.clone() else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let member_ty = btf.get_type_by_id(member.type_id).map_err(|e| {
                BtfError::KernelBtfError(format!(
                    "failed to resolve kernel BTF type {}: {}",
                    member.type_id, e
                ))
            })?;
            let type_info = Self::type_info_from_btf_type_inner(
                btf,
                &member_ty,
                raw_type_sizes,
                raw_pointer_targets,
                active_type_ids,
                pointer_type_depth,
            )?;
            let raw_size_bytes = raw_type_sizes
                .get(&member.type_id)
                .copied()
                .map(|size| size as usize);
            let (offset, size, bitfield) = if let Some(bit_size) =
                member.bits.filter(|bits| *bits != 0)
            {
                if !matches!(type_info, TypeInfo::Int { .. }) {
                    continue;
                }
                let storage_size = Self::trampoline_size_bytes(btf, &member_ty, raw_size_bytes)?;
                let storage_bits = u32::try_from(storage_size.checked_mul(8).ok_or_else(|| {
                    BtfError::KernelBtfError(format!(
                        "size overflow while resolving trampoline aggregate member '{}'",
                        name
                    ))
                })?)
                .map_err(|_| {
                    BtfError::KernelBtfError(format!(
                        "size overflow while resolving trampoline aggregate member '{}'",
                        name
                    ))
                })?;
                if storage_bits == 0 {
                    continue;
                }
                let storage_base_bits = (member.offset / storage_bits)
                    .checked_mul(storage_bits)
                    .ok_or_else(|| {
                        BtfError::KernelBtfError(format!(
                            "offset overflow while resolving trampoline aggregate member '{}'",
                            name
                        ))
                    })?;
                let bit_offset = member
                    .offset
                    .checked_sub(storage_base_bits)
                    .ok_or_else(|| {
                        BtfError::KernelBtfError(format!(
                            "offset underflow while resolving trampoline aggregate member '{}'",
                            name
                        ))
                    })?;
                let end_bits = bit_offset.checked_add(bit_size).ok_or_else(|| {
                    BtfError::KernelBtfError(format!(
                        "size overflow while resolving trampoline aggregate member '{}'",
                        name
                    ))
                })?;
                if end_bits > storage_bits {
                    continue;
                }
                (
                    usize::try_from(storage_base_bits / 8).map_err(|_| {
                        BtfError::KernelBtfError(format!(
                            "offset overflow while resolving trampoline aggregate member '{}'",
                            name
                        ))
                    })?,
                    storage_size,
                    Some(BitfieldInfo {
                        bit_offset,
                        bit_size,
                    }),
                )
            } else {
                if member.offset % 8 != 0 {
                    continue;
                }
                (
                    usize::try_from(member.offset / 8).map_err(|_| {
                        BtfError::KernelBtfError(format!(
                            "offset overflow while resolving trampoline aggregate member '{}'",
                            name
                        ))
                    })?,
                    Self::trampoline_size_bytes(btf, &member_ty, raw_size_bytes)?,
                    None,
                )
            };
            let end = offset.checked_add(size).ok_or_else(|| {
                BtfError::KernelBtfError(format!(
                    "size overflow while resolving trampoline aggregate member '{}'",
                    name
                ))
            })?;
            if end > struct_size {
                continue;
            }

            fields.push(FieldInfo {
                name,
                type_info,
                offset,
                size,
                bitfield,
            });
        }

        Ok(fields)
    }
}
