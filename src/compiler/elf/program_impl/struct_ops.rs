use super::*;

impl StructOpsObjectBuilder {
    fn value_type_name(&self) -> &str {
        match &self.object.kind {
            EbpfObjectKind::StructOps {
                value_type_name, ..
            } => value_type_name,
            EbpfObjectKind::Program => {
                panic!("StructOpsObjectBuilder must always wrap a struct_ops object")
            }
        }
    }

    fn value_symbol_mut(&mut self) -> &mut ObjectDataSymbol {
        self.object
            .extra_data_symbols
            .first_mut()
            .expect("struct_ops builder must always have a value symbol")
    }

    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.object.license = license.into();
        self
    }

    pub fn with_maps(mut self, maps: Vec<EbpfMap>) -> Self {
        self.object.maps = maps;
        self
    }

    pub fn with_readonly_globals(mut self, readonly_globals: Vec<ReadonlyGlobal>) -> Self {
        self.object.readonly_globals = readonly_globals;
        self
    }

    pub fn with_data_globals(mut self, data_globals: Vec<DataGlobal>) -> Self {
        self.object.data_globals = data_globals;
        self
    }

    pub fn with_bss_globals(mut self, bss_globals: Vec<BssGlobal>) -> Self {
        self.object.bss_globals = bss_globals;
        self
    }

    pub fn with_value_alignment(mut self, align: u64) -> Self {
        self.value_symbol_mut().align = align;
        self
    }

    pub fn with_value_data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.value_symbol_mut().data = data.into();
        self
    }

    pub fn with_callback_slot(mut self, slot_name: impl Into<String>, offset: usize) -> Self {
        self.callback_slots.insert(slot_name.into(), offset);
        self
    }

    pub fn add_value_relocation(mut self, offset: usize, symbol_name: impl Into<String>) -> Self {
        self.value_symbol_mut()
            .relocations
            .push(ObjectDataRelocation {
                offset,
                field_name: None,
                symbol_name: symbol_name.into(),
            });
        self
    }

    pub fn add_callback(mut self, program: EbpfProgram, callback_name: impl Into<String>) -> Self {
        let callback_name = callback_name.into();
        let value_type_name = self.value_type_name().to_string();
        self.object.programs.push(program.into_struct_ops_callback(
            &value_type_name,
            &callback_name,
            callback_name.clone(),
        ));
        self
    }

    pub fn add_callback_section(mut self, section: EbpfProgramSection) -> Self {
        self.object.programs.push(section);
        self
    }

    pub fn bind_callback(
        mut self,
        slot_name: impl AsRef<str>,
        program: EbpfProgram,
        callback_name: impl Into<String>,
    ) -> Result<Self, CompileError> {
        let slot_name = slot_name.as_ref();
        let offset = *self.callback_slots.get(slot_name).ok_or_else(|| {
            CompileError::InvalidProgram(format!(
                "unknown struct_ops callback slot '{}' for object builder",
                slot_name
            ))
        })?;
        let callback_name = callback_name.into();
        let value_type_name = self.value_type_name().to_string();
        self.object.programs.push(program.into_struct_ops_callback(
            &value_type_name,
            slot_name,
            callback_name.clone(),
        ));
        self.value_symbol_mut()
            .relocations
            .push(ObjectDataRelocation {
                offset,
                field_name: Some(slot_name.to_string()),
                symbol_name: callback_name,
            });
        Ok(self)
    }

    pub fn build(self) -> EbpfObject {
        self.object
    }
}

impl StructOpsObjectSpec {
    pub fn new(
        name: impl Into<String>,
        value_type_name: impl Into<String>,
        value_data: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            name: name.into(),
            value_type_name: value_type_name.into(),
            license: "GPL".to_string(),
            value_data: value_data.into(),
            maps: Vec::new(),
            readonly_globals: Vec::new(),
            data_globals: Vec::new(),
            bss_globals: Vec::new(),
            callback_slots: Vec::new(),
            callbacks: Vec::new(),
        }
    }

    pub fn zeroed_from_kernel_btf(
        name: impl Into<String>,
        value_type_name: impl Into<String>,
    ) -> Result<Self, CompileError> {
        let name = name.into();
        let value_type_name = value_type_name.into();
        let size = KernelBtf::get()
            .kernel_named_type_size_bytes(&value_type_name)
            .map_err(|err| {
                CompileError::InvalidProgram(format!(
                    "failed to resolve struct_ops value type '{}' from kernel BTF: {}",
                    value_type_name, err
                ))
            })?;
        Ok(Self::new(name, value_type_name, vec![0; size]))
    }

    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = license.into();
        self
    }

    pub fn with_callback_slot(mut self, name: impl Into<String>, offset: usize) -> Self {
        self.callback_slots.push(StructOpsCallbackSlot {
            name: name.into(),
            offset,
        });
        self
    }

    pub fn with_maps(mut self, maps: Vec<EbpfMap>) -> Self {
        self.maps = maps;
        self
    }

    pub fn with_readonly_globals(mut self, readonly_globals: Vec<ReadonlyGlobal>) -> Self {
        self.readonly_globals = readonly_globals;
        self
    }

    pub fn with_data_globals(mut self, data_globals: Vec<DataGlobal>) -> Self {
        self.data_globals = data_globals;
        self
    }

    pub fn with_bss_globals(mut self, bss_globals: Vec<BssGlobal>) -> Self {
        self.bss_globals = bss_globals;
        self
    }

    pub fn with_callback(
        mut self,
        slot_name: impl Into<String>,
        callback_name: impl Into<String>,
        program: EbpfProgram,
    ) -> Self {
        self.callbacks.push(StructOpsCallbackSpec {
            slot_name: slot_name.into(),
            callback_name: callback_name.into(),
            program,
        });
        self
    }

    pub fn with_value_field(
        mut self,
        field_name: impl Into<String>,
        value: StructOpsValueField,
    ) -> Result<Self, CompileError> {
        let field_name = field_name.into();
        self.set_value_field_path(&[TrampolineFieldSelector::Field(field_name)], &value)?;
        Ok(self)
    }

    pub fn with_value_field_path(
        mut self,
        field_path: &[TrampolineFieldSelector],
        value: StructOpsValueField,
    ) -> Result<Self, CompileError> {
        self.set_value_field_path(field_path, &value)?;
        Ok(self)
    }

    pub fn to_object_with_compiled_callbacks(
        &self,
        callbacks: Vec<CompiledStructOpsCallback>,
    ) -> Result<EbpfObject, CompileError> {
        let mut merged = self.clone();

        for callback in callbacks {
            if callback.program.license != self.license {
                return Err(CompileError::InvalidProgram(format!(
                    "compiled struct_ops callback '{}' uses license '{}' but object '{}' uses '{}'",
                    callback.callback_name, callback.program.license, self.name, self.license
                )));
            }
            if callback.program.event_schema.is_some() {
                return Err(CompileError::InvalidProgram(format!(
                    "compiled struct_ops callback '{}' cannot emit event schemas",
                    callback.callback_name
                )));
            }
            if callback.program.bytes_counter_key_schema.is_some() {
                return Err(CompileError::InvalidProgram(format!(
                    "compiled struct_ops callback '{}' cannot emit bytes counter schemas",
                    callback.callback_name
                )));
            }

            Self::merge_maps(
                &mut merged.maps,
                &callback.program.maps,
                &callback.callback_name,
            )?;
            Self::merge_readonly_globals(
                &mut merged.readonly_globals,
                &callback.program.readonly_globals,
                &callback.callback_name,
            )?;
            Self::merge_data_globals(
                &mut merged.data_globals,
                &callback.program.data_globals,
                &callback.callback_name,
            )?;
            Self::merge_bss_globals(
                &mut merged.bss_globals,
                &callback.program.bss_globals,
                &callback.callback_name,
            )?;
            merged.callbacks.push(StructOpsCallbackSpec {
                slot_name: callback.slot_name,
                callback_name: callback.callback_name,
                program: callback.program,
            });
        }

        merged.to_object()
    }

    pub fn to_object(&self) -> Result<EbpfObject, CompileError> {
        let mut seen_slots = HashSet::new();
        for slot in &self.callback_slots {
            if !seen_slots.insert(slot.name.as_str()) {
                return Err(CompileError::InvalidProgram(format!(
                    "duplicate struct_ops callback slot '{}'",
                    slot.name
                )));
            }
        }

        let mut resolved_slots: HashMap<String, usize> = self
            .callback_slots
            .iter()
            .map(|slot| (slot.name.clone(), slot.offset))
            .collect();
        let mut seen_bindings = HashSet::new();
        for callback in &self.callbacks {
            if !seen_bindings.insert(callback.slot_name.as_str()) {
                return Err(CompileError::InvalidProgram(format!(
                    "duplicate struct_ops callback binding for slot '{}'",
                    callback.slot_name
                )));
            }
            if !resolved_slots.contains_key(&callback.slot_name) {
                let projection = KernelBtf::get()
                    .kernel_named_type_field_projection(
                        &self.value_type_name,
                        &[TrampolineFieldSelector::Field(callback.slot_name.clone())],
                    )
                    .map_err(|err| {
                        CompileError::InvalidProgram(format!(
                            "failed to resolve struct_ops callback slot '{}.{}' from kernel BTF: {}",
                            self.value_type_name, callback.slot_name, err
                        ))
                    })?;
                let Some(offset) = projection.path.first().map(|segment| segment.offset_bytes)
                else {
                    return Err(CompileError::InvalidProgram(format!(
                        "struct_ops callback slot '{}.{}' resolved to an empty field projection",
                        self.value_type_name, callback.slot_name
                    )));
                };
                if !matches!(projection.type_info, TypeInfo::Ptr { .. }) {
                    return Err(CompileError::InvalidProgram(format!(
                        "struct_ops callback slot '{}.{}' resolved to a non-pointer member {:?}",
                        self.value_type_name, callback.slot_name, projection.type_info
                    )));
                }
                resolved_slots.insert(callback.slot_name.clone(), offset);
            }
        }

        let mut builder = EbpfObject::struct_ops(
            self.name.clone(),
            self.value_type_name.clone(),
            self.value_data.clone(),
        )
        .with_license(self.license.clone())
        .with_maps(self.maps.clone())
        .with_readonly_globals(self.readonly_globals.clone())
        .with_data_globals(self.data_globals.clone())
        .with_bss_globals(self.bss_globals.clone());
        for (slot_name, offset) in resolved_slots {
            builder = builder.with_callback_slot(slot_name, offset);
        }
        for callback in &self.callbacks {
            builder = builder.bind_callback(
                &callback.slot_name,
                callback.program.clone(),
                callback.callback_name.clone(),
            )?;
        }
        Ok(builder.build())
    }

    fn format_value_field_path(field_path: &[TrampolineFieldSelector]) -> String {
        field_path
            .iter()
            .map(|segment| match segment {
                TrampolineFieldSelector::Field(name) => name.clone(),
                TrampolineFieldSelector::Index(index) => index.to_string(),
            })
            .collect::<Vec<_>>()
            .join(".")
    }

    fn set_value_field_path(
        &mut self,
        field_path: &[TrampolineFieldSelector],
        value: &StructOpsValueField,
    ) -> Result<(), CompileError> {
        if field_path.is_empty() {
            return Err(CompileError::InvalidProgram(
                "struct_ops value field path cannot be empty".to_string(),
            ));
        }
        let field_path_label = Self::format_value_field_path(field_path);
        let projection = KernelBtf::get()
            .kernel_named_type_field_projection(&self.value_type_name, field_path)
            .map_err(|err| {
                CompileError::InvalidProgram(format!(
                    "failed to resolve struct_ops value field '{}.{}' from kernel BTF: {}",
                    self.value_type_name, field_path_label, err
                ))
            })?;
        if projection
            .path
            .iter()
            .take(projection.path.len().saturating_sub(1))
            .any(|segment| matches!(segment.type_info, TypeInfo::Ptr { .. }))
        {
            return Err(CompileError::InvalidProgram(format!(
                "struct_ops value field '{}.{}' crosses a pointer hop, which is not supported for constant value initialization",
                self.value_type_name, field_path_label
            )));
        }
        if projection.path.is_empty() {
            return Err(CompileError::InvalidProgram(format!(
                "struct_ops value field '{}.{}' resolved to an empty projection",
                self.value_type_name, field_path_label
            )));
        }
        let offset = projection
            .path
            .iter()
            .try_fold(0usize, |acc, segment| acc.checked_add(segment.offset_bytes))
            .ok_or_else(|| {
                CompileError::InvalidProgram(format!(
                    "struct_ops value field '{}.{}' overflowed value-data offset accounting",
                    self.value_type_name, field_path_label
                ))
            })?;
        let size = projection.type_info.size();
        let end = offset.checked_add(size).ok_or_else(|| {
            CompileError::InvalidProgram(format!(
                "struct_ops value field '{}.{}' overflowed value-data bounds",
                self.value_type_name, field_path_label
            ))
        })?;
        if end > self.value_data.len() {
            return Err(CompileError::InvalidProgram(format!(
                "struct_ops value field '{}.{}' exceeds value-data bounds (end {}, len {})",
                self.value_type_name,
                field_path_label,
                end,
                self.value_data.len()
            )));
        }

        let field_bytes = &mut self.value_data[offset..end];
        field_bytes.fill(0);
        Self::encode_value_field_bytes(
            &self.value_type_name,
            &field_path_label,
            &projection.type_info,
            value,
            field_bytes,
        )
    }

    fn encode_value_field_bytes(
        value_type_name: &str,
        field_name: &str,
        type_info: &TypeInfo,
        value: &StructOpsValueField,
        out: &mut [u8],
    ) -> Result<(), CompileError> {
        match (type_info, value) {
            (TypeInfo::Int { size, signed }, StructOpsValueField::Int(v)) => {
                Self::write_int_value(*size, *signed, *v, out).map_err(|msg| {
                    CompileError::InvalidProgram(format!(
                        "invalid initializer for struct_ops value field '{}.{}': {}",
                        value_type_name, field_name, msg
                    ))
                })
            }
            (TypeInfo::Int { size, signed }, StructOpsValueField::Bool(v)) => {
                let raw = if *v { 1 } else { 0 };
                Self::write_int_value(*size, *signed, raw, out).map_err(|msg| {
                    CompileError::InvalidProgram(format!(
                        "invalid initializer for struct_ops value field '{}.{}': {}",
                        value_type_name, field_name, msg
                    ))
                })
            }
            (TypeInfo::Array { element, len }, StructOpsValueField::String(s))
                if matches!(element.as_ref(), TypeInfo::Int { size: 1, .. }) =>
            {
                let bytes = s.as_bytes();
                if bytes.len() >= *len {
                    return Err(CompileError::InvalidProgram(format!(
                        "string initializer for struct_ops value field '{}.{}' is too long: {} bytes for {}-byte field",
                        value_type_name,
                        field_name,
                        bytes.len(),
                        len
                    )));
                }
                out[..bytes.len()].copy_from_slice(bytes);
                Ok(())
            }
            (TypeInfo::Array { element, len }, StructOpsValueField::Bytes(bytes))
                if matches!(element.as_ref(), TypeInfo::Int { size: 1, .. }) =>
            {
                if bytes.len() > *len {
                    return Err(CompileError::InvalidProgram(format!(
                        "byte initializer for struct_ops value field '{}.{}' is too long: {} bytes for {}-byte field",
                        value_type_name,
                        field_name,
                        bytes.len(),
                        len
                    )));
                }
                out[..bytes.len()].copy_from_slice(bytes);
                Ok(())
            }
            (TypeInfo::Array { element, len }, StructOpsValueField::IntList(values))
                if matches!(element.as_ref(), TypeInfo::Int { .. }) =>
            {
                let TypeInfo::Int { size, signed } = element.as_ref() else {
                    unreachable!("matched integer array element");
                };
                if values.len() > *len {
                    return Err(CompileError::InvalidProgram(format!(
                        "integer-list initializer for struct_ops value field '{}.{}' is too long: {} items for {}-element field",
                        value_type_name,
                        field_name,
                        values.len(),
                        len
                    )));
                }
                for (idx, value) in values.iter().enumerate() {
                    let byte_offset = idx.checked_mul(*size).ok_or_else(|| {
                        CompileError::InvalidProgram(format!(
                            "integer-list initializer for struct_ops value field '{}.{}' overflowed element layout",
                            value_type_name, field_name
                        ))
                    })?;
                    let byte_end = byte_offset.checked_add(*size).ok_or_else(|| {
                        CompileError::InvalidProgram(format!(
                            "integer-list initializer for struct_ops value field '{}.{}' overflowed element layout",
                            value_type_name, field_name
                        ))
                    })?;
                    Self::write_int_value(*size, *signed, *value, &mut out[byte_offset..byte_end])
                        .map_err(|msg| {
                            CompileError::InvalidProgram(format!(
                                "invalid initializer for struct_ops value field '{}.{}' at index {}: {}",
                                value_type_name, field_name, idx, msg
                            ))
                        })?;
                }
                Ok(())
            }
            (actual, init) => Err(CompileError::InvalidProgram(format!(
                "unsupported initializer {:?} for struct_ops value field '{}.{}' of type {:?}",
                init, value_type_name, field_name, actual
            ))),
        }
    }

    fn write_int_value(
        size: usize,
        signed: bool,
        value: i64,
        out: &mut [u8],
    ) -> Result<(), String> {
        match (size, signed) {
            (1, true) => {
                let value = i8::try_from(value)
                    .map_err(|_| format!("expected signed 8-bit integer, got {}", value))?;
                out.copy_from_slice(&value.to_le_bytes());
                Ok(())
            }
            (2, true) => {
                let value = i16::try_from(value)
                    .map_err(|_| format!("expected signed 16-bit integer, got {}", value))?;
                out.copy_from_slice(&value.to_le_bytes());
                Ok(())
            }
            (4, true) => {
                let value = i32::try_from(value)
                    .map_err(|_| format!("expected signed 32-bit integer, got {}", value))?;
                out.copy_from_slice(&value.to_le_bytes());
                Ok(())
            }
            (8, true) => {
                out.copy_from_slice(&value.to_le_bytes());
                Ok(())
            }
            (1, false) => {
                let value = u8::try_from(value)
                    .map_err(|_| format!("expected unsigned 8-bit integer, got {}", value))?;
                out.copy_from_slice(&value.to_le_bytes());
                Ok(())
            }
            (2, false) => {
                let value = u16::try_from(value)
                    .map_err(|_| format!("expected unsigned 16-bit integer, got {}", value))?;
                out.copy_from_slice(&value.to_le_bytes());
                Ok(())
            }
            (4, false) => {
                let value = u32::try_from(value)
                    .map_err(|_| format!("expected unsigned 32-bit integer, got {}", value))?;
                out.copy_from_slice(&value.to_le_bytes());
                Ok(())
            }
            (8, false) => {
                let value = u64::try_from(value)
                    .map_err(|_| format!("expected unsigned 64-bit integer, got {}", value))?;
                out.copy_from_slice(&value.to_le_bytes());
                Ok(())
            }
            _ => Err(format!("unsupported integer field width {}", size)),
        }
    }

    fn merge_maps(
        existing: &mut Vec<EbpfMap>,
        incoming: &[EbpfMap],
        callback_name: &str,
    ) -> Result<(), CompileError> {
        for map in incoming {
            if let Some(current) = existing.iter().find(|current| current.name == map.name) {
                if current != map {
                    return Err(CompileError::InvalidProgram(format!(
                        "compiled struct_ops callback '{}' uses incompatible map definition for '{}'",
                        callback_name, map.name
                    )));
                }
            } else {
                existing.push(map.clone());
            }
        }
        Ok(())
    }

    fn merge_readonly_globals(
        existing: &mut Vec<ReadonlyGlobal>,
        incoming: &[ReadonlyGlobal],
        callback_name: &str,
    ) -> Result<(), CompileError> {
        for global in incoming {
            if let Some(current) = existing.iter().find(|current| current.name == global.name) {
                if current != global {
                    return Err(CompileError::InvalidProgram(format!(
                        "compiled struct_ops callback '{}' uses incompatible readonly global '{}'",
                        callback_name, global.name
                    )));
                }
            } else {
                existing.push(global.clone());
            }
        }
        Ok(())
    }

    fn merge_data_globals(
        existing: &mut Vec<DataGlobal>,
        incoming: &[DataGlobal],
        callback_name: &str,
    ) -> Result<(), CompileError> {
        for global in incoming {
            if let Some(current) = existing.iter().find(|current| current.name == global.name) {
                if current != global {
                    return Err(CompileError::InvalidProgram(format!(
                        "compiled struct_ops callback '{}' uses incompatible data global '{}'",
                        callback_name, global.name
                    )));
                }
            } else {
                existing.push(global.clone());
            }
        }
        Ok(())
    }

    fn merge_bss_globals(
        existing: &mut Vec<BssGlobal>,
        incoming: &[BssGlobal],
        callback_name: &str,
    ) -> Result<(), CompileError> {
        for global in incoming {
            if let Some(current) = existing.iter().find(|current| current.name == global.name) {
                if current != global {
                    return Err(CompileError::InvalidProgram(format!(
                        "compiled struct_ops callback '{}' uses incompatible bss global '{}'",
                        callback_name, global.name
                    )));
                }
            } else {
                existing.push(global.clone());
            }
        }
        Ok(())
    }
}
