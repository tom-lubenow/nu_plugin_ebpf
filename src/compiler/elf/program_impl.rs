use super::*;
use std::collections::{HashMap, HashSet};

use crate::compiler::ir_to_mir::AnnotatedValueSemantics;
use crate::kernel_btf::TypeInfo;
use crate::kernel_btf::{FieldInfo, KernelBtf, TrampolineFieldSelector};
use crate::program_spec::ProgramSpec;

mod struct_ops;

fn parsed_program_spec_for_program(
    prog_type: EbpfProgramType,
    target: &str,
) -> Option<ProgramSpec> {
    if let Some(program_spec) = ProgramSpec::parse_matching_program_type(target, prog_type) {
        return Some(program_spec);
    }
    ProgramSpec::from_program_type_target(prog_type, target).ok()
}

fn require_program_spec_for_program(
    prog_type: EbpfProgramType,
    target: &str,
) -> Result<ProgramSpec, CompileError> {
    if let Some(program_spec) = ProgramSpec::parse_matching_program_type(target, prog_type) {
        return Ok(program_spec);
    }
    ProgramSpec::from_program_type_target(prog_type, target)
        .map_err(|err| CompileError::InvalidProgram(err.to_string()))
}

fn section_name_for_program(
    prog_type: EbpfProgramType,
    target: &str,
) -> Result<String, CompileError> {
    Ok(require_program_spec_for_program(prog_type, target)?.section_name())
}

impl EbpfProgram {
    /// Create a new eBPF program from a builder
    pub fn new(
        prog_type: EbpfProgramType,
        target: impl Into<String>,
        name: impl Into<String>,
        builder: EbpfBuilder,
    ) -> Self {
        let target = target.into();
        let bytecode = builder.build();
        Self {
            prog_type,
            program_spec: parsed_program_spec_for_program(prog_type, &target),
            target,
            name: name.into(),
            main_size: bytecode.len(),
            bytecode,
            license: "GPL".to_string(),
            maps: Vec::new(),
            readonly_globals: Vec::new(),
            data_globals: Vec::new(),
            bss_globals: Vec::new(),
            relocations: Vec::new(),
            subfunctions: Vec::new(),
            event_schema: None,
            bytes_counter_key_schema: None,
            generic_map_key_types: HashMap::new(),
            generic_map_max_entries: HashMap::new(),
            generic_map_value_types: HashMap::new(),
            generic_map_value_semantics: HashMap::new(),
        }
    }

    /// Create a new eBPF program from raw bytecode
    pub fn from_bytecode(
        prog_type: EbpfProgramType,
        target: impl Into<String>,
        name: impl Into<String>,
        bytecode: Vec<u8>,
    ) -> Self {
        let target = target.into();
        let main_size = bytecode.len();
        Self {
            prog_type,
            program_spec: parsed_program_spec_for_program(prog_type, &target),
            target,
            name: name.into(),
            bytecode,
            main_size,
            license: "GPL".to_string(),
            maps: Vec::new(),
            readonly_globals: Vec::new(),
            data_globals: Vec::new(),
            bss_globals: Vec::new(),
            relocations: Vec::new(),
            subfunctions: Vec::new(),
            event_schema: None,
            bytes_counter_key_schema: None,
            generic_map_key_types: HashMap::new(),
            generic_map_max_entries: HashMap::new(),
            generic_map_value_types: HashMap::new(),
            generic_map_value_semantics: HashMap::new(),
        }
    }

    /// Create a new eBPF program with maps and relocations
    pub fn with_maps(
        prog_type: EbpfProgramType,
        target: impl Into<String>,
        name: impl Into<String>,
        bytecode: Vec<u8>,
        main_size: usize,
        maps: Vec<EbpfMap>,
        relocations: Vec<SymbolRelocation>,
        subfunctions: Vec<SubfunctionSymbol>,
        event_schema: Option<EventSchema>,
        bytes_counter_key_schema: Option<CounterKeySchema>,
        generic_map_value_types: HashMap<MapRef, MirType>,
        generic_map_value_semantics: HashMap<MapRef, AnnotatedValueSemantics>,
    ) -> Self {
        let target = target.into();
        Self {
            prog_type,
            program_spec: parsed_program_spec_for_program(prog_type, &target),
            target,
            name: name.into(),
            bytecode,
            main_size,
            license: "GPL".to_string(),
            maps,
            readonly_globals: Vec::new(),
            data_globals: Vec::new(),
            bss_globals: Vec::new(),
            relocations,
            subfunctions,
            event_schema,
            bytes_counter_key_schema,
            generic_map_key_types: HashMap::new(),
            generic_map_max_entries: HashMap::new(),
            generic_map_value_types,
            generic_map_value_semantics,
        }
    }

    /// Enable pinning on all maps in this program
    ///
    /// When pinning is enabled, maps will be pinned to the BPF filesystem
    /// and can be shared between separate eBPF programs. This is required
    /// for latency measurement using start-timer/stop-timer across
    /// kprobe/kretprobe pairs.
    pub fn with_pinning(mut self) -> Self {
        for map in &mut self.maps {
            map.def.pinning = BpfPinningType::ByName;
        }
        self
    }

    /// Attach readonly globals to this program's `.rodata` section.
    pub fn with_readonly_globals(mut self, readonly_globals: Vec<ReadonlyGlobal>) -> Self {
        self.readonly_globals = readonly_globals;
        self
    }

    /// Attach writable initialized globals to this program's `.data` section.
    pub fn with_data_globals(mut self, data_globals: Vec<DataGlobal>) -> Self {
        self.data_globals = data_globals;
        self
    }

    /// Attach writable zero-initialized globals to this program's `.bss` section.
    pub fn with_bss_globals(mut self, bss_globals: Vec<BssGlobal>) -> Self {
        self.bss_globals = bss_globals;
        self
    }

    /// Attach typed generic map key schemas recovered during lowering.
    pub fn with_generic_map_key_types(
        mut self,
        generic_map_key_types: HashMap<MapRef, MirType>,
    ) -> Self {
        self.generic_map_key_types = generic_map_key_types;
        self
    }

    /// Attach generic map capacity declarations recovered during lowering.
    pub fn with_generic_map_max_entries(
        mut self,
        generic_map_max_entries: HashMap<MapRef, u32>,
    ) -> Self {
        self.generic_map_max_entries = generic_map_max_entries;
        self
    }

    /// Attach the parsed program spec so target-sensitive metadata survives
    /// from command parsing through ELF section emission and loader attach.
    pub fn with_program_spec(mut self, program_spec: ProgramSpec) -> Self {
        self.target = program_spec.target_string();
        self.program_spec = Some(program_spec);
        self
    }

    /// Convert this program into an object with a single program section.
    pub fn into_object(self) -> EbpfObject {
        let EbpfProgram {
            prog_type,
            target,
            program_spec,
            name,
            bytecode,
            main_size,
            license,
            maps,
            readonly_globals,
            data_globals,
            bss_globals,
            relocations,
            subfunctions,
            event_schema,
            bytes_counter_key_schema,
            generic_map_key_types,
            generic_map_max_entries,
            generic_map_value_types,
            generic_map_value_semantics,
        } = self;

        EbpfObject {
            kind: EbpfObjectKind::Program,
            license,
            maps,
            readonly_globals,
            data_globals,
            bss_globals,
            extra_data_symbols: Vec::new(),
            programs: vec![EbpfProgramSection {
                section_name_override: None,
                prog_type,
                target,
                program_spec,
                name,
                bytecode,
                main_size,
                relocations,
                subfunctions,
                event_schema,
                bytes_counter_key_schema,
                generic_map_key_types,
                generic_map_max_entries,
                generic_map_value_types,
                generic_map_value_semantics,
            }],
        }
    }

    /// Convert this program into its object-local program section form.
    pub fn into_program_section(self) -> EbpfProgramSection {
        EbpfProgramSection {
            section_name_override: None,
            prog_type: self.prog_type,
            target: self.target,
            program_spec: self.program_spec,
            name: self.name,
            bytecode: self.bytecode,
            main_size: self.main_size,
            relocations: self.relocations,
            subfunctions: self.subfunctions,
            event_schema: self.event_schema,
            bytes_counter_key_schema: self.bytes_counter_key_schema,
            generic_map_key_types: self.generic_map_key_types,
            generic_map_max_entries: self.generic_map_max_entries,
            generic_map_value_types: self.generic_map_value_types,
            generic_map_value_semantics: self.generic_map_value_semantics,
        }
    }

    /// Convert this program into a typed `struct_ops` callback section.
    pub fn into_struct_ops_callback(
        self,
        value_type_name: &str,
        slot_name: &str,
        callback_name: impl Into<String>,
    ) -> EbpfProgramSection {
        let callback_name = callback_name.into();
        let mut section = self.into_program_section();
        section.section_name_override = Some(struct_ops_callback_section_name(
            value_type_name,
            slot_name,
            &callback_name,
        ));
        section.prog_type = EbpfProgramType::StructOps;
        section.target = callback_name.clone();
        section.program_spec = Some(ProgramSpec::StructOpsCallback {
            value_type_name: value_type_name.to_string(),
            callback_name: slot_name.to_string(),
        });
        section.name = callback_name;
        section
    }

    /// Create a simple "hello world" kprobe that just returns 0
    ///
    /// This is useful for testing the loading infrastructure.
    pub fn hello_world(target: impl Into<String>) -> Self {
        use crate::compiler::instruction::{EbpfInsn, EbpfReg};

        let mut builder = EbpfBuilder::new();

        // Simple program: mov r0, 0; exit
        // This just returns 0, which is a valid kprobe return
        builder
            .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
            .push(EbpfInsn::exit());

        Self::new(EbpfProgramType::Kprobe, target, "hello_world", builder)
    }

    /// Get the ELF section name for this program
    pub fn section_name(&self) -> Result<String, CompileError> {
        if let Some(program_spec) = &self.program_spec {
            return Ok(program_spec.section_name());
        }
        section_name_for_program(self.prog_type, &self.target)
    }

    pub fn validate_runtime_artifacts(&self) -> Result<(), CompileError> {
        self.validate_runtime_artifacts_for_info(self.prog_type.info())
    }

    pub(crate) fn validate_runtime_artifacts_for_info(
        &self,
        program: &ProgramTypeInfo,
    ) -> Result<(), CompileError> {
        fn invalid(msg: impl Into<String>) -> CompileError {
            CompileError::InvalidProgram(msg.into())
        }

        fn require_capability(
            program: &ProgramTypeInfo,
            capability: ProgramCapability,
            artifact: &str,
        ) -> Result<(), CompileError> {
            if program.supported_capabilities.contains(&capability) {
                return Ok(());
            }
            Err(invalid(format!(
                "{} programs do not support {} required by {}",
                program.canonical_prefix,
                capability.description(),
                artifact
            )))
        }

        fn is_hash_runtime_map(map_type: u32) -> bool {
            map_type == BpfMapType::Hash as u32 || map_type == BpfMapType::PerCpuHash as u32
        }

        let mut seen_names = HashSet::new();
        let mut events_map = None;
        let mut bytes_counter_map = None;

        for global in &self.readonly_globals {
            if global.data.is_empty() {
                return Err(invalid(format!(
                    "readonly global '{}' must have a non-zero size",
                    global.name
                )));
            }
            require_capability(
                program,
                ProgramCapability::Globals,
                &format!("readonly global '{}'", global.name),
            )?;
            if !seen_names.insert(global.name.as_str()) {
                return Err(invalid(format!(
                    "duplicate global or map name '{}'",
                    global.name
                )));
            }
        }

        for global in &self.data_globals {
            if global.data.is_empty() {
                return Err(invalid(format!(
                    "data global '{}' must have a non-zero size",
                    global.name
                )));
            }
            require_capability(
                program,
                ProgramCapability::Globals,
                &format!("data global '{}'", global.name),
            )?;
            if !seen_names.insert(global.name.as_str()) {
                return Err(invalid(format!(
                    "duplicate global or map name '{}'",
                    global.name
                )));
            }
        }

        for global in &self.bss_globals {
            if global.size == 0 {
                return Err(invalid(format!(
                    "bss global '{}' must have a non-zero size",
                    global.name
                )));
            }
            require_capability(
                program,
                ProgramCapability::Globals,
                &format!("bss global '{}'", global.name),
            )?;
            if !seen_names.insert(global.name.as_str()) {
                return Err(invalid(format!(
                    "duplicate global or map name '{}'",
                    global.name
                )));
            }
        }

        for map in &self.maps {
            if !seen_names.insert(map.name.as_str()) {
                return Err(invalid(format!(
                    "duplicate global or map name '{}'",
                    map.name
                )));
            }
            map.def.validate_common_shape(&map.name)?;

            match map.name.as_str() {
                RINGBUF_MAP_NAME => {
                    require_capability(program, ProgramCapability::Emit, "runtime map 'events'")?;
                    if map.def.map_type != BpfMapType::RingBuf as u32 {
                        return Err(invalid(format!(
                            "runtime map '{}' must be a RingBuf, got {}",
                            map.name,
                            BpfMapType::name_for_raw(map.def.map_type)
                        )));
                    }
                    events_map = Some(map);
                }
                COUNTER_MAP_NAME => {
                    require_capability(
                        program,
                        ProgramCapability::Counters,
                        "runtime map 'counters'",
                    )?;
                    if !is_hash_runtime_map(map.def.map_type)
                        || map.def.key_size != 8
                        || map.def.value_size != 8
                    {
                        return Err(invalid(format!(
                            "runtime map '{}' must be a hash/per-cpu-hash with 8-byte keys and values",
                            map.name
                        )));
                    }
                }
                STRING_COUNTER_MAP_NAME => {
                    require_capability(
                        program,
                        ProgramCapability::Counters,
                        "runtime map 'str_counters'",
                    )?;
                    if !is_hash_runtime_map(map.def.map_type)
                        || map.def.key_size != 16
                        || map.def.value_size != 8
                    {
                        return Err(invalid(format!(
                            "runtime map '{}' must be a hash/per-cpu-hash with 16-byte keys and 8-byte values",
                            map.name
                        )));
                    }
                }
                BYTES_COUNTER_MAP_NAME => {
                    require_capability(
                        program,
                        ProgramCapability::Counters,
                        "runtime map 'bytes_counters'",
                    )?;
                    if !is_hash_runtime_map(map.def.map_type) || map.def.value_size != 8 {
                        return Err(invalid(format!(
                            "runtime map '{}' must be a hash/per-cpu-hash with 8-byte values",
                            map.name
                        )));
                    }
                    if map.def.key_size == 0 {
                        return Err(invalid(
                            "runtime map 'bytes_counters' must have a non-zero key size",
                        ));
                    }
                    bytes_counter_map = Some(map);
                }
                HISTOGRAM_MAP_NAME => {
                    require_capability(
                        program,
                        ProgramCapability::Histograms,
                        "runtime map 'histogram'",
                    )?;
                    if !is_hash_runtime_map(map.def.map_type)
                        || map.def.key_size != 8
                        || map.def.value_size != 8
                    {
                        return Err(invalid(format!(
                            "runtime map '{}' must be a hash/per-cpu-hash with 8-byte keys and values",
                            map.name
                        )));
                    }
                }
                TIMESTAMP_MAP_NAME => {
                    require_capability(
                        program,
                        ProgramCapability::Timers,
                        "runtime map 'timestamps'",
                    )?;
                    if !is_hash_runtime_map(map.def.map_type)
                        || map.def.key_size != 8
                        || map.def.value_size != 8
                    {
                        return Err(invalid(format!(
                            "runtime map '{}' must be a hash/per-cpu-hash with 8-byte keys and values",
                            map.name
                        )));
                    }
                }
                KSTACK_MAP_NAME | USTACK_MAP_NAME => {
                    require_capability(
                        program,
                        ProgramCapability::StackTraces,
                        &format!("runtime map '{}'", map.name),
                    )?;
                    if map.def.map_type != BpfMapType::StackTrace as u32 {
                        return Err(invalid(format!(
                            "runtime map '{}' must be a StackTrace map, got {}",
                            map.name,
                            BpfMapType::name_for_raw(map.def.map_type)
                        )));
                    }
                }
                _ => match map.def.map_type {
                    x if x == BpfMapType::RingBuf as u32 => {
                        return Err(invalid(format!(
                            "ring buffer runtime maps must be named '{}', got '{}'",
                            RINGBUF_MAP_NAME, map.name
                        )));
                    }
                    x if x == BpfMapType::StackTrace as u32 => {
                        return Err(invalid(format!(
                            "stack trace runtime maps must be named '{}' or '{}', got '{}'",
                            KSTACK_MAP_NAME, USTACK_MAP_NAME, map.name
                        )));
                    }
                    x if x == BpfMapType::ProgArray as u32 => {
                        require_capability(
                            program,
                            ProgramCapability::TailCalls,
                            &format!("tail-call map '{}'", map.name),
                        )?;
                        if map.def.key_size != 4 || map.def.value_size != 4 {
                            return Err(invalid(format!(
                                "tail-call map '{}' must use 4-byte keys and values",
                                map.name
                            )));
                        }
                    }
                    _ => {
                        require_capability(
                            program,
                            ProgramCapability::GenericMaps,
                            &format!("runtime map '{}'", map.name),
                        )?;
                    }
                },
            }
        }

        if self.event_schema.is_some() && events_map.is_none() {
            return Err(invalid(format!(
                "event schema requires runtime map '{}'",
                RINGBUF_MAP_NAME
            )));
        }

        if let Some(schema) = &self.bytes_counter_key_schema {
            let Some(map) = bytes_counter_map else {
                return Err(invalid(format!(
                    "bytes counter key schema requires runtime map '{}'",
                    BYTES_COUNTER_MAP_NAME
                )));
            };
            if map.def.key_size as usize != schema.size() {
                return Err(invalid(format!(
                    "bytes counter key schema size {} does not match map '{}' key size {}",
                    schema.size(),
                    BYTES_COUNTER_MAP_NAME,
                    map.def.key_size
                )));
            }
        }

        Ok(())
    }
}

impl EbpfProgramSection {
    pub fn parsed_program_spec(&self) -> Option<&ProgramSpec> {
        self.program_spec.as_ref()
    }

    pub fn with_section_name_override(mut self, section_name: impl Into<String>) -> Self {
        self.section_name_override = Some(section_name.into());
        self
    }

    pub fn section_name(&self) -> Result<String, CompileError> {
        if let Some(section_name) = &self.section_name_override {
            return Ok(section_name.clone());
        }
        if let Some(program_spec) = &self.program_spec {
            return Ok(program_spec.section_name());
        }
        section_name_for_program(self.prog_type, &self.target)
    }
}

impl EbpfObject {
    /// Wrap a single program as an ELF object.
    pub fn single_program(program: EbpfProgram) -> Self {
        program.into_object()
    }

    /// Start building a `struct_ops` ELF object.
    pub fn struct_ops(
        name: impl Into<String>,
        value_type_name: impl Into<String>,
        value_data: impl Into<Vec<u8>>,
    ) -> StructOpsObjectBuilder {
        let name = name.into();
        StructOpsObjectBuilder {
            object: EbpfObject {
                kind: EbpfObjectKind::StructOps {
                    name: name.clone(),
                    value_type_name: value_type_name.into(),
                },
                license: "GPL".to_string(),
                maps: vec![],
                readonly_globals: vec![],
                data_globals: vec![],
                bss_globals: vec![],
                extra_data_symbols: vec![ObjectDataSymbol {
                    section_name: ".struct_ops".to_string(),
                    name,
                    data: value_data.into(),
                    align: 8,
                    writable: true,
                    relocations: vec![],
                }],
                programs: vec![],
            },
            callback_slots: HashMap::new(),
        }
    }

    /// Return the primary program when this object contains exactly one attachable program.
    pub fn primary_program(&self) -> Result<&EbpfProgramSection, CompileError> {
        if !matches!(self.kind, EbpfObjectKind::Program) {
            return Err(CompileError::InvalidProgram(format!(
                "loader attach requires a program object, got {}",
                match &self.kind {
                    EbpfObjectKind::Program => "program",
                    EbpfObjectKind::StructOps { .. } => "struct_ops",
                }
            )));
        }
        match self.programs.as_slice() {
            [program] => Ok(program),
            [] => Err(CompileError::InvalidProgram(
                "eBPF object contains no program sections".to_string(),
            )),
            programs => Err(CompileError::InvalidProgram(format!(
                "eBPF object contains {} program sections; runtime attach currently supports exactly one",
                programs.len()
            ))),
        }
    }

    pub fn validate_runtime_artifacts(&self) -> Result<(), CompileError> {
        if self.programs.is_empty() && matches!(self.kind, EbpfObjectKind::Program) {
            return Err(CompileError::InvalidProgram(
                "eBPF object must contain at least one program section".to_string(),
            ));
        }

        if let EbpfObjectKind::StructOps {
            name,
            value_type_name,
            ..
        } = &self.kind
        {
            if value_type_name.is_empty() {
                return Err(CompileError::InvalidProgram(
                    "struct_ops object must declare a non-empty value type name".to_string(),
                ));
            }
            if self.extra_data_symbols.is_empty() {
                return Err(CompileError::InvalidProgram(
                    "struct_ops object must contain at least one .struct_ops value symbol"
                        .to_string(),
                ));
            }
            if self.extra_data_symbols.len() != 1 {
                return Err(CompileError::InvalidProgram(format!(
                    "struct_ops object '{}' currently requires exactly one .struct_ops value symbol, got {}",
                    name,
                    self.extra_data_symbols.len()
                )));
            }
            for data_symbol in &self.extra_data_symbols {
                if data_symbol.section_name != ".struct_ops" {
                    return Err(CompileError::InvalidProgram(format!(
                        "struct_ops value symbol '{}' must live in '.struct_ops', got '{}'",
                        data_symbol.name, data_symbol.section_name
                    )));
                }
                if data_symbol.name != *name {
                    return Err(CompileError::InvalidProgram(format!(
                        "struct_ops object '{}' must use a .struct_ops value symbol with the same name, got '{}'",
                        name, data_symbol.name
                    )));
                }
                if !data_symbol.writable {
                    return Err(CompileError::InvalidProgram(format!(
                        "struct_ops value symbol '{}' must be writable",
                        data_symbol.name
                    )));
                }
            }
            for program in &self.programs {
                let section_name = program.section_name()?;
                if !section_name.starts_with("struct_ops") {
                    return Err(CompileError::InvalidProgram(format!(
                        "struct_ops callback program '{}' must use a struct_ops* section name, got '{}'",
                        program.name, section_name
                    )));
                }
            }
        }

        let mut artifact_symbol_names = HashSet::new();
        for global in &self.readonly_globals {
            artifact_symbol_names.insert(global.name.as_str());
        }
        for global in &self.data_globals {
            artifact_symbol_names.insert(global.name.as_str());
        }
        for global in &self.bss_globals {
            artifact_symbol_names.insert(global.name.as_str());
        }
        for map in &self.maps {
            artifact_symbol_names.insert(map.name.as_str());
        }
        for data_symbol in &self.extra_data_symbols {
            if data_symbol.section_name.is_empty() {
                return Err(CompileError::InvalidProgram(format!(
                    "extra data symbol '{}' must use a non-empty section name",
                    data_symbol.name
                )));
            }
            if data_symbol.name.is_empty() {
                return Err(CompileError::InvalidProgram(
                    "extra data symbols must use non-empty symbol names".to_string(),
                ));
            }
            if data_symbol.data.is_empty() {
                return Err(CompileError::InvalidProgram(format!(
                    "extra data symbol '{}' must have a non-zero size",
                    data_symbol.name
                )));
            }
            if data_symbol.align == 0 {
                return Err(CompileError::InvalidProgram(format!(
                    "extra data symbol '{}' must use non-zero alignment",
                    data_symbol.name
                )));
            }
            if !artifact_symbol_names.insert(data_symbol.name.as_str()) {
                return Err(CompileError::InvalidProgram(format!(
                    "duplicate global, map, or data symbol name '{}'",
                    data_symbol.name
                )));
            }
        }

        if let Some(data_symbol) = self.extra_data_symbols.first() {
            for program in &self.programs {
                if !program
                    .prog_type
                    .supports_capability(ProgramCapability::Globals)
                {
                    return Err(CompileError::InvalidProgram(format!(
                        "{} programs do not support {} required by extra data symbol '{}'",
                        program.prog_type.info().canonical_prefix,
                        ProgramCapability::Globals.description(),
                        data_symbol.name
                    )));
                }
            }
        }

        let mut program_names = HashSet::new();
        for program in &self.programs {
            if artifact_symbol_names.contains(program.name.as_str()) {
                return Err(CompileError::InvalidProgram(format!(
                    "program symbol name '{}' conflicts with a map, global, or data symbol",
                    program.name
                )));
            }
            if !program_names.insert(program.name.as_str()) {
                return Err(CompileError::InvalidProgram(format!(
                    "duplicate program symbol name '{}'",
                    program.name
                )));
            }

            let temp = EbpfProgram {
                prog_type: program.prog_type,
                target: program.target.clone(),
                program_spec: program.program_spec.clone(),
                name: program.name.clone(),
                bytecode: program.bytecode.clone(),
                main_size: program.main_size,
                license: self.license.clone(),
                maps: self.maps.clone(),
                readonly_globals: self.readonly_globals.clone(),
                data_globals: self.data_globals.clone(),
                bss_globals: self.bss_globals.clone(),
                relocations: program.relocations.clone(),
                subfunctions: program.subfunctions.clone(),
                event_schema: program.event_schema.clone(),
                bytes_counter_key_schema: program.bytes_counter_key_schema.clone(),
                generic_map_key_types: program.generic_map_key_types.clone(),
                generic_map_max_entries: program.generic_map_max_entries.clone(),
                generic_map_value_types: program.generic_map_value_types.clone(),
                generic_map_value_semantics: program.generic_map_value_semantics.clone(),
            };
            temp.validate_runtime_artifacts()?;
        }

        Ok(())
    }

    /// Generate an ELF object file containing these programs.
    pub fn to_elf(&self) -> Result<Vec<u8>, CompileError> {
        use std::collections::HashMap;

        self.validate_runtime_artifacts()?;

        let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

        // Track global/map/program symbol IDs for relocations.
        let mut symbol_ids: HashMap<String, object::write::SymbolId> = HashMap::new();

        if !self.readonly_globals.is_empty() {
            let rodata_section_id =
                obj.add_section(vec![], b".rodata".to_vec(), SectionKind::ReadOnlyData);

            let rodata_section = obj.section_mut(rodata_section_id);
            rodata_section.flags = SectionFlags::Elf {
                sh_flags: object::elf::SHF_ALLOC as u64,
            };

            for global in &self.readonly_globals {
                let global_offset = obj.append_section_data(rodata_section_id, &global.data, 8);
                let sym_id = obj.add_symbol(Symbol {
                    name: global.name.as_bytes().to_vec(),
                    value: global_offset,
                    size: global.data.len() as u64,
                    kind: SymbolKind::Data,
                    scope: SymbolScope::Linkage,
                    weak: false,
                    section: SymbolSection::Section(rodata_section_id),
                    flags: SymbolFlags::Elf {
                        st_info: (object::elf::STB_GLOBAL << 4) | object::elf::STT_OBJECT,
                        st_other: object::elf::STV_DEFAULT,
                    },
                });
                symbol_ids.insert(global.name.clone(), sym_id);
            }
        }

        if !self.data_globals.is_empty() {
            let data_section_id = obj.add_section(vec![], b".data".to_vec(), SectionKind::Data);

            let data_section = obj.section_mut(data_section_id);
            data_section.flags = SectionFlags::Elf {
                sh_flags: object::elf::SHF_ALLOC as u64 | object::elf::SHF_WRITE as u64,
            };

            for global in &self.data_globals {
                let global_offset = obj.append_section_data(data_section_id, &global.data, 8);
                let sym_id = obj.add_symbol(Symbol {
                    name: global.name.as_bytes().to_vec(),
                    value: global_offset,
                    size: global.data.len() as u64,
                    kind: SymbolKind::Data,
                    scope: SymbolScope::Linkage,
                    weak: false,
                    section: SymbolSection::Section(data_section_id),
                    flags: SymbolFlags::Elf {
                        st_info: (object::elf::STB_GLOBAL << 4) | object::elf::STT_OBJECT,
                        st_other: object::elf::STV_DEFAULT,
                    },
                });
                symbol_ids.insert(global.name.clone(), sym_id);
            }
        }

        if !self.bss_globals.is_empty() {
            let bss_section_id =
                obj.add_section(vec![], b".bss".to_vec(), SectionKind::UninitializedData);

            let bss_section = obj.section_mut(bss_section_id);
            bss_section.flags = SectionFlags::Elf {
                sh_flags: object::elf::SHF_ALLOC as u64 | object::elf::SHF_WRITE as u64,
            };

            for global in &self.bss_globals {
                let global_offset = obj.append_section_bss(bss_section_id, global.size as u64, 8);
                let sym_id = obj.add_symbol(Symbol {
                    name: global.name.as_bytes().to_vec(),
                    value: global_offset,
                    size: global.size as u64,
                    kind: SymbolKind::Data,
                    scope: SymbolScope::Linkage,
                    weak: false,
                    section: SymbolSection::Section(bss_section_id),
                    flags: SymbolFlags::Elf {
                        st_info: (object::elf::STB_GLOBAL << 4) | object::elf::STT_OBJECT,
                        st_other: object::elf::STV_DEFAULT,
                    },
                });
                symbol_ids.insert(global.name.clone(), sym_id);
            }
        }

        // Add maps section if we have any maps (using BTF-defined format)
        if !self.maps.is_empty() {
            let maps_section_id = obj.add_section(vec![], b".maps".to_vec(), SectionKind::Data);

            let maps_section = obj.section_mut(maps_section_id);
            maps_section.flags = SectionFlags::Elf {
                sh_flags: object::elf::SHF_ALLOC as u64 | object::elf::SHF_WRITE as u64,
            };

            // BTF-defined maps use a struct with pointer-sized fields (40 bytes per map)
            // Fields: type, key_size, value_size, max_entries, pinning (5 pointers * 8 bytes)
            let btf_map_size = 40u64;

            for map in &self.maps {
                // BTF-defined map data is all zeros (values come from BTF type metadata)
                let map_data = [0u8; 40];
                let map_offset = obj.append_section_data(maps_section_id, &map_data, 8);

                // Add a symbol for this map (must be GLOBAL with DEFAULT visibility for libbpf/Aya)
                let sym_id = obj.add_symbol(Symbol {
                    name: map.name.as_bytes().to_vec(),
                    value: map_offset,
                    size: btf_map_size,
                    kind: SymbolKind::Data,
                    scope: SymbolScope::Linkage, // GLOBAL binding
                    weak: false,
                    section: SymbolSection::Section(maps_section_id),
                    flags: SymbolFlags::Elf {
                        st_info: (object::elf::STB_GLOBAL << 4) | object::elf::STT_OBJECT,
                        st_other: object::elf::STV_DEFAULT,
                    },
                });
                symbol_ids.insert(map.name.clone(), sym_id);
            }
        }

        // Emit custom object-local data before programs so program relocations
        // can target those symbols. Relocations from the data back to program
        // symbols are applied after all program symbols have been emitted.
        let mut data_sections: HashMap<(String, bool), object::write::SectionId> = HashMap::new();
        let mut pending_data_relocations = Vec::new();
        for data_symbol in &self.extra_data_symbols {
            let section_key = (data_symbol.section_name.clone(), data_symbol.writable);
            let section_id = if let Some(&section_id) = data_sections.get(&section_key) {
                section_id
            } else {
                let kind = if data_symbol.writable {
                    SectionKind::Data
                } else {
                    SectionKind::ReadOnlyData
                };
                let section_id =
                    obj.add_section(vec![], data_symbol.section_name.as_bytes().to_vec(), kind);
                let section = obj.section_mut(section_id);
                let mut sh_flags = object::elf::SHF_ALLOC as u64;
                if data_symbol.writable {
                    sh_flags |= object::elf::SHF_WRITE as u64;
                }
                section.flags = SectionFlags::Elf { sh_flags };
                data_sections.insert(section_key, section_id);
                section_id
            };

            let symbol_offset =
                obj.append_section_data(section_id, &data_symbol.data, data_symbol.align);
            let sym_id = obj.add_symbol(Symbol {
                name: data_symbol.name.as_bytes().to_vec(),
                value: symbol_offset,
                size: data_symbol.data.len() as u64,
                kind: SymbolKind::Data,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(section_id),
                flags: SymbolFlags::Elf {
                    st_info: (object::elf::STB_GLOBAL << 4) | object::elf::STT_OBJECT,
                    st_other: object::elf::STV_DEFAULT,
                },
            });
            symbol_ids.insert(data_symbol.name.clone(), sym_id);
            pending_data_relocations.push((section_id, symbol_offset, data_symbol));
        }

        if let Some(btf_data) = self.generate_btf() {
            let btf_section_id = obj.add_section(vec![], b".BTF".to_vec(), SectionKind::Metadata);
            obj.append_section_data(btf_section_id, &btf_data, 1);
        }

        for program in &self.programs {
            let section_name = program.section_name()?;
            let section_id =
                obj.add_section(vec![], section_name.as_bytes().to_vec(), SectionKind::Text);

            let section = obj.section_mut(section_id);
            section.flags = SectionFlags::Elf {
                sh_flags: object::elf::SHF_ALLOC as u64 | object::elf::SHF_EXECINSTR as u64,
            };

            let offset = obj.append_section_data(section_id, &program.bytecode, 8);

            let prog_sym_id = obj.add_symbol(Symbol {
                name: program.name.as_bytes().to_vec(),
                value: offset,
                size: program.main_size as u64,
                kind: SymbolKind::Text,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(section_id),
                flags: SymbolFlags::Elf {
                    st_info: (object::elf::STB_GLOBAL << 4) | object::elf::STT_FUNC,
                    st_other: object::elf::STV_DEFAULT,
                },
            });
            symbol_ids.insert(program.name.clone(), prog_sym_id);

            let mut program_symbol_ids = symbol_ids.clone();
            for subfn in &program.subfunctions {
                let subfn_sym_id = obj.add_symbol(Symbol {
                    name: subfn.name.as_bytes().to_vec(),
                    value: offset + subfn.offset as u64,
                    size: subfn.size as u64,
                    kind: SymbolKind::Text,
                    scope: SymbolScope::Compilation,
                    weak: false,
                    section: SymbolSection::Section(section_id),
                    flags: SymbolFlags::Elf {
                        st_info: (object::elf::STB_LOCAL << 4) | object::elf::STT_FUNC,
                        st_other: object::elf::STV_DEFAULT,
                    },
                });
                if program_symbol_ids
                    .insert(subfn.name.clone(), subfn_sym_id)
                    .is_some()
                {
                    return Err(CompileError::InvalidProgram(format!(
                        "subfunction symbol '{}' conflicts with an existing ELF symbol",
                        subfn.name
                    )));
                }
            }

            for reloc in &program.relocations {
                let sym_id = *program_symbol_ids.get(&reloc.symbol_name).ok_or_else(|| {
                    CompileError::InvalidProgram(format!(
                        "program '{}' references missing ELF symbol '{}'",
                        program.name, reloc.symbol_name
                    ))
                })?;
                obj.add_relocation(
                    section_id,
                    Relocation {
                        offset: offset + reloc.insn_offset as u64,
                        symbol: sym_id,
                        addend: 0,
                        flags: RelocationFlags::Elf { r_type: 1 },
                    },
                )
                .map_err(|e| CompileError::ElfError(e.to_string()))?;
            }
        }

        for (section_id, symbol_offset, data_symbol) in pending_data_relocations {
            for reloc in &data_symbol.relocations {
                let sym_id = *symbol_ids.get(&reloc.symbol_name).ok_or_else(|| {
                    CompileError::InvalidProgram(format!(
                        "data symbol '{}' references missing ELF symbol '{}'",
                        data_symbol.name, reloc.symbol_name
                    ))
                })?;
                obj.add_relocation(
                    section_id,
                    Relocation {
                        offset: symbol_offset + reloc.offset as u64,
                        symbol: sym_id,
                        addend: 0,
                        flags: RelocationFlags::Elf { r_type: 1 },
                    },
                )
                .map_err(|e| CompileError::ElfError(e.to_string()))?;
            }
        }

        // Add the license section
        let license_section_id = obj.add_section(vec![], b"license".to_vec(), SectionKind::Data);

        // License must be null-terminated
        let mut license_data = self.license.as_bytes().to_vec();
        license_data.push(0);
        obj.append_section_data(license_section_id, &license_data, 1);

        // Write the ELF file
        obj.write()
            .map_err(|e| CompileError::ElfError(e.to_string()))
    }

    /// Check if this object uses any maps (and thus needs perf buffer support)
    pub fn has_maps(&self) -> bool {
        !self.maps.is_empty()
    }

    fn local_btf_int_name(size: u32, signed: bool) -> &'static str {
        match (size, signed) {
            (1, false) => "u8",
            (1, true) => "s8",
            (2, false) => "u16",
            (2, true) => "s16",
            (4, false) => "u32",
            (4, true) => "s32",
            (8, false) => "u64",
            (8, true) => "s64",
            _ if signed => "int",
            _ => "uint",
        }
    }

    fn sanitize_local_btf_struct_name(name: &str, size: usize, field_count: usize) -> String {
        let mut sanitized: String = name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        if sanitized.is_empty() || sanitized == "_anonymous_" {
            sanitized = format!("__anon_struct_{}_{}", size, field_count);
        }
        sanitized
    }

    fn emit_local_btf_type(
        btf: &mut BtfBuilder,
        type_info: &TypeInfo,
        fallback_size: usize,
        array_index_type: u32,
    ) -> u32 {
        match type_info {
            TypeInfo::Int { size, signed } => {
                let size = *size as u32;
                btf.add_int(Self::local_btf_int_name(size, *signed), size, *signed)
            }
            TypeInfo::Ptr { target, .. } => {
                let target_type = match target.as_ref() {
                    TypeInfo::Void | TypeInfo::Unknown => 0,
                    other => {
                        let target_fallback_size = match other {
                            TypeInfo::Void | TypeInfo::Unknown => 0,
                            _ => other.size(),
                        };
                        Self::emit_local_btf_type(
                            btf,
                            other,
                            target_fallback_size,
                            array_index_type,
                        )
                    }
                };
                btf.add_ptr(target_type)
            }
            TypeInfo::Array { element, len } => {
                let elem_fallback_size = if *len == 0 { 0 } else { fallback_size / *len };
                let elem_type =
                    Self::emit_local_btf_type(btf, element, elem_fallback_size, array_index_type);
                btf.add_array(elem_type, array_index_type, *len as u32)
            }
            TypeInfo::Struct {
                name, size, fields, ..
            } => Self::emit_local_btf_struct_type(btf, name, *size, fields, None, array_index_type),
            TypeInfo::Void | TypeInfo::Unknown => {
                if fallback_size == 0 {
                    return 0;
                }
                let byte_type = btf.add_int("u8", 1, false);
                if fallback_size == 1 {
                    byte_type
                } else {
                    btf.add_array(byte_type, array_index_type, fallback_size as u32)
                }
            }
        }
    }

    fn emit_local_btf_struct_type(
        btf: &mut BtfBuilder,
        name: &str,
        size: usize,
        fields: &[FieldInfo],
        callback_member_types: Option<&HashMap<String, u32>>,
        array_index_type: u32,
    ) -> u32 {
        let members: Vec<(String, u32, u32)> = fields
            .iter()
            .map(|field| {
                let field_type = callback_member_types
                    .and_then(|members| members.get(&field.name).copied())
                    .unwrap_or_else(|| {
                        Self::emit_local_btf_type(
                            btf,
                            &field.type_info,
                            field.size,
                            array_index_type,
                        )
                    });
                (field.name.clone(), field_type, field.offset as u32)
            })
            .collect();
        let member_refs: Vec<(&str, u32, u32)> = members
            .iter()
            .map(|(name, field_type, offset)| (name.as_str(), *field_type, *offset))
            .collect();
        let sanitized_name = Self::sanitize_local_btf_struct_name(name, size, fields.len());
        btf.add_struct_with_offsets(&sanitized_name, size as u32, &member_refs)
    }

    fn emit_local_btf_mir_type(btf: &mut BtfBuilder, ty: &MirType, array_index_type: u32) -> u32 {
        if let Some(pointee_name) = ty.bpf_kptr_pointee_name() {
            let pointee_type = btf.add_fwd(pointee_name, false);
            let tagged_type = btf.add_type_tag("__kptr", pointee_type);
            return btf.add_ptr(tagged_type);
        }

        match ty {
            MirType::I8 => btf.add_int("s8", 1, true),
            MirType::I16 => btf.add_int("s16", 2, true),
            MirType::I32 => btf.add_int("s32", 4, true),
            MirType::I64 => btf.add_int("s64", 8, true),
            MirType::U8 | MirType::Bool => btf.add_int("u8", 1, false),
            MirType::U16 => btf.add_int("u16", 2, false),
            MirType::U32 => btf.add_int("u32", 4, false),
            MirType::U64 => btf.add_int("u64", 8, false),
            MirType::Ptr { pointee, .. } => {
                let pointee_type = Self::emit_local_btf_mir_type(btf, pointee, array_index_type);
                btf.add_ptr(pointee_type)
            }
            MirType::Array { elem, len } => {
                let elem_type = Self::emit_local_btf_mir_type(btf, elem, array_index_type);
                btf.add_array(elem_type, array_index_type, *len as u32)
            }
            MirType::Struct { name, fields, .. } => {
                let mut members = Vec::with_capacity(fields.len());
                for field in fields.iter().filter(|field| !field.synthetic) {
                    let field_type =
                        Self::emit_local_btf_mir_type(btf, &field.ty, array_index_type);
                    members.push((field.name.clone(), field_type, field.offset as u32));
                }
                let member_refs: Vec<(&str, u32, u32)> = members
                    .iter()
                    .map(|(name, field_type, offset)| (name.as_str(), *field_type, *offset))
                    .collect();
                let name = name.as_deref().unwrap_or("_anonymous_");
                let sanitized_name =
                    Self::sanitize_local_btf_struct_name(name, ty.size(), fields.len());
                btf.add_struct_with_offsets(&sanitized_name, ty.size() as u32, &member_refs)
            }
            MirType::Subprogram { .. } | MirType::MapRef { .. } | MirType::Unknown => {
                let fallback_size = ty.size().max(1);
                let byte_type = btf.add_int("u8", 1, false);
                if fallback_size == 1 {
                    byte_type
                } else {
                    btf.add_array(byte_type, array_index_type, fallback_size as u32)
                }
            }
        }
    }

    fn generic_map_value_btf_type(&self, map: &EbpfMap) -> Option<&MirType> {
        let kind = map.def.map_kind()?;
        let map_ref = MapRef {
            name: map.name.clone(),
            kind,
        };
        self.programs
            .iter()
            .find_map(|program| program.generic_map_value_types.get(&map_ref))
    }

    fn generic_map_key_btf_type(&self, map: &EbpfMap) -> Option<&MirType> {
        let kind = map.def.map_kind()?;
        let map_ref = MapRef {
            name: map.name.clone(),
            kind,
        };
        self.programs
            .iter()
            .find_map(|program| program.generic_map_key_types.get(&map_ref))
    }

    fn emit_struct_ops_value_btf_type(
        btf: &mut BtfBuilder,
        value_type_name: &str,
        value_size: usize,
        callback_members_with_offsets: &[(String, u32, u32)],
        callback_member_types: &HashMap<String, u32>,
        array_index_type: u32,
    ) -> u32 {
        let mut fallback_type = || {
            let fallback_member_refs: Vec<(&str, u32, u32)> = callback_members_with_offsets
                .iter()
                .map(|(name, field_type, offset)| (name.as_str(), *field_type, *offset))
                .collect();
            btf.add_struct_with_offsets(value_type_name, value_size as u32, &fallback_member_refs)
        };
        let Ok(type_info) = KernelBtf::get().kernel_named_type_info(value_type_name) else {
            return fallback_type();
        };
        let TypeInfo::Struct { size, fields, .. } = type_info else {
            return fallback_type();
        };
        if size != value_size {
            return fallback_type();
        }
        Self::emit_local_btf_struct_type(
            btf,
            value_type_name,
            size,
            &fields,
            Some(callback_member_types),
            array_index_type,
        )
    }

    /// Generate BTF (BPF Type Format) metadata for object-local loader metadata.
    ///
    /// Today this covers:
    /// - BTF-defined maps in `.maps`
    /// - `struct_ops` value sections in `.struct_ops`
    fn generate_btf(&self) -> Option<Vec<u8>> {
        use crate::compiler::btf::BtfVarLinkage;

        let mut btf = BtfBuilder::new();
        let mut emitted_anything = false;

        // Add base int type (used as array element and index type)
        let int_type = btf.add_int("int", 4, true);

        if !self.maps.is_empty() {
            emitted_anything = true;

            // Track variable type IDs and offsets for datasec
            let mut vars: Vec<(u32, u32, u32)> = Vec::new();
            let mut offset = 0u32;

            for map in &self.maps {
                // Create __uint types for each map attribute
                // __uint(name, val) expands to: int (*name)[val]

                // type field: __uint(type, map_type_value)
                let type_ptr = btf.add_uint_type(int_type, map.def.map_type);

                // Typed schemas use __type(key, T); untyped maps keep __uint(key_size, N).
                let key_member = if let Some(key_ty) = self.generic_map_key_btf_type(map) {
                    let key_type = Self::emit_local_btf_mir_type(&mut btf, key_ty, int_type);
                    ("key", btf.add_ptr(key_type))
                } else {
                    ("key_size", btf.add_uint_type(int_type, map.def.key_size))
                };

                // Typed schemas use __type(value, T) so verifier-managed map fields
                // are visible to the kernel; untyped maps keep __uint(value_size, N).
                let value_member = if let Some(value_ty) = self.generic_map_value_btf_type(map) {
                    let value_type = Self::emit_local_btf_mir_type(&mut btf, value_ty, int_type);
                    ("value", btf.add_ptr(value_type))
                } else {
                    (
                        "value_size",
                        btf.add_uint_type(int_type, map.def.value_size),
                    )
                };

                // max_entries field: __uint(max_entries, count)
                // Note: 0 means auto-size (e.g., num_cpus for perf event arrays)
                let max_entries_ptr = btf.add_uint_type(int_type, map.def.max_entries);

                // pinning field: __uint(pinning, LIBBPF_PIN_BY_NAME) for shared maps
                let pinning_ptr = btf.add_uint_type(int_type, map.def.pinning as u32);

                // Create the anonymous map struct with pointer-sized members
                let struct_type = btf.add_btf_map_struct(&[
                    ("type", type_ptr),
                    key_member,
                    value_member,
                    ("max_entries", max_entries_ptr),
                    ("pinning", pinning_ptr),
                ]);

                // Add a variable for this map
                let var_type = btf.add_var(&map.name, struct_type, BtfVarLinkage::GlobalAlloc);

                // Size of BTF-defined map struct (5 pointers * 8 bytes = 40 bytes)
                let map_size = 40u32;
                vars.push((var_type, offset, map_size));
                offset += map_size;
            }

            // Add datasec for .maps section
            btf.add_datasec(".maps", &vars);
        }

        if let EbpfObjectKind::StructOps {
            value_type_name, ..
        } = &self.kind
        {
            let callback_proto = btf.add_func_proto(0, &[]);
            let callback_ptr_type = btf.add_ptr(callback_proto);

            for data_symbol in &self.extra_data_symbols {
                if !data_symbol.section_name.starts_with(".struct_ops") {
                    continue;
                }

                emitted_anything = true;

                let mut callback_members_with_offsets: Vec<(String, u32, u32)> = data_symbol
                    .relocations
                    .iter()
                    .filter_map(|reloc| {
                        reloc.field_name.as_deref().map(|field_name| {
                            (
                                field_name.to_string(),
                                callback_ptr_type,
                                reloc.offset as u32,
                            )
                        })
                    })
                    .collect();
                callback_members_with_offsets.sort_by_key(|(_, _, offset)| *offset);
                let callback_members: HashMap<String, u32> = callback_members_with_offsets
                    .iter()
                    .map(|(name, field_type, _)| (name.clone(), *field_type))
                    .collect();
                let value_type = Self::emit_struct_ops_value_btf_type(
                    &mut btf,
                    value_type_name,
                    data_symbol.data.len(),
                    &callback_members_with_offsets,
                    &callback_members,
                    int_type,
                );
                let var_type =
                    btf.add_var(&data_symbol.name, value_type, BtfVarLinkage::GlobalAlloc);
                btf.add_datasec(
                    &data_symbol.section_name,
                    &[(var_type, 0, data_symbol.data.len() as u32)],
                );
            }
        }

        emitted_anything.then(|| btf.build())
    }

    /// Generate map section data for BTF-defined maps
    ///
    /// For BTF-defined maps, the .maps section contains the struct with
    /// pointer-sized fields (all zeros since values are in BTF type metadata).
    #[allow(dead_code)]
    fn generate_btf_map_data(&self) -> Vec<u8> {
        let mut data = Vec::new();

        for _map in &self.maps {
            // BTF-defined map struct has 5 pointer fields = 40 bytes
            // All zeros - actual values are encoded in BTF type metadata
            data.extend_from_slice(&[0u8; 40]);
        }

        data
    }
}

impl EbpfProgram {
    pub fn parsed_program_spec(&self) -> Option<&ProgramSpec> {
        self.program_spec.as_ref()
    }

    /// Generate an ELF object file containing this program.
    pub fn to_elf(&self) -> Result<Vec<u8>, CompileError> {
        self.clone().into_object().to_elf()
    }

    /// Check if this program uses any maps (and thus needs perf buffer support)
    pub fn has_maps(&self) -> bool {
        !self.maps.is_empty()
    }

    pub fn map_compatibility_requirements(&self) -> Vec<MapCompatibilityRequirement> {
        let mut seen = HashSet::new();
        let mut requirements = Vec::new();

        for map in &self.maps {
            let Some(kind) = map.def.map_kind() else {
                continue;
            };
            if seen.insert(kind) {
                requirements.push(kind.compatibility_requirement());
            }
        }

        requirements
    }

    pub fn map_compatibility_minimum_kernel(&self) -> Option<&'static str> {
        MapCompatibilityRequirement::effective_minimum_kernel(
            &self.map_compatibility_requirements(),
        )
    }
}
