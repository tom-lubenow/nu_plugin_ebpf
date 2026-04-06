use super::*;
use std::collections::{HashMap, HashSet};

use crate::kernel_btf::TypeInfo;
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector};

fn section_name_for_program(
    prog_type: EbpfProgramType,
    target: &str,
) -> Result<String, CompileError> {
    match prog_type {
        EbpfProgramType::CgroupSkb => {
            let (_path, attach_type) = target.rsplit_once(':').ok_or_else(|| {
                CompileError::InvalidProgram(format!(
                    "invalid cgroup_skb target '{}': expected cgroup_path:ingress or cgroup_path:egress",
                    target
                ))
            })?;
            match attach_type {
                "ingress" | "egress" => Ok(format!("cgroup_skb/{attach_type}")),
                other => Err(CompileError::InvalidProgram(format!(
                    "invalid cgroup_skb attach type '{}': expected ingress or egress",
                    other
                ))),
            }
        }
        EbpfProgramType::CgroupSockAddr => {
            let (_path, attach_type) = target.rsplit_once(':').ok_or_else(|| {
                CompileError::InvalidProgram(format!(
                    "invalid cgroup_sock_addr target '{}': expected cgroup_path:attach_kind",
                    target
                ))
            })?;
            match attach_type {
                "bind4" | "bind6" | "connect4" | "connect6" | "getpeername4" | "getpeername6"
                | "getsockname4" | "getsockname6" | "sendmsg4" | "sendmsg6" | "recvmsg4"
                | "recvmsg6" => Ok(format!("cgroup/{attach_type}")),
                other => Err(CompileError::InvalidProgram(format!(
                    "invalid cgroup_sock_addr attach type '{}'",
                    other
                ))),
            }
        }
        _ => {
            if prog_type.info().section_uses_target {
                Ok(format!("{}/{}", prog_type.section_prefix(), target))
            } else {
                Ok(prog_type.section_prefix().to_string())
            }
        }
    }
}

impl EbpfProgram {
    /// Create a new eBPF program from a builder
    pub fn new(
        prog_type: EbpfProgramType,
        target: impl Into<String>,
        name: impl Into<String>,
        builder: EbpfBuilder,
    ) -> Self {
        let bytecode = builder.build();
        Self {
            prog_type,
            target: target.into(),
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
            generic_map_value_types: HashMap::new(),
        }
    }

    /// Create a new eBPF program from raw bytecode
    pub fn from_bytecode(
        prog_type: EbpfProgramType,
        target: impl Into<String>,
        name: impl Into<String>,
        bytecode: Vec<u8>,
    ) -> Self {
        let main_size = bytecode.len();
        Self {
            prog_type,
            target: target.into(),
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
            generic_map_value_types: HashMap::new(),
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
    ) -> Self {
        Self {
            prog_type,
            target: target.into(),
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
            generic_map_value_types,
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

    /// Convert this program into an object with a single program section.
    pub fn into_object(self) -> EbpfObject {
        let EbpfProgram {
            prog_type,
            target,
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
            generic_map_value_types,
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
                name,
                bytecode,
                main_size,
                relocations,
                subfunctions,
                event_schema,
                bytes_counter_key_schema,
                generic_map_value_types,
            }],
        }
    }

    /// Convert this program into its object-local program section form.
    pub fn into_program_section(self) -> EbpfProgramSection {
        EbpfProgramSection {
            section_name_override: None,
            prog_type: self.prog_type,
            target: self.target,
            name: self.name,
            bytecode: self.bytecode,
            main_size: self.main_size,
            relocations: self.relocations,
            subfunctions: self.subfunctions,
            event_schema: self.event_schema,
            bytes_counter_key_schema: self.bytes_counter_key_schema,
            generic_map_value_types: self.generic_map_value_types,
        }
    }

    /// Convert this program into a typed `struct_ops` callback section.
    pub fn into_struct_ops_callback(self, callback_name: impl Into<String>) -> EbpfProgramSection {
        let callback_name = callback_name.into();
        let mut section = self.into_program_section();
        section.section_name_override = None;
        section.prog_type = EbpfProgramType::StructOps;
        section.target = callback_name.clone();
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

        fn map_type_name(map_type: u32) -> &'static str {
            match map_type {
                x if x == BpfMapType::Hash as u32 => "Hash",
                x if x == BpfMapType::Array as u32 => "Array",
                x if x == BpfMapType::ProgArray as u32 => "ProgArray",
                x if x == BpfMapType::PerfEventArray as u32 => "PerfEventArray",
                x if x == BpfMapType::PerCpuHash as u32 => "PerCpuHash",
                x if x == BpfMapType::PerCpuArray as u32 => "PerCpuArray",
                x if x == BpfMapType::LruHash as u32 => "LruHash",
                x if x == BpfMapType::LruPerCpuHash as u32 => "LruPerCpuHash",
                x if x == BpfMapType::StackTrace as u32 => "StackTrace",
                x if x == BpfMapType::RingBuf as u32 => "RingBuf",
                _ => "Unknown",
            }
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

            match map.name.as_str() {
                RINGBUF_MAP_NAME => {
                    require_capability(program, ProgramCapability::Emit, "runtime map 'events'")?;
                    if map.def.map_type != BpfMapType::RingBuf as u32 {
                        return Err(invalid(format!(
                            "runtime map '{}' must be a RingBuf, got {}",
                            map.name,
                            map_type_name(map.def.map_type)
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
                            "runtime map '{}' must be a Hash/PerCpuHash with 8-byte keys and values",
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
                            "runtime map '{}' must be a Hash/PerCpuHash with 16-byte keys and 8-byte values",
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
                            "runtime map '{}' must be a Hash/PerCpuHash with 8-byte values",
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
                            "runtime map '{}' must be a Hash/PerCpuHash with 8-byte keys and values",
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
                            "runtime map '{}' must be a Hash/PerCpuHash with 8-byte keys and values",
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
                            map_type_name(map.def.map_type)
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
                    _ => {}
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
    pub fn with_section_name_override(mut self, section_name: impl Into<String>) -> Self {
        self.section_name_override = Some(section_name.into());
        self
    }

    pub fn section_name(&self) -> Result<String, CompileError> {
        if let Some(section_name) = &self.section_name_override {
            return Ok(section_name.clone());
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
        if self.programs.is_empty() {
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

        if matches!(self.kind, EbpfObjectKind::Program) && !self.extra_data_symbols.is_empty() {
            return Err(CompileError::InvalidProgram(
                "ordinary program objects do not yet support extra data symbols".to_string(),
            ));
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
                generic_map_value_types: program.generic_map_value_types.clone(),
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

            // Generate BTF for BTF-defined maps
            let btf_data = self.generate_btf();
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

            for subfn in &program.subfunctions {
                obj.add_symbol(Symbol {
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
            }

            for reloc in &program.relocations {
                let sym_id = *symbol_ids.get(&reloc.symbol_name).ok_or_else(|| {
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

    /// Generate BTF (BPF Type Format) metadata for BTF-defined maps
    ///
    /// This implements the libbpf BTF-defined map format where map attributes
    /// are encoded using the __uint macro pattern: int (*name)[value]
    ///
    /// The BTF represents:
    /// - An anonymous struct with pointer members
    /// - Each pointer points to an array whose size encodes the attribute value
    /// - e.g., __uint(type, 4) becomes: PTR -> ARRAY[4] -> INT
    fn generate_btf(&self) -> Vec<u8> {
        use crate::compiler::btf::BtfVarLinkage;

        let mut btf = BtfBuilder::new();

        // Add base int type (used as array element and index type)
        let int_type = btf.add_int("int", 4, true);

        // Track variable type IDs and offsets for datasec
        let mut vars: Vec<(u32, u32, u32)> = Vec::new();
        let mut offset = 0u32;

        for map in &self.maps {
            // Create __uint types for each map attribute
            // __uint(name, val) expands to: int (*name)[val]

            // type field: __uint(type, map_type_value)
            let type_ptr = btf.add_uint_type(int_type, map.def.map_type);

            // key_size field: __uint(key_size, size_value)
            let key_size_ptr = btf.add_uint_type(int_type, map.def.key_size);

            // value_size field: __uint(value_size, size_value)
            let value_size_ptr = btf.add_uint_type(int_type, map.def.value_size);

            // max_entries field: __uint(max_entries, count)
            // Note: 0 means auto-size (e.g., num_cpus for perf event arrays)
            let max_entries_ptr = btf.add_uint_type(int_type, map.def.max_entries);

            // pinning field: __uint(pinning, LIBBPF_PIN_BY_NAME) for shared maps
            let pinning_ptr = btf.add_uint_type(int_type, map.def.pinning as u32);

            // Create the anonymous map struct with pointer-sized members
            let struct_type = btf.add_btf_map_struct(&[
                ("type", type_ptr),
                ("key_size", key_size_ptr),
                ("value_size", value_size_ptr),
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

        btf.build()
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

impl StructOpsObjectBuilder {
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
                symbol_name: symbol_name.into(),
            });
        self
    }

    pub fn add_callback(mut self, program: EbpfProgram, callback_name: impl Into<String>) -> Self {
        self.object
            .programs
            .push(program.into_struct_ops_callback(callback_name));
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
        self.object
            .programs
            .push(program.into_struct_ops_callback(callback_name.clone()));
        self.value_symbol_mut()
            .relocations
            .push(ObjectDataRelocation {
                offset,
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
}

impl EbpfProgram {
    /// Generate an ELF object file containing this program.
    pub fn to_elf(&self) -> Result<Vec<u8>, CompileError> {
        self.clone().into_object().to_elf()
    }

    /// Check if this program uses any maps (and thus needs perf buffer support)
    pub fn has_maps(&self) -> bool {
        !self.maps.is_empty()
    }
}
