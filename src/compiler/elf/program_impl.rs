use super::*;

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
            relocations: Vec::new(),
            subfunctions: Vec::new(),
            event_schema: None,
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
            relocations: Vec::new(),
            subfunctions: Vec::new(),
            event_schema: None,
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
        relocations: Vec<MapRelocation>,
        subfunctions: Vec<SubfunctionSymbol>,
        event_schema: Option<EventSchema>,
    ) -> Self {
        Self {
            prog_type,
            target: target.into(),
            name: name.into(),
            bytecode,
            main_size,
            license: "GPL".to_string(),
            maps,
            relocations,
            subfunctions,
            event_schema,
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
    pub fn section_name(&self) -> String {
        format!("{}/{}", self.prog_type.section_prefix(), self.target)
    }

    /// Generate an ELF object file containing this program
    pub fn to_elf(&self) -> Result<Vec<u8>, CompileError> {
        use std::collections::HashMap;

        let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

        // Track map symbol IDs for relocations
        let mut map_symbols: HashMap<String, object::write::SymbolId> = HashMap::new();

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
                map_symbols.insert(map.name.clone(), sym_id);
            }

            // Generate BTF for BTF-defined maps
            let btf_data = self.generate_btf();
            let btf_section_id = obj.add_section(vec![], b".BTF".to_vec(), SectionKind::Metadata);
            obj.append_section_data(btf_section_id, &btf_data, 1);
        }

        // Create the program section (e.g., "kprobe/sys_clone")
        let section_name = self.section_name();
        let section_id = obj.add_section(
            vec![], // No segment
            section_name.as_bytes().to_vec(),
            SectionKind::Text,
        );

        // Set section flags for eBPF
        let section = obj.section_mut(section_id);
        section.flags = SectionFlags::Elf {
            sh_flags: object::elf::SHF_ALLOC as u64 | object::elf::SHF_EXECINSTR as u64,
        };

        // Add the bytecode to the section
        let offset = obj.append_section_data(section_id, &self.bytecode, 8);

        // Add a symbol for the program (must be GLOBAL with DEFAULT visibility for libbpf/Aya)
        obj.add_symbol(Symbol {
            name: self.name.as_bytes().to_vec(),
            value: offset,
            size: self.main_size as u64,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage, // GLOBAL binding
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::Elf {
                st_info: (object::elf::STB_GLOBAL << 4) | object::elf::STT_FUNC,
                st_other: object::elf::STV_DEFAULT,
            },
        });

        // Add symbols for subfunctions to support BPF-to-BPF call relocation
        for subfn in &self.subfunctions {
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

        // Add relocations for map references
        for reloc in &self.relocations {
            if let Some(&sym_id) = map_symbols.get(&reloc.map_name) {
                // BPF uses R_BPF_64_64 relocation type (value = 1)
                obj.add_relocation(
                    section_id,
                    Relocation {
                        offset: (offset + reloc.insn_offset as u64),
                        symbol: sym_id,
                        addend: 0,
                        flags: RelocationFlags::Elf {
                            r_type: 1, // R_BPF_64_64
                        },
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

    /// Check if this program uses any maps (and thus needs perf buffer support)
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
