use super::*;

#[test]
fn test_string_literal_lowering_populates_buffer() {
    use crate::compiler::mir::{MirInst, StringAppendType};
    use nu_protocol::ir::DataSlice;

    let mut data = Vec::new();
    data.extend_from_slice(b"hello");
    let ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::String(DataSlice { start: 0, len: 5 }),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from(data),
        ast: vec![],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };

    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();

    let saw_literal_append = mir_program.main.blocks.iter().any(|block| {
        block.instructions.iter().any(|inst| match inst {
            MirInst::StringAppend {
                val_type: StringAppendType::Literal { bytes },
                ..
            } => bytes.starts_with(b"hello") && bytes.len() == 16 && bytes[5] == 0,
            _ => false,
        })
    });

    assert!(
        saw_literal_append,
        "Expected string literal to populate stack buffer via StringAppend"
    );
}

#[test]
fn test_emit_event_copies_buffer() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let v0 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitEvent { data: v0, size: 16 });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        v0,
        MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            }),
            address_space: AddressSpace::Stack,
        },
    );
    let mut compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types.clone());
    compiler.current_types = program_types.main.clone();
    compiler
        .prepare_function_state(
            &lir.main,
            compiler.available_regs.clone(),
            lir.main.precolored.clone(),
        )
        .unwrap();
    compiler.compile_function(&lir.main).unwrap();
    compiler.fixup_jumps().unwrap();

    // After graph coloring, VReg(0) should be assigned a register
    let data_reg = compiler
        .vreg_to_phys
        .get(&VReg(0))
        .copied()
        .expect("VReg(0) should be assigned a physical register by graph coloring");
    let saw_copy = compiler.instructions.iter().any(|insn| {
        insn.opcode == (opcode::BPF_LDX | opcode::BPF_DW | opcode::BPF_MEM)
            && insn.dst_reg == EbpfReg::R0.as_u8()
            && insn.src_reg == data_reg.as_u8()
    });

    assert!(saw_copy, "Expected buffer copy from pointer for emit");
}

#[test]
fn test_emit_event_copies_small_stack_backed_buffer() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let v0 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitEvent { data: v0, size: 4 });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        v0,
        MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 4,
            }),
            address_space: AddressSpace::Stack,
        },
    );
    let mut compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types.clone());
    compiler.current_types = program_types.main.clone();
    compiler
        .prepare_function_state(
            &lir.main,
            compiler.available_regs.clone(),
            lir.main.precolored.clone(),
        )
        .unwrap();
    compiler.compile_function(&lir.main).unwrap();
    compiler.fixup_jumps().unwrap();

    let data_reg = compiler
        .vreg_to_phys
        .get(&VReg(0))
        .copied()
        .expect("VReg(0) should be assigned a physical register");
    let saw_copy = compiler.instructions.iter().any(|insn| {
        insn.opcode == (opcode::BPF_LDX | opcode::BPF_W | opcode::BPF_MEM)
            && insn.dst_reg == EbpfReg::R0.as_u8()
            && insn.src_reg == data_reg.as_u8()
    });
    let scalar_store_from_pointer = compiler.instructions.iter().any(|insn| {
        (insn.opcode == (opcode::BPF_STX | opcode::BPF_W | opcode::BPF_MEM)
            || insn.opcode == (opcode::BPF_STX | opcode::BPF_DW | opcode::BPF_MEM))
            && insn.dst_reg == EbpfReg::R10.as_u8()
            && insn.src_reg == data_reg.as_u8()
    });

    assert!(saw_copy, "Expected 4-byte emit to copy from pointer input");
    assert!(
        !scalar_store_from_pointer,
        "Small pointer-backed emit should not store the pointer value itself"
    );
}

#[test]
fn test_emit_event_registers_bytes_schema_for_struct_payload() {
    use crate::compiler::elf::BpfFieldType;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(24, 8, StackSlotKind::Local);
    let v0 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitEvent { data: v0, size: 24 });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        v0,
        MirType::Ptr {
            pointee: Box::new(MirType::Struct {
                name: Some("opaque_path".to_string()),
                kernel_btf_type_id: None,
                fields: vec![StructField {
                    name: "__opaque".to_string(),
                    ty: MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: 24,
                    },
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                }],
            }),
            address_space: AddressSpace::Stack,
        },
    );

    let lir = lower_mir_to_lir(&program);
    let compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types);
    let result = compiler.compile().expect("struct emit should compile");
    let schema = result.event_schema.expect("expected emit schema");

    assert_eq!(schema.total_size, 24);
    assert_eq!(schema.fields.len(), 1);
    assert_eq!(schema.fields[0].name, "value");
    assert_eq!(schema.fields[0].field_type, BpfFieldType::Bytes(24));
    assert_eq!(schema.fields[0].offset, 0);
}

#[test]
fn test_emit_event_registers_typed_schema_for_struct_payload() {
    use crate::compiler::elf::BpfFieldType;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);
    let v0 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitEvent { data: v0, size: 16 });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        v0,
        MirType::Ptr {
            pointee: Box::new(MirType::Struct {
                name: Some("path".to_string()),
                kernel_btf_type_id: None,
                fields: vec![
                    StructField {
                        name: "mnt".to_string(),
                        ty: MirType::Ptr {
                            pointee: Box::new(MirType::U8),
                            address_space: AddressSpace::Kernel,
                        },
                        offset: 0,
                        synthetic: false,
                        bitfield: None,
                    },
                    StructField {
                        name: "dentry".to_string(),
                        ty: MirType::Ptr {
                            pointee: Box::new(MirType::U8),
                            address_space: AddressSpace::Kernel,
                        },
                        offset: 8,
                        synthetic: false,
                        bitfield: None,
                    },
                ],
            }),
            address_space: AddressSpace::Stack,
        },
    );

    let lir = lower_mir_to_lir(&program);
    let compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types);
    let result = compiler
        .compile()
        .expect("typed struct emit should compile");
    let schema = result.event_schema.expect("expected emit schema");

    assert_eq!(schema.total_size, 16);
    assert_eq!(schema.fields.len(), 2);
    assert_eq!(schema.fields[0].name, "mnt");
    assert_eq!(
        schema.fields[0].field_type,
        BpfFieldType::Int {
            size: 8,
            signed: false,
        }
    );
    assert_eq!(schema.fields[0].offset, 0);
    assert_eq!(schema.fields[1].name, "dentry");
    assert_eq!(
        schema.fields[1].field_type,
        BpfFieldType::Int {
            size: 8,
            signed: false,
        }
    );
    assert_eq!(schema.fields[1].offset, 8);
}

#[test]
fn test_emit_event_preserves_nested_field_schemas() {
    use crate::compiler::elf::BpfFieldType;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(12, 8, StackSlotKind::Local);
    let v0 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitEvent { data: v0, size: 12 });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let inner_ty = MirType::Struct {
        name: Some("inner".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "id".to_string(),
                ty: MirType::U32,
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "tag".to_string(),
                ty: MirType::U8,
                offset: 4,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "__layout_pad0".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 3,
                },
                offset: 5,
                synthetic: true,
                bitfield: None,
            },
        ],
    };

    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        v0,
        MirType::Ptr {
            pointee: Box::new(MirType::Struct {
                name: Some("outer".to_string()),
                kernel_btf_type_id: None,
                fields: vec![
                    StructField {
                        name: "inner".to_string(),
                        ty: inner_ty.clone(),
                        offset: 0,
                        synthetic: false,
                        bitfield: None,
                    },
                    StructField {
                        name: "nums".to_string(),
                        ty: MirType::Array {
                            elem: Box::new(MirType::U16),
                            len: 2,
                        },
                        offset: 8,
                        synthetic: false,
                        bitfield: None,
                    },
                ],
            }),
            address_space: AddressSpace::Stack,
        },
    );

    let lir = lower_mir_to_lir(&program);
    let compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types);
    let result = compiler
        .compile()
        .expect("nested typed struct emit should compile");
    let schema = result.event_schema.expect("expected emit schema");

    assert_eq!(schema.total_size, 12);
    assert_eq!(schema.fields.len(), 2);
    assert_eq!(schema.fields[0].name, "inner");
    assert_eq!(schema.fields[0].field_type, BpfFieldType::Bytes(8));
    assert_eq!(
        schema.fields[0].value_schema,
        Some(crate::compiler::CounterKeySchema::Record {
            name: Some("inner".to_string()),
            fields: vec![
                crate::compiler::CounterKeySchemaField {
                    name: "id".to_string(),
                    schema: crate::compiler::CounterKeySchema::Int {
                        size: 4,
                        signed: false,
                    },
                    offset: 0,
                    bitfield: None,
                },
                crate::compiler::CounterKeySchemaField {
                    name: "tag".to_string(),
                    schema: crate::compiler::CounterKeySchema::Int {
                        size: 1,
                        signed: false,
                    },
                    offset: 4,
                    bitfield: None,
                },
            ],
            total_size: 8,
        })
    );
    assert_eq!(schema.fields[1].name, "nums");
    assert_eq!(schema.fields[1].field_type, BpfFieldType::Bytes(4));
    assert_eq!(
        schema.fields[1].value_schema,
        Some(crate::compiler::CounterKeySchema::Array {
            elem: Box::new(crate::compiler::CounterKeySchema::Int {
                size: 2,
                signed: false,
            }),
            len: 2,
        })
    );
}

#[test]
fn test_emit_record_schema_mismatch_errors() {
    use crate::compiler::CompileError;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(2),
    });

    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitRecord {
            fields: vec![RecordFieldDef {
                name: "a".to_string(),
                value: v0,
                ty: MirType::I64,
            }],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitRecord {
            fields: vec![RecordFieldDef {
                name: "b".to_string(),
                value: v1,
                ty: MirType::I64,
            }],
        });

    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None);
    match result {
        Err(CompileError::UnsupportedInstruction(msg)) => {
            assert!(
                msg.contains("schema mismatch"),
                "Unexpected error message: {msg}"
            );
        }
        Ok(_) => panic!("Expected schema mismatch error, got Ok"),
        Err(e) => panic!("Expected schema mismatch error, got: {e:?}"),
    }
}

#[test]
fn test_emit_record_preserves_nested_struct_field_schema() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);
    let v0 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitRecord {
            fields: vec![RecordFieldDef {
                name: "path".to_string(),
                value: v0,
                ty: MirType::Struct {
                    name: Some("path".to_string()),
                    kernel_btf_type_id: None,
                    fields: vec![
                        StructField {
                            name: "mnt".to_string(),
                            ty: MirType::Ptr {
                                pointee: Box::new(MirType::U8),
                                address_space: AddressSpace::Kernel,
                            },
                            offset: 0,
                            synthetic: false,
                            bitfield: None,
                        },
                        StructField {
                            name: "dentry".to_string(),
                            ty: MirType::Ptr {
                                pointee: Box::new(MirType::U8),
                                address_space: AddressSpace::Kernel,
                            },
                            offset: 8,
                            synthetic: false,
                            bitfield: None,
                        },
                    ],
                },
            }],
        });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        v0,
        MirType::Ptr {
            pointee: Box::new(MirType::Struct {
                name: Some("path".to_string()),
                kernel_btf_type_id: None,
                fields: vec![
                    StructField {
                        name: "mnt".to_string(),
                        ty: MirType::Ptr {
                            pointee: Box::new(MirType::U8),
                            address_space: AddressSpace::Kernel,
                        },
                        offset: 0,
                        synthetic: false,
                        bitfield: None,
                    },
                    StructField {
                        name: "dentry".to_string(),
                        ty: MirType::Ptr {
                            pointee: Box::new(MirType::U8),
                            address_space: AddressSpace::Kernel,
                        },
                        offset: 8,
                        synthetic: false,
                        bitfield: None,
                    },
                ],
            }),
            address_space: AddressSpace::Stack,
        },
    );

    let lir = lower_mir_to_lir(&program);
    let compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types);
    let result = compiler
        .compile()
        .expect("emit record with nested struct field should compile");
    assert_eq!(
        result.event_schema,
        Some(crate::compiler::EventSchema {
            fields: vec![crate::compiler::SchemaField {
                name: "path".to_string(),
                field_type: BpfFieldType::Bytes(16),
                value_schema: Some(crate::compiler::CounterKeySchema::Record {
                    name: Some("path".to_string()),
                    fields: vec![
                        crate::compiler::CounterKeySchemaField {
                            name: "mnt".to_string(),
                            schema: crate::compiler::CounterKeySchema::Int {
                                size: 8,
                                signed: false,
                            },
                            offset: 0,
                            bitfield: None,
                        },
                        crate::compiler::CounterKeySchemaField {
                            name: "dentry".to_string(),
                            schema: crate::compiler::CounterKeySchema::Int {
                                size: 8,
                                signed: false,
                            },
                            offset: 8,
                            bitfield: None,
                        },
                    ],
                    total_size: 16,
                }),
                offset: 0,
                bitfield: None,
            }],
            total_size: 16,
        })
    );
}

#[test]
fn test_string_counter_map_emitted() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let v0 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: STRING_COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key: v0,
        val: v0,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    let map = result
        .maps
        .iter()
        .find(|m| m.name == STRING_COUNTER_MAP_NAME)
        .expect("Expected string counter map");
    assert_eq!(map.def.key_size, 16);
}

#[test]
fn test_counter_map_emits_per_cpu_kind() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::PerCpuHash,
        },
        key,
        val: key,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let result = compile_mir_to_ebpf(&program, None).expect("counter map should compile");

    let map = result
        .maps
        .iter()
        .find(|m| m.name == COUNTER_MAP_NAME)
        .expect("expected counters map");
    assert_eq!(
        map.def.map_type,
        crate::compiler::elf::BpfMapType::PerCpuHash as u32
    );
}

#[test]
fn test_counter_map_kind_conflict_rejected() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key0 = func.alloc_vreg();
    let key1 = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key0,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key1,
        src: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key: key0,
        val: key0,
        flags: 0,
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::PerCpuHash,
        },
        key: key1,
        val: key1,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected kind conflict"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("conflicting kinds"),
                "unexpected error message: {msg}"
            );
        }
    }
}

#[test]
fn test_bytes_counter_map_emits_struct_key_size() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(24, 8, StackSlotKind::Local);
    let key = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: BYTES_COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key,
        val: key,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        key,
        MirType::Ptr {
            pointee: Box::new(MirType::Struct {
                name: Some("opaque_path".to_string()),
                kernel_btf_type_id: None,
                fields: vec![StructField {
                    name: "__opaque".to_string(),
                    ty: MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: 24,
                    },
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                }],
            }),
            address_space: AddressSpace::Stack,
        },
    );

    let compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types);
    let result = compiler
        .compile()
        .expect("bytes counter map with struct key should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == BYTES_COUNTER_MAP_NAME)
        .expect("expected bytes counter map");
    assert_eq!(map.def.key_size, 24);
    assert_eq!(map.def.value_size, 8);
    assert_eq!(
        result.bytes_counter_key_schema,
        Some(crate::compiler::CounterKeySchema::Bytes { size: 24 })
    );
}

#[test]
fn test_bytes_counter_map_rejects_mixed_key_schemas() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let bytes_slot = func.alloc_stack_slot(8, 1, StackSlotKind::Local);
    let struct_slot = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let bytes_key = func.alloc_vreg();
    let struct_key = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: bytes_key,
        src: MirValue::StackSlot(bytes_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: BYTES_COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key: bytes_key,
        val: bytes_key,
        flags: 0,
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: struct_key,
        src: MirValue::StackSlot(struct_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: BYTES_COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key: struct_key,
        val: struct_key,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        bytes_key,
        MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 8,
            }),
            address_space: AddressSpace::Stack,
        },
    );
    program_types.main.insert(
        struct_key,
        MirType::Ptr {
            pointee: Box::new(MirType::Struct {
                name: Some("pair".to_string()),
                kernel_btf_type_id: None,
                fields: vec![StructField {
                    name: "value".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                }],
            }),
            address_space: AddressSpace::Stack,
        },
    );

    let compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types);
    match compiler.compile() {
        Ok(_) => panic!("expected bytes counter key schema mismatch"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("bytes_counters key schema mismatch"),
                "unexpected error message: {msg}"
            );
        }
    }
}

#[test]
fn test_bytes_counter_map_preserves_struct_record_schema() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);
    let key = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: BYTES_COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key,
        val: key,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        key,
        MirType::Ptr {
            pointee: Box::new(MirType::Struct {
                name: Some("path".to_string()),
                kernel_btf_type_id: None,
                fields: vec![
                    StructField {
                        name: "mnt".to_string(),
                        ty: MirType::Ptr {
                            pointee: Box::new(MirType::U8),
                            address_space: AddressSpace::Kernel,
                        },
                        offset: 0,
                        synthetic: false,
                        bitfield: None,
                    },
                    StructField {
                        name: "dentry".to_string(),
                        ty: MirType::Ptr {
                            pointee: Box::new(MirType::U8),
                            address_space: AddressSpace::Kernel,
                        },
                        offset: 8,
                        synthetic: false,
                        bitfield: None,
                    },
                ],
            }),
            address_space: AddressSpace::Stack,
        },
    );

    let compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types);
    let result = compiler
        .compile()
        .expect("bytes counter map with typed struct key should compile");

    assert_eq!(
        result.bytes_counter_key_schema,
        Some(crate::compiler::CounterKeySchema::Record {
            name: Some("path".to_string()),
            fields: vec![
                crate::compiler::CounterKeySchemaField {
                    name: "mnt".to_string(),
                    schema: crate::compiler::CounterKeySchema::Int {
                        size: 8,
                        signed: false,
                    },
                    offset: 0,
                    bitfield: None,
                },
                crate::compiler::CounterKeySchemaField {
                    name: "dentry".to_string(),
                    schema: crate::compiler::CounterKeySchema::Int {
                        size: 8,
                        signed: false,
                    },
                    offset: 8,
                    bitfield: None,
                },
            ],
            total_size: 16,
        })
    );
}

#[test]
fn test_counter_map_rejects_stack_struct_pointer_key() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(24, 8, StackSlotKind::Local);
    let key = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key,
        val: key,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        key,
        MirType::Ptr {
            pointee: Box::new(MirType::Struct {
                name: Some("opaque_path".to_string()),
                kernel_btf_type_id: None,
                fields: vec![StructField {
                    name: "__opaque".to_string(),
                    ty: MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: 24,
                    },
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                }],
            }),
            address_space: AddressSpace::Stack,
        },
    );

    let compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types);
    match compiler.compile() {
        Ok(_) => panic!("expected aggregate counter key rejection"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("aggregate byte-buffer keys must use bytes_counters"),
                "unexpected error message: {msg}"
            );
        }
    }
}

#[test]
fn test_counter_map_rejects_non_hash_kind() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(9),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Array,
        },
        key,
        val: key,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected kind rejection"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("Hash/PerCpuHash"),
                "unexpected error message: {msg}"
            );
        }
    }
}

#[test]
fn test_map_lookup_compiles_and_emits_generic_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "custom_lookup".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("map lookup should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == "custom_lookup")
        .expect("expected generic map definition");
    assert_eq!(map.def.key_size, 8);
    assert_eq!(map.def.value_size, 8);
    assert!(
        result
            .relocations
            .iter()
            .any(|r| r.symbol_name == "custom_lookup")
    );

    let has_lookup_helper = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == opcode::CALL
            && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                == BpfHelper::MapLookupElem as i32
    });
    assert!(
        has_lookup_helper,
        "expected bpf_map_lookup_elem helper call"
    );
}

#[test]
fn test_lru_hash_lookup_compiles_and_emits_generic_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "custom_lru_lookup".to_string(),
            kind: MapKind::LruHash,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("lru map lookup should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == "custom_lru_lookup")
        .expect("expected generic map definition");
    assert_eq!(
        map.def.map_type,
        crate::compiler::elf::BpfMapType::LruHash as u32
    );
    assert_eq!(map.def.key_size, 8);
    assert_eq!(map.def.value_size, 8);
}

#[test]
fn test_lpm_trie_lookup_compiles_and_emits_generic_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "custom_lpm_lookup".to_string(),
            kind: MapKind::LpmTrie,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("lpm trie lookup should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == "custom_lpm_lookup")
        .expect("expected generic map definition");
    assert_eq!(
        map.def.map_type,
        crate::compiler::elf::BpfMapType::LpmTrie as u32
    );
    assert_eq!(map.def.key_size, 8);
    assert_eq!(map.def.value_size, 8);
    assert_eq!(map.def.map_flags, 1);
}

#[test]
fn test_map_update_compiles_and_emits_generic_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let val = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(42),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val,
        src: MirValue::Const(99),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: "custom_update".to_string(),
            kind: MapKind::Hash,
        },
        key,
        val,
        flags: 1,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("map update should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == "custom_update")
        .expect("expected generic map definition");
    assert_eq!(map.def.key_size, 8);
    assert_eq!(map.def.value_size, 8);
    assert!(
        result
            .relocations
            .iter()
            .any(|r| r.symbol_name == "custom_update")
    );

    let has_update_helper = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == opcode::CALL
            && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                == BpfHelper::MapUpdateElem as i32
    });
    assert!(
        has_update_helper,
        "expected bpf_map_update_elem helper call"
    );
}

#[test]
fn test_map_delete_compiles_and_emits_generic_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(11),
    });
    func.block_mut(entry).instructions.push(MirInst::MapDelete {
        map: MapRef {
            name: "custom_delete".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("map delete should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == "custom_delete")
        .expect("expected generic map definition");
    assert_eq!(map.def.key_size, 8);
    assert_eq!(map.def.value_size, 8);
    assert!(
        result
            .relocations
            .iter()
            .any(|r| r.symbol_name == "custom_delete")
    );

    let has_delete_helper = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == opcode::CALL
            && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                == BpfHelper::MapDeleteElem as i32
    });
    assert!(
        has_delete_helper,
        "expected bpf_map_delete_elem helper call"
    );
}

#[test]
fn test_map_delete_rejects_array_maps() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapDelete {
        map: MapRef {
            name: "array_delete".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected array map delete rejection, got Ok"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("array map kind") || msg.contains("Array"),
                "unexpected error: {msg}"
            );
        }
    }
}

#[test]
fn test_tail_call_compiles_and_emits_prog_array_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let idx = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(3),
    });
    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "tail_targets".to_string(),
            kind: MapKind::ProgArray,
        },
        index: MirValue::VReg(idx),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("tail call should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == "tail_targets")
        .expect("expected prog array map");
    assert_eq!(
        map.def.map_type,
        crate::compiler::elf::BpfMapType::ProgArray as u32
    );
    assert!(
        result
            .relocations
            .iter()
            .any(|r| r.symbol_name == "tail_targets")
    );

    let has_tail_call_helper = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == opcode::CALL
            && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                == BpfHelper::TailCall as i32
    });
    assert!(has_tail_call_helper, "expected bpf_tail_call helper call");
}

#[test]
fn test_tail_call_rejects_non_prog_array_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "bad_tail_map".to_string(),
            kind: MapKind::Hash,
        },
        index: MirValue::Const(0),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected non-prog-array map error, got Ok"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("ProgArray") || msg.contains("prog array"),
                "unexpected error: {msg}"
            );
        }
    }
}

#[test]
fn test_helper_call_rejects_more_than_five_args() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let mut args = Vec::new();
    for n in 0..6 {
        let v = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v,
            src: MirValue::Const(n),
        });
        args.push(MirValue::VReg(v));
    }
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 9999, // Unknown helper still follows generic 5-arg limit
            args,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected argument-limit error, got Ok"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("at most 5 arguments"),
                "unexpected error: {msg}"
            );
        }
    }
}

#[test]
fn test_kfunc_call_with_explicit_btf_id_compiles() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let cgid = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let level = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ptr,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: level,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };
    func.block_mut(call).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_cgroup_ancestor".to_string(),
        btf_id: Some(321),
        args: vec![ptr, level],
    });
    func.block_mut(call).terminator = MirInst::Jump { target: release };
    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cgroup_release".to_string(),
            btf_id: None,
            args: vec![ptr],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("kfunc call should compile");
    let has_kfunc_call = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == opcode::CALL
            && ((chunk[1] >> 4) & 0x0f) == 2
            && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) == 321
    });
    assert!(has_kfunc_call, "expected BPF_PSEUDO_KFUNC_CALL bytecode");
}

#[test]
fn test_kfunc_task_release_compiles_with_copied_cond_and_join() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond0 = func.alloc_vreg();
    let cond1 = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let then_val = func.alloc_vreg();
    let else_val = func.alloc_vreg();
    let result = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond0,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond1,
        src: MirValue::VReg(cond0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cond1,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).instructions.push(MirInst::Copy {
        dst: then_val,
        src: MirValue::Const(0),
    });
    func.block_mut(release).terminator = MirInst::Jump { target: join };

    func.block_mut(done).instructions.push(MirInst::Copy {
        dst: else_val,
        src: MirValue::Const(0),
    });
    func.block_mut(done).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: result,
        args: vec![(release, then_val), (done, else_val)],
    });
    func.block_mut(join).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    compile_mir_to_ebpf(&program, None)
        .expect("expected copied null-check guard to preserve kfunc release semantics");
}

#[test]
fn test_kfunc_task_release_compiles_with_negated_cond() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let negated = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::UnaryOp {
        dst: negated,
        op: UnaryOpKind::Not,
        src: MirValue::VReg(cond),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: negated,
        if_true: done,
        if_false: release,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    compile_mir_to_ebpf(&program, None)
        .expect("expected negated null-check guard to preserve kfunc release semantics");
}

#[test]
fn test_kfunc_call_rejects_unknown_signature() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let arg = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: arg,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "definitely_not_a_known_kfunc".to_string(),
        btf_id: Some(1),
        args: vec![arg],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected unknown-kfunc error, got Ok"),
        Err(err) => {
            let msg = err.to_string();
            assert!(msg.contains("unknown kfunc"), "unexpected error: {msg}");
        }
    }
}

#[test]
fn test_compile_sockmap_helper_with_loaded_map_fd() {
    use crate::compiler::elf::BpfMapType;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_sockmap".to_string(),
            kind: MapKind::SockMap,
        },
    });
    func.block_mut(entry).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkRedirectMap as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::VReg(map),
            MirValue::Const(7),
            MirValue::Const(0),
        ],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let compiled =
        compile_mir_to_ebpf(&program, Some(&probe_ctx)).expect("sockmap helper should compile");

    assert!(compiled.maps.iter().any(|map| {
        map.name == "demo_sockmap" && map.def.map_type == BpfMapType::SockMap as u32
    }));
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_sockmap"),
        "expected sockmap relocation"
    );
}

#[test]
fn test_compile_ringbuf_query_helper_with_loaded_map_fd() {
    use crate::compiler::elf::BpfMapType;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_ringbuf".to_string(),
            kind: MapKind::RingBuf,
        },
    });
    func.block_mut(entry).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RingbufQuery as u32,
        args: vec![MirValue::VReg(map), MirValue::Const(0)],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let compiled = compile_mir_to_ebpf(&program, None).expect("ringbuf helper should compile");

    assert!(compiled.maps.iter().any(|map| {
        map.name == "demo_ringbuf" && map.def.map_type == BpfMapType::RingBuf as u32
    }));
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_ringbuf"),
        "expected ringbuf relocation"
    );
}

#[test]
fn test_compile_perf_event_output_helper_with_loaded_map_fd() {
    use crate::compiler::elf::BpfMapType;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);
    let ctx = func.alloc_vreg();
    let map = func.alloc_vreg();
    let data = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_perf_events".to_string(),
            kind: MapKind::PerfEventArray,
        },
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::PerfEventOutput as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::VReg(map),
            MirValue::Const(0),
            MirValue::VReg(data),
            MirValue::Const(16),
        ],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_v4_connect");
    let compiled = compile_mir_to_ebpf(&program, Some(&probe_ctx))
        .expect("perf_event_output helper should compile");

    assert!(compiled.maps.iter().any(|map| {
        map.name == "demo_perf_events" && map.def.map_type == BpfMapType::PerfEventArray as u32
    }));
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_perf_events"),
        "expected perf-event map relocation"
    );
}

#[test]
fn test_compile_get_stackid_helper_with_loaded_map_fd() {
    use crate::compiler::elf::BpfMapType;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_stacks".to_string(),
            kind: MapKind::StackTrace,
        },
    });
    func.block_mut(entry).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetStackId as u32,
        args: vec![MirValue::VReg(ctx), MirValue::VReg(map), MirValue::Const(0)],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_v4_connect");
    let compiled =
        compile_mir_to_ebpf(&program, Some(&probe_ctx)).expect("get_stackid helper should compile");

    assert!(compiled.maps.iter().any(|map| {
        map.name == "demo_stacks" && map.def.map_type == BpfMapType::StackTrace as u32
    }));
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_stacks"),
        "expected stack-trace map relocation"
    );
}

#[test]
fn test_compile_tail_call_helper_with_loaded_map_fd() {
    use crate::compiler::elf::BpfMapType;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_tail_targets".to_string(),
            kind: MapKind::ProgArray,
        },
    });
    func.block_mut(entry).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TailCall as u32,
        args: vec![MirValue::VReg(ctx), MirValue::VReg(map), MirValue::Const(0)],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_v4_connect");
    let compiled =
        compile_mir_to_ebpf(&program, Some(&probe_ctx)).expect("tail_call helper should compile");

    assert!(compiled.maps.iter().any(|map| {
        map.name == "demo_tail_targets" && map.def.map_type == BpfMapType::ProgArray as u32
    }));
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_tail_targets"),
        "expected prog-array map relocation"
    );
}

#[test]
fn test_compile_map_push_helper_with_loaded_queue_map_fd() {
    use crate::compiler::elf::BpfMapType;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let map = func.alloc_vreg();
    let value = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_queue".to_string(),
            kind: MapKind::Queue,
        },
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: value,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::MapPushElem as u32,
        args: vec![MirValue::VReg(map), MirValue::VReg(value), MirValue::Const(0)],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let compiled =
        compile_mir_to_ebpf(&program, None).expect("map_push helper with local queue should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_queue")
        .expect("expected queue map");
    assert_eq!(map.def.map_type, BpfMapType::Queue as u32);
    assert_eq!(map.def.value_size, 8);
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_queue"),
        "expected queue relocation"
    );
}
