use std::collections::HashMap;

use crate::compiler::elf::ProbeContext;
use crate::compiler::mir::{
    AddressSpace, BinOpKind, CtxField, MirFunction, MirInst, MirProgram, MirType, MirTypeHints,
    MirValue, StackSlotId, StructField, VReg,
};
use crate::kernel_btf::{KernelBtf, TypeInfo};

fn pointer_hint(address_space: AddressSpace) -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space,
    }
}

fn byte_array_mir_type(size: usize) -> Option<MirType> {
    if size == 0 {
        return None;
    }
    Some(MirType::Array {
        elem: Box::new(MirType::U8),
        len: size,
    })
}

fn opaque_struct_mir_type(
    name: &str,
    size: usize,
    kernel_btf_type_id: Option<u32>,
) -> Option<MirType> {
    Some(MirType::Struct {
        name: Some(name.to_string()),
        kernel_btf_type_id,
        fields: vec![StructField {
            name: "__opaque".to_string(),
            ty: byte_array_mir_type(size)?,
            offset: 0,
            synthetic: false,
            bitfield: None,
        }],
    })
}

fn mir_type_from_type_info(type_info: &TypeInfo) -> Option<MirType> {
    match type_info {
        TypeInfo::Int { size, signed } => Some(match (*size, *signed) {
            (1, false) => MirType::U8,
            (1, true) => MirType::I8,
            (2, false) => MirType::U16,
            (2, true) => MirType::I16,
            (4, false) => MirType::U32,
            (4, true) => MirType::I32,
            (8, false) => MirType::U64,
            (8, true) => MirType::I64,
            _ => return None,
        }),
        TypeInfo::Ptr { target, is_user } => Some(MirType::Ptr {
            pointee: Box::new(mir_type_from_type_info(target).unwrap_or(MirType::U8)),
            address_space: if *is_user {
                AddressSpace::User
            } else {
                AddressSpace::Kernel
            },
        }),
        TypeInfo::Array { element, len } => Some(MirType::Array {
            elem: Box::new(mir_type_from_type_info(element)?),
            len: *len,
        }),
        TypeInfo::Struct {
            name,
            btf_type_id,
            fields,
            size,
        } => {
            if *size == 0 {
                return None;
            }
            if fields.is_empty() {
                return opaque_struct_mir_type(name, *size, *btf_type_id);
            }

            let mut out = Vec::with_capacity(fields.len() + 1);
            let mut cursor = 0usize;
            let mut pad_index = 0usize;
            for field in fields {
                if field.size == 0
                    || field.offset >= *size
                    || (field.offset < cursor && field.bitfield.is_none())
                {
                    continue;
                }
                if field.offset > cursor {
                    out.push(StructField {
                        name: format!("__layout_pad{}", pad_index),
                        ty: byte_array_mir_type(field.offset - cursor)?,
                        offset: cursor,
                        synthetic: false,
                        bitfield: None,
                    });
                    pad_index += 1;
                }
                let ty = mir_type_from_type_info(&field.type_info)
                    .or_else(|| byte_array_mir_type(field.size))
                    .filter(|ty| ty.size() == field.size)
                    .or_else(|| byte_array_mir_type(field.size))?;
                let field_end = field.offset.checked_add(field.size)?;
                if field_end > *size {
                    continue;
                }
                out.push(StructField {
                    name: field.name.clone(),
                    ty,
                    offset: field.offset,
                    synthetic: false,
                    bitfield: field
                        .bitfield
                        .map(|bitfield| crate::compiler::mir::BitfieldInfo {
                            bit_offset: bitfield.bit_offset,
                            bit_size: bitfield.bit_size,
                        }),
                });
                cursor = cursor.max(field_end);
            }
            if out.is_empty() {
                return opaque_struct_mir_type(name, *size, *btf_type_id);
            }
            if cursor < *size {
                out.push(StructField {
                    name: format!("__layout_pad{}", pad_index),
                    ty: byte_array_mir_type(*size - cursor)?,
                    offset: cursor,
                    synthetic: false,
                    bitfield: None,
                });
            }
            Some(MirType::Struct {
                name: Some(name.clone()),
                kernel_btf_type_id: *btf_type_id,
                fields: out,
            })
        }
        _ => None,
    }
}

fn runtime_trampoline_root_type(type_info: &TypeInfo) -> Option<MirType> {
    match type_info {
        TypeInfo::Struct { .. } | TypeInfo::Array { .. } => Some(MirType::Ptr {
            pointee: Box::new(
                mir_type_from_type_info(type_info).unwrap_or(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: type_info.size(),
                }),
            ),
            address_space: AddressSpace::Stack,
        }),
        _ => mir_type_from_type_info(type_info),
    }
}

fn recover_ctx_field_hint(
    probe_ctx: Option<&ProbeContext>,
    field: &CtxField,
    has_backing_slot: bool,
) -> Option<MirType> {
    if has_backing_slot {
        return Some(pointer_hint(AddressSpace::Stack));
    }

    match field {
        CtxField::Comm => Some(MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            }),
            address_space: AddressSpace::Stack,
        }),
        CtxField::Arg(idx) => {
            let ctx = probe_ctx?;
            if matches!(
                ctx.probe_type,
                crate::compiler::EbpfProgramType::Fentry | crate::compiler::EbpfProgramType::Fexit
            ) {
                let type_info = KernelBtf::get()
                    .function_trampoline_arg_type_info(&ctx.target, *idx as usize)
                    .ok()
                    .flatten()?;
                runtime_trampoline_root_type(&type_info)
            } else if ctx.is_userspace() {
                Some(pointer_hint(AddressSpace::User))
            } else {
                None
            }
        }
        CtxField::RetVal => {
            let ctx = probe_ctx?;
            if !matches!(ctx.probe_type, crate::compiler::EbpfProgramType::Fexit) {
                return None;
            }
            let type_info = KernelBtf::get()
                .function_trampoline_ret_type_info(&ctx.target)
                .ok()
                .flatten()?;
            runtime_trampoline_root_type(&type_info)
        }
        _ => None,
    }
}

fn recover_pointer_arith_result_hint(ty: &MirType) -> MirType {
    match ty {
        MirType::Ptr {
            pointee,
            address_space,
        } => match pointee.as_ref() {
            MirType::Array { elem, .. } => MirType::Ptr {
                pointee: Box::new(elem.as_ref().clone()),
                address_space: *address_space,
            },
            _ => ty.clone(),
        },
        _ => ty.clone(),
    }
}

fn recover_function_type_hints(
    func: &MirFunction,
    probe_ctx: Option<&ProbeContext>,
    hints: &mut HashMap<VReg, MirType>,
    stack_slot_hints: &HashMap<StackSlotId, MirType>,
) {
    let mut changed = true;
    while changed {
        changed = false;
        for inst in func.blocks.iter().flat_map(|block| {
            block
                .instructions
                .iter()
                .chain(std::iter::once(&block.terminator))
        }) {
            let recovered = match inst {
                MirInst::Copy { dst, src } => match src {
                    MirValue::VReg(src_vreg) => hints.get(src_vreg).cloned().map(|ty| (*dst, ty)),
                    MirValue::StackSlot(slot) => Some((
                        *dst,
                        stack_slot_hints
                            .get(slot)
                            .cloned()
                            .map(|ty| MirType::Ptr {
                                pointee: Box::new(ty),
                                address_space: AddressSpace::Stack,
                            })
                            .unwrap_or_else(|| pointer_hint(AddressSpace::Stack)),
                    )),
                    MirValue::Const(_) => None,
                },
                MirInst::Load { dst, ty, .. } | MirInst::LoadSlot { dst, ty, .. } => {
                    (!matches!(ty, MirType::Unknown)).then(|| (*dst, ty.clone()))
                }
                MirInst::LoadCtxField { dst, field, slot } => slot
                    .and_then(|slot| {
                        stack_slot_hints.get(&slot).cloned().map(|ty| {
                            (
                                *dst,
                                MirType::Ptr {
                                    pointee: Box::new(ty),
                                    address_space: AddressSpace::Stack,
                                },
                            )
                        })
                    })
                    .or_else(|| {
                        recover_ctx_field_hint(probe_ctx, field, slot.is_some())
                            .map(|ty| (*dst, ty))
                    }),
                MirInst::MapLookup { dst, .. } => Some((*dst, pointer_hint(AddressSpace::Map))),
                MirInst::BinOp { dst, op, lhs, rhs }
                    if matches!(op, BinOpKind::Add | BinOpKind::Sub) =>
                {
                    let lhs_ptr = match lhs {
                        MirValue::VReg(vreg) => hints.get(vreg),
                        _ => None,
                    };
                    let rhs_ptr = match rhs {
                        MirValue::VReg(vreg) => hints.get(vreg),
                        _ => None,
                    };
                    lhs_ptr
                        .filter(|ty| matches!(ty, MirType::Ptr { .. }))
                        .map(recover_pointer_arith_result_hint)
                        .or_else(|| {
                            if matches!(op, BinOpKind::Add) {
                                rhs_ptr
                                    .filter(|ty| matches!(ty, MirType::Ptr { .. }))
                                    .map(recover_pointer_arith_result_hint)
                            } else {
                                None
                            }
                        })
                        .map(|ty| (*dst, ty))
                }
                _ => None,
            };

            if let Some((dst, ty)) = recovered
                && hints.get(&dst).is_none()
            {
                hints.insert(dst, ty);
                changed = true;
            }
        }
    }
}

pub(crate) fn recover_optimized_mir_type_hints(
    program: &MirProgram,
    probe_ctx: Option<&ProbeContext>,
    hints: &mut MirTypeHints,
) {
    recover_function_type_hints(
        &program.main,
        probe_ctx,
        &mut hints.main,
        &hints.main_stack_slots,
    );
    if hints.subfunctions.len() < program.subfunctions.len() {
        hints
            .subfunctions
            .resize_with(program.subfunctions.len(), HashMap::new);
    }
    if hints.subfunction_stack_slots.len() < program.subfunctions.len() {
        hints
            .subfunction_stack_slots
            .resize_with(program.subfunctions.len(), HashMap::new);
    }
    for ((subfn, subfn_hints), subfn_stack_slot_hints) in program
        .subfunctions
        .iter()
        .zip(hints.subfunctions.iter_mut())
        .zip(hints.subfunction_stack_slots.iter())
    {
        recover_function_type_hints(subfn, None, subfn_hints, subfn_stack_slot_hints);
    }
}
