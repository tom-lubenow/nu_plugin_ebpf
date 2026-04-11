use std::collections::{HashMap, HashSet};

use crate::compiler::elf::ProbeContext;
use crate::compiler::mir::{
    AddressSpace, BinOpKind, CtxField, MapRef, MirFunction, MirInst, MirProgram, MirType,
    MirTypeHints, MirValue, StackSlotId, StructField, VReg,
};
use crate::kernel_btf::TypeInfo;

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

fn synthetic_bpf_sock_type() -> MirType {
    MirType::Struct {
        name: Some("bpf_sock".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "bound_dev_if".to_string(),
                ty: MirType::U32,
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "family".to_string(),
                ty: MirType::U32,
                offset: 4,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "type".to_string(),
                ty: MirType::U32,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "protocol".to_string(),
                ty: MirType::U32,
                offset: 12,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "mark".to_string(),
                ty: MirType::U32,
                offset: 16,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "priority".to_string(),
                ty: MirType::U32,
                offset: 20,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "src_port".to_string(),
                ty: MirType::U32,
                offset: 44,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "dst_port".to_string(),
                ty: MirType::U16,
                offset: 48,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "state".to_string(),
                ty: MirType::U32,
                offset: 72,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "rx_queue_mapping".to_string(),
                ty: MirType::I32,
                offset: 76,
                synthetic: false,
                bitfield: None,
            },
        ],
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
        CtxField::Pid
        | CtxField::Tid
        | CtxField::Uid
        | CtxField::Gid
        | CtxField::Cpu
        | CtxField::PacketLen
        | CtxField::PktType
        | CtxField::QueueMapping
        | CtxField::EthProtocol
        | CtxField::VlanPresent
        | CtxField::VlanTci
        | CtxField::VlanProto
        | CtxField::TcClassid
        | CtxField::NapiId
        | CtxField::WireLen
        | CtxField::GsoSegs
        | CtxField::GsoSize
        | CtxField::IngressIfindex
        | CtxField::Ifindex
        | CtxField::RxQueueIndex
        | CtxField::EgressIfindex
        | CtxField::TcIndex
        | CtxField::SkbHash
        | CtxField::UserFamily
        | CtxField::UserIp4
        | CtxField::UserPort
        | CtxField::Family
        | CtxField::SockType
        | CtxField::Protocol
        | CtxField::BoundDevIf
        | CtxField::SockMark
        | CtxField::SockPriority
        | CtxField::MsgSrcIp4
        | CtxField::RemoteIp4
        | CtxField::RemotePort
        | CtxField::LocalIp4
        | CtxField::LocalPort
        | CtxField::LircSample
        | CtxField::LircValue
        | CtxField::LircMode
        | CtxField::DeviceAccessType
        | CtxField::DeviceMajor
        | CtxField::DeviceMinor
        | CtxField::SockOp
        | CtxField::IsFullsock
        | CtxField::SockOpsSndCwnd
        | CtxField::SockOpsSrttUs
        | CtxField::SockOpsCbFlags
        | CtxField::SockState
        | CtxField::SockOpsRttMin
        | CtxField::SockOpsSndSsthresh
        | CtxField::SockOpsRcvNxt
        | CtxField::SockOpsSndNxt
        | CtxField::SockOpsSndUna
        | CtxField::SockOpsMssCache
        | CtxField::SockOpsEcnFlags
        | CtxField::SockOpsRateDelivered
        | CtxField::SockOpsRateIntervalUs
        | CtxField::SockOpsPacketsOut
        | CtxField::SockOpsRetransOut
        | CtxField::SockOpsTotalRetrans
        | CtxField::SockOpsSegsIn
        | CtxField::SockOpsDataSegsIn
        | CtxField::SockOpsSegsOut
        | CtxField::SockOpsDataSegsOut
        | CtxField::SockOpsLostOut
        | CtxField::SockOpsSackedOut
        | CtxField::SockOpsSkTxhash
        | CtxField::SockOpsSkbLen
        | CtxField::SockOpsSkbTcpFlags
        | CtxField::SysctlWrite
        | CtxField::SysctlFilePos => Some(MirType::U32),
        CtxField::Hwtstamp
        | CtxField::SockOpsSkbHwtstamp
        | CtxField::SockOpsBytesReceived
        | CtxField::SockOpsBytesAcked => Some(MirType::U64),
        CtxField::SockoptLevel
        | CtxField::SockoptOptname
        | CtxField::SockoptOptlen
        | CtxField::SockoptRetval => Some(MirType::I32),
        CtxField::Context => Some(MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        }),
        CtxField::Socket => Some(MirType::Ptr {
            pointee: Box::new(synthetic_bpf_sock_type()),
            address_space: AddressSpace::Kernel,
        }),
        CtxField::SockoptOptval | CtxField::SockoptOptvalEnd => Some(MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        }),
        CtxField::UserIp6
        | CtxField::MsgSrcIp6
        | CtxField::RemoteIp6
        | CtxField::LocalIp6
        | CtxField::SockOpsArgs => Some(MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 4,
            }),
            address_space: AddressSpace::Stack,
        }),
        CtxField::SkbCb => Some(MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 5,
            }),
            address_space: AddressSpace::Stack,
        }),
        CtxField::Data | CtxField::DataEnd => Some(MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        }),
        CtxField::Timestamp
        | CtxField::CgroupId
        | CtxField::LookupCookie
        | CtxField::SocketCookie
        | CtxField::NetnsCookie => Some(MirType::U64),
        CtxField::SocketUid => Some(MirType::U32),
        CtxField::Comm => Some(MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            }),
            address_space: AddressSpace::Stack,
        }),
        CtxField::Arg(idx) => {
            let ctx = probe_ctx?;
            if ctx.probe_type.uses_btf_trampoline() {
                let type_info = ctx.btf_arg_type_info(*idx as usize).ok().flatten()?;
                runtime_trampoline_root_type(&type_info)
            } else if ctx.probe_type.uses_raw_tracepoint_args() {
                Some(MirType::U64)
            } else if ctx.is_userspace() {
                Some(pointer_hint(AddressSpace::User))
            } else {
                None
            }
        }
        CtxField::RetVal => {
            let ctx = probe_ctx?;
            if !matches!(
                ctx.probe_type.retval_access(),
                crate::compiler::ProgramValueAccess::Trampoline
            ) {
                return None;
            }
            let type_info = ctx.btf_ret_type_info().ok().flatten()?;
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

fn stored_generic_map_value_type(ty: &MirType) -> MirType {
    match ty {
        MirType::Ptr {
            pointee,
            address_space: AddressSpace::Stack | AddressSpace::Map,
        } if matches!(
            pointee.as_ref(),
            MirType::Array { .. } | MirType::Struct { .. }
        ) =>
        {
            pointee.as_ref().clone()
        }
        _ => ty.clone(),
    }
}

pub(crate) fn infer_generic_map_value_types(
    func: &MirFunction,
    hints: &HashMap<VReg, MirType>,
    seed: Option<&HashMap<MapRef, MirType>>,
) -> HashMap<MapRef, MirType> {
    let mut value_types = seed.cloned().unwrap_or_default();
    let mut conflicts = HashSet::new();

    for inst in func
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
    {
        let MirInst::MapUpdate { map, val, .. } = inst else {
            continue;
        };
        if conflicts.contains(map) {
            continue;
        }
        let Some(value_ty) = hints.get(val).map(stored_generic_map_value_type) else {
            continue;
        };
        match value_types.get(map) {
            Some(existing) if existing != &value_ty => {
                value_types.remove(map);
                conflicts.insert(map.clone());
            }
            Some(_) => {}
            None => {
                value_types.insert(map.clone(), value_ty);
            }
        }
    }

    value_types
}

pub(crate) fn infer_instruction_def_type(
    inst: &MirInst,
    probe_ctx: Option<&ProbeContext>,
    hints: &HashMap<VReg, MirType>,
    stack_slot_hints: &HashMap<StackSlotId, MirType>,
    map_value_types: &HashMap<MapRef, MirType>,
) -> Option<(VReg, MirType, bool)> {
    match inst {
        MirInst::Copy { dst, src } => match src {
            MirValue::VReg(src_vreg) => hints.get(src_vreg).cloned().map(|ty| (*dst, ty, false)),
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
                true,
            )),
            MirValue::Const(_) => None,
        },
        MirInst::Load { dst, ty, .. } | MirInst::LoadSlot { dst, ty, .. } => {
            (!matches!(ty, MirType::Unknown)).then(|| (*dst, ty.clone(), true))
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
                        true,
                    )
                })
            })
            .or_else(|| {
                recover_ctx_field_hint(probe_ctx, field, slot.is_some()).map(|ty| (*dst, ty, true))
            }),
        MirInst::MapLookup { dst, map, .. } => Some((
            *dst,
            MirType::Ptr {
                pointee: Box::new(match map_value_types.get(map).cloned() {
                    Some(ty) => ty,
                    None => match hints.get(dst) {
                        Some(MirType::Ptr {
                            pointee,
                            address_space: AddressSpace::Map,
                        }) => pointee.as_ref().clone(),
                        _ => MirType::U8,
                    },
                }),
                address_space: AddressSpace::Map,
            },
            true,
        )),
        MirInst::LoadGlobal { dst, ty, .. } => Some((
            *dst,
            MirType::Ptr {
                pointee: Box::new(ty.clone()),
                address_space: AddressSpace::Map,
            },
            true,
        )),
        MirInst::BinOp { dst, op, lhs, rhs } if matches!(op, BinOpKind::Add | BinOpKind::Sub) => {
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
                .map(|ty| (*dst, ty, false))
        }
        MirInst::Phi { dst, args } => {
            let mut arg_types = args.iter().filter_map(|(_, vreg)| hints.get(vreg).cloned());
            let first = arg_types.next()?;
            arg_types
                .all(|ty| ty == first)
                .then_some((*dst, first, false))
        }
        _ => None,
    }
}

pub(crate) fn recover_optimized_function_type_hints(
    func: &MirFunction,
    probe_ctx: Option<&ProbeContext>,
    hints: &mut HashMap<VReg, MirType>,
    stack_slot_hints: &HashMap<StackSlotId, MirType>,
    generic_map_value_types: &HashMap<MapRef, MirType>,
) {
    let mut trusted_hints: HashSet<VReg> = HashSet::new();
    let mut changed = true;
    while changed {
        changed = false;
        let mut working_hints = hints.clone();
        let mut working_trusted = trusted_hints.clone();
        let map_value_types =
            infer_generic_map_value_types(func, &working_hints, Some(generic_map_value_types));
        for inst in func.blocks.iter().flat_map(|block| {
            block
                .instructions
                .iter()
                .chain(std::iter::once(&block.terminator))
        }) {
            let recovered = infer_instruction_def_type(
                inst,
                probe_ctx,
                &working_hints,
                stack_slot_hints,
                &map_value_types,
            )
            .map(|(dst, ty, trustworthy)| {
                let propagated = if trustworthy {
                    true
                } else {
                    match inst {
                        MirInst::Copy {
                            src: MirValue::VReg(src_vreg),
                            ..
                        } => working_trusted.contains(src_vreg),
                        MirInst::BinOp { op, lhs, rhs, .. }
                            if matches!(op, BinOpKind::Add | BinOpKind::Sub) =>
                        {
                            let lhs_trusted = match lhs {
                                MirValue::VReg(vreg) => working_trusted.contains(vreg),
                                _ => false,
                            };
                            let rhs_trusted = match rhs {
                                MirValue::VReg(vreg) => working_trusted.contains(vreg),
                                _ => false,
                            };
                            lhs_trusted || (matches!(op, BinOpKind::Add) && rhs_trusted)
                        }
                        MirInst::Phi { args, .. } => {
                            args.iter().all(|(_, vreg)| working_trusted.contains(vreg))
                        }
                        _ => false,
                    }
                };
                (dst, ty, propagated)
            });

            if let Some((dst, ty, trustworthy)) = recovered {
                let existing = working_hints.get(&dst).cloned();
                let should_update = match existing.as_ref() {
                    None => true,
                    Some(existing_ty) if existing_ty == &ty => {
                        trustworthy && !working_trusted.contains(&dst)
                    }
                    Some(_) => trustworthy,
                };
                if should_update {
                    working_hints.insert(dst, ty);
                }
                if trustworthy {
                    working_trusted.insert(dst);
                }
            }
        }
        if working_hints != *hints {
            *hints = working_hints;
            changed = true;
        }
        if working_trusted != trusted_hints {
            trusted_hints = working_trusted;
            changed = true;
        }
    }
}

pub(crate) fn recover_optimized_mir_type_hints(
    program: &MirProgram,
    probe_ctx: Option<&ProbeContext>,
    hints: &mut MirTypeHints,
) {
    recover_optimized_function_type_hints(
        &program.main,
        probe_ctx,
        &mut hints.main,
        &hints.main_stack_slots,
        &hints.generic_map_value_types,
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
        recover_optimized_function_type_hints(
            subfn,
            None,
            subfn_hints,
            subfn_stack_slot_hints,
            &hints.generic_map_value_types,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::EbpfProgramType;
    use crate::compiler::mir::StackSlotKind;
    use crate::kernel_btf::KernelBtf;

    fn recover_ctx_arg_hint(probe_ctx: &ProbeContext) -> Option<MirType> {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let arg = func.alloc_vreg();
        func.block_mut(bb0)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: arg,
                field: CtxField::Arg(0),
                slot: None,
            });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(arg)),
        };

        let mut hints = HashMap::new();
        recover_optimized_function_type_hints(
            &func,
            Some(probe_ctx),
            &mut hints,
            &HashMap::new(),
            &HashMap::new(),
        );
        hints.remove(&arg)
    }

    fn find_tp_btf_arg_candidate() -> Option<&'static str> {
        for tracepoint_name in [
            "sys_enter",
            "sys_exit",
            "sched_process_exec",
            "sched_process_fork",
        ] {
            if matches!(
                KernelBtf::get().tp_btf_arg_type_info(tracepoint_name, 0),
                Ok(Some(_))
            ) {
                return Some(tracepoint_name);
            }
        }
        None
    }

    fn find_struct_ops_arg_candidate() -> Option<(&'static str, &'static str)> {
        for (value_type_name, callback_name) in [
            ("sched_ext_ops", "select_cpu"),
            ("tcp_congestion_ops", "cong_avoid"),
            ("tcp_congestion_ops", "init"),
        ] {
            if matches!(
                KernelBtf::get().struct_ops_callback_arg_type_info(
                    value_type_name,
                    callback_name,
                    0
                ),
                Ok(Some(_))
            ) {
                return Some((value_type_name, callback_name));
            }
        }
        None
    }

    #[test]
    fn test_synthetic_bpf_sock_type_uses_uapi_offsets() {
        let MirType::Struct { fields, .. } = synthetic_bpf_sock_type() else {
            panic!("synthetic_bpf_sock_type should return a struct");
        };

        assert!(fields.iter().any(|field| field.name == "src_port"
            && field.ty == MirType::U32
            && field.offset == 44));
        assert!(fields.iter().any(|field| field.name == "dst_port"
            && field.ty == MirType::U16
            && field.offset == 48));
        assert!(
            fields.iter().any(|field| field.name == "state"
                && field.ty == MirType::U32
                && field.offset == 72)
        );
        assert!(fields.iter().any(|field| field.name == "rx_queue_mapping"
            && field.ty == MirType::I32
            && field.offset == 76));
    }

    #[test]
    fn test_recover_optimized_function_type_hints_overrides_stale_hint_chain() {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let slot = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1)),
        };

        let mut hints = HashMap::from([(v0, MirType::U32), (v1, MirType::U32)]);
        let stack_slot_hints = HashMap::from([(slot, MirType::U64)]);

        recover_optimized_function_type_hints(
            &func,
            None,
            &mut hints,
            &stack_slot_hints,
            &HashMap::new(),
        );

        let expected = MirType::Ptr {
            pointee: Box::new(MirType::U64),
            address_space: AddressSpace::Stack,
        };
        assert_eq!(hints.get(&v0), Some(&expected));
        assert_eq!(hints.get(&v1), Some(&expected));
    }

    #[test]
    fn test_recover_optimized_function_type_hints_keeps_untrusted_conflict() {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1)),
        };

        let mut hints = HashMap::from([(v0, MirType::U32), (v1, MirType::Bool)]);
        recover_optimized_function_type_hints(
            &func,
            None,
            &mut hints,
            &HashMap::new(),
            &HashMap::new(),
        );

        assert_eq!(hints.get(&v0), Some(&MirType::U32));
        assert_eq!(hints.get(&v1), Some(&MirType::Bool));
    }

    #[test]
    fn test_recover_optimized_function_type_hints_preserves_typed_map_lookup_without_local_update()
    {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let key = func.alloc_vreg();
        let lookup = func.alloc_vreg();
        let looked_up_ty = MirType::Ptr {
            pointee: Box::new(MirType::Struct {
                name: Some("path".to_string()),
                kernel_btf_type_id: None,
                fields: vec![],
            }),
            address_space: AddressSpace::Map,
        };

        func.block_mut(bb0).instructions.push(MirInst::MapLookup {
            dst: lookup,
            map: MapRef {
                name: "cached_path".to_string(),
                kind: crate::compiler::mir::MapKind::Hash,
            },
            key,
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(lookup)),
        };

        let mut hints = HashMap::from([(lookup, looked_up_ty.clone())]);
        recover_optimized_function_type_hints(
            &func,
            None,
            &mut hints,
            &HashMap::new(),
            &HashMap::new(),
        );

        assert_eq!(hints.get(&lookup), Some(&looked_up_ty));
    }

    #[test]
    fn test_recover_optimized_function_type_hints_for_list_buffer_pointer_math() {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let slot = func.alloc_stack_slot(24, 8, StackSlotKind::ListBuffer);
        let base_ptr = func.alloc_vreg();
        let elem_ptr = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: base_ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: elem_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(base_ptr),
            rhs: MirValue::Const(8),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(elem_ptr)),
        };

        let mut hints = HashMap::new();
        let stack_slot_hints = HashMap::from([(
            slot,
            MirType::Array {
                elem: Box::new(MirType::I64),
                len: 3,
            },
        )]);
        recover_optimized_function_type_hints(
            &func,
            None,
            &mut hints,
            &stack_slot_hints,
            &HashMap::new(),
        );

        assert_eq!(
            hints.get(&base_ptr),
            Some(&MirType::Ptr {
                pointee: Box::new(MirType::Array {
                    elem: Box::new(MirType::I64),
                    len: 3,
                }),
                address_space: AddressSpace::Stack,
            })
        );
        assert_eq!(
            hints.get(&elem_ptr),
            Some(&MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            })
        );
    }

    #[test]
    fn test_recover_optimized_function_type_hints_converges_with_reused_vreg_defs() {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();
        let v3 = func.alloc_vreg();
        let v4 = func.alloc_vreg();

        func.block_mut(bb0)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v1,
                field: CtxField::Data,
                slot: None,
            });
        func.block_mut(bb0)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v2,
                field: CtxField::DataEnd,
                slot: None,
            });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v3,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v1),
            rhs: MirValue::Const(2),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v4,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(v3),
            rhs: MirValue::VReg(v2),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: v4,
            if_true: bb1,
            if_false: bb2,
        };

        func.block_mut(bb1).instructions.push(MirInst::Load {
            dst: v0,
            ptr: v1,
            offset: 0,
            ty: MirType::U16,
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb2 };

        func.block_mut(bb2).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v0)),
        };

        let packet_ptr = MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        };
        let mut hints = HashMap::from([
            (v0, MirType::U16),
            (v1, packet_ptr.clone()),
            (v2, packet_ptr.clone()),
            (v3, packet_ptr.clone()),
        ]);

        recover_optimized_function_type_hints(
            &func,
            None,
            &mut hints,
            &HashMap::new(),
            &HashMap::new(),
        );

        assert_eq!(hints.get(&v0), Some(&MirType::U16));
        assert_eq!(hints.get(&v1), Some(&packet_ptr));
        assert_eq!(hints.get(&v2), Some(&packet_ptr));
        assert_eq!(hints.get(&v3), Some(&packet_ptr));
    }

    #[test]
    fn test_recover_optimized_function_type_hints_uses_tp_btf_arg_metadata() {
        let Some(tracepoint_name) = find_tp_btf_arg_candidate() else {
            return;
        };

        let expected_info = KernelBtf::get()
            .tp_btf_arg_type_info(tracepoint_name, 0)
            .expect("tp_btf arg type query should succeed")
            .expect("tp_btf arg0 should exist");
        let expected = runtime_trampoline_root_type(&expected_info)
            .expect("tp_btf arg0 should produce a MIR hint");

        let probe_ctx = ProbeContext::new(EbpfProgramType::TpBtf, tracepoint_name);
        let actual = recover_ctx_arg_hint(&probe_ctx).expect("tp_btf arg0 should recover a hint");

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_recover_optimized_function_type_hints_uses_struct_ops_arg_metadata() {
        let Some((value_type_name, callback_name)) = find_struct_ops_arg_candidate() else {
            return;
        };

        let expected_info = KernelBtf::get()
            .struct_ops_callback_arg_type_info(value_type_name, callback_name, 0)
            .expect("struct_ops arg type query should succeed")
            .expect("struct_ops arg0 should exist");
        let expected = runtime_trampoline_root_type(&expected_info)
            .expect("struct_ops arg0 should produce a MIR hint");

        let probe_ctx = ProbeContext::new_struct_ops_callback(value_type_name, callback_name);
        let actual =
            recover_ctx_arg_hint(&probe_ctx).expect("struct_ops arg0 should recover a hint");

        assert_eq!(actual, expected);
    }
}
