use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::instruction::unknown_kfunc_signature_message;

impl<'a> TypeInference<'a> {
    fn active_sched_ext_callback(&self) -> Option<&str> {
        let ctx = self.probe_ctx.as_ref()?;
        if ctx.probe_type != EbpfProgramType::StructOps {
            return None;
        }
        if ctx.struct_ops_value_type_name.as_deref() != Some("sched_ext_ops") {
            return None;
        }
        Some(ctx.target.as_str())
    }

    fn sched_ext_callback_is_sleepable(callback: &str) -> bool {
        super::super::elf::struct_ops_callback_is_sleepable("sched_ext_ops", callback)
    }

    fn sched_ext_kfunc_allowed_callbacks(kfunc: &str) -> Option<&'static [&'static str]> {
        match kfunc {
            "scx_bpf_dispatch_nr_slots"
            | "scx_bpf_dsq_move_to_local"
            | "scx_bpf_dispatch_cancel"
            | "scx_bpf_dsq_move"
            | "scx_bpf_dsq_move_vtime"
            | "scx_bpf_dsq_move_set_slice"
            | "scx_bpf_dsq_move_set_vtime" => Some(&["dispatch"]),
            "scx_bpf_reenqueue_local" => Some(&["cpu_release"]),
            "scx_bpf_select_cpu_dfl" => Some(&["select_cpu", "enqueue"]),
            "scx_bpf_select_cpu_and" => Some(&["select_cpu", "enqueue"]),
            "scx_bpf_dsq_insert" | "scx_bpf_dsq_insert_vtime" => {
                Some(&["select_cpu", "enqueue", "dispatch"])
            }
            _ => None,
        }
    }

    fn format_sched_ext_callback_list(callbacks: &[&str]) -> String {
        match callbacks {
            [] => String::new(),
            [only] => format!("sched_ext_ops.{only}"),
            [left, right] => format!("sched_ext_ops.{left} or sched_ext_ops.{right}"),
            _ => {
                let mut names = callbacks
                    .iter()
                    .map(|callback| format!("sched_ext_ops.{callback}"))
                    .collect::<Vec<_>>();
                let last = names.pop().unwrap();
                format!("{}, or {}", names.join(", "), last)
            }
        }
    }

    fn validate_sched_ext_kfunc_callback_context(&self, kfunc: &str, errors: &mut Vec<TypeError>) {
        let Some(active_callback) = self.active_sched_ext_callback() else {
            return;
        };
        if kfunc == "scx_bpf_create_dsq" && !Self::sched_ext_callback_is_sleepable(active_callback)
        {
            errors.push(TypeError::new(format!(
                "kfunc '{}' is only valid in sleepable sched_ext_ops callbacks, not sched_ext_ops.{}",
                kfunc, active_callback
            )));
            return;
        }
        let Some(allowed_callbacks) = Self::sched_ext_kfunc_allowed_callbacks(kfunc) else {
            return;
        };
        if allowed_callbacks.contains(&active_callback) {
            return;
        }
        let allowed = Self::format_sched_ext_callback_list(allowed_callbacks);
        errors.push(TypeError::new(format!(
            "kfunc '{}' is only valid in {}, not sched_ext_ops.{}",
            kfunc, allowed, active_callback
        )));
    }

    pub(super) fn required_program_capability(inst: &MirInst) -> Option<ProgramCapability> {
        match inst {
            MirInst::ReadStr {
                user_space: true, ..
            } => Some(ProgramCapability::ReadUserString),
            MirInst::ReadStr {
                user_space: false, ..
            } => Some(ProgramCapability::ReadKernelString),
            MirInst::LoadCtxField {
                field: CtxField::KStack | CtxField::UStack,
                ..
            } => Some(ProgramCapability::StackTraces),
            MirInst::EmitEvent { .. } | MirInst::EmitRecord { .. } => Some(ProgramCapability::Emit),
            MirInst::Histogram { .. } => Some(ProgramCapability::Histograms),
            MirInst::StartTimer | MirInst::StopTimer { .. } => Some(ProgramCapability::Timers),
            MirInst::CallKfunc { .. } => Some(ProgramCapability::KfuncCalls),
            MirInst::TailCall { .. } => Some(ProgramCapability::TailCalls),
            MirInst::MapLookup { map, .. }
            | MirInst::MapUpdate { map, .. }
            | MirInst::MapDelete { map, .. } => match map.name.as_str() {
                COUNTER_MAP_NAME | STRING_COUNTER_MAP_NAME | BYTES_COUNTER_MAP_NAME => {
                    Some(ProgramCapability::Counters)
                }
                HISTOGRAM_MAP_NAME => Some(ProgramCapability::Histograms),
                TIMESTAMP_MAP_NAME => Some(ProgramCapability::Timers),
                _ => Some(ProgramCapability::GenericMaps),
            },
            _ => None,
        }
    }

    pub(super) fn validate_program_capability_for_info(
        inst: &MirInst,
        program: &ProgramTypeInfo,
        errors: &mut Vec<TypeError>,
    ) {
        let Some(required) = Self::required_program_capability(inst) else {
            return;
        };
        if program.supported_capabilities.contains(&required) {
            return;
        }
        errors.push(TypeError::new(format!(
            "{} programs do not support {}",
            program.canonical_prefix,
            required.description()
        )));
    }

    pub(super) fn validate_types(
        &self,
        func: &MirFunction,
        types: &HashMap<VReg, MirType>,
        errors: &mut Vec<TypeError>,
    ) {
        let list_caps = self.compute_list_caps(func);
        let value_ranges = self.compute_value_ranges(func, types, &list_caps);
        let stack_bounds = self.compute_stack_bounds(func, types, &value_ranges);
        let slot_sizes: HashMap<StackSlotId, i64> = func
            .stack_slots
            .iter()
            .map(|slot| (slot.id, slot.size as i64))
            .collect();

        for block in &func.blocks {
            for inst in &block.instructions {
                self.validate_inst(
                    inst,
                    types,
                    &value_ranges,
                    &stack_bounds,
                    &slot_sizes,
                    errors,
                );
            }
            self.validate_inst(
                &block.terminator,
                types,
                &value_ranges,
                &stack_bounds,
                &slot_sizes,
                errors,
            );
        }
    }

    pub(super) fn validate_inst(
        &self,
        inst: &MirInst,
        types: &HashMap<VReg, MirType>,
        value_ranges: &HashMap<VReg, ValueRange>,
        stack_bounds: &HashMap<VReg, StackBounds>,
        slot_sizes: &HashMap<StackSlotId, i64>,
        errors: &mut Vec<TypeError>,
    ) {
        if let Some(ctx) = self.probe_ctx.as_ref() {
            Self::validate_program_capability_for_info(inst, ctx.probe_type.info(), errors);
        }

        match inst {
            MirInst::BinOp { op, lhs, rhs, .. } => {
                let lhs_ty = self.mir_type_for_value(lhs, types);
                let rhs_ty = self.mir_type_for_value(rhs, types);
                let lhs_ptr = Self::mir_ptr_space(&lhs_ty);
                let rhs_ptr = Self::mir_ptr_space(&rhs_ty);

                match op {
                    BinOpKind::Eq | BinOpKind::Ne => {
                        if lhs_ptr.is_some() || rhs_ptr.is_some() {
                            match (lhs_ptr, rhs_ptr) {
                                (Some(lhs_space), Some(rhs_space)) => {
                                    if lhs_space != rhs_space {
                                        errors.push(TypeError::new(format!(
                                            "pointer comparison requires same address space (lhs={:?}, rhs={:?})",
                                            lhs_space, rhs_space
                                        )));
                                    }
                                }
                                (Some(_), None) => {
                                    if !Self::is_const_zero(rhs) {
                                        errors.push(TypeError::new(
                                            "pointer comparison only supports null (0) constants"
                                                .to_string(),
                                        ));
                                    }
                                }
                                (None, Some(_)) => {
                                    if !Self::is_const_zero(lhs) {
                                        errors.push(TypeError::new(
                                            "pointer comparison only supports null (0) constants"
                                                .to_string(),
                                        ));
                                    }
                                }
                                _ => {}
                            }
                        } else if !Self::mir_is_numeric(&lhs_ty) || !Self::mir_is_numeric(&rhs_ty) {
                            errors.push(TypeError::new(format!(
                                "comparison expects numeric types, got {:?} and {:?}",
                                lhs_ty, rhs_ty
                            )));
                        }
                    }
                    BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge => {
                        if lhs_ptr.is_some() || rhs_ptr.is_some() {
                            match (lhs_ptr, rhs_ptr) {
                                (Some(lhs_space), Some(rhs_space))
                                    if lhs_space == AddressSpace::Packet
                                        && rhs_space == AddressSpace::Packet => {}
                                _ => errors.push(TypeError::new(
                                    "ordering comparisons on pointers are not supported"
                                        .to_string(),
                                )),
                            }
                        } else if !Self::mir_is_numeric(&lhs_ty) || !Self::mir_is_numeric(&rhs_ty) {
                            errors.push(TypeError::new(format!(
                                "comparison expects numeric types, got {:?} and {:?}",
                                lhs_ty, rhs_ty
                            )));
                        }
                    }
                    BinOpKind::Add | BinOpKind::Sub => {
                        let is_add = matches!(op, BinOpKind::Add);
                        match (lhs_ptr, rhs_ptr) {
                            (Some(_), Some(_)) => {
                                errors.push(TypeError::new(
                                    "pointer + pointer arithmetic is not supported".to_string(),
                                ));
                            }
                            (Some(space), None) => {
                                if !Self::mir_is_numeric(&rhs_ty) {
                                    errors.push(TypeError::new(format!(
                                        "pointer arithmetic expects numeric offset, got {:?}",
                                        rhs_ty
                                    )));
                                } else if let Err(msg) = self.pointer_arith_check(
                                    space,
                                    self.stack_bounds_for_value(lhs, stack_bounds),
                                    rhs,
                                    is_add,
                                    value_ranges,
                                ) {
                                    errors.push(TypeError::new(msg));
                                }
                            }
                            (None, Some(space)) => {
                                if !is_add {
                                    errors.push(TypeError::new(
                                        "numeric - pointer is not supported".to_string(),
                                    ));
                                } else if !Self::mir_is_numeric(&lhs_ty) {
                                    errors.push(TypeError::new(format!(
                                        "pointer arithmetic expects numeric offset, got {:?}",
                                        lhs_ty
                                    )));
                                } else if let Err(msg) = self.pointer_arith_check(
                                    space,
                                    self.stack_bounds_for_value(rhs, stack_bounds),
                                    lhs,
                                    true,
                                    value_ranges,
                                ) {
                                    errors.push(TypeError::new(msg));
                                }
                            }
                            (None, None) => {
                                if !Self::mir_is_numeric(&lhs_ty) || !Self::mir_is_numeric(&rhs_ty)
                                {
                                    errors.push(TypeError::new(format!(
                                        "arithmetic expects numeric types, got {:?} and {:?}",
                                        lhs_ty, rhs_ty
                                    )));
                                }
                            }
                        }
                    }
                    BinOpKind::Mul
                    | BinOpKind::Div
                    | BinOpKind::Mod
                    | BinOpKind::And
                    | BinOpKind::Or
                    | BinOpKind::Xor
                    | BinOpKind::Shl
                    | BinOpKind::Shr => {
                        if lhs_ptr.is_some() || rhs_ptr.is_some() {
                            errors.push(TypeError::new(
                                "bitwise/arithmetic ops on pointers are not supported".to_string(),
                            ));
                        } else if !Self::mir_is_numeric(&lhs_ty) || !Self::mir_is_numeric(&rhs_ty) {
                            errors.push(TypeError::new(format!(
                                "operation expects numeric types, got {:?} and {:?}",
                                lhs_ty, rhs_ty
                            )));
                        }
                    }
                }
            }

            MirInst::UnaryOp { op, src, .. } => {
                let src_ty = self.mir_type_for_value(src, types);
                if Self::mir_ptr_space(&src_ty).is_some() {
                    errors.push(TypeError::new(format!(
                        "unary {:?} is not supported for pointers",
                        op
                    )));
                } else if !Self::mir_is_numeric(&src_ty) {
                    errors.push(TypeError::new(format!(
                        "unary {:?} expects numeric type, got {:?}",
                        op, src_ty
                    )));
                }
            }

            MirInst::ReadStr {
                ptr, user_space, ..
            } => {
                let ptr_ty = self.mir_type_for_vreg(*ptr, types);
                match ptr_ty {
                    MirType::Ptr { address_space, .. } => {
                        let expected = if *user_space {
                            AddressSpace::User
                        } else {
                            AddressSpace::Kernel
                        };
                        if address_space != expected {
                            errors.push(TypeError::new(format!(
                                "read_str expects {:?} pointer, got {:?}",
                                expected, address_space
                            )));
                        }
                    }
                    _ => {
                        errors.push(TypeError::new(format!(
                            "read_str expects pointer, got {:?}",
                            ptr_ty
                        )));
                    }
                }
            }

            MirInst::EmitEvent { data, size } => {
                let data_ty = self.mir_type_for_vreg(*data, types);
                if !Self::mir_is_stack_or_map_ptr(&data_ty) && *size > 8 {
                    match data_ty {
                        MirType::Ptr { .. } => errors.push(TypeError::new(format!(
                            "emit event of size {} expects stack/map pointer, got {:?}",
                            size, data_ty
                        ))),
                        _ => errors.push(TypeError::new(format!(
                            "emit event of size {} expects stack/map pointer, got {:?}",
                            size, data_ty
                        ))),
                    }
                }
            }

            MirInst::EmitRecord { fields } => {
                for field in fields {
                    let value_ty = self.mir_type_for_vreg(field.value, types);
                    if Self::mir_requires_pointer_value(&field.ty) {
                        if !Self::mir_is_stack_or_map_ptr(&value_ty) {
                            errors.push(TypeError::new(format!(
                                "record field '{}' expects pointer value, got {:?}",
                                field.name, value_ty
                            )));
                        }
                    } else if !Self::mir_is_numeric(&value_ty) {
                        errors.push(TypeError::new(format!(
                            "record field '{}' expects numeric value, got {:?}",
                            field.name, value_ty
                        )));
                    }
                }
            }

            MirInst::RecordStore { val, ty, .. } => {
                let value_ty = self.mir_type_for_value(val, types);
                if Self::mir_requires_pointer_value(ty) {
                    if !Self::mir_is_stack_or_map_ptr(&value_ty) {
                        errors.push(TypeError::new(format!(
                            "record store expects pointer for {:?}, got {:?}",
                            ty, value_ty
                        )));
                    }
                } else if !Self::mir_is_numeric(&value_ty) {
                    errors.push(TypeError::new(format!(
                        "record store expects numeric value for {:?}, got {:?}",
                        ty, value_ty
                    )));
                }
            }

            MirInst::MapUpdate { map, key, val, .. } => {
                let key_ty = self.mir_type_for_vreg(*key, types);
                if map.name == STRING_COUNTER_MAP_NAME || map.name == BYTES_COUNTER_MAP_NAME {
                    match key_ty {
                        MirType::Ptr { address_space, .. }
                            if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {
                        }
                        _ => errors.push(TypeError::new(format!(
                            "map '{}' expects stack/map byte-buffer pointer key, got {:?}",
                            map.name, key_ty
                        ))),
                    }
                } else {
                    match key_ty {
                        MirType::Ptr { address_space, .. }
                            if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {
                        }
                        _ if Self::mir_is_numeric(&key_ty) => {}
                        _ => errors.push(TypeError::new(format!(
                            "map '{}' key expects numeric or stack/map pointer, got {:?}",
                            map.name, key_ty
                        ))),
                    }
                }

                let val_ty = self.mir_type_for_vreg(*val, types);
                match val_ty {
                    MirType::Ptr { address_space, .. }
                        if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {}
                    _ if Self::mir_is_numeric(&val_ty) => {}
                    _ => errors.push(TypeError::new(format!(
                        "map '{}' value expects numeric or stack/map pointer, got {:?}",
                        map.name, val_ty
                    ))),
                }
            }

            MirInst::MapDelete { map, key } => {
                let key_ty = self.mir_type_for_vreg(*key, types);
                if map.name == STRING_COUNTER_MAP_NAME || map.name == BYTES_COUNTER_MAP_NAME {
                    match key_ty {
                        MirType::Ptr { address_space, .. }
                            if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {
                        }
                        _ => errors.push(TypeError::new(format!(
                            "map '{}' expects stack/map byte-buffer pointer key, got {:?}",
                            map.name, key_ty
                        ))),
                    }
                } else {
                    match key_ty {
                        MirType::Ptr { address_space, .. }
                            if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {
                        }
                        _ if Self::mir_is_numeric(&key_ty) => {}
                        _ => errors.push(TypeError::new(format!(
                            "map '{}' key expects numeric or stack/map pointer, got {:?}",
                            map.name, key_ty
                        ))),
                    }
                }
            }

            MirInst::Histogram { value } => {
                let value_ty = self.mir_type_for_vreg(*value, types);
                if !Self::mir_is_numeric(&value_ty) {
                    errors.push(TypeError::new(format!(
                        "histogram expects numeric value, got {:?}",
                        value_ty
                    )));
                }
            }

            MirInst::ListPush { list, item } => {
                let list_ty = self.mir_type_for_vreg(*list, types);
                if !matches!(
                    list_ty,
                    MirType::Ptr {
                        address_space: AddressSpace::Stack,
                        ..
                    }
                ) {
                    errors.push(TypeError::new(format!(
                        "list expects stack pointer, got {:?}",
                        list_ty
                    )));
                }
                let item_ty = self.mir_type_for_vreg(*item, types);
                if !Self::mir_is_numeric(&item_ty) {
                    errors.push(TypeError::new(format!(
                        "list push expects numeric item, got {:?}",
                        item_ty
                    )));
                }
            }

            MirInst::ListLen { list, .. } => {
                let list_ty = self.mir_type_for_vreg(*list, types);
                if !matches!(
                    list_ty,
                    MirType::Ptr {
                        address_space: AddressSpace::Stack,
                        ..
                    }
                ) {
                    errors.push(TypeError::new(format!(
                        "list expects stack pointer, got {:?}",
                        list_ty
                    )));
                }
            }

            MirInst::ListGet { list, idx, .. } => {
                let list_ty = self.mir_type_for_vreg(*list, types);
                if !matches!(
                    list_ty,
                    MirType::Ptr {
                        address_space: AddressSpace::Stack,
                        ..
                    }
                ) {
                    errors.push(TypeError::new(format!(
                        "list expects stack pointer, got {:?}",
                        list_ty
                    )));
                }
                let idx_ty = self.mir_type_for_value(idx, types);
                if !Self::mir_is_numeric(&idx_ty) {
                    errors.push(TypeError::new(format!(
                        "list index expects numeric type, got {:?}",
                        idx_ty
                    )));
                }
            }

            MirInst::StringAppend {
                dst_len,
                val,
                val_type,
                ..
            } => {
                let len_ty = self.mir_type_for_vreg(*dst_len, types);
                if !Self::mir_is_numeric(&len_ty) {
                    errors.push(TypeError::new(format!(
                        "string append length expects numeric type, got {:?}",
                        len_ty
                    )));
                }
                if matches!(val_type, StringAppendType::Integer) {
                    let val_ty = self.mir_type_for_value(val, types);
                    if !Self::mir_is_numeric(&val_ty) {
                        errors.push(TypeError::new(format!(
                            "string append integer expects numeric type, got {:?}",
                            val_ty
                        )));
                    }
                }
            }

            MirInst::IntToString { dst_len, val, .. } => {
                let len_ty = self.mir_type_for_vreg(*dst_len, types);
                if !Self::mir_is_numeric(&len_ty) {
                    errors.push(TypeError::new(format!(
                        "int to string length expects numeric type, got {:?}",
                        len_ty
                    )));
                }
                let val_ty = self.mir_type_for_vreg(*val, types);
                if !Self::mir_is_numeric(&val_ty) {
                    errors.push(TypeError::new(format!(
                        "int to string expects numeric value, got {:?}",
                        val_ty
                    )));
                }
            }

            MirInst::Branch { cond, .. } => {
                let cond_ty = self.mir_type_for_vreg(*cond, types);
                if !Self::mir_is_numeric(&cond_ty) && Self::mir_ptr_space(&cond_ty).is_none() {
                    errors.push(TypeError::new(format!(
                        "branch condition expects numeric or pointer, got {:?}",
                        cond_ty
                    )));
                }
            }

            MirInst::TailCall { prog_map, index } => {
                if prog_map.kind != MapKind::ProgArray {
                    errors.push(TypeError::new(format!(
                        "tail call requires ProgArray map kind, got {:?} for '{}'",
                        prog_map.kind, prog_map.name
                    )));
                }
                let idx_ty = self.mir_type_for_value(index, types);
                if !Self::mir_is_numeric(&idx_ty) {
                    errors.push(TypeError::new(format!(
                        "tail call index expects numeric type, got {:?}",
                        idx_ty
                    )));
                }
            }

            MirInst::CallHelper { helper, args, .. } => {
                if let Some(sig) = HelperSignature::for_id(*helper) {
                    if args.len() < sig.min_args || args.len() > sig.max_args {
                        errors.push(TypeError::new(format!(
                            "helper {} expects {}..={} arguments, got {}",
                            helper,
                            sig.min_args,
                            sig.max_args,
                            args.len()
                        )));
                    }
                    for (idx, arg) in args.iter().take(sig.max_args.min(5)).enumerate() {
                        let arg_ty = self.mir_type_for_value(arg, types);
                        match sig.arg_kind(idx) {
                            HelperArgKind::Scalar => {
                                if !Self::mir_is_numeric(&arg_ty) {
                                    errors.push(TypeError::new(format!(
                                        "helper {} arg{} expects scalar, got {:?}",
                                        helper, idx, arg_ty
                                    )));
                                }
                            }
                            HelperArgKind::Pointer => {
                                let is_known_zero = matches!(
                                    self.value_range_for(arg, value_ranges),
                                    ValueRange::Known { min: 0, max: 0 }
                                );
                                if !matches!(arg_ty, MirType::Ptr { .. })
                                    && !(is_known_zero
                                        && Self::helper_pointer_arg_allows_const_zero(*helper, idx))
                                {
                                    errors.push(TypeError::new(format!(
                                        "helper {} arg{} expects pointer, got {:?}",
                                        helper, idx, arg_ty
                                    )));
                                }
                            }
                        }
                    }
                    self.validate_helper_semantics(
                        *helper,
                        args,
                        types,
                        value_ranges,
                        stack_bounds,
                        slot_sizes,
                        errors,
                    );
                } else if args.len() > 5 {
                    errors.push(TypeError::new(
                        "BPF helpers support at most 5 arguments".to_string(),
                    ));
                }
            }

            MirInst::CallKfunc { kfunc, args, .. } => {
                let Some(sig) = KfuncSignature::for_name_or_kernel_btf(kfunc) else {
                    errors.push(TypeError::new(unknown_kfunc_signature_message(kfunc)));
                    return;
                };
                self.validate_sched_ext_kfunc_callback_context(kfunc, errors);
                if args.len() < sig.min_args || args.len() > sig.max_args {
                    errors.push(TypeError::new(format!(
                        "kfunc '{}' expects {}..={} arguments, got {}",
                        kfunc,
                        sig.min_args,
                        sig.max_args,
                        args.len()
                    )));
                }
                if args.len() > 5 {
                    errors.push(TypeError::new(
                        "BPF kfunc calls support at most 5 arguments".to_string(),
                    ));
                }
                for (idx, arg) in args.iter().take(sig.max_args.min(5)).enumerate() {
                    let arg_ty = self.mir_type_for_vreg(*arg, types);
                    match sig.arg_kind(idx) {
                        KfuncArgKind::Scalar => {
                            if !Self::mir_is_numeric(&arg_ty) {
                                errors.push(TypeError::new(format!(
                                    "kfunc '{}' arg{} expects scalar, got {:?}",
                                    kfunc, idx, arg_ty
                                )));
                            }
                        }
                        KfuncArgKind::Pointer => match arg_ty {
                            MirType::Ptr { address_space, .. } => {
                                let requires_stack =
                                    Self::kfunc_pointer_arg_requires_stack(kfunc, idx);
                                if requires_stack && address_space != AddressSpace::Stack {
                                    errors.push(TypeError::new(format!(
                                        "kfunc '{}' arg{} expects stack pointer, got {:?}",
                                        kfunc, idx, address_space
                                    )));
                                }
                                if Self::kfunc_pointer_arg_requires_kernel(kfunc, idx)
                                    && address_space != AddressSpace::Kernel
                                {
                                    errors.push(TypeError::new(format!(
                                        "kfunc '{}' arg{} expects kernel pointer, got {:?}",
                                        kfunc, idx, address_space
                                    )));
                                }
                                if Self::kfunc_pointer_arg_requires_user(kfunc, idx)
                                    && address_space != AddressSpace::User
                                {
                                    errors.push(TypeError::new(format!(
                                        "kfunc '{}' arg{} expects user pointer, got {:?}",
                                        kfunc, idx, address_space
                                    )));
                                }
                                if Self::kfunc_pointer_arg_requires_stack_or_map(kfunc, idx)
                                    && !matches!(
                                        address_space,
                                        AddressSpace::Stack | AddressSpace::Map
                                    )
                                {
                                    errors.push(TypeError::new(format!(
                                        "kfunc '{}' arg{} expects stack or map pointer, got {:?}",
                                        kfunc, idx, address_space
                                    )));
                                }
                                if !requires_stack
                                    && address_space == AddressSpace::Stack
                                    && Self::kfunc_pointer_arg_requires_stack_slot_base(kfunc, idx)
                                {
                                    let is_base = stack_bounds
                                        .get(arg)
                                        .is_some_and(|bounds| bounds.min == 0 && bounds.max == 0);
                                    if !is_base {
                                        errors.push(TypeError::new(format!(
                                            "kfunc '{}' arg{} expects stack slot base pointer",
                                            kfunc, idx
                                        )));
                                    }
                                }
                            }
                            _ => {
                                let allows_zero =
                                    Self::kfunc_pointer_arg_allows_const_zero(kfunc, idx)
                                        && matches!(
                                            self.value_range_for(
                                                &MirValue::VReg(*arg),
                                                value_ranges
                                            ),
                                            ValueRange::Known { min: 0, max: 0 }
                                        );
                                if !allows_zero {
                                    if Self::kfunc_pointer_arg_allows_const_zero(kfunc, idx) {
                                        errors.push(TypeError::new(format!(
                                            "kfunc '{}' arg{} expects null (0) or pointer, got {:?}",
                                            kfunc, idx, arg_ty
                                        )));
                                    } else {
                                        errors.push(TypeError::new(format!(
                                            "kfunc '{}' arg{} expects pointer, got {:?}",
                                            kfunc, idx, arg_ty
                                        )));
                                    }
                                }
                            }
                        },
                    }
                }
                self.validate_kfunc_semantics(
                    kfunc,
                    args,
                    types,
                    value_ranges,
                    stack_bounds,
                    errors,
                );
            }

            MirInst::CallSubfn { args, .. } => {
                if args.len() > 5 {
                    errors.push(TypeError::new(
                        "BPF subfunctions support at most 5 arguments".to_string(),
                    ));
                }
            }

            _ => {}
        }
    }

    pub(super) fn pointer_arith_check(
        &self,
        space: AddressSpace,
        base_bounds: Option<&StackBounds>,
        offset: &MirValue,
        is_add: bool,
        value_ranges: &HashMap<VReg, ValueRange>,
    ) -> Result<(), String> {
        match space {
            AddressSpace::Stack => {
                if Self::const_value(offset).is_some() {
                    return Ok(());
                }
                let Some(bounds) = base_bounds else {
                    return Err("stack pointer arithmetic requires constant offsets".to_string());
                };
                match self.value_range_for(offset, value_ranges) {
                    ValueRange::Known { min, max } => {
                        if min < 0 {
                            return Err("stack pointer arithmetic requires non-negative offsets"
                                .to_string());
                        }
                        let (new_min, new_max) = if is_add {
                            (bounds.min + min, bounds.max + max)
                        } else {
                            (bounds.min - max, bounds.max - min)
                        };
                        if new_min < 0 || new_max > bounds.limit {
                            return Err(format!(
                                "stack pointer arithmetic offset range [{}..{}] exceeds bounds [0..{}]",
                                new_min, new_max, bounds.limit
                            ));
                        }
                        Ok(())
                    }
                    ValueRange::Unknown | ValueRange::Unset => Err(
                        "stack pointer arithmetic requires constant or bounded offsets".to_string(),
                    ),
                }
            }
            AddressSpace::Map => Ok(()),
            AddressSpace::Kernel | AddressSpace::User | AddressSpace::Packet => {
                match self.value_range_for(offset, value_ranges) {
                    ValueRange::Known { min, .. } if min >= 0 => Ok(()),
                    ValueRange::Known { .. } => Err(format!(
                        "{:?} pointer arithmetic requires non-negative offsets",
                        space
                    )),
                    ValueRange::Unknown | ValueRange::Unset => Err(format!(
                        "{:?} pointer arithmetic requires constant or bounded non-negative offsets",
                        space
                    )),
                }
            }
        }
    }
}
