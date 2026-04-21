use super::*;
use crate::compiler::ProgramIntrinsic;
use crate::compiler::elf::{MessageAdjustMode, PacketAdjustMode};
use crate::compiler::instruction::{
    BpfHelper, kfunc_pointer_arg_fixed_size, kfunc_pointer_arg_requires_stack_slot_base,
};
use crate::compiler::mir::AddressSpace;

#[derive(Debug, Clone)]
pub(super) struct ScalarKfuncOutArgWriteback {
    slot: StackSlotId,
    source_var: VarId,
    scalar_ty: MirType,
    original_arg_vreg: VReg,
}

impl<'a> HirToMirLowering<'a> {
    pub(super) fn aggregate_call_value_type<'b>(ty: &'b MirType) -> Option<&'b MirType> {
        match ty {
            MirType::Array { .. } | MirType::Struct { .. } => Some(ty),
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } if matches!(
                pointee.as_ref(),
                MirType::Array { .. } | MirType::Struct { .. }
            ) =>
            {
                Some(pointee.as_ref())
            }
            _ => None,
        }
    }

    pub(super) fn aggregate_call_value_byte_array_len(ty: &MirType) -> Option<usize> {
        match ty {
            ty if ty.byte_array_len().is_some() => ty.byte_array_len(),
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } => pointee.byte_array_len(),
            _ => None,
        }
    }

    pub(super) fn literal_string_arg(
        &self,
        reg: RegId,
        context: &str,
    ) -> Result<String, CompileError> {
        self.get_metadata(reg)
            .and_then(|m| m.literal_string.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{context} requires a compile-time string literal"
                ))
            })
    }

    pub(super) fn lower_probe_read_string(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        ptr_vreg: VReg,
        user_space: bool,
        aligned_len: usize,
    ) -> Result<(), CompileError> {
        let slot = self
            .func
            .alloc_stack_slot(aligned_len, 8, StackSlotKind::StringBuffer);
        let string_ty = MirType::Array {
            elem: Box::new(MirType::U8),
            len: aligned_len,
        };
        self.record_stack_slot_type(slot, string_ty.clone());

        let slot_ptr_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: slot_ptr_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            slot_ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(string_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        self.vreg_type_hints.insert(
            ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: if user_space {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                },
            },
        );

        let raw_len_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: raw_len_vreg,
            helper: if user_space {
                BpfHelper::ProbeReadUserStr as u32
            } else {
                BpfHelper::ProbeReadKernelStr as u32
            },
            args: vec![
                MirValue::VReg(slot_ptr_vreg),
                MirValue::Const(aligned_len as i64),
                MirValue::VReg(ptr_vreg),
            ],
        });
        self.vreg_type_hints.insert(raw_len_vreg, MirType::I64);

        let has_content_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: has_content_vreg,
            op: BinOpKind::Gt,
            lhs: MirValue::VReg(raw_len_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(has_content_vreg, MirType::Bool);

        let len_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(len_vreg, MirType::U64);
        let len_ok_block = self.func.alloc_block();
        let len_zero_block = self.func.alloc_block();
        let continue_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: has_content_vreg,
            if_true: len_ok_block,
            if_false: len_zero_block,
        });

        self.current_block = len_ok_block;
        self.emit(MirInst::BinOp {
            dst: len_vreg,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(raw_len_vreg),
            rhs: MirValue::Const(1),
        });
        self.terminate(MirInst::Jump {
            target: continue_block,
        });

        self.current_block = len_zero_block;
        self.emit(MirInst::Copy {
            dst: len_vreg,
            src: MirValue::Const(0),
        });
        self.terminate(MirInst::Jump {
            target: continue_block,
        });

        self.current_block = continue_block;
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            dst_vreg,
            MirType::Ptr {
                pointee: Box::new(string_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );

        let meta = self.get_or_create_metadata(src_dst);
        meta.string_slot = Some(slot);
        meta.string_len_vreg = Some(len_vreg);
        meta.string_len_bound = Some(aligned_len.saturating_sub(1));
        meta.field_type = Some(string_ty);
        Ok(())
    }

    pub(super) fn parse_generic_map_kind(kind: &str) -> Option<MapKind> {
        match kind {
            "hash" => Some(MapKind::Hash),
            "array" => Some(MapKind::Array),
            "cgroup-array" | "cgroup_array" | "cgrouparray" => Some(MapKind::CgroupArray),
            "queue" => Some(MapKind::Queue),
            "stack" => Some(MapKind::Stack),
            "bloom-filter" | "bloom_filter" | "bloomfilter" => Some(MapKind::BloomFilter),
            "lpm-trie" | "lpm_trie" | "lpmtrie" => Some(MapKind::LpmTrie),
            "lru-hash" | "lru_hash" | "lruhash" => Some(MapKind::LruHash),
            "per-cpu-hash" | "percpu-hash" | "per_cpu_hash" => Some(MapKind::PerCpuHash),
            "per-cpu-array" | "percpu-array" | "per_cpu_array" => Some(MapKind::PerCpuArray),
            "lru-per-cpu-hash" | "lru-percpu-hash" | "lru_per_cpu_hash" | "lrupercpuhash" => {
                Some(MapKind::LruPerCpuHash)
            }
            "devmap" | "dev-map" | "dev_map" => Some(MapKind::DevMap),
            "devmap-hash" | "devmap_hash" | "devmaphash" | "dev-map-hash" | "dev_map_hash" => {
                Some(MapKind::DevMapHash)
            }
            "cpumap" | "cpu-map" | "cpu_map" => Some(MapKind::CpuMap),
            "xskmap" | "xsk-map" | "xsk_map" => Some(MapKind::XskMap),
            "sock-map" | "sock_map" | "sockmap" => Some(MapKind::SockMap),
            "sock-hash" | "sock_hash" | "sockhash" => Some(MapKind::SockHash),
            "sk-storage" | "sk_storage" | "skstorage" => Some(MapKind::SkStorage),
            "inode-storage" | "inode_storage" | "inodestorage" => Some(MapKind::InodeStorage),
            "task-storage" | "task_storage" | "taskstorage" => Some(MapKind::TaskStorage),
            "cgrp-storage" | "cgrp_storage" | "cgrpstorage" | "cgroup-storage"
            | "cgroup_storage" | "cgroupstorage" => Some(MapKind::CgrpStorage),
            _ => None,
        }
    }

    fn is_generic_data_map_kind(kind: MapKind) -> bool {
        matches!(
            kind,
            MapKind::Hash
                | MapKind::Array
                | MapKind::Queue
                | MapKind::Stack
                | MapKind::LpmTrie
                | MapKind::LruHash
                | MapKind::PerCpuHash
                | MapKind::PerCpuArray
                | MapKind::LruPerCpuHash
                | MapKind::SockMap
                | MapKind::SockHash
        )
    }

    pub(super) fn generic_map_kind_arg(&self, context: &str) -> Result<MapKind, CompileError> {
        let Some((_, reg)) = self.named_args.get("kind") else {
            return Ok(MapKind::Hash);
        };
        let kind = self.literal_string_arg(*reg, &format!("{context} --kind"))?;
        match Self::parse_generic_map_kind(&kind) {
            Some(kind) if Self::is_generic_data_map_kind(kind) => Ok(kind),
            Some(MapKind::CgroupArray) => Err(CompileError::UnsupportedInstruction(format!(
                "{context} --kind {kind} is reserved for cgroup membership helper-calls; pass a literal map name to bpf_skb_under_cgroup or bpf_current_task_under_cgroup instead"
            ))),
            Some(MapKind::DevMap | MapKind::DevMapHash | MapKind::CpuMap | MapKind::XskMap) => {
                Err(CompileError::UnsupportedInstruction(format!(
                    "{context} --kind {kind} is reserved for bpf_redirect_map helper-call; generic map commands only support: hash, array, queue, stack, lpm-trie, lru-hash, per-cpu-hash, per-cpu-array, lru-per-cpu-hash; socket map kinds still require their specialized helpers"
                )))
            }
            Some(
                MapKind::SkStorage
                | MapKind::InodeStorage
                | MapKind::TaskStorage
                | MapKind::CgrpStorage,
            ) => Err(CompileError::UnsupportedInstruction(format!(
                "{context} --kind {kind} is reserved for BPF local-storage helpers; pass a literal map name as arg0 to the matching storage helper-call instead"
            ))),
            Some(_) | None => Err(CompileError::UnsupportedInstruction(format!(
                "{context} --kind must name a recognized map family; generic map commands support: hash, array, queue, stack, lpm-trie, lru-hash, per-cpu-hash, per-cpu-array, lru-per-cpu-hash; socket map kinds still use their specialized helpers"
            ))),
        }
    }

    pub(super) fn required_queue_stack_map_kind_arg(
        &self,
        context: &str,
    ) -> Result<MapKind, CompileError> {
        let Some((_, reg)) = self.named_args.get("kind") else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind queue or --kind stack"
            )));
        };
        let kind = self.literal_string_arg(*reg, &format!("{context} --kind"))?;
        match Self::parse_generic_map_kind(&kind) {
            Some(MapKind::Queue) => Ok(MapKind::Queue),
            Some(MapKind::Stack) => Ok(MapKind::Stack),
            Some(other) => Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind queue or --kind stack, got {:?}",
                other
            ))),
            None => Err(CompileError::UnsupportedInstruction(format!(
                "{context} --kind must be one of: queue, stack"
            ))),
        }
    }

    pub(super) fn required_queue_stack_bloom_map_kind_arg(
        &self,
        context: &str,
    ) -> Result<MapKind, CompileError> {
        let Some((_, reg)) = self.named_args.get("kind") else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind queue, --kind stack, or --kind bloom-filter"
            )));
        };
        let kind = self.literal_string_arg(*reg, &format!("{context} --kind"))?;
        match Self::parse_generic_map_kind(&kind) {
            Some(MapKind::Queue) => Ok(MapKind::Queue),
            Some(MapKind::Stack) => Ok(MapKind::Stack),
            Some(MapKind::BloomFilter) => Ok(MapKind::BloomFilter),
            Some(other) => Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind queue, --kind stack, or --kind bloom-filter, got {:?}",
                other
            ))),
            None => Err(CompileError::UnsupportedInstruction(format!(
                "{context} --kind must be one of: queue, stack, bloom-filter"
            ))),
        }
    }

    pub(super) fn required_bloom_filter_map_kind_arg(
        &self,
        context: &str,
    ) -> Result<MapKind, CompileError> {
        let Some((_, reg)) = self.named_args.get("kind") else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind bloom-filter"
            )));
        };
        let kind = self.literal_string_arg(*reg, &format!("{context} --kind"))?;
        match Self::parse_generic_map_kind(&kind) {
            Some(MapKind::BloomFilter) => Ok(MapKind::BloomFilter),
            Some(other) => Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind bloom-filter, got {:?}",
                other
            ))),
            None => Err(CompileError::UnsupportedInstruction(format!(
                "{context} --kind must be bloom-filter"
            ))),
        }
    }

    pub(super) fn required_redirect_map_kind_arg(
        &self,
        context: &str,
    ) -> Result<MapKind, CompileError> {
        let Some((_, reg)) = self.named_args.get("kind") else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind devmap, --kind devmap-hash, --kind cpumap, or --kind xskmap"
            )));
        };
        let kind = self.literal_string_arg(*reg, &format!("{context} --kind"))?;
        match Self::parse_generic_map_kind(&kind) {
            Some(MapKind::DevMap) => Ok(MapKind::DevMap),
            Some(MapKind::DevMapHash) => Ok(MapKind::DevMapHash),
            Some(MapKind::CpuMap) => Ok(MapKind::CpuMap),
            Some(MapKind::XskMap) => Ok(MapKind::XskMap),
            Some(other) => Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind devmap, --kind devmap-hash, --kind cpumap, or --kind xskmap, got {:?}",
                other
            ))),
            None => Err(CompileError::UnsupportedInstruction(format!(
                "{context} --kind must be one of: devmap, devmap-hash, cpumap, xskmap"
            ))),
        }
    }

    pub(super) fn required_socket_map_kind_arg(
        &self,
        context: &str,
    ) -> Result<MapKind, CompileError> {
        let Some((_, reg)) = self.named_args.get("kind") else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind sockmap or --kind sockhash"
            )));
        };
        let kind = self.literal_string_arg(*reg, &format!("{context} --kind"))?;
        match Self::parse_generic_map_kind(&kind) {
            Some(MapKind::SockMap) => Ok(MapKind::SockMap),
            Some(MapKind::SockHash) => Ok(MapKind::SockHash),
            Some(other) => Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires --kind sockmap or --kind sockhash, got {:?}",
                other
            ))),
            None => Err(CompileError::UnsupportedInstruction(format!(
                "{context} --kind must be one of: sockmap, sockhash"
            ))),
        }
    }

    pub(super) fn optional_nonnegative_named_u64_arg(
        &self,
        context: &str,
        name: &str,
    ) -> Result<Option<u64>, CompileError> {
        self.named_args
            .get(name)
            .map(|(_, reg)| {
                let raw = self
                    .get_metadata(*reg)
                    .and_then(|m| m.literal_int)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{context} --{name} must be a compile-time integer literal"
                        ))
                    })?;
                u64::try_from(raw).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!("{context} --{name} must be >= 0"))
                })
            })
            .transpose()
    }

    pub(super) fn packet_redirect_helper_from_named_flags(
        &self,
        context: &str,
    ) -> Result<BpfHelper, CompileError> {
        let mut peer = false;
        let mut neigh = false;
        for flag in &self.named_flags {
            match flag.as_str() {
                "peer" => peer = true,
                "neigh" => neigh = true,
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} does not accept flag '{}'",
                        flag
                    )));
                }
            }
        }
        if peer && neigh {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} accepts at most one of --peer or --neigh"
            )));
        }
        Ok(if let Some(ctx) = self.probe_ctx {
            if peer {
                ctx.program_type()
                    .packet_redirect_peer_helper()
                    .unwrap_or(BpfHelper::RedirectPeer)
            } else if neigh {
                ctx.program_type()
                    .packet_redirect_neigh_helper()
                    .unwrap_or(BpfHelper::RedirectNeigh)
            } else {
                ctx.program_type()
                    .packet_redirect_helper()
                    .unwrap_or(BpfHelper::Redirect)
            }
        } else if peer {
            BpfHelper::RedirectPeer
        } else if neigh {
            BpfHelper::RedirectNeigh
        } else {
            BpfHelper::Redirect
        })
    }

    pub(super) fn packet_adjust_mode_from_named_flags(
        &self,
        context: &str,
    ) -> Result<PacketAdjustMode, CompileError> {
        let mut mode = None;
        for flag in &self.named_flags {
            let candidate = match flag.as_str() {
                "head" => PacketAdjustMode::Head,
                "meta" => PacketAdjustMode::Meta,
                "tail" => PacketAdjustMode::Tail,
                "pull" => PacketAdjustMode::Pull,
                "room" => PacketAdjustMode::Room,
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} does not accept flag '{}'",
                        flag
                    )));
                }
            };
            if mode.replace(candidate).is_some() {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} requires exactly one of --head, --meta, --tail, --pull, or --room"
                )));
            }
        }

        mode.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{context} requires exactly one of --head, --meta, --tail, --pull, or --room"
            ))
        })
    }

    pub(super) fn packet_adjust_helper_for_current_program(
        &self,
        context: &str,
        mode: PacketAdjustMode,
    ) -> Result<BpfHelper, CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires a known attached program context"
            )));
        };

        let helper = ctx
            .program_type()
            .packet_adjust_helper(mode)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{context} --{} is only valid in {} programs",
                    mode.flag_name(),
                    mode.supported_programs_label()
                ))
            })?;

        if let Some(message) = ctx.helper_call_error(helper) {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        Ok(helper)
    }

    pub(super) fn message_adjust_mode_from_named_flags(
        &self,
        context: &str,
    ) -> Result<MessageAdjustMode, CompileError> {
        let mut mode = None;
        for flag in &self.named_flags {
            let candidate = match flag.as_str() {
                "apply" => MessageAdjustMode::Apply,
                "cork" => MessageAdjustMode::Cork,
                "pull" => MessageAdjustMode::Pull,
                "push" => MessageAdjustMode::Push,
                "pop" => MessageAdjustMode::Pop,
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} does not accept flag '{}'",
                        flag
                    )));
                }
            };
            if mode.replace(candidate).is_some() {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} requires exactly one of --apply, --cork, --pull, --push, or --pop"
                )));
            }
        }

        mode.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{context} requires exactly one of --apply, --cork, --pull, --push, or --pop"
            ))
        })
    }

    pub(super) fn message_adjust_helper_for_current_program(
        &self,
        context: &str,
        mode: MessageAdjustMode,
    ) -> Result<BpfHelper, CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires a known attached program context"
            )));
        };

        let helper = ctx
            .program_type()
            .message_adjust_helper(mode)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{context} --{} is only valid in {} programs",
                    mode.flag_name(),
                    mode.supported_programs_label()
                ))
            })?;

        if let Some(message) = ctx.helper_call_error(helper) {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        Ok(helper)
    }

    pub(super) fn validate_packet_redirect_flags(
        &self,
        helper: BpfHelper,
        flags: u64,
    ) -> Result<(), CompileError> {
        if flags == 0 {
            return Ok(());
        }

        if let Some((arg_idx, message)) = self
            .probe_ctx
            .and_then(|ctx| ctx.helper_zero_arg_requirement(helper))
        {
            if matches!(helper, BpfHelper::Redirect) && arg_idx == 1 {
                return Err(CompileError::UnsupportedInstruction(message.to_string()));
            }
        }

        if let Some((arg_idx, message)) = helper.zero_scalar_arg_requirement() {
            let flags_arg_idx = match helper {
                BpfHelper::RedirectPeer => Some(1),
                BpfHelper::RedirectNeigh => Some(3),
                _ => None,
            };
            if Some(arg_idx) == flags_arg_idx {
                return Err(CompileError::UnsupportedInstruction(message.to_string()));
            }
        }

        Ok(())
    }

    pub(super) fn socket_redirect_helper_for_current_program(
        &self,
        context: &str,
        map_kind: MapKind,
    ) -> Result<BpfHelper, CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires a known attached program context"
            )));
        };

        let helper = ctx
            .program_type()
            .socket_redirect_helper(map_kind)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{context} is only valid in sk_msg, sk_skb, and sk_skb_parser programs"
                ))
            })?;

        if let Some(message) = ctx.helper_call_error(helper) {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        Ok(helper)
    }

    pub(super) fn validate_generic_map_name(
        &self,
        map_name: &str,
        context: &str,
    ) -> Result<(), CompileError> {
        let mut chars = map_name.chars();
        let Some(first) = chars.next() else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} map name must not be empty"
            )));
        };
        if !(first == '_' || first.is_ascii_alphabetic())
            || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} map name '{map_name}' must match [A-Za-z_][A-Za-z0-9_]*"
            )));
        }
        Ok(())
    }

    pub(super) fn validate_generic_map_delete_kind(
        &self,
        map_kind: MapKind,
        map_name: &str,
    ) -> Result<(), CompileError> {
        if matches!(map_kind, MapKind::Array | MapKind::PerCpuArray) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map delete is not supported for array map kind {:?} ('{}')",
                map_kind, map_name
            )));
        }
        if matches!(map_kind, MapKind::Queue | MapKind::Stack) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map delete is not supported for map kind {:?} ('{}')",
                map_kind, map_name
            )));
        }
        if matches!(map_kind, MapKind::SockMap | MapKind::SockHash) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map-delete is not supported for socket map kind {:?} ('{}'); socket maps require specialized redirect/update helpers instead of generic map-delete",
                map_kind, map_name
            )));
        }
        Ok(())
    }

    pub(super) fn validate_generic_map_lookup_kind(
        &self,
        map_kind: MapKind,
        map_name: &str,
    ) -> Result<(), CompileError> {
        if matches!(map_kind, MapKind::Queue | MapKind::Stack) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map-get is not supported for map kind {:?} ('{}'); use map-push and future queue/stack-specific operations instead",
                map_kind, map_name
            )));
        }
        if matches!(map_kind, MapKind::SockMap | MapKind::SockHash) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map-get is not supported for socket map kind {:?} ('{}'); use specialized socket-map helpers instead",
                map_kind, map_name
            )));
        }
        Ok(())
    }

    pub(super) fn validate_generic_map_update_kind(
        &self,
        map_kind: MapKind,
        map_name: &str,
    ) -> Result<(), CompileError> {
        if matches!(map_kind, MapKind::Queue | MapKind::Stack) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map-put is not supported for map kind {:?} ('{}'); use map-push instead",
                map_kind, map_name
            )));
        }
        if matches!(map_kind, MapKind::SockMap | MapKind::SockHash) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map-put is not supported for socket map kind {:?} ('{}'); use specialized socket-map update helpers instead",
                map_kind, map_name
            )));
        }
        Ok(())
    }

    pub(super) fn require_only_named_args(
        &self,
        context: &str,
        allowed: &[&str],
    ) -> Result<(), CompileError> {
        for key in self.named_args.keys() {
            if !allowed.iter().any(|allowed_key| allowed_key == key) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} does not accept named argument '{}'",
                    key
                )));
            }
        }
        Ok(())
    }

    pub(super) fn reset_call_result_metadata(&mut self, reg: RegId) {
        *self.get_or_create_metadata(reg) = RegMetadata::default();
    }

    pub(super) fn materialize_scalar_kfunc_out_arg(
        &mut self,
        kfunc: &str,
        arg_idx: usize,
        arg_vreg: VReg,
        arg_reg: Option<RegId>,
    ) -> Result<(VReg, Option<ScalarKfuncOutArgWriteback>), CompileError> {
        let Some(arg_reg) = arg_reg else {
            return Ok((arg_vreg, None));
        };
        if matches!(
            self.vreg_type_hints.get(&arg_vreg),
            Some(MirType::Ptr { .. })
        ) {
            return Ok((arg_vreg, None));
        }

        if !kfunc_pointer_arg_requires_stack_slot_base(kfunc, arg_idx) {
            return Ok((arg_vreg, None));
        }

        let Some(source_var) = self.get_metadata(arg_reg).and_then(|meta| meta.source_var) else {
            return Ok((arg_vreg, None));
        };
        let Some(fixed_size) = kfunc_pointer_arg_fixed_size(kfunc, arg_idx) else {
            return Ok((arg_vreg, None));
        };
        let Some(scalar_ty) = self.direct_scalar_var_out_arg_type(arg_reg, arg_vreg, fixed_size)
        else {
            return Ok((arg_vreg, None));
        };

        let slot = self.func.alloc_stack_slot(
            align_to_eight(fixed_size.max(scalar_ty.size())),
            8,
            StackSlotKind::Local,
        );
        self.record_stack_slot_type(slot, scalar_ty.clone());
        self.emit(MirInst::StoreSlot {
            slot,
            offset: 0,
            val: MirValue::VReg(arg_vreg),
            ty: scalar_ty.clone(),
        });

        let ptr_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: ptr_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(scalar_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );

        Ok((
            ptr_vreg,
            Some(ScalarKfuncOutArgWriteback {
                slot,
                source_var,
                scalar_ty,
                original_arg_vreg: arg_vreg,
            }),
        ))
    }

    pub(super) fn write_back_scalar_kfunc_out_args(
        &mut self,
        writebacks: Vec<ScalarKfuncOutArgWriteback>,
    ) -> Result<(), CompileError> {
        for writeback in writebacks {
            let reloaded_vreg = self.func.alloc_vreg();
            self.emit(MirInst::LoadSlot {
                dst: reloaded_vreg,
                slot: writeback.slot,
                offset: 0,
                ty: writeback.scalar_ty.clone(),
            });
            self.vreg_type_hints
                .insert(reloaded_vreg, writeback.scalar_ty.clone());
            self.emit(MirInst::Copy {
                dst: writeback.original_arg_vreg,
                src: MirValue::VReg(reloaded_vreg),
            });
            self.vreg_type_hints
                .insert(writeback.original_arg_vreg, writeback.scalar_ty.clone());
            self.write_back_direct_scalar_var(
                writeback.source_var,
                writeback.scalar_ty,
                reloaded_vreg,
            )?;
        }
        Ok(())
    }

    pub(super) fn validate_intrinsic_support(
        &self,
        intrinsic: ProgramIntrinsic,
    ) -> Result<(), CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Ok(());
        };
        if ctx.program_type().supports_intrinsic(intrinsic) {
            return Ok(());
        }
        Err(CompileError::UnsupportedInstruction(format!(
            "{} is not supported on {} programs",
            intrinsic.command_name(),
            ctx.canonical_prefix()
        )))
    }

    pub(super) fn set_call_args(&mut self, args: &HirCallArgs) -> Result<(), CompileError> {
        self.positional_args.clear();
        self.named_flags.clear();
        self.named_args.clear();

        for reg in &args.positional {
            let vreg = self.get_vreg(*reg);
            self.positional_args.push((vreg, *reg));
        }
        for reg in &args.rest {
            let vreg = self.get_vreg(*reg);
            self.positional_args.push((vreg, *reg));
        }
        for (name, reg) in &args.named {
            let name = std::str::from_utf8(name)
                .map_err(|_| CompileError::UnsupportedInstruction("Invalid arg name".into()))?
                .to_string();
            let vreg = self.get_vreg(*reg);
            self.named_args.insert(name, (vreg, *reg));
        }
        for flag in &args.flags {
            let flag = std::str::from_utf8(flag)
                .map_err(|_| CompileError::UnsupportedInstruction("Invalid flag name".into()))?
                .to_string();
            self.named_flags.push(flag);
        }

        Ok(())
    }

    pub(super) fn clear_call_state(&mut self) {
        self.pipeline_input = None;
        self.pipeline_input_reg = None;
        self.positional_args.clear();
        self.named_flags.clear();
        self.named_args.clear();
    }

    pub(super) fn const_vreg(&mut self, value: i64) -> VReg {
        let vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: vreg,
            src: MirValue::Const(value),
        });
        vreg
    }

    pub(super) fn input_vreg_for_call(&mut self, src_dst: RegId) -> VReg {
        if let Some(vreg) = self.pipeline_input {
            return vreg;
        }
        if self.reg_map.contains_key(&src_dst.get()) {
            return self.get_vreg(src_dst);
        }
        self.const_vreg(0)
    }
}
