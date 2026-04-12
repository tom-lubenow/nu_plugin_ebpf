use super::*;

pub(in crate::compiler::ir_to_mir) enum PacketPayloadStepKind {
    Ethernet,
    Ipv4,
    Ipv6,
    Icmp,
    Icmpv6,
    Udp,
    Tcp,
}

impl<'a> HirToMirLowering<'a> {
    pub(super) fn packet_load_ptr_vreg(
        &mut self,
        packet_ptr_vreg: VReg,
        packet_ptr_ty: MirType,
        dst_vreg: VReg,
    ) -> VReg {
        if packet_ptr_vreg != dst_vreg {
            return packet_ptr_vreg;
        }

        let preserved_ptr_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(preserved_ptr_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::Copy {
            dst: preserved_ptr_vreg,
            src: MirValue::VReg(packet_ptr_vreg),
        });
        preserved_ptr_vreg
    }

    pub(in crate::compiler::ir_to_mir) fn lower_trampoline_field_projection(
        &mut self,
        dst_vreg: VReg,
        ctx_field: &CtxField,
        spec: TrampolineValueSpec,
        projection: &TrampolineFieldProjection,
        root_runtime_ty: &MirType,
        projected_ty: &MirType,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let projected_by_ref =
            matches!(projected_ty, MirType::Array { .. } | MirType::Struct { .. });

        enum TrampolineCursor {
            Stack {
                base_vreg: VReg,
                base_offset: usize,
            },
            Pointer {
                ptr_vreg: VReg,
                address_space: AddressSpace,
                base_offset: usize,
            },
        }

        let mut cursor = match spec.kind {
            TrampolineValueKind::Aggregate { size_bytes } => {
                let backing_slot =
                    self.func
                        .alloc_stack_slot(align_to_eight(size_bytes), 8, StackSlotKind::Local);
                if let MirType::Ptr {
                    pointee,
                    address_space: AddressSpace::Stack,
                } = root_runtime_ty
                {
                    self.record_stack_slot_type(backing_slot, pointee.as_ref().clone());
                } else {
                    self.record_stack_slot_type(
                        backing_slot,
                        MirType::Struct {
                            name: None,
                            kernel_btf_type_id: None,
                            fields: vec![crate::compiler::mir::StructField {
                                name: "__opaque".to_string(),
                                ty: MirType::Array {
                                    elem: Box::new(MirType::U8),
                                    len: size_bytes,
                                },
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        },
                    );
                }
                let aggregate_vreg = self.func.alloc_vreg();
                self.vreg_type_hints
                    .insert(aggregate_vreg, root_runtime_ty.clone());
                self.emit(MirInst::LoadCtxField {
                    dst: aggregate_vreg,
                    field: ctx_field.clone(),
                    slot: Some(backing_slot),
                });
                TrampolineCursor::Stack {
                    base_vreg: aggregate_vreg,
                    base_offset: 0,
                }
            }
            TrampolineValueKind::Pointer { user_space } => {
                let address_space = if user_space {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                };
                let root_ptr_ty = match root_runtime_ty {
                    MirType::Ptr { .. } => root_runtime_ty.clone(),
                    _ => Self::trampoline_pointer_type(address_space),
                };
                let root_ptr_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(root_ptr_vreg, root_ptr_ty);
                self.emit(MirInst::LoadCtxField {
                    dst: root_ptr_vreg,
                    field: ctx_field.clone(),
                    slot: None,
                });
                TrampolineCursor::Pointer {
                    ptr_vreg: root_ptr_vreg,
                    address_space,
                    base_offset: 0,
                }
            }
            TrampolineValueKind::Scalar => {
                return Err(CompileError::UnsupportedInstruction(
                    "nested ctx field access requires a struct/union trampoline value or pointer to one"
                        .into(),
                ));
            }
        };

        for (segment_idx, segment) in projection.path.iter().enumerate() {
            let is_last = segment_idx + 1 == projection.path.len();
            match cursor {
                TrampolineCursor::Stack {
                    base_vreg,
                    base_offset,
                } => {
                    let field_offset =
                        base_offset
                            .checked_add(segment.offset_bytes)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "projected trampoline field '{}' offset overflowed",
                                    path_desc
                                ))
                            })?;

                    if is_last {
                        if projected_by_ref {
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(projected_ty.clone()),
                                    address_space: AddressSpace::Stack,
                                },
                            );
                            if field_offset == 0 {
                                self.emit(MirInst::Copy {
                                    dst: dst_vreg,
                                    src: MirValue::VReg(base_vreg),
                                });
                            } else {
                                self.emit(MirInst::BinOp {
                                    dst: dst_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                            }
                        } else {
                            let loaded_vreg = if segment.bitfield.is_some() {
                                let storage_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints
                                    .insert(storage_vreg, projected_ty.clone());
                                self.emit(MirInst::Load {
                                    dst: storage_vreg,
                                    ptr: base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: projected_ty.clone(),
                                });
                                storage_vreg
                            } else {
                                dst_vreg
                            };
                            if let Some(bitfield) = segment.bitfield {
                                self.emit_bitfield_extract(
                                    dst_vreg,
                                    loaded_vreg,
                                    projected_ty,
                                    bitfield,
                                )?;
                            } else {
                                self.vreg_type_hints.insert(dst_vreg, projected_ty.clone());
                                self.emit(MirInst::Load {
                                    dst: dst_vreg,
                                    ptr: base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: projected_ty.clone(),
                                });
                            }
                        }
                        break;
                    }

                    match &segment.type_info {
                        TypeInfo::Struct { .. } | TypeInfo::Array { .. } => {
                            cursor = TrampolineCursor::Stack {
                                base_vreg,
                                base_offset: field_offset,
                            };
                        }
                        TypeInfo::Ptr { is_user, .. } => {
                            let address_space = if *is_user {
                                AddressSpace::User
                            } else {
                                AddressSpace::Kernel
                            };
                            let ptr_ty = Self::trampoline_pointer_type(address_space);
                            let ptr_vreg = self.func.alloc_vreg();
                            self.vreg_type_hints.insert(ptr_vreg, ptr_ty.clone());
                            self.emit(MirInst::Load {
                                dst: ptr_vreg,
                                ptr: base_vreg,
                                offset: Self::trampoline_projection_offset_i32(
                                    field_offset,
                                    path_desc,
                                )?,
                                ty: ptr_ty,
                            });
                            cursor = TrampolineCursor::Pointer {
                                ptr_vreg,
                                address_space,
                                base_offset: 0,
                            };
                        }
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "projected trampoline field '{}' requires an aggregate or pointer before the final segment",
                                path_desc
                            )));
                        }
                    }
                }
                TrampolineCursor::Pointer {
                    ptr_vreg,
                    address_space,
                    base_offset,
                } => {
                    let field_offset =
                        base_offset
                            .checked_add(segment.offset_bytes)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "projected trampoline field '{}' offset overflowed",
                                    path_desc
                                ))
                            })?;

                    if is_last {
                        let projected_slot = self.func.alloc_stack_slot(
                            align_to_eight(projected_ty.size()),
                            8,
                            StackSlotKind::Local,
                        );
                        self.record_stack_slot_type(projected_slot, projected_ty.clone());
                        self.emit_trampoline_probe_read_to_slot(
                            ptr_vreg,
                            address_space,
                            field_offset,
                            projected_slot,
                            projected_ty,
                            path_desc,
                        )?;
                        if projected_by_ref {
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(projected_ty.clone()),
                                    address_space: AddressSpace::Stack,
                                },
                            );
                            self.emit(MirInst::Copy {
                                dst: dst_vreg,
                                src: MirValue::StackSlot(projected_slot),
                            });
                        } else {
                            let loaded_vreg = if segment.bitfield.is_some() {
                                let storage_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints
                                    .insert(storage_vreg, projected_ty.clone());
                                self.emit(MirInst::LoadSlot {
                                    dst: storage_vreg,
                                    slot: projected_slot,
                                    offset: 0,
                                    ty: projected_ty.clone(),
                                });
                                storage_vreg
                            } else {
                                dst_vreg
                            };
                            if let Some(bitfield) = segment.bitfield {
                                self.emit_bitfield_extract(
                                    dst_vreg,
                                    loaded_vreg,
                                    projected_ty,
                                    bitfield,
                                )?;
                            } else {
                                self.vreg_type_hints.insert(dst_vreg, projected_ty.clone());
                                self.emit(MirInst::LoadSlot {
                                    dst: dst_vreg,
                                    slot: projected_slot,
                                    offset: 0,
                                    ty: projected_ty.clone(),
                                });
                            }
                        }
                        break;
                    }

                    match &segment.type_info {
                        TypeInfo::Struct { .. } | TypeInfo::Array { .. } => {
                            cursor = TrampolineCursor::Pointer {
                                ptr_vreg,
                                address_space,
                                base_offset: field_offset,
                            };
                        }
                        TypeInfo::Ptr { is_user, .. } => {
                            let next_address_space = if *is_user {
                                AddressSpace::User
                            } else {
                                AddressSpace::Kernel
                            };
                            let ptr_ty = Self::trampoline_pointer_type(next_address_space);
                            let pointer_slot = self.func.alloc_stack_slot(
                                align_to_eight(8),
                                8,
                                StackSlotKind::Local,
                            );
                            self.record_stack_slot_type(pointer_slot, ptr_ty.clone());
                            self.emit_trampoline_probe_read_to_slot(
                                ptr_vreg,
                                address_space,
                                field_offset,
                                pointer_slot,
                                &ptr_ty,
                                path_desc,
                            )?;
                            let next_ptr_vreg = self.func.alloc_vreg();
                            self.vreg_type_hints.insert(next_ptr_vreg, ptr_ty.clone());
                            self.emit(MirInst::LoadSlot {
                                dst: next_ptr_vreg,
                                slot: pointer_slot,
                                offset: 0,
                                ty: ptr_ty,
                            });
                            cursor = TrampolineCursor::Pointer {
                                ptr_vreg: next_ptr_vreg,
                                address_space: next_address_space,
                                base_offset: 0,
                            };
                        }
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "projected trampoline field '{}' requires an aggregate or pointer before the final segment",
                                path_desc
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn resolve_kernel_btf_struct_field_step(
        type_id: u32,
        field_name: &str,
        path_desc: &str,
    ) -> Result<TypedProjectionStep, CompileError> {
        let projection = KernelBtf::get()
            .kernel_type_field_projection(
                type_id,
                &[TrampolineFieldSelector::Field(field_name.to_string())],
            )
            .map_err(|e| {
                CompileError::UnsupportedInstruction(format!(
                    "failed to resolve typed field path '{}' from kernel BTF: {}",
                    path_desc, e
                ))
            })?;
        let offset = projection
            .path
            .first()
            .map(|segment| segment.offset_bytes)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "failed to resolve typed field path '{}' from kernel BTF",
                    path_desc
                ))
            })?;
        let projected_ty = Self::projected_trampoline_field_type(&projection.type_info)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' resolved to unsupported kernel type {:?}",
                    path_desc, projection.type_info
                ))
            })?;
        Ok(TypedProjectionStep {
            offset,
            ty: projected_ty,
            bitfield: projection.path[0].bitfield,
            packet_big_endian: false,
        })
    }

    fn packet_struct_field(
        name: &str,
        ty: MirType,
        offset: usize,
    ) -> crate::compiler::mir::StructField {
        crate::compiler::mir::StructField {
            name: name.to_string(),
            ty,
            offset,
            synthetic: false,
            bitfield: None,
        }
    }

    fn packet_bytes(len: usize) -> MirType {
        MirType::Array {
            elem: Box::new(MirType::U8),
            len,
        }
    }

    fn packet_eth_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_eth".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("dst", Self::packet_bytes(6), 0),
                Self::packet_struct_field("src", Self::packet_bytes(6), 6),
                Self::packet_struct_field("ethertype", MirType::U16, 12),
            ],
        }
    }

    fn packet_ipv4_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_ipv4".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("version_ihl", MirType::U8, 0),
                Self::packet_struct_field("dscp_ecn", MirType::U8, 1),
                Self::packet_struct_field("total_len", MirType::U16, 2),
                Self::packet_struct_field("identification", MirType::U16, 4),
                Self::packet_struct_field("flags_fragment_offset", MirType::U16, 6),
                Self::packet_struct_field("ttl", MirType::U8, 8),
                Self::packet_struct_field("protocol", MirType::U8, 9),
                Self::packet_struct_field("checksum", MirType::U16, 10),
                Self::packet_struct_field("src", Self::packet_bytes(4), 12),
                Self::packet_struct_field("dst", Self::packet_bytes(4), 16),
            ],
        }
    }

    fn packet_ipv6_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_ipv6".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("version_tc_flow_label", MirType::U32, 0),
                Self::packet_struct_field("payload_len", MirType::U16, 4),
                Self::packet_struct_field("next_header", MirType::U8, 6),
                Self::packet_struct_field("hop_limit", MirType::U8, 7),
                Self::packet_struct_field("src", Self::packet_bytes(16), 8),
                Self::packet_struct_field("dst", Self::packet_bytes(16), 24),
            ],
        }
    }

    fn packet_udp_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_udp".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("src", MirType::U16, 0),
                Self::packet_struct_field("dst", MirType::U16, 2),
                Self::packet_struct_field("len", MirType::U16, 4),
                Self::packet_struct_field("checksum", MirType::U16, 6),
            ],
        }
    }

    fn packet_icmp_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_icmp".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("type", MirType::U8, 0),
                Self::packet_struct_field("code", MirType::U8, 1),
                Self::packet_struct_field("checksum", MirType::U16, 2),
                Self::packet_struct_field("body", Self::packet_bytes(4), 4),
            ],
        }
    }

    fn packet_icmpv6_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_icmpv6".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("type", MirType::U8, 0),
                Self::packet_struct_field("code", MirType::U8, 1),
                Self::packet_struct_field("checksum", MirType::U16, 2),
                Self::packet_struct_field("body", Self::packet_bytes(4), 4),
            ],
        }
    }

    fn packet_tcp_header_type() -> MirType {
        MirType::Struct {
            name: Some("__packet_tcp".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                Self::packet_struct_field("src", MirType::U16, 0),
                Self::packet_struct_field("dst", MirType::U16, 2),
                Self::packet_struct_field("seq", MirType::U32, 4),
                Self::packet_struct_field("ack_seq", MirType::U32, 8),
                Self::packet_struct_field("data_offset_flags", MirType::U16, 12),
                Self::packet_struct_field("window", MirType::U16, 14),
                Self::packet_struct_field("checksum", MirType::U16, 16),
                Self::packet_struct_field("urg_ptr", MirType::U16, 18),
            ],
        }
    }

    pub(in crate::compiler::ir_to_mir) fn packet_header_view_spec(
        current_ty: &MirType,
        member: &PathMember,
    ) -> Option<TypedProjectionStep> {
        let PathMember::String { val, .. } = member else {
            return None;
        };

        let current_name = match current_ty {
            MirType::Struct { name, .. } => name.as_deref(),
            _ => None,
        };
        let is_raw_packet = matches!(current_ty, MirType::U8);

        match (current_name, is_raw_packet, val.as_str()) {
            (_, true, "eth" | "ethhdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_eth_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (_, true, "ipv4" | "iphdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_ipv4_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (_, true, "ipv6" | "ipv6hdr" | "ip6hdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_ipv6_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (_, true, "udp" | "udphdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_udp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (_, true, "icmp" | "icmphdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_icmp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (_, true, "icmpv6" | "icmp6" | "icmpv6hdr" | "icmp6hdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_icmpv6_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (_, true, "tcp" | "tcphdr") => Some(TypedProjectionStep {
                offset: 0,
                ty: Self::packet_tcp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (Some("__packet_eth"), _, "ipv4" | "iphdr") => Some(TypedProjectionStep {
                offset: current_ty.size(),
                ty: Self::packet_ipv4_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (Some("__packet_eth"), _, "ipv6" | "ipv6hdr" | "ip6hdr") => Some(TypedProjectionStep {
                offset: current_ty.size(),
                ty: Self::packet_ipv6_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (Some("__packet_ipv4"), _, "udp" | "udphdr") => Some(TypedProjectionStep {
                offset: current_ty.size(),
                ty: Self::packet_udp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (Some("__packet_ipv4"), _, "icmp" | "icmphdr") => Some(TypedProjectionStep {
                offset: current_ty.size(),
                ty: Self::packet_icmp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (Some("__packet_ipv4"), _, "tcp" | "tcphdr") => Some(TypedProjectionStep {
                offset: current_ty.size(),
                ty: Self::packet_tcp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (Some("__packet_ipv6"), _, "udp" | "udphdr") => Some(TypedProjectionStep {
                offset: current_ty.size(),
                ty: Self::packet_udp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            (Some("__packet_ipv6"), _, "icmpv6" | "icmp6" | "icmpv6hdr" | "icmp6hdr") => {
                Some(TypedProjectionStep {
                    offset: current_ty.size(),
                    ty: Self::packet_icmpv6_header_type(),
                    bitfield: None,
                    packet_big_endian: false,
                })
            }
            (Some("__packet_ipv6"), _, "tcp" | "tcphdr") => Some(TypedProjectionStep {
                offset: current_ty.size(),
                ty: Self::packet_tcp_header_type(),
                bitfield: None,
                packet_big_endian: false,
            }),
            _ => None,
        }
    }

    pub(in crate::compiler::ir_to_mir) fn packet_payload_step_kind(
        current_ty: &MirType,
        member: &PathMember,
    ) -> Option<PacketPayloadStepKind> {
        let PathMember::String { val, .. } = member else {
            return None;
        };
        if val != "payload" {
            return None;
        }

        match current_ty {
            MirType::Struct {
                name: Some(name), ..
            } => match name.as_str() {
                "__packet_eth" => Some(PacketPayloadStepKind::Ethernet),
                "__packet_ipv4" => Some(PacketPayloadStepKind::Ipv4),
                "__packet_ipv6" => Some(PacketPayloadStepKind::Ipv6),
                "__packet_icmp" => Some(PacketPayloadStepKind::Icmp),
                "__packet_icmpv6" => Some(PacketPayloadStepKind::Icmpv6),
                "__packet_udp" => Some(PacketPayloadStepKind::Udp),
                "__packet_tcp" => Some(PacketPayloadStepKind::Tcp),
                _ => None,
            },
            _ => None,
        }
    }

    fn packet_field_is_big_endian(current_ty: &MirType, member: &PathMember) -> bool {
        let MirType::Struct {
            name: Some(name), ..
        } = current_ty
        else {
            return false;
        };
        let PathMember::String { val, .. } = member else {
            return false;
        };

        match (name.as_str(), val.as_str()) {
            ("__packet_eth", "ethertype") => true,
            (
                "__packet_ipv4",
                "total_len" | "identification" | "flags_fragment_offset" | "checksum",
            ) => true,
            ("__packet_ipv6", "version_tc_flow_label" | "payload_len") => true,
            ("__packet_icmp", "checksum") => true,
            ("__packet_icmpv6", "checksum") => true,
            ("__packet_udp", "src" | "dst" | "len" | "checksum") => true,
            (
                "__packet_tcp",
                "src" | "dst" | "seq" | "ack_seq" | "data_offset_flags" | "window" | "checksum"
                | "urg_ptr",
            ) => true,
            _ => false,
        }
    }

    pub(in crate::compiler::ir_to_mir) fn resolve_typed_value_projection_step(
        current_ty: &MirType,
        member: &PathMember,
        path_desc: &str,
    ) -> Result<TypedProjectionStep, CompileError> {
        match (current_ty, member) {
            (
                MirType::Struct {
                    fields,
                    kernel_btf_type_id,
                    ..
                },
                PathMember::String { val, .. },
            ) => {
                let field = fields
                    .iter()
                    .find(|field| !field.synthetic && field.name == *val)
                    .map(|field| TypedProjectionStep {
                        offset: field.offset,
                        ty: field.ty.clone(),
                        bitfield: field.bitfield.map(|bitfield| TrampolineBitfieldInfo {
                            bit_offset: bitfield.bit_offset,
                            bit_size: bitfield.bit_size,
                        }),
                        packet_big_endian: Self::packet_field_is_big_endian(current_ty, member),
                    });
                if let Some(field) = field {
                    return Ok(field);
                }
                if let Some(type_id) = *kernel_btf_type_id {
                    return Self::resolve_kernel_btf_struct_field_step(type_id, val, path_desc);
                }
                Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' has no field '{}'",
                    path_desc, val
                )))
            }
            (MirType::Struct { .. }, PathMember::Int { val, .. }) => {
                Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' cannot index {} on a struct",
                    path_desc, val
                )))
            }
            (MirType::Array { elem, len }, PathMember::Int { val, .. }) => {
                let index = usize::try_from(*val).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' requires a non-negative array index",
                        path_desc
                    ))
                })?;
                if index >= *len {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' index {} is out of bounds (len {})",
                        path_desc, index, len
                    )));
                }
                Ok(TypedProjectionStep {
                    offset: index * elem.size(),
                    ty: elem.as_ref().clone(),
                    bitfield: None,
                    packet_big_endian: false,
                })
            }
            (MirType::Array { .. }, PathMember::String { val, .. }) => {
                Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' cannot access field '{}' on an array; use a numeric index",
                    path_desc, val
                )))
            }
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "typed field path '{}' requires an aggregate or pointer to one, got {:?}",
                path_desc, current_ty
            ))),
        }
    }

    pub(in crate::compiler::ir_to_mir) fn resolve_typed_value_projection_path(
        current_ty: &MirType,
        members: &[PathMember],
        path_desc: &str,
    ) -> Result<TypedProjectionStep, CompileError> {
        let mut offset = 0usize;
        let mut ty = current_ty.clone();
        let mut final_step = None;

        for (idx, member) in members.iter().enumerate() {
            let step = Self::resolve_typed_value_projection_step(&ty, member, path_desc)?;
            if idx + 1 != members.len() && step.bitfield.is_some() {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' cannot traverse through bitfield member '{}'",
                    path_desc,
                    match member {
                        PathMember::String { val, .. } => val.as_str(),
                        PathMember::Int { .. } => "<index>",
                    }
                )));
            }
            offset = offset.checked_add(step.offset).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' offset overflowed",
                    path_desc
                ))
            })?;
            ty = step.ty.clone();
            final_step = Some(TypedProjectionStep {
                offset,
                ty: step.ty,
                bitfield: step.bitfield,
                packet_big_endian: step.packet_big_endian,
            });
        }

        final_step.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "typed field path '{}' cannot be empty",
                path_desc
            ))
        })
    }

    pub(in crate::compiler::ir_to_mir) fn resolve_pointer_sequence_index_step(
        current_ty: &MirType,
        index: usize,
        path_desc: &str,
    ) -> Result<TypedProjectionStep, CompileError> {
        let offset = index.checked_mul(current_ty.size()).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "typed field path '{}' pointer index {} overflowed",
                path_desc, index
            ))
        })?;
        Ok(TypedProjectionStep {
            offset,
            ty: current_ty.clone(),
            bitfield: None,
            packet_big_endian: false,
        })
    }

    pub(in crate::compiler::ir_to_mir) fn packet_scalar_view_spec(
        member: &PathMember,
    ) -> Option<(MirType, usize, bool)> {
        let PathMember::String { val, .. } = member else {
            return None;
        };
        match val.as_str() {
            "u16be" => Some((MirType::U16, 2, true)),
            "u32be" => Some((MirType::U32, 4, true)),
            _ => None,
        }
    }

    fn emit_packet_scalar_load_at_offset(
        &mut self,
        dst_vreg: VReg,
        base_vreg: VReg,
        base_offset: usize,
        load_ty: &MirType,
        big_endian: bool,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let packet_ptr_vreg = if base_offset == 0 {
            base_vreg
        } else {
            let ptr_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(
                ptr_vreg,
                MirType::Ptr {
                    pointee: Box::new(load_ty.clone()),
                    address_space: AddressSpace::Packet,
                },
            );
            self.emit(MirInst::BinOp {
                dst: ptr_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(base_vreg),
                rhs: MirValue::Const(i64::from(Self::trampoline_projection_offset_i32(
                    base_offset,
                    path_desc,
                )?)),
            });
            ptr_vreg
        };
        let packet_ptr_vreg = self.packet_load_ptr_vreg(
            packet_ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(load_ty.clone()),
                address_space: AddressSpace::Packet,
            },
            dst_vreg,
        );
        self.emit_xdp_packet_guarded_load(dst_vreg, packet_ptr_vreg, load_ty, path_desc)?;
        if big_endian {
            self.emit_packet_big_endian_scalar_normalize(dst_vreg, load_ty)?;
        }
        Ok(())
    }

    fn emit_normalize_boolean_vreg(&mut self, dst_vreg: VReg, src_vreg: VReg) {
        let not_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(not_vreg, MirType::Bool);
        self.emit(MirInst::UnaryOp {
            dst: not_vreg,
            op: UnaryOpKind::Not,
            src: MirValue::VReg(src_vreg),
        });

        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.emit(MirInst::UnaryOp {
            dst: dst_vreg,
            op: UnaryOpKind::Not,
            src: MirValue::VReg(not_vreg),
        });
    }

    fn emit_packet_vlan_ethertype_match(&mut self, ethertype_vreg: VReg) -> VReg {
        let vlan_8021q = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: vlan_8021q,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(ethertype_vreg),
            rhs: MirValue::Const(0x8100),
        });
        self.emit_normalize_boolean_vreg(vlan_8021q, vlan_8021q);

        let vlan_8021ad = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: vlan_8021ad,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(ethertype_vreg),
            rhs: MirValue::Const(0x88a8),
        });
        self.emit_normalize_boolean_vreg(vlan_8021ad, vlan_8021ad);

        let vlan_9100 = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: vlan_9100,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(ethertype_vreg),
            rhs: MirValue::Const(0x9100),
        });
        self.emit_normalize_boolean_vreg(vlan_9100, vlan_9100);

        let vlan_present = self.func.alloc_vreg();
        self.vreg_type_hints.insert(vlan_present, MirType::Bool);
        self.emit(MirInst::BinOp {
            dst: vlan_present,
            op: BinOpKind::Or,
            lhs: MirValue::VReg(vlan_8021q),
            rhs: MirValue::VReg(vlan_8021ad),
        });
        self.emit_normalize_boolean_vreg(vlan_present, vlan_present);
        self.emit(MirInst::BinOp {
            dst: vlan_present,
            op: BinOpKind::Or,
            lhs: MirValue::VReg(vlan_present),
            rhs: MirValue::VReg(vlan_9100),
        });
        self.emit_normalize_boolean_vreg(vlan_present, vlan_present);
        vlan_present
    }

    pub(in crate::compiler::ir_to_mir) fn emit_packet_payload_ptr_step(
        &mut self,
        base_vreg: VReg,
        base_offset: usize,
        kind: PacketPayloadStepKind,
        path_desc: &str,
    ) -> Result<VReg, CompileError> {
        let base_ptr_vreg = if base_offset == 0 {
            base_vreg
        } else {
            let ptr_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(
                ptr_vreg,
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Packet,
                },
            );
            self.emit(MirInst::BinOp {
                dst: ptr_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(base_vreg),
                rhs: MirValue::Const(i64::from(Self::trampoline_projection_offset_i32(
                    base_offset,
                    path_desc,
                )?)),
            });
            ptr_vreg
        };

        let payload_ptr_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(
            payload_ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Packet,
            },
        );

        match kind {
            PacketPayloadStepKind::Ethernet => {
                let ethertype_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(ethertype_vreg, MirType::U16);
                self.emit_packet_scalar_load_at_offset(
                    ethertype_vreg,
                    base_ptr_vreg,
                    12,
                    &MirType::U16,
                    true,
                    path_desc,
                )?;
                let outer_vlan_present = self.emit_packet_vlan_ethertype_match(ethertype_vreg);

                let eth_payload_base_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(
                    eth_payload_base_vreg,
                    MirType::Ptr {
                        pointee: Box::new(MirType::U8),
                        address_space: AddressSpace::Packet,
                    },
                );
                self.emit(MirInst::BinOp {
                    dst: eth_payload_base_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(base_ptr_vreg),
                    rhs: MirValue::Const(14),
                });

                self.emit(MirInst::Copy {
                    dst: payload_ptr_vreg,
                    src: MirValue::VReg(eth_payload_base_vreg),
                });

                let stacked_vlan_block = self.func.alloc_block();
                let continue_block = self.func.alloc_block();
                self.terminate(MirInst::Branch {
                    cond: outer_vlan_present,
                    if_true: stacked_vlan_block,
                    if_false: continue_block,
                });

                self.current_block = stacked_vlan_block;
                let inner_ethertype_vreg = self.func.alloc_vreg();
                self.vreg_type_hints
                    .insert(inner_ethertype_vreg, MirType::U16);
                self.emit_packet_scalar_load_at_offset(
                    inner_ethertype_vreg,
                    base_ptr_vreg,
                    16,
                    &MirType::U16,
                    true,
                    path_desc,
                )?;
                let inner_vlan_present =
                    self.emit_packet_vlan_ethertype_match(inner_ethertype_vreg);

                let inner_vlan_bytes_vreg = self.func.alloc_vreg();
                self.vreg_type_hints
                    .insert(inner_vlan_bytes_vreg, MirType::U64);
                self.emit(MirInst::BinOp {
                    dst: inner_vlan_bytes_vreg,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(inner_vlan_present),
                    rhs: MirValue::Const(2),
                });

                let first_vlan_payload_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(
                    first_vlan_payload_vreg,
                    MirType::Ptr {
                        pointee: Box::new(MirType::U8),
                        address_space: AddressSpace::Packet,
                    },
                );
                self.emit(MirInst::BinOp {
                    dst: first_vlan_payload_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(eth_payload_base_vreg),
                    rhs: MirValue::Const(4),
                });
                self.emit(MirInst::BinOp {
                    dst: payload_ptr_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(first_vlan_payload_vreg),
                    rhs: MirValue::VReg(inner_vlan_bytes_vreg),
                });
                self.terminate(MirInst::Jump {
                    target: continue_block,
                });
                self.current_block = continue_block;
            }
            PacketPayloadStepKind::Ipv4 => {
                let version_ihl_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(version_ihl_vreg, MirType::U8);
                self.emit_packet_scalar_load_at_offset(
                    version_ihl_vreg,
                    base_ptr_vreg,
                    0,
                    &MirType::U8,
                    false,
                    path_desc,
                )?;

                let ihl_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(ihl_vreg, MirType::U64);
                self.emit(MirInst::BinOp {
                    dst: ihl_vreg,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(version_ihl_vreg),
                    rhs: MirValue::Const(0x0f),
                });
                self.emit(MirInst::BinOp {
                    dst: ihl_vreg,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(ihl_vreg),
                    rhs: MirValue::Const(2),
                });
                self.emit(MirInst::BinOp {
                    dst: payload_ptr_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(base_ptr_vreg),
                    rhs: MirValue::VReg(ihl_vreg),
                });
            }
            PacketPayloadStepKind::Ipv6 => {
                self.emit(MirInst::BinOp {
                    dst: payload_ptr_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(base_ptr_vreg),
                    rhs: MirValue::Const(40),
                });
            }
            PacketPayloadStepKind::Icmp | PacketPayloadStepKind::Icmpv6 => {
                self.emit(MirInst::BinOp {
                    dst: payload_ptr_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(base_ptr_vreg),
                    rhs: MirValue::Const(8),
                });
            }
            PacketPayloadStepKind::Udp => {
                self.emit(MirInst::BinOp {
                    dst: payload_ptr_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(base_ptr_vreg),
                    rhs: MirValue::Const(8),
                });
            }
            PacketPayloadStepKind::Tcp => {
                let data_offset_flags_vreg = self.func.alloc_vreg();
                self.vreg_type_hints
                    .insert(data_offset_flags_vreg, MirType::U16);
                self.emit_packet_scalar_load_at_offset(
                    data_offset_flags_vreg,
                    base_ptr_vreg,
                    12,
                    &MirType::U16,
                    true,
                    path_desc,
                )?;

                let data_offset_words_vreg = self.func.alloc_vreg();
                self.vreg_type_hints
                    .insert(data_offset_words_vreg, MirType::U64);
                self.emit(MirInst::BinOp {
                    dst: data_offset_words_vreg,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(data_offset_flags_vreg),
                    rhs: MirValue::Const(12),
                });
                self.emit(MirInst::BinOp {
                    dst: data_offset_words_vreg,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(data_offset_words_vreg),
                    rhs: MirValue::Const(2),
                });
                self.emit(MirInst::BinOp {
                    dst: payload_ptr_vreg,
                    op: BinOpKind::Add,
                    lhs: MirValue::VReg(base_ptr_vreg),
                    rhs: MirValue::VReg(data_offset_words_vreg),
                });
            }
        }

        Ok(payload_ptr_vreg)
    }
}
