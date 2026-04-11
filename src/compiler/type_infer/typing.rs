use super::*;
use crate::compiler::ProgramValueAccess;
use crate::kernel_btf::TypeInfo;

impl<'a> TypeInference<'a> {
    fn synthetic_bpf_sock_hm_type() -> HMType {
        HMType::Struct {
            name: Some("bpf_sock".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                ("bound_dev_if".to_string(), HMType::U32),
                ("family".to_string(), HMType::U32),
                ("type".to_string(), HMType::U32),
                ("protocol".to_string(), HMType::U32),
                ("mark".to_string(), HMType::U32),
                ("priority".to_string(), HMType::U32),
                ("src_port".to_string(), HMType::U32),
                ("dst_port".to_string(), HMType::U16),
                ("state".to_string(), HMType::U32),
                ("rx_queue_mapping".to_string(), HMType::I32),
            ],
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
            fields: vec![crate::compiler::mir::StructField {
                name: "__opaque".to_string(),
                ty: Self::byte_array_mir_type(size)?,
                offset: 0,
                synthetic: false,
                bitfield: None,
            }],
        })
    }

    fn synthetic_padding_field(
        offset: usize,
        size: usize,
        pad_index: usize,
    ) -> Option<crate::compiler::mir::StructField> {
        Some(crate::compiler::mir::StructField {
            name: format!("__layout_pad{}", pad_index),
            ty: Self::byte_array_mir_type(size)?,
            offset,
            synthetic: true,
            bitfield: None,
        })
    }

    fn mir_type_from_type_info(type_info: &TypeInfo) -> Option<MirType> {
        match type_info {
            TypeInfo::Int { size, signed } => Some(
                match (*size, *signed) {
                    (1, false) => HMType::U8,
                    (1, true) => HMType::I8,
                    (2, false) => HMType::U16,
                    (2, true) => HMType::I16,
                    (4, false) => HMType::U32,
                    (4, true) => HMType::I32,
                    (8, false) => HMType::U64,
                    (8, true) => HMType::I64,
                    _ => return None,
                }
                .to_mir_type()?,
            ),
            TypeInfo::Ptr { target, is_user } => Some(MirType::Ptr {
                pointee: Box::new(Self::mir_type_from_type_info(target).unwrap_or(MirType::U8)),
                address_space: if *is_user {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                },
            }),
            TypeInfo::Array { element, len } => Some(MirType::Array {
                elem: Box::new(Self::mir_type_from_type_info(element)?),
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
                    return Self::opaque_struct_mir_type(name, *size, *btf_type_id);
                }

                let mut mir_fields = Vec::with_capacity(fields.len() + 1);
                let mut cursor = 0usize;
                let mut pad_index = 0usize;
                for field in fields {
                    if field.size == 0 || field.offset >= *size {
                        continue;
                    }
                    if field.offset < cursor && field.bitfield.is_none() {
                        continue;
                    }
                    if field.offset > cursor {
                        mir_fields.push(Self::synthetic_padding_field(
                            cursor,
                            field.offset - cursor,
                            pad_index,
                        )?);
                        pad_index += 1;
                    }

                    let field_ty = Self::mir_type_from_type_info(&field.type_info)
                        .or_else(|| Self::byte_array_mir_type(field.size))
                        .filter(|ty| ty.size() == field.size)
                        .or_else(|| Self::byte_array_mir_type(field.size))?;
                    let field_end = field.offset.checked_add(field.size)?;
                    if field_end > *size {
                        continue;
                    }
                    mir_fields.push(crate::compiler::mir::StructField {
                        name: field.name.clone(),
                        ty: field_ty,
                        offset: field.offset,
                        synthetic: false,
                        bitfield: field.bitfield.map(|bitfield| {
                            crate::compiler::mir::BitfieldInfo {
                                bit_offset: bitfield.bit_offset,
                                bit_size: bitfield.bit_size,
                            }
                        }),
                    });
                    cursor = cursor.max(field_end);
                }
                if mir_fields.is_empty() {
                    return Self::opaque_struct_mir_type(name, *size, *btf_type_id);
                }
                if cursor < *size {
                    mir_fields.push(Self::synthetic_padding_field(
                        cursor,
                        *size - cursor,
                        pad_index,
                    )?);
                }

                Some(MirType::Struct {
                    name: Some(name.clone()),
                    kernel_btf_type_id: *btf_type_id,
                    fields: mir_fields,
                })
            }
            _ => None,
        }
    }

    fn hm_type_from_type_info(type_info: &TypeInfo) -> Option<HMType> {
        Some(HMType::from_mir_type(&Self::mir_type_from_type_info(
            type_info,
        )?))
    }

    fn trampoline_arg_type(&self, idx: u8) -> Result<Option<HMType>, TypeError> {
        let Some(ctx) = self.probe_ctx.as_ref() else {
            return Ok(None);
        };
        if !ctx.probe_type.uses_btf_trampoline() {
            return Ok(None);
        }

        let type_info = ctx
            .btf_arg_type_info(idx as usize)
            .map_err(TypeError::new)?
            .ok_or_else(|| TypeError::new(ctx.btf_arg_unavailable_error(idx as usize)))?;
        Ok(Some(match type_info {
            TypeInfo::Struct { .. } | TypeInfo::Array { .. } => HMType::Ptr {
                pointee: Box::new(Self::hm_type_from_type_info(&type_info).unwrap_or(
                    HMType::Array {
                        elem: Box::new(HMType::U8),
                        len: type_info.size(),
                    },
                )),
                address_space: AddressSpace::Stack,
            },
            _ => Self::hm_type_from_type_info(&type_info).unwrap_or(HMType::I64),
        }))
    }

    fn trampoline_ret_type(&self) -> Result<Option<HMType>, TypeError> {
        let Some(ctx) = self.probe_ctx.as_ref() else {
            return Ok(None);
        };
        if !matches!(
            ctx.probe_type.retval_access(),
            ProgramValueAccess::Trampoline
        ) {
            return Ok(None);
        }

        let type_info = ctx
            .btf_ret_type_info()
            .map_err(TypeError::new)?
            .ok_or_else(|| TypeError::new(ctx.btf_ret_unavailable_error()))?;
        Ok(Some(match type_info {
            TypeInfo::Struct { .. } | TypeInfo::Array { .. } => HMType::Ptr {
                pointee: Box::new(Self::hm_type_from_type_info(&type_info).unwrap_or(
                    HMType::Array {
                        elem: Box::new(HMType::U8),
                        len: type_info.size(),
                    },
                )),
                address_space: AddressSpace::Stack,
            },
            _ => Self::hm_type_from_type_info(&type_info).unwrap_or(HMType::I64),
        }))
    }

    pub(super) fn validate_ctx_field_access(&self, field: &CtxField) -> Result<(), TypeError> {
        if let Some(ctx) = self.probe_ctx.as_ref() {
            ctx.validate_ctx_field_access(field)
                .map_err(|err| TypeError::new(err.to_string()))?;
        }
        Ok(())
    }

    pub(super) fn ctx_field_type(&mut self, field: &CtxField) -> HMType {
        match field {
            CtxField::Context => HMType::Ptr {
                pointee: Box::new(HMType::U8),
                address_space: AddressSpace::Kernel,
            },
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
            | CtxField::SysctlFilePos => HMType::U32,

            CtxField::SockoptLevel
            | CtxField::SockoptOptname
            | CtxField::SockoptOptlen
            | CtxField::SockoptRetval => HMType::I32,
            CtxField::Socket => HMType::Ptr {
                pointee: Box::new(Self::synthetic_bpf_sock_hm_type()),
                address_space: AddressSpace::Kernel,
            },

            CtxField::SockoptOptval | CtxField::SockoptOptvalEnd => HMType::Ptr {
                pointee: Box::new(HMType::U8),
                address_space: AddressSpace::Kernel,
            },

            CtxField::UserIp6
            | CtxField::MsgSrcIp6
            | CtxField::RemoteIp6
            | CtxField::LocalIp6
            | CtxField::SockOpsArgs => HMType::Ptr {
                pointee: Box::new(HMType::Array {
                    elem: Box::new(HMType::U32),
                    len: 4,
                }),
                address_space: AddressSpace::Stack,
            },
            CtxField::SkbCb => HMType::Ptr {
                pointee: Box::new(HMType::Array {
                    elem: Box::new(HMType::U32),
                    len: 5,
                }),
                address_space: AddressSpace::Stack,
            },

            CtxField::Data | CtxField::DataEnd => HMType::Ptr {
                pointee: Box::new(HMType::U8),
                address_space: AddressSpace::Packet,
            },

            CtxField::Timestamp
            | CtxField::CgroupId
            | CtxField::LookupCookie
            | CtxField::SocketCookie
            | CtxField::NetnsCookie
            | CtxField::Hwtstamp
            | CtxField::SockOpsBytesReceived
            | CtxField::SockOpsBytesAcked
            | CtxField::SockOpsSkbHwtstamp => HMType::U64,
            CtxField::SocketUid => HMType::U32,

            CtxField::Arg(idx) => {
                if let Some(ty) = self.trampoline_arg_type(*idx).ok().flatten() {
                    return ty;
                }
                if self
                    .probe_ctx
                    .as_ref()
                    .is_some_and(|ctx| ctx.probe_type.uses_raw_tracepoint_args())
                {
                    return HMType::U64;
                }
                if self.is_userspace_probe() {
                    HMType::Ptr {
                        pointee: Box::new(HMType::U8),
                        address_space: AddressSpace::User,
                    }
                } else {
                    let tvar = *self
                        .ctx_arg_vars
                        .entry(*idx as usize)
                        .or_insert_with(|| self.tvar_gen.fresh());
                    HMType::Var(tvar)
                }
            }

            CtxField::RetVal => {
                if let Some(ty) = self.trampoline_ret_type().ok().flatten() {
                    return ty;
                }
                HMType::I64
            }
            CtxField::KStack | CtxField::UStack => HMType::I64,

            CtxField::Comm => HMType::Ptr {
                pointee: Box::new(HMType::Array {
                    elem: Box::new(HMType::U8),
                    len: 16,
                }),
                address_space: AddressSpace::Stack,
            },

            CtxField::TracepointField(name) => {
                let tvar = *self
                    .ctx_tp_vars
                    .entry(name.clone())
                    .or_insert_with(|| self.tvar_gen.fresh());
                HMType::Var(tvar)
            }
        }
    }

    /// Check if the current probe is a userspace probe
    pub(super) fn is_userspace_probe(&self) -> bool {
        self.probe_ctx
            .as_ref()
            .map(|ctx| ctx.is_userspace())
            .unwrap_or(false)
    }

    /// Determine result type of a binary operation
    pub(super) fn binop_result_type(
        &mut self,
        op: BinOpKind,
        lhs: &HMType,
        rhs: &HMType,
    ) -> Result<HMType, TypeError> {
        // Comparison operators return bool
        if matches!(
            op,
            BinOpKind::Eq
                | BinOpKind::Ne
                | BinOpKind::Lt
                | BinOpKind::Le
                | BinOpKind::Gt
                | BinOpKind::Ge
        ) {
            // Add constraint that operands are comparable
            // For now, we allow comparing any types and check at unification
            return Ok(HMType::Bool);
        }

        // Arithmetic operations
        match op {
            BinOpKind::Add | BinOpKind::Sub => {
                // Pointer arithmetic: ptr + int -> ptr
                if let HMType::Ptr { .. } = lhs {
                    return Ok(lhs.clone());
                }
                // Regular arithmetic - result is larger type
                Ok(self.promote_numeric(lhs, rhs))
            }

            BinOpKind::Mul | BinOpKind::Div | BinOpKind::Mod => Ok(self.promote_numeric(lhs, rhs)),

            BinOpKind::And | BinOpKind::Or | BinOpKind::Xor => Ok(self.promote_numeric(lhs, rhs)),

            BinOpKind::Shl | BinOpKind::Shr => {
                // Shift result type is lhs type
                Ok(lhs.clone())
            }

            _ => Ok(HMType::I64),
        }
    }

    /// Determine result type of a unary operation
    pub(super) fn unaryop_result_type(
        &self,
        op: UnaryOpKind,
        src: &HMType,
    ) -> Result<HMType, TypeError> {
        match op {
            UnaryOpKind::Not => Ok(HMType::Bool),
            UnaryOpKind::BitNot | UnaryOpKind::Neg => Ok(src.clone()),
        }
    }

    /// Promote two numeric types to a common type
    pub(super) fn promote_numeric(&self, lhs: &HMType, rhs: &HMType) -> HMType {
        // If either is a type variable, return I64 as default
        if matches!(lhs, HMType::Var(_)) || matches!(rhs, HMType::Var(_)) {
            return HMType::I64;
        }

        // If either is unknown, return I64
        if matches!(lhs, HMType::Unknown) || matches!(rhs, HMType::Unknown) {
            return HMType::I64;
        }

        // Get sizes
        let lhs_size = self.type_size(lhs);
        let rhs_size = self.type_size(rhs);

        // Prefer signed if either is signed
        let is_signed = self.is_signed(lhs) || self.is_signed(rhs);
        let size = lhs_size.max(rhs_size);

        if is_signed {
            match size {
                1 => HMType::I8,
                2 => HMType::I16,
                4 => HMType::I32,
                _ => HMType::I64,
            }
        } else {
            match size {
                1 => HMType::U8,
                2 => HMType::U16,
                4 => HMType::U32,
                _ => HMType::U64,
            }
        }
    }

    pub(super) fn type_size(&self, ty: &HMType) -> usize {
        match ty {
            HMType::I8 | HMType::U8 | HMType::Bool => 1,
            HMType::I16 | HMType::U16 => 2,
            HMType::I32 | HMType::U32 => 4,
            HMType::I64 | HMType::U64 => 8,
            _ => 8,
        }
    }

    pub(super) fn is_signed(&self, ty: &HMType) -> bool {
        matches!(ty, HMType::I8 | HMType::I16 | HMType::I32 | HMType::I64)
    }

    pub(super) fn hm_type_for_vreg(&self, vreg: VReg) -> HMType {
        self.substitution.apply(&self.vreg_type(vreg))
    }

    pub(super) fn hm_return_type(&self) -> HMType {
        match self.return_var {
            Some(var) => self.substitution.apply(&HMType::Var(var)),
            None => HMType::Unknown,
        }
    }

    pub(super) fn scheme_for_function(
        &self,
        func: &MirFunction,
        env: Option<&SubfnSchemeMap>,
    ) -> TypeScheme {
        let args: Vec<HMType> = (0..func.param_count)
            .map(|i| self.hm_type_for_vreg(VReg(i as u32)))
            .collect();
        let ret = self.hm_return_type();
        let ty = HMType::Fn {
            args,
            ret: Box::new(ret),
        };
        let env_vars = env
            .map(super::subfunctions::env_free_vars)
            .unwrap_or_default();
        let ty_vars = ty.free_vars();
        let quantified = ty_vars.difference(&env_vars).copied().collect();
        TypeScheme { quantified, ty }
    }

    /// Convert HMType to MirType
    pub(super) fn hm_to_mir(&self, ty: &HMType) -> MirType {
        // Apply current substitution first
        let resolved = self.substitution.apply(ty);

        match resolved {
            HMType::Var(_) => MirType::I64, // Unresolved var defaults to I64
            HMType::I8 => MirType::I8,
            HMType::I16 => MirType::I16,
            HMType::I32 => MirType::I32,
            HMType::I64 => MirType::I64,
            HMType::U8 => MirType::U8,
            HMType::U16 => MirType::U16,
            HMType::U32 => MirType::U32,
            HMType::U64 => MirType::U64,
            HMType::Bool => MirType::Bool,
            HMType::Ptr {
                pointee,
                address_space,
            } => MirType::Ptr {
                pointee: Box::new(self.hm_to_mir(&pointee)),
                address_space,
            },
            HMType::Array { elem, len } => MirType::Array {
                elem: Box::new(self.hm_to_mir(&elem)),
                len,
            },
            HMType::Struct {
                name,
                kernel_btf_type_id,
                fields,
            } => {
                let mut mir_fields = Vec::new();
                let mut offset = 0;
                for (field_name, field_ty) in fields {
                    let mir_ty = self.hm_to_mir(&field_ty);
                    let size = mir_ty.size();
                    mir_fields.push(crate::compiler::mir::StructField {
                        name: field_name,
                        ty: mir_ty,
                        offset,
                        synthetic: false,
                        bitfield: None,
                    });
                    offset += size;
                }
                MirType::Struct {
                    name,
                    kernel_btf_type_id,
                    fields: mir_fields,
                }
            }
            HMType::MapRef { key_ty, val_ty } => MirType::MapRef {
                key_ty: Box::new(self.hm_to_mir(&key_ty)),
                val_ty: Box::new(self.hm_to_mir(&val_ty)),
            },
            HMType::Fn { .. } => MirType::I64, // Functions not in MirType
            HMType::Unknown => MirType::Unknown,
        }
    }

    fn mir_type_carries_non_hm_layout(ty: &MirType) -> bool {
        match ty {
            MirType::Ptr { pointee, .. } => Self::mir_type_carries_non_hm_layout(pointee),
            MirType::Array { elem, .. } => Self::mir_type_carries_non_hm_layout(elem),
            MirType::Struct {
                kernel_btf_type_id,
                fields,
                ..
            } => {
                if kernel_btf_type_id.is_some() {
                    return true;
                }

                let mut cursor = 0usize;
                for field in fields {
                    if field.synthetic || field.bitfield.is_some() {
                        return true;
                    }
                    if field.offset != cursor {
                        return true;
                    }
                    let Some(next_cursor) = cursor.checked_add(field.ty.size()) else {
                        return true;
                    };
                    cursor = next_cursor;
                }
                false
            }
            _ => false,
        }
    }

    fn preferred_hint_layout(&self, vreg: VReg, inferred: MirType) -> MirType {
        let Some(hints) = self.type_hints else {
            return inferred;
        };
        let Some(hint) = hints.get(&vreg) else {
            return inferred;
        };
        if !Self::mir_type_carries_non_hm_layout(hint) {
            return inferred;
        }
        if HMType::from_mir_type(hint) == HMType::from_mir_type(&inferred) {
            hint.clone()
        } else {
            inferred
        }
    }

    /// Get the type for a vreg (after inference)
    pub fn get_type(&self, vreg: VReg) -> Option<MirType> {
        let tvar = self.vreg_vars.get(&vreg)?;
        let hm_type = self.substitution.apply(&HMType::Var(*tvar));
        Some(self.preferred_hint_layout(vreg, self.hm_to_mir(&hm_type)))
    }

    /// Get all inferred types
    pub fn types(&self) -> HashMap<VReg, MirType> {
        let mut result = HashMap::new();
        for (vreg, tvar) in &self.vreg_vars {
            let hm_type = self.substitution.apply(&HMType::Var(*tvar));
            result.insert(
                *vreg,
                self.preferred_hint_layout(*vreg, self.hm_to_mir(&hm_type)),
            );
        }
        result
    }
}
