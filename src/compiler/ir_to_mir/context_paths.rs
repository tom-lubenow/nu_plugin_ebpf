use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::mir::CtxStoreTarget;
use crate::kernel_btf::KernelBtf;

impl<'a> HirToMirLowering<'a> {
    fn ctx_path_member_name(member: &PathMember) -> Result<String, CompileError> {
        match member {
            PathMember::String { val, .. } => Ok(val.clone()),
            PathMember::Int { val, .. } => Ok(format!("arg{}", val)),
        }
    }

    fn ctx_field_from_name(field_name: String) -> Result<CtxField, CompileError> {
        Ok(match field_name.as_str() {
            "pid" => CtxField::Pid,
            "tid" | "tgid" => CtxField::Tid,
            "uid" => CtxField::Uid,
            "gid" => CtxField::Gid,
            "comm" => CtxField::Comm,
            "cpu" => CtxField::Cpu,
            "ktime" | "timestamp" => CtxField::Timestamp,
            "cgroup_id" => CtxField::CgroupId,
            "packet_len" | "len" => CtxField::PacketLen,
            "pkt_type" => CtxField::PktType,
            "queue_mapping" => CtxField::QueueMapping,
            "eth_protocol" => CtxField::EthProtocol,
            "vlan_present" => CtxField::VlanPresent,
            "vlan_tci" => CtxField::VlanTci,
            "vlan_proto" => CtxField::VlanProto,
            "cb" => CtxField::SkbCb,
            "tc_classid" => CtxField::TcClassid,
            "napi_id" => CtxField::NapiId,
            "wire_len" => CtxField::WireLen,
            "gso_segs" => CtxField::GsoSegs,
            "gso_size" => CtxField::GsoSize,
            "hwtstamp" => CtxField::Hwtstamp,
            "data" => CtxField::Data,
            "data_end" => CtxField::DataEnd,
            "ingress_ifindex" => CtxField::IngressIfindex,
            "rx_queue_index" => CtxField::RxQueueIndex,
            "egress_ifindex" => CtxField::EgressIfindex,
            "tc_index" => CtxField::TcIndex,
            "hash" => CtxField::SkbHash,
            "user_family" => CtxField::UserFamily,
            "user_ip4" => CtxField::UserIp4,
            "user_ip6" => CtxField::UserIp6,
            "user_port" => CtxField::UserPort,
            "family" => CtxField::Family,
            "sock_type" | "type" => CtxField::SockType,
            "protocol" => CtxField::Protocol,
            "sk" => CtxField::Socket,
            "bound_dev_if" => CtxField::BoundDevIf,
            "mark" => CtxField::SockMark,
            "priority" => CtxField::SockPriority,
            "msg_src_ip4" => CtxField::MsgSrcIp4,
            "msg_src_ip6" => CtxField::MsgSrcIp6,
            "remote_ip4" => CtxField::RemoteIp4,
            "remote_ip6" => CtxField::RemoteIp6,
            "remote_port" => CtxField::RemotePort,
            "local_ip4" => CtxField::LocalIp4,
            "local_ip6" => CtxField::LocalIp6,
            "local_port" => CtxField::LocalPort,
            "cookie" => CtxField::LookupCookie,
            "sample" | "raw" => CtxField::LircSample,
            "value" => CtxField::LircValue,
            "mode" => CtxField::LircMode,
            "socket_cookie" => CtxField::SocketCookie,
            "socket_uid" => CtxField::SocketUid,
            "netns_cookie" => CtxField::NetnsCookie,
            "args" => CtxField::SockOpsArgs,
            "snd_cwnd" => CtxField::SockOpsSndCwnd,
            "srtt_us" => CtxField::SockOpsSrttUs,
            "write" => CtxField::SysctlWrite,
            "file_pos" => CtxField::SysctlFilePos,
            "rtt_min" => CtxField::SockOpsRttMin,
            "snd_ssthresh" => CtxField::SockOpsSndSsthresh,
            "rcv_nxt" => CtxField::SockOpsRcvNxt,
            "snd_nxt" => CtxField::SockOpsSndNxt,
            "snd_una" => CtxField::SockOpsSndUna,
            "packets_out" => CtxField::SockOpsPacketsOut,
            "retrans_out" => CtxField::SockOpsRetransOut,
            "total_retrans" => CtxField::SockOpsTotalRetrans,
            "bytes_received" => CtxField::SockOpsBytesReceived,
            "bytes_acked" => CtxField::SockOpsBytesAcked,
            "skb_len" => CtxField::SockOpsSkbLen,
            "skb_tcp_flags" => CtxField::SockOpsSkbTcpFlags,
            "skb_hwtstamp" => CtxField::SockOpsSkbHwtstamp,
            "level" => CtxField::SockoptLevel,
            "optname" => CtxField::SockoptOptname,
            "optlen" => CtxField::SockoptOptlen,
            "optval" => CtxField::SockoptOptval,
            "optval_end" => CtxField::SockoptOptvalEnd,
            "sockopt_retval" => CtxField::SockoptRetval,
            "retval" => CtxField::RetVal,
            "kstack" => CtxField::KStack,
            "ustack" => CtxField::UStack,
            s if s.starts_with("arg") => {
                let num: u8 = s[3..].parse().map_err(|_| {
                    CompileError::UnsupportedInstruction(format!("Invalid arg: {}", s))
                })?;
                CtxField::Arg(num)
            }
            _ => CtxField::TracepointField(field_name),
        })
    }

    fn non_tracepoint_ctx_field_from_name(field_name: &str) -> Option<CtxField> {
        Some(match field_name {
            "ifindex" => CtxField::Ifindex,
            "access_type" => CtxField::DeviceAccessType,
            "major" => CtxField::DeviceMajor,
            "minor" => CtxField::DeviceMinor,
            "op" => CtxField::SockOp,
            "is_fullsock" => CtxField::IsFullsock,
            "snd_cwnd" => CtxField::SockOpsSndCwnd,
            "srtt_us" => CtxField::SockOpsSrttUs,
            "cb_flags" => CtxField::SockOpsCbFlags,
            "state" => CtxField::SockState,
            "rtt_min" => CtxField::SockOpsRttMin,
            "snd_ssthresh" => CtxField::SockOpsSndSsthresh,
            "rcv_nxt" => CtxField::SockOpsRcvNxt,
            "snd_nxt" => CtxField::SockOpsSndNxt,
            "snd_una" => CtxField::SockOpsSndUna,
            "mss_cache" => CtxField::SockOpsMssCache,
            "ecn_flags" => CtxField::SockOpsEcnFlags,
            "rate_delivered" => CtxField::SockOpsRateDelivered,
            "rate_interval_us" => CtxField::SockOpsRateIntervalUs,
            "packets_out" => CtxField::SockOpsPacketsOut,
            "retrans_out" => CtxField::SockOpsRetransOut,
            "total_retrans" => CtxField::SockOpsTotalRetrans,
            "segs_in" => CtxField::SockOpsSegsIn,
            "data_segs_in" => CtxField::SockOpsDataSegsIn,
            "segs_out" => CtxField::SockOpsSegsOut,
            "data_segs_out" => CtxField::SockOpsDataSegsOut,
            "lost_out" => CtxField::SockOpsLostOut,
            "sacked_out" => CtxField::SockOpsSackedOut,
            "sk_txhash" => CtxField::SockOpsSkTxhash,
            "bytes_received" => CtxField::SockOpsBytesReceived,
            "bytes_acked" => CtxField::SockOpsBytesAcked,
            "skb_len" => CtxField::SockOpsSkbLen,
            "skb_tcp_flags" => CtxField::SockOpsSkbTcpFlags,
            "skb_hwtstamp" => CtxField::SockOpsSkbHwtstamp,
            _ => return None,
        })
    }

    pub(super) fn resolve_ctx_field_from_path(
        &self,
        path: &CellPath,
    ) -> Result<(CtxField, usize), CompileError> {
        let field_name = Self::ctx_path_member_name(&path.members[0])?;
        if field_name == "arg" {
            let Some(arg_member) = path.members.get(1) else {
                return Err(CompileError::UnsupportedInstruction(
                    "ctx.arg.<name> requires a named BTF parameter".into(),
                ));
            };
            let PathMember::String { val: arg_name, .. } = arg_member else {
                return Err(CompileError::UnsupportedInstruction(
                    "ctx.arg.<name> requires a named BTF parameter".into(),
                ));
            };
            let Some(ctx) = self.probe_ctx else {
                return Err(CompileError::UnsupportedInstruction(
                    "ctx.arg.<name> is only available on kernel-BTF-backed contexts".into(),
                ));
            };
            let Some(arg_idx) = (match ctx.probe_type {
                EbpfProgramType::StructOps => {
                    let value_type_name =
                        ctx.struct_ops_value_type_name.as_deref().ok_or_else(|| {
                            CompileError::UnsupportedInstruction(format!(
                                "missing struct_ops value type for callback '{}'",
                                ctx.target
                            ))
                        })?;
                    KernelBtf::get()
                        .struct_ops_callback_arg_index_by_name(
                            value_type_name,
                            &ctx.target,
                            arg_name,
                        )
                        .map_err(|e| {
                            CompileError::UnsupportedInstruction(format!(
                                "failed to resolve ctx.arg.{} for struct_ops {}.{}: {}",
                                arg_name, value_type_name, ctx.target, e
                            ))
                        })?
                }
                EbpfProgramType::TpBtf => KernelBtf::get()
                    .tp_btf_arg_index_by_name(&ctx.target, arg_name)
                    .map_err(|e| {
                        CompileError::UnsupportedInstruction(format!(
                            "failed to resolve ctx.arg.{} for tp_btf:{}: {}",
                            arg_name, ctx.target, e
                        ))
                    })?,
                EbpfProgramType::Lsm => KernelBtf::get()
                    .lsm_hook_arg_index_by_name(&ctx.target, arg_name)
                    .map_err(|e| {
                        CompileError::UnsupportedInstruction(format!(
                            "failed to resolve ctx.arg.{} for lsm:{}: {}",
                            arg_name, ctx.target, e
                        ))
                    })?,
                probe_type if probe_type.uses_btf_trampoline() => KernelBtf::get()
                    .function_trampoline_arg_index_by_name(&ctx.target, arg_name)
                    .map_err(|e| {
                        CompileError::UnsupportedInstruction(format!(
                            "failed to resolve ctx.arg.{} for {}:{}: {}",
                            arg_name,
                            ctx.probe_type.section_prefix(),
                            ctx.target,
                            e
                        ))
                    })?,
                _ => {
                    return Err(CompileError::UnsupportedInstruction(
                        "ctx.arg.<name> is only available on kernel-BTF-backed contexts".into(),
                    ));
                }
            }) else {
                let context = match ctx.probe_type {
                    EbpfProgramType::StructOps => {
                        let value_type_name = ctx
                            .struct_ops_value_type_name
                            .as_deref()
                            .unwrap_or("<unknown>");
                        format!("struct_ops {}.{}", value_type_name, ctx.target)
                    }
                    EbpfProgramType::TpBtf => format!("tp_btf:{}", ctx.target),
                    EbpfProgramType::Lsm => format!("lsm:{}", ctx.target),
                    _ => format!("{}:{}", ctx.probe_type.section_prefix(), ctx.target),
                };
                return Err(CompileError::UnsupportedInstruction(format!(
                    "ctx.arg.{} is not a valid argument name for {}",
                    arg_name, context
                )));
            };
            let arg_idx = u8::try_from(arg_idx).map_err(|_| {
                CompileError::UnsupportedInstruction(format!(
                    "ctx.arg.{} resolved to unsupported parameter index {}",
                    arg_name, arg_idx
                ))
            })?;
            return Ok((CtxField::Arg(arg_idx), 2));
        }

        if let Some(field) = self
            .probe_ctx
            .and_then(|ctx| ctx.probe_type.ctx_field_alias(&field_name))
        {
            return Ok((field, 1));
        }

        let field = match (
            self.probe_ctx.map(|ctx| ctx.probe_type),
            field_name.as_str(),
        ) {
            (Some(EbpfProgramType::Tracepoint), _) => Self::ctx_field_from_name(field_name)?,
            _ => Self::non_tracepoint_ctx_field_from_name(&field_name)
                .unwrap_or(Self::ctx_field_from_name(field_name)?),
        };

        Ok((field, 1))
    }

    fn resolve_ctx_store_target_from_path(
        &self,
        path: &CellPath,
    ) -> Result<CtxStoreTarget, CompileError> {
        let path_desc = Self::typed_value_path_desc(&path.members);
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires probe context",
                path_desc
            )));
        };
        match (ctx.probe_type, path.members.as_slice()) {
            (EbpfProgramType::SockOps, [PathMember::String { val, .. }]) if val == "reply" => {
                Ok(CtxStoreTarget::SockOpsReply)
            }
            (
                EbpfProgramType::SockOps,
                [
                    PathMember::String { val, .. },
                    PathMember::Int { val: index, .. },
                ],
            ) if val == "replylong" => {
                let index = u8::try_from(*index).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "ctx.replylong index must be in 0..=3, got {}",
                        index
                    ))
                })?;
                if index >= 4 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "ctx.replylong index must be in 0..=3, got {}",
                        index
                    )));
                }
                Ok(CtxStoreTarget::SockOpsReplyLong(index))
            }
            (EbpfProgramType::SockOps, [PathMember::String { val, .. }]) if val == "replylong" => {
                Err(CompileError::UnsupportedInstruction(
                    "ctx.replylong assignment requires a fixed index, e.g. $ctx.replylong.0 = ..."
                        .into(),
                ))
            }
            (EbpfProgramType::CgroupSockopt, [PathMember::String { val, .. }])
                if val == "sockopt_retval" =>
            {
                ctx.validate_ctx_field_access(&CtxField::SockoptRetval)?;
                Ok(CtxStoreTarget::SockoptRetval)
            }
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' is only supported for sock_ops reply fields and cgroup_sockopt:get sockopt_retval",
                path_desc
            ))),
        }
    }

    fn ctx_store_target_type(target: &CtxStoreTarget) -> MirType {
        match target {
            CtxStoreTarget::SockOpsReply | CtxStoreTarget::SockOpsReplyLong(_) => MirType::U32,
            CtxStoreTarget::SockoptRetval => MirType::I32,
        }
    }

    pub(super) fn lower_context_upsert_cell_path(
        &mut self,
        src_dst: RegId,
        path: &CellPath,
        new_value: RegId,
    ) -> Result<(), CompileError> {
        let target = self.resolve_ctx_store_target_from_path(path)?;
        let new_value_vreg = self.get_vreg(new_value);
        let new_value_runtime_ty = self
            .typed_value_runtime_type(new_value, new_value_vreg)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' requires type information for the new value",
                    Self::typed_value_path_desc(&path.members)
                ))
            })?;
        let target_ty = Self::ctx_store_target_type(&target);
        let stored_vreg = match new_value_runtime_ty {
            MirType::Bool
            | MirType::I8
            | MirType::U8
            | MirType::I16
            | MirType::U16
            | MirType::I32
            | MirType::U32
            | MirType::I64
            | MirType::U64 => {
                let widened = self.func.alloc_vreg();
                self.vreg_type_hints.insert(widened, target_ty.clone());
                self.emit(MirInst::Copy {
                    dst: widened,
                    src: MirValue::VReg(new_value_vreg),
                });
                widened
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' requires an integer-compatible scalar value",
                    Self::typed_value_path_desc(&path.members)
                )));
            }
        };
        self.emit(MirInst::StoreCtxField {
            target,
            val: MirValue::VReg(stored_vreg),
            ty: target_ty,
        });
        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = true;
        Ok(())
    }
}
