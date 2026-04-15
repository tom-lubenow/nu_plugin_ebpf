use crate::compiler::{
    EbpfProgramType,
    mir::{AddressSpace, CtxField, MirType, StructField},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextFieldTypeSpec {
    pub semantic_ty: MirType,
    pub runtime_ty: MirType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextFieldLoadGuard {
    SockOpsCallback(SockOpsCallbackGuard),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockOpsCallbackGuard {
    PacketData,
    PacketMetadata,
    TcpFlags,
    Hwtstamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextFieldProjectionSpec {
    pub runtime_ty: MirType,
    pub stack_slot_ty: Option<MirType>,
    pub normalize_u32_words_host_order: bool,
    pub validate_socket_projection: bool,
}

impl ContextFieldTypeSpec {
    fn value(ty: MirType) -> Self {
        Self {
            semantic_ty: ty.clone(),
            runtime_ty: ty,
        }
    }

    fn stack_backed(semantic_ty: MirType) -> Self {
        Self {
            runtime_ty: MirType::Ptr {
                pointee: Box::new(semantic_ty.clone()),
                address_space: AddressSpace::Stack,
            },
            semantic_ty,
        }
    }
}

impl ContextFieldProjectionSpec {
    fn direct(runtime_ty: MirType) -> Self {
        Self {
            runtime_ty,
            stack_slot_ty: None,
            normalize_u32_words_host_order: false,
            validate_socket_projection: false,
        }
    }

    fn stack_backed(semantic_ty: MirType, normalize_u32_words_host_order: bool) -> Self {
        Self {
            runtime_ty: MirType::Ptr {
                pointee: Box::new(semantic_ty.clone()),
                address_space: AddressSpace::Stack,
            },
            stack_slot_ty: Some(semantic_ty),
            normalize_u32_words_host_order,
            validate_socket_projection: false,
        }
    }
}

const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: i64 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: i64 = 5;
const BPF_SOCK_OPS_PARSE_HDR_OPT_CB: i64 = 13;
const BPF_SOCK_OPS_HDR_OPT_LEN_CB: i64 = 14;
const BPF_SOCK_OPS_WRITE_HDR_OPT_CB: i64 = 15;
const BPF_SOCK_OPS_TSTAMP_SCHED_CB: i64 = 16;
const BPF_SOCK_OPS_TSTAMP_SND_SW_CB: i64 = 17;
const BPF_SOCK_OPS_TSTAMP_SND_HW_CB: i64 = 18;
const BPF_SOCK_OPS_TSTAMP_ACK_CB: i64 = 19;
const BPF_SOCK_OPS_TSTAMP_SENDMSG_CB: i64 = 20;

impl ContextFieldLoadGuard {
    pub(crate) fn witness_field(self) -> CtxField {
        match self {
            Self::SockOpsCallback(_) => CtxField::SockOp,
        }
    }

    pub(crate) fn allows_value(self, value: i64) -> bool {
        match self {
            Self::SockOpsCallback(guard) => guard.allows_callback_op(value),
        }
    }

    pub(crate) fn error(self, field: &CtxField) -> String {
        match self {
            Self::SockOpsCallback(_) => format!(
                "ctx.{} on sock_ops requires proving a packet-aware ctx.op callback before use",
                field.display_name()
            ),
        }
    }
}

impl SockOpsCallbackGuard {
    fn allows_callback_op(self, op: i64) -> bool {
        match self {
            Self::PacketData => Self::callback_has_packet_data(op),
            Self::PacketMetadata => Self::callback_has_packet_metadata(op),
            Self::TcpFlags => Self::callback_has_tcp_flags(op),
            Self::Hwtstamp => Self::callback_has_hwtstamp(op),
        }
    }

    fn callback_has_packet_data(op: i64) -> bool {
        matches!(
            op,
            BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
                | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
                | BPF_SOCK_OPS_PARSE_HDR_OPT_CB
                | BPF_SOCK_OPS_WRITE_HDR_OPT_CB
        )
    }

    fn callback_has_packet_metadata(op: i64) -> bool {
        Self::callback_has_packet_data(op) || Self::callback_has_hwtstamp(op)
    }

    fn callback_has_tcp_flags(op: i64) -> bool {
        Self::callback_has_packet_data(op) || op == BPF_SOCK_OPS_HDR_OPT_LEN_CB
    }

    fn callback_has_hwtstamp(op: i64) -> bool {
        matches!(
            op,
            BPF_SOCK_OPS_TSTAMP_SCHED_CB
                | BPF_SOCK_OPS_TSTAMP_SND_SW_CB
                | BPF_SOCK_OPS_TSTAMP_SND_HW_CB
                | BPF_SOCK_OPS_TSTAMP_ACK_CB
                | BPF_SOCK_OPS_TSTAMP_SENDMSG_CB
        )
    }
}

pub(crate) fn synthetic_bpf_sock_type() -> MirType {
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
                name: "src_ip4".to_string(),
                ty: MirType::U32,
                offset: 24,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "src_ip6".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U32),
                    len: 4,
                },
                offset: 28,
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
                name: "dst_ip4".to_string(),
                ty: MirType::U32,
                offset: 52,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "dst_ip6".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U32),
                    len: 4,
                },
                offset: 56,
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

fn raw_ctx_field_type_spec(field: &CtxField) -> Option<ContextFieldTypeSpec> {
    Some(match field {
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
        | CtxField::SysctlFilePos
        | CtxField::SocketUid => ContextFieldTypeSpec::value(MirType::U32),
        CtxField::TstampType => ContextFieldTypeSpec::value(MirType::U8),
        CtxField::Timestamp
        | CtxField::CgroupId
        | CtxField::PerfSamplePeriod
        | CtxField::PerfAddr
        | CtxField::LookupCookie
        | CtxField::SocketCookie
        | CtxField::NetnsCookie
        | CtxField::Tstamp
        | CtxField::Hwtstamp
        | CtxField::SockOpsBytesReceived
        | CtxField::SockOpsBytesAcked
        | CtxField::SockOpsSkbHwtstamp => ContextFieldTypeSpec::value(MirType::U64),
        CtxField::SockoptLevel
        | CtxField::SockoptOptname
        | CtxField::SockoptOptlen
        | CtxField::SockoptRetval => ContextFieldTypeSpec::value(MirType::I32),
        CtxField::Context => ContextFieldTypeSpec::value(MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        }),
        CtxField::Socket => ContextFieldTypeSpec::value(MirType::Ptr {
            pointee: Box::new(synthetic_bpf_sock_type()),
            address_space: AddressSpace::Kernel,
        }),
        CtxField::SockoptOptval | CtxField::SockoptOptvalEnd => {
            ContextFieldTypeSpec::value(MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            })
        }
        CtxField::UserIp6
        | CtxField::MsgSrcIp6
        | CtxField::RemoteIp6
        | CtxField::LocalIp6
        | CtxField::SockOpsArgs => ContextFieldTypeSpec::stack_backed(MirType::Array {
            elem: Box::new(MirType::U32),
            len: 4,
        }),
        CtxField::SkbCb => ContextFieldTypeSpec::stack_backed(MirType::Array {
            elem: Box::new(MirType::U32),
            len: 5,
        }),
        CtxField::Data | CtxField::DataMeta | CtxField::DataEnd => {
            ContextFieldTypeSpec::value(MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Packet,
            })
        }
        CtxField::Comm => ContextFieldTypeSpec::stack_backed(MirType::Array {
            elem: Box::new(MirType::U8),
            len: 16,
        }),
        CtxField::Arg(_) | CtxField::RetVal | CtxField::KStack | CtxField::UStack => {
            return None;
        }
        CtxField::TracepointField(_) => return None,
    })
}

pub(crate) fn static_ctx_field_type_spec(field: &CtxField) -> Option<ContextFieldTypeSpec> {
    raw_ctx_field_type_spec(field)
}

pub(crate) fn program_type_ctx_field_type_spec(
    program_type: EbpfProgramType,
    field: &CtxField,
) -> Option<ContextFieldTypeSpec> {
    program_type
        .base_ctx_field_access_error(field)
        .is_none()
        .then(|| raw_ctx_field_type_spec(field))
        .flatten()
}

pub(crate) fn program_type_ctx_field_load_guard(
    program_type: EbpfProgramType,
    field: &CtxField,
) -> Option<ContextFieldLoadGuard> {
    if program_type != EbpfProgramType::SockOps {
        return None;
    }
    Some(match field {
        CtxField::Data | CtxField::DataEnd => {
            ContextFieldLoadGuard::SockOpsCallback(SockOpsCallbackGuard::PacketData)
        }
        CtxField::PacketLen | CtxField::SockOpsSkbLen => {
            ContextFieldLoadGuard::SockOpsCallback(SockOpsCallbackGuard::PacketMetadata)
        }
        CtxField::SockOpsSkbTcpFlags => {
            ContextFieldLoadGuard::SockOpsCallback(SockOpsCallbackGuard::TcpFlags)
        }
        CtxField::SockOpsSkbHwtstamp => {
            ContextFieldLoadGuard::SockOpsCallback(SockOpsCallbackGuard::Hwtstamp)
        }
        _ => return None,
    })
}

fn raw_ctx_field_projection_spec(field: &CtxField) -> Option<ContextFieldProjectionSpec> {
    let type_spec = raw_ctx_field_type_spec(field)?;
    Some(match field {
        CtxField::Data
        | CtxField::DataMeta
        | CtxField::DataEnd
        | CtxField::SockoptOptval
        | CtxField::SockoptOptvalEnd => ContextFieldProjectionSpec::direct(type_spec.runtime_ty),
        CtxField::Socket => ContextFieldProjectionSpec {
            runtime_ty: type_spec.runtime_ty,
            stack_slot_ty: None,
            normalize_u32_words_host_order: false,
            validate_socket_projection: true,
        },
        CtxField::Comm => ContextFieldProjectionSpec::stack_backed(type_spec.semantic_ty, false),
        CtxField::UserIp6 | CtxField::MsgSrcIp6 => {
            ContextFieldProjectionSpec::stack_backed(type_spec.semantic_ty, true)
        }
        CtxField::RemoteIp6 | CtxField::LocalIp6 | CtxField::SockOpsArgs | CtxField::SkbCb => {
            ContextFieldProjectionSpec::stack_backed(type_spec.semantic_ty, false)
        }
        _ => return None,
    })
}

pub(crate) fn static_ctx_field_projection_spec(
    field: &CtxField,
) -> Option<ContextFieldProjectionSpec> {
    raw_ctx_field_projection_spec(field)
}

pub(crate) fn program_type_ctx_field_projection_spec(
    program_type: EbpfProgramType,
    field: &CtxField,
) -> Option<ContextFieldProjectionSpec> {
    program_type
        .base_ctx_field_access_error(field)
        .is_none()
        .then(|| raw_ctx_field_projection_spec(field))
        .flatten()
}
